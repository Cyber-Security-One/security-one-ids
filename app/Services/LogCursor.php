<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

/**
 * Follows an append-only log file across rotations, truncations and restarts.
 *
 * Extracted rather than reimplemented. Every bug in a log cursor is silent —
 * the agent keeps running and simply stops seeing part of what happened — and
 * this one has already had three of them found and fixed:
 *
 *  - A truncate-and-rewrite that landed on a similar length was undetectable
 *    by inode and size alone, leaving the cursor parked past the new content
 *    forever. It now fingerprints the opening bytes.
 *  - A rotation dropped whatever had been written to the old file since the
 *    last read. The old file is now located by inode and drained first.
 *  - A partial trailing line was consumed, permanently losing the record that
 *    was mid-write.
 *
 * The cursor is returned rather than committed, so the caller can persist it
 * only once the data is safely somewhere. Committing inside the read would
 * mean a crash between reading and storing loses that window, because the
 * cursor already claims those bytes were handled.
 */
class LogCursor
{
    private string $statePath;
    private int $maxBytesPerCycle;

    public function __construct(string $statePath, int $maxBytesPerCycle = 8 * 1024 * 1024)
    {
        $this->statePath = $statePath;
        $this->maxBytesPerCycle = max(64 * 1024, $maxBytesPerCycle);
    }

    public function getStatePath(): string
    {
        return $this->statePath;
    }

    /**
     * @return array{lines: array<int, string>, cursor: ?array}
     */
    public function read(string $logPath): array
    {
        $state = $this->load();

        clearstatcache(true, $logPath);
        $stat = @stat($logPath);

        if ($stat === false) {
            return ['lines' => [], 'cursor' => null];
        }

        $inode = (int) $stat['ino'];
        $size = (int) $stat['size'];
        $position = (int) ($state['position'] ?? 0);
        $previousInode = (int) ($state['inode'] ?? 0);

        // Inode plus size cannot detect a truncate-and-rewrite that lands on
        // a similar length; comparing the first bytes is what catches it, and
        // it is what log shippers do for the same reason.
        $fingerprint = $this->fingerprint($logPath);
        $previousFingerprint = (string) ($state['fingerprint'] ?? '');

        $lines = [];
        $budget = $this->maxBytesPerCycle;

        if ($previousInode !== 0 && $previousInode !== $inode) {
            // The file we were following still exists under another name, and
            // its tail holds everything written between our last read and the
            // rotation.
            $rotated = $this->findRotatedFile($logPath, $previousInode);

            if ($rotated !== null) {
                $tail = $this->readFrom($rotated, $position, $budget);
                $lines = $tail['lines'];
                $budget -= $tail['consumed'];

                Log::info('[LogCursor] Drained rotated file', [
                    'file' => basename($rotated),
                    'lines' => count($tail['lines']),
                ]);
            }

            $position = 0;
        } elseif ($size < $position
            || ($previousFingerprint !== '' && $fingerprint !== null && $fingerprint !== $previousFingerprint)
        ) {
            Log::warning('[LogCursor] File replaced in place, restarting from top', ['file' => basename($logPath)]);
            $position = 0;
        }

        if ($size <= $position) {
            return [
                'lines' => $lines,
                'cursor' => ['inode' => $inode, 'position' => $position, 'fingerprint' => $fingerprint],
            ];
        }

        $skipAhead = false;

        if ($size - $position > $budget) {
            $skipped = $size - $position - $budget;
            $position = $size - $budget;
            $skipAhead = true;

            Log::warning('[LogCursor] Backlog exceeded cycle budget, skipping ahead', [
                'file' => basename($logPath),
                'skipped_bytes' => $skipped,
            ]);
        }

        $current = $this->readFrom($logPath, $position, $budget, $skipAhead && $position > 0);

        return [
            'lines' => array_merge($lines, $current['lines']),
            'cursor' => [
                'inode' => $inode,
                'position' => $position + $current['consumed'],
                'fingerprint' => $fingerprint,
            ],
        ];
    }

    /**
     * Persist the cursor. Call only once the data it covers is safely stored.
     */
    public function commit(?array $cursor): void
    {
        if ($cursor === null) {
            return;
        }

        // Write-then-rename: a torn write would leave a truncated cursor
        // file, which restarts the reader from byte zero and replays the
        // entire log.
        $payload = json_encode([
            'inode' => (int) $cursor['inode'],
            'position' => (int) $cursor['position'],
            'fingerprint' => $cursor['fingerprint'] ?? null,
            'updated_at' => now()->toIso8601String(),
        ]);

        $tmp = $this->statePath . '.tmp';

        if (@file_put_contents($tmp, $payload) !== false) {
            @rename($tmp, $this->statePath);
        }
    }

    private function load(): array
    {
        if (!is_file($this->statePath)) {
            return [];
        }

        $state = json_decode((string) @file_get_contents($this->statePath), true);

        return is_array($state) ? $state : [];
    }

    /**
     * Read complete lines from an offset, never consuming a partial trailing
     * line: the writer may be mid-write, and advancing past half a record
     * would drop it permanently.
     *
     * @return array{lines: array<int, string>, consumed: int}
     */
    private function readFrom(string $path, int $offset, int $budget, bool $dropFirstPartial = false): array
    {
        $handle = @fopen($path, 'r');

        if ($handle === false) {
            return ['lines' => [], 'consumed' => 0];
        }

        fseek($handle, $offset);

        $consumed = 0;

        if ($dropFirstPartial) {
            $discard = fgets($handle);

            if ($discard !== false) {
                $consumed += strlen($discard);
            }
        }

        $lines = [];

        while ($consumed < $budget && ($raw = fgets($handle)) !== false) {
            if (!str_ends_with($raw, "\n")) {
                break;
            }

            $consumed += strlen($raw);
            $line = trim($raw);

            if ($line !== '') {
                $lines[] = $line;
            }
        }

        fclose($handle);

        return ['lines' => $lines, 'consumed' => $consumed];
    }

    /**
     * Locate the file we were following after a rotation, by inode. Matching
     * on inode rather than a naming convention keeps this working whether the
     * writer rotates to `.1`, a timestamp suffix, or something else.
     */
    private function findRotatedFile(string $logPath, int $inode): ?string
    {
        foreach ((array) @glob($logPath . '*') as $candidate) {
            if ($candidate === $logPath || !is_file($candidate)) {
                continue;
            }

            clearstatcache(true, $candidate);
            $stat = @stat($candidate);

            if ($stat !== false && (int) $stat['ino'] === $inode) {
                return $candidate;
            }
        }

        return null;
    }

    private function fingerprint(string $path, int $bytes = 256): ?string
    {
        $handle = @fopen($path, 'r');

        if ($handle === false) {
            return null;
        }

        $head = fread($handle, $bytes);
        fclose($handle);

        return $head === false || $head === '' ? null : md5($head);
    }
}

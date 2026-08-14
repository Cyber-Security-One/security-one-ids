<?php

namespace App\Services;

use App\Services\Detection\OsqueryEngine;
use Illuminate\Support\Facades\Log;

/**
 * EDR Event Collector
 *
 * Tails the endpoint sensor's NDJSON results log, normalises each row into a
 * platform-neutral process event, runs the behaviour rules, and hands the
 * resulting alerts to the Hub.
 *
 * The read side deliberately mirrors WafSyncService::collectSuricataAlerts():
 * a byte offset in storage/, rotation detection, a per-cycle cap. What is new
 * is that we do NOT forward the raw stream. A moderately busy host emits on
 * the order of half a million exec events a day; only rule hits and a compact
 * rollup travel to the Hub.
 */
class EdrEventCollector
{
    /** Never read more than this per cycle — a fork bomb must not OOM PHP. */
    private const MAX_BYTES_PER_CYCLE = 8 * 1024 * 1024;

    /** Upper bound on alerts shipped per cycle. */
    private const MAX_ALERTS_PER_CYCLE = 100;

    /** Binaries belonging to this product; their execs are our own noise. */
    private const AGENT_BINARIES = [
        'osqueryd', 'osqueryi', 'suricata', 'snort',
        'clamscan', 'freshclam', 'clamd',
    ];

    private OsqueryEngine $engine;
    private EdrRuleEngine $rules;
    private EdrEventSpool $spool;
    private EdrAlertFactory $factory;
    private \App\Services\Quality\EdrRuleGovernor $governor;

    /** @var array<int, string> uid => username */
    private array $userCache = [];

    public function __construct(
        OsqueryEngine $engine,
        EdrRuleEngine $rules,
        EdrEventSpool $spool,
        EdrAlertFactory $factory,
        \App\Services\Quality\EdrRuleGovernor $governor
    ) {
        $this->engine = $engine;
        $this->rules = $rules;
        $this->spool = $spool;
        $this->factory = $factory;
        $this->governor = $governor;
    }

    /**
     * Read new sensor output and return alerts plus a rollup.
     *
     * @return array{alerts: array<int, array>, stats: array}
     */
    public function collect(array $options = []): array
    {
        $empty = [
            'alerts' => [],
            'stats' => [
                'events' => 0,
                'alerts' => 0,
                'spooled' => 0,
                'suppressed' => 0,
                'by_rule' => [],
                'by_suppression' => [],
                'backend' => $this->engine->resolveBackend(),
            ],
        ];

        // Deliberately not gated on the sensor being alive: if osqueryd was
        // killed — including by an attacker who noticed it — the events it
        // captured before dying are the most valuable ones on the box. Drain
        // whatever is on disk and let the caller worry about restarting.
        $logPath = $this->engine->getResultsLogPath();
        if (!is_file($logPath) || !is_readable($logPath)) {
            Log::debug('[EDR] Results log not readable', ['path' => $logPath]);

            return $empty;
        }

        $this->rules->setExclusions($options['exclusions'] ?? []);
        $this->rules->setWebAccountAllowlist($options['web_account_allowlist'] ?? []);
        $this->spool->setEncryption((bool) ($options['spool_encrypt'] ?? false));
        $this->governor->ensureBaselineStarted();

        $read = $this->readNewLines($logPath);
        $lines = $read['lines'];

        if ($lines === []) {
            // Nothing to spool, so the cursor can move immediately — this is
            // the path that skips past an idle or already-drained file.
            $this->commitCursor($read['cursor']);

            return $empty;
        }

        $events = [];
        $alerts = [];
        $byRule = [];
        $findingsByEvent = [];
        $deliverable = [];
        $bySuppression = [];
        $suppressed = 0;

        foreach ($lines as $line) {
            $event = $this->normalize($line);
            if ($event === null || $this->isAgentNoise($event)) {
                continue;
            }

            $events[] = $event;
            $eventIndex = count($events) - 1;

            $findings = $this->rules->evaluate($event);
            if ($findings === []) {
                continue;
            }

            // Governance decides what a match is allowed to do here: an
            // unproven rule, a host still learning, or a shape that recurs
            // constantly on this machine all produce a hit that is counted
            // but not raised.
            $emitted = [];

            foreach ($findings as $finding) {
                $decision = $this->governor->assess($finding, $event, $options);
                $this->governor->record($decision, $finding, $event, $options);

                // Count every hit, including suppressed ones — the suppression
                // rate per rule is exactly what tells you whether a rule is
                // earning its place.
                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;

                if ($decision['emit']) {
                    $finding['stage'] = $decision['stage'];
                    $finding['allow_response'] = $decision['allow_response'];
                    $emitted[] = $finding;
                } else {
                    $suppressed++;
                    $bySuppression[$decision['reason'] ?? 'unknown'] =
                        ($bySuppression[$decision['reason'] ?? 'unknown'] ?? 0) + 1;
                }
            }

            // Store every finding, emitted or not. A suppressed match is the
            // raw material for tuning, and a retro-hunt after new intel needs
            // to see what was held back at the time.
            $findingsByEvent[$eventIndex] = $findings;
            $deliverable[$eventIndex] = $emitted !== [];

            if ($emitted !== [] && count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = ['event' => $event, 'findings' => $emitted];
            }
        }

        $alerts = $this->collapseWrappers($alerts);

        // Cross-event rules run over the whole batch, and go through the same
        // governance as single-event ones — a burst rule is no more entitled
        // to bypass a learning window than any other.
        foreach ($this->rules->evaluateBatch($events) as $batchHit) {
            $emitted = [];

            foreach ($batchHit['findings'] as $finding) {
                $decision = $this->governor->assess($finding, $batchHit['event'], $options);
                $this->governor->record($decision, $finding, $batchHit['event'], $options);

                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;

                if ($decision['emit']) {
                    $finding['stage'] = $decision['stage'];
                    $finding['allow_response'] = $decision['allow_response'];
                    $emitted[] = $finding;
                } else {
                    $suppressed++;
                    $bySuppression[$decision['reason'] ?? 'unknown'] =
                        ($bySuppression[$decision['reason'] ?? 'unknown'] ?? 0) + 1;
                }
            }

            if ($emitted !== [] && count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = ['event' => $batchHit['event'], 'findings' => $emitted];
            }
        }

        arsort($byRule);

        // Persist the whole batch, not just the alerting slice. Retro-hunting
        // only over past alerts is pointless — you already have those. The
        // value is being able to answer "did this binary ever run here" when
        // the intel arrives a week later.
        $spoolEnabled = $options['spool_enabled'] ?? true;
        $spooled = $spoolEnabled ? $this->spool->store($events, $findingsByEvent, $deliverable) : 0;

        // Advance the cursor only now. If the spool write failed we leave it
        // where it was and re-read the same window next cycle: duplicated
        // events are cheap, and a gap in the retro-hunt corpus is not
        // recoverable.
        if (!$spoolEnabled || $events === [] || $spooled > 0) {
            $this->commitCursor($read['cursor']);
        } else {
            Log::warning('[EDR] Spool write failed, holding cursor to re-read next cycle', [
                'events' => count($events),
            ]);
        }

        // Returned for the dry-run view only. Real delivery happens from the
        // spool, so an alert surviving a Hub outage does not depend on the
        // caller doing anything with this array.
        $shaped = array_map(
            fn (array $hit): array => $this->factory->fromEvent($hit['event'], $hit['findings']),
            $alerts
        );

        return [
            'alerts' => $shaped,
            'stats' => [
                'events' => count($events),
                'alerts' => count($alerts),
                'spooled' => $spooled,
                'suppressed' => $suppressed,
                'by_rule' => $byRule,
                'by_suppression' => $bySuppression,
                'learning' => $this->governor->isLearning((int) ($options['baseline_days'] ?? 7)),
                'backend' => $this->engine->resolveBackend(),
            ],
        ];
    }

    /**
     * Collapse `sh -c 'do-bad-thing'` + `do-bad-thing` into one alert.
     *
     * The same action reaches us twice in two different shapes:
     *   fork — the shell spawns a child, so child.ppid == shell.pid
     *   exec — the shell execs in place, so both rows carry the SAME pid
     * In both cases the two command lines trip the same rule and an analyst
     * would be reading one incident twice. Keep the narrower command line —
     * it names the actual action — and drop the wrapper.
     *
     * @param  array<int, array{event:array,findings:array}> $hits
     * @return array<int, array{event:array,findings:array}>
     */
    private function collapseWrappers(array $hits): array
    {
        if (count($hits) < 2) {
            return $hits;
        }

        // rule => list of [relatedPid, cmdline, index] for every hit, indexed
        // by the pid that could be its wrapper (its own pid for an exec
        // chain, its parent's pid for a fork chain).
        $candidates = [];

        foreach ($hits as $index => $hit) {
            $pid = (int) ($hit['event']['pid'] ?? 0);
            $ppid = (int) ($hit['event']['ppid'] ?? 0);
            $cmdline = (string) ($hit['event']['cmdline'] ?? '');

            if ($cmdline === '') {
                continue;
            }

            foreach ($hit['findings'] as $finding) {
                foreach (array_unique([$pid, $ppid]) as $wrapperPid) {
                    if ($wrapperPid > 0) {
                        $candidates[$finding['rule']][$wrapperPid][] = ['cmdline' => $cmdline, 'index' => $index];
                    }
                }
            }
        }

        $kept = [];

        foreach ($hits as $index => $hit) {
            $pid = (int) ($hit['event']['pid'] ?? 0);
            $cmdline = (string) ($hit['event']['cmdline'] ?? '');

            $remaining = array_filter(
                $hit['findings'],
                static function (array $finding) use ($candidates, $pid, $cmdline, $index): bool {
                    foreach ($candidates[$finding['rule']][$pid] ?? [] as $other) {
                        if ($other['index'] === $index) {
                            continue;
                        }

                        // Strictly shorter and contained: this row is the
                        // wrapper around a more specific one. Unrelated
                        // same-rule hits are not substrings, so they survive.
                        if ($other['cmdline'] !== $cmdline && str_contains($cmdline, $other['cmdline'])) {
                            return false;
                        }

                        // Exact duplicate — keep only the first occurrence.
                        if ($other['cmdline'] === $cmdline && $other['index'] < $index) {
                            return false;
                        }
                    }

                    return true;
                }
            );

            if ($remaining !== []) {
                $hit['findings'] = array_values($remaining);
                $kept[] = $hit;
            }
        }

        return $kept;
    }

    /* ------------------------------------------------------------------ */
    /* Reading                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Read whatever is new since last cycle.
     *
     * The cursor is returned rather than saved. Committing it here would mean
     * a crash between the read and the spool write silently loses that
     * window — the cursor would already say those bytes were handled. The
     * caller commits only once the events are durably on disk, so the worst
     * case becomes re-reading a batch (harmless) instead of dropping one.
     *
     * @return array{lines: array<int, string>, cursor: ?array}
     */
    private function readNewLines(string $logPath): array
    {
        $state = $this->loadCursor();

        clearstatcache(true, $logPath);
        $stat = @stat($logPath);
        if ($stat === false) {
            return ['lines' => [], 'cursor' => null];
        }

        $inode = (int) $stat['ino'];
        $size = (int) $stat['size'];
        $position = (int) ($state['position'] ?? 0);
        $previousInode = (int) ($state['inode'] ?? 0);

        // Fingerprint the head of the file. Inode plus size cannot detect a
        // truncate-and-rewrite that lands on a similar length — the cursor
        // would sit past the new content and the agent would silently stop
        // reading. Comparing the first bytes is what log shippers do, and it
        // is the only thing that catches this case.
        $fingerprint = $this->fingerprint($logPath);
        $previousFingerprint = (string) ($state['fingerprint'] ?? '');

        $lines = [];
        $budget = self::MAX_BYTES_PER_CYCLE;

        // Rotation: the file we were following still exists under another
        // name, and its tail holds every event written between our last read
        // and the rotation. Drain that first — without this, a rotation
        // silently eats up to one cycle's worth of telemetry.
        if ($previousInode !== 0 && $previousInode !== $inode) {
            $rotated = $this->findRotatedFile($logPath, $previousInode);

            if ($rotated !== null) {
                $tail = $this->readFrom($rotated, $position, $budget);
                $lines = $tail['lines'];
                $budget -= $tail['consumed'];

                Log::info('[EDR] Drained rotated sensor log', [
                    'file' => basename($rotated),
                    'lines' => count($tail['lines']),
                ]);
            }

            // Either way the new file starts from the top.
            $position = 0;
        } elseif ($size < $position
            || ($previousFingerprint !== '' && $fingerprint !== null && $fingerprint !== $previousFingerprint)
        ) {
            // Replaced in place (truncate-and-rewrite) — nothing to recover
            // from the old content, but we must not stay parked past the end
            // of the new content.
            Log::warning('[EDR] Sensor log replaced in place, restarting from top');
            $position = 0;
        }

        if ($size <= $position) {
            return [
                'lines' => $lines,
                'cursor' => ['inode' => $inode, 'position' => $position, 'fingerprint' => $fingerprint],
            ];
        }

        // On a backlog, skip forward rather than trying to catch up: stale
        // process events are not worth blocking the sync cycle for.
        if ($size - $position > $budget) {
            $skipped = $size - $position - $budget;
            $position = $size - $budget;
            Log::warning('[EDR] Sensor backlog exceeded cycle budget, skipping ahead', [
                'skipped_bytes' => $skipped,
            ]);
        }

        $current = $this->readFrom($logPath, $position, $budget, $position > 0 && $size - $position >= $budget);

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
     * Hash of the file's opening bytes, used to notice that the file we are
     * following has been replaced even when inode and size look unchanged.
     */
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

    /**
     * Read complete lines from an offset, never consuming a partial trailing
     * line: osquery may be mid-write, and advancing past half a JSON object
     * would drop that event permanently.
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

        // A skip-ahead almost certainly landed mid-line; drop the remainder.
        if ($dropFirstPartial) {
            $discard = fgets($handle);
            if ($discard !== false) {
                $consumed += strlen($discard);
            }
        }

        $lines = [];

        while ($consumed < $budget && ($raw = fgets($handle)) !== false) {
            // No trailing newline means the writer has not finished this
            // line. Leave it for the next cycle.
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
     * on inode rather than a naming convention means this keeps working
     * whether osquery rotates to `.1`, a timestamp suffix, or something else
     * entirely.
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

    private function loadCursor(): array
    {
        $stateFile = storage_path('app/edr_log_position.json');

        if (!is_file($stateFile)) {
            return [];
        }

        $state = json_decode((string) @file_get_contents($stateFile), true);

        return is_array($state) ? $state : [];
    }

    /**
     * Persist the cursor. Called only after the batch is safely spooled.
     */
    private function commitCursor(?array $cursor): void
    {
        if ($cursor === null) {
            return;
        }

        $this->saveState(
            storage_path('app/edr_log_position.json'),
            (int) $cursor['inode'],
            (int) $cursor['position'],
            $cursor['fingerprint'] ?? null
        );
    }

    private function saveState(string $stateFile, int $inode, int $position, ?string $fingerprint = null): void
    {
        // Write-then-rename so a crash mid-write cannot leave a truncated
        // cursor file, which would restart the collector from byte zero and
        // replay the whole sensor log.
        $payload = json_encode([
            'inode' => $inode,
            'position' => $position,
            'fingerprint' => $fingerprint,
            'updated_at' => now()->toIso8601String(),
        ]);

        $tmp = $stateFile . '.tmp';

        if (@file_put_contents($tmp, $payload) !== false) {
            @rename($tmp, $stateFile);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Normalisation                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Map one osquery result row to the neutral event shape. Keeping the
     * sensor's schema behind this function is what will let a different
     * sensor (ETW on Windows, ESF on macOS) feed the same rule engine.
     */
    private function normalize(string $line): ?array
    {
        $row = json_decode($line, true);
        if (!is_array($row)) {
            return null;
        }

        // Only additions matter; osquery also emits "removed" rows for
        // differential queries, which would double-count every exec.
        if (($row['action'] ?? '') !== 'added') {
            return null;
        }

        $columns = $row['columns'] ?? null;
        if (!is_array($columns)) {
            return null;
        }

        $name = (string) ($row['name'] ?? '');
        $isSocket = str_contains($name, 'socket');

        $uid = isset($columns['uid']) ? (int) $columns['uid'] : -1;

        $event = [
            'ts' => (int) ($row['unixTime'] ?? time()),
            'host' => (string) ($row['hostIdentifier'] ?? gethostname()),
            'action' => $isSocket ? 'connect' : 'exec',
            'sensor' => 'osquery',
            'pid' => (int) ($columns['pid'] ?? 0),
            'ppid' => (int) ($columns['parent'] ?? 0),
            'uid' => $uid,
            'gid' => isset($columns['gid']) ? (int) $columns['gid'] : -1,
            'username' => $this->resolveUsername($uid),
            'path' => (string) ($columns['path'] ?? ''),
            'cmdline' => (string) ($columns['cmdline'] ?? ''),
            'cwd' => (string) ($columns['cwd'] ?? ''),
            'exit_code' => isset($columns['exit_code']) ? (int) $columns['exit_code'] : null,
            'container_id' => (string) ($columns['cid'] ?? ''),
            'syscall' => (string) ($columns['syscall'] ?? ''),
        ];

        if ($isSocket) {
            $event['remote_address'] = (string) ($columns['remote_address'] ?? '');
            $event['remote_port'] = (int) ($columns['remote_port'] ?? 0);
            $event['local_port'] = (int) ($columns['local_port'] ?? 0);
            $event['family'] = (string) ($columns['family'] ?? '');
        }

        // An exec row with neither a path nor a command line carries no
        // detection value — osquery emits these when the BPF probe loses the
        // string buffer under load.
        if ($event['action'] === 'exec' && $event['path'] === '' && $event['cmdline'] === '') {
            return null;
        }

        return $event;
    }

    /**
     * Suppress this product's own activity. The agent runs `php artisan` every
     * few seconds and shells out constantly; without this the sensor mostly
     * watches itself.
     *
     * Deliberately narrow: it matches our binaries and our install directory,
     * not a generic "anything under /opt" rule, so an attacker cannot hide by
     * choosing a convenient working directory.
     */
    private function isAgentNoise(array $event): bool
    {
        $path = (string) $event['path'];
        $binary = $path !== '' ? basename($path) : '';

        if ($binary !== '' && in_array($binary, self::AGENT_BINARIES, true)) {
            return true;
        }

        $cmdline = (string) $event['cmdline'];
        $installDir = base_path();

        // Our own artisan invocations and watchdog loops.
        if ($installDir !== '' && str_contains($cmdline, $installDir)) {
            if (preg_match('/\b(php|bash|sh)\b/', $binary) === 1
                || str_contains($cmdline, 'artisan')
                || str_contains($cmdline, 'security-one-watchdog')
            ) {
                return true;
            }
        }

        return false;
    }

    private function resolveUsername(int $uid): string
    {
        if ($uid < 0) {
            return '';
        }

        if ($this->userCache === []) {
            $this->loadUserCache();
        }

        return $this->userCache[$uid] ?? (string) $uid;
    }

    private function loadUserCache(): void
    {
        // posix_getpwuid is not always available (php-cli without ext-posix),
        // so parse passwd directly and cache for the life of the process.
        $this->userCache = [-1 => ''];

        $passwd = @file('/etc/passwd', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($passwd === false) {
            return;
        }

        foreach ($passwd as $line) {
            $parts = explode(':', $line);
            if (count($parts) >= 3) {
                $this->userCache[(int) $parts[2]] = $parts[0];
            }
        }
    }

}

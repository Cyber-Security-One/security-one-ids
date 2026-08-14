<?php

namespace App\Services\Response;

use Illuminate\Support\Facades\Log;

/**
 * Moves a suspicious file out of reach and can put it back exactly as it was.
 *
 * Quarantine is the response analysts reach for when they are fairly sure but
 * not certain, so the restore path matters as much as the removal path. Every
 * attribute needed to reconstruct the original — mode, owner, group, mtime,
 * size, digest — is captured before the file moves, and the restore verifies
 * the content still hashes to what was taken.
 *
 * Two things drive the implementation:
 *
 * **Do not brick the host.** Quarantining libc or /bin/sh is unrecoverable
 * from the customer's point of view, so a small set of paths can never be
 * touched and the shared-library directories need an explicit force.
 *
 * **Fail towards keeping the file.** A cross-filesystem move cannot be
 * atomic, so the sequence is copy, verify, then unlink. A crash in the middle
 * leaves the original in place plus a stray copy — recoverable. The reverse
 * order would lose the file outright.
 */
class FileQuarantine
{
    /**
     * Removing any of these takes the machine down or takes us with it.
     * No force override: bricking a customer's host is not a capability.
     */
    private const NEVER_QUARANTINE = [
        '/bin/sh', '/bin/bash', '/bin/dash', '/usr/bin/sh', '/usr/bin/bash',
        '/bin/systemctl', '/sbin/init', '/usr/lib/systemd/systemd',
        '/usr/bin/env', '/bin/env', '/usr/bin/dpkg', '/usr/bin/rpm',
        '/bin/mount', '/bin/umount', '/usr/bin/sudo', '/bin/login',
    ];

    /** Pseudo-filesystems: nothing here is a real file to quarantine. */
    private const NEVER_PREFIXES = ['/proc/', '/sys/', '/dev/', '/run/udev/'];

    /**
     * Pulling a shared library out from under a running system breaks
     * everything linked against it, so these need a deliberate decision.
     */
    private const PROTECTED_PREFIXES = ['/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/', '/etc/'];

    /** Beyond this a quarantine is a disk-space incident of its own. */
    private const MAX_SIZE_BYTES = 512 * 1024 * 1024;

    private string $directory;

    public function __construct(?string $directory = null)
    {
        $this->directory = $directory ?? storage_path('app/edr/quarantine');
    }

    public function getDirectory(): string
    {
        return $this->directory;
    }

    /**
     * @return array{allowed:bool, reason:?string, requires_force:bool}
     */
    public function checkGuardrails(string $path, bool $force = false): array
    {
        $real = realpath($path);

        // Both forms matter. On a usr-merge system `/bin/sh` resolves to
        // `/usr/bin/dash` and `/sbin/init` to `/usr/lib/systemd/systemd`, so
        // checking only the literal path lets the deny list be walked around
        // by naming the target directly — and checking only the resolved path
        // misses an entry written in its literal form. Comparing both against
        // a deny set that is itself resolved closes it from either direction.
        $candidates = array_unique(array_filter([$path, $real !== false ? $real : null]));

        foreach ($candidates as $candidate) {
            foreach (self::NEVER_PREFIXES as $prefix) {
                if (str_starts_with($candidate, $prefix)) {
                    return ['allowed' => false, 'reason' => 'pseudo_filesystem', 'requires_force' => false];
                }
            }
        }

        $denied = $this->resolvedDenyList();

        foreach ($candidates as $candidate) {
            if (in_array($candidate, $denied, true)) {
                return ['allowed' => false, 'reason' => 'critical_system_binary', 'requires_force' => false];
            }
        }

        $candidate = $real !== false ? $real : $path;

        // Taking our own binaries or config turns the EDR off, which no
        // legitimate response does.
        $installDir = rtrim(base_path(), '/');
        if ($installDir !== '' && str_starts_with($candidate, $installDir . '/')) {
            return ['allowed' => false, 'reason' => 'agent_file', 'requires_force' => false];
        }

        if (str_starts_with($candidate, rtrim($this->directory, '/') . '/')) {
            return ['allowed' => false, 'reason' => 'already_quarantined', 'requires_force' => false];
        }

        foreach (self::PROTECTED_PREFIXES as $prefix) {
            if (str_starts_with($candidate, $prefix) && !$force) {
                return ['allowed' => false, 'reason' => 'protected_system_path', 'requires_force' => true];
            }
        }

        return ['allowed' => true, 'reason' => null, 'requires_force' => false];
    }

    /**
     * Move a file into quarantine.
     *
     * @return array{success:bool, error:?string, restore_data:?array, result:?array}
     */
    public function quarantine(string $path, bool $force = false): array
    {
        clearstatcache(true, $path);

        if (!is_file($path)) {
            return $this->failure(is_dir($path) ? 'target_is_a_directory' : 'file_not_found');
        }

        if (is_link($path)) {
            // Quarantining the link would leave the payload in place and
            // restore would recreate a dangling reference.
            return $this->failure('target_is_a_symlink');
        }

        $guard = $this->checkGuardrails($path, $force);
        if (!$guard['allowed']) {
            Log::warning('[EDR response] Refused to quarantine file', [
                'path' => $path,
                'reason' => $guard['reason'],
            ]);

            return [
                'success' => false,
                'error' => $guard['reason'],
                'requires_force' => $guard['requires_force'],
                'restore_data' => null,
                'result' => null,
            ];
        }

        $stat = @stat($path);
        if ($stat === false) {
            return $this->failure('stat_failed');
        }

        if ($stat['size'] > self::MAX_SIZE_BYTES) {
            return $this->failure('file_too_large');
        }

        $digest = @hash_file('sha256', $path);
        if ($digest === false) {
            return $this->failure('unreadable');
        }

        if (!$this->ensureDirectory()) {
            return $this->failure('quarantine_directory_unavailable');
        }

        $storedName = date('Ymd-His') . '-' . substr($digest, 0, 16) . '.quarantined';
        $storedPath = $this->directory . '/' . $storedName;

        // Copy first: a crash from here on leaves the original intact and at
        // worst a stray copy behind.
        if (!@copy($path, $storedPath)) {
            @unlink($storedPath);

            return $this->failure('copy_failed');
        }

        // No execute bit, root-only. The file keeps its bytes so it can be
        // restored and analysed, but nothing can run it where it now sits.
        @chmod($storedPath, 0600);

        if (@hash_file('sha256', $storedPath) !== $digest) {
            @unlink($storedPath);

            return $this->failure('copy_verification_failed');
        }

        // Only now is it safe to remove the original.
        if (!@unlink($path)) {
            @unlink($storedPath);

            return $this->failure('original_could_not_be_removed');
        }

        $restoreData = [
            'original_path' => $path,
            'stored_path' => $storedPath,
            'sha256' => $digest,
            'size' => (int) $stat['size'],
            'mode' => $stat['mode'] & 0777,
            'uid' => (int) $stat['uid'],
            'gid' => (int) $stat['gid'],
            'mtime' => (int) $stat['mtime'],
        ];

        // A sidecar copy of the metadata, so a file can still be identified
        // and restored by hand if the ledger is ever lost.
        @file_put_contents(
            $storedPath . '.json',
            json_encode($restoreData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)
        );
        @chmod($storedPath . '.json', 0600);

        Log::info('[EDR response] File quarantined', [
            'path' => $path,
            'sha256' => $digest,
            'size' => $stat['size'],
        ]);

        return [
            'success' => true,
            'error' => null,
            'restore_data' => $restoreData,
            'result' => [
                'original_path' => $path,
                'sha256' => $digest,
                'size' => (int) $stat['size'],
                'quarantined_as' => $storedName,
            ],
        ];
    }

    /**
     * Put a quarantined file back exactly as it was.
     *
     * @return array{success:bool, error:?string, result:?array}
     */
    public function restore(array $restoreData): array
    {
        $stored = (string) ($restoreData['stored_path'] ?? '');
        $original = (string) ($restoreData['original_path'] ?? '');
        $expectedDigest = (string) ($restoreData['sha256'] ?? '');

        if ($stored === '' || $original === '') {
            return ['success' => false, 'error' => 'incomplete_restore_data', 'result' => null];
        }

        if (!is_file($stored)) {
            return ['success' => false, 'error' => 'quarantined_file_missing', 'result' => null];
        }

        // Something may legitimately occupy the path now — a reinstall, a
        // package update. Overwriting it would turn a restore into a second
        // incident.
        if (file_exists($original)) {
            return ['success' => false, 'error' => 'original_path_occupied', 'result' => null];
        }

        if ($expectedDigest !== '' && @hash_file('sha256', $stored) !== $expectedDigest) {
            return ['success' => false, 'error' => 'quarantined_file_modified', 'result' => null];
        }

        $parent = dirname($original);
        if (!is_dir($parent)) {
            return ['success' => false, 'error' => 'original_directory_missing', 'result' => null];
        }

        if (!@copy($stored, $original)) {
            return ['success' => false, 'error' => 'restore_copy_failed', 'result' => null];
        }

        if ($expectedDigest !== '' && @hash_file('sha256', $original) !== $expectedDigest) {
            @unlink($original);

            return ['success' => false, 'error' => 'restore_verification_failed', 'result' => null];
        }

        // Attributes last, so a partially-restored file is never briefly
        // executable with its original permissions.
        if (isset($restoreData['mode'])) {
            @chmod($original, (int) $restoreData['mode']);
        }
        if (isset($restoreData['uid'], $restoreData['gid'])) {
            @chown($original, (int) $restoreData['uid']);
            @chgrp($original, (int) $restoreData['gid']);
        }
        if (isset($restoreData['mtime'])) {
            @touch($original, (int) $restoreData['mtime']);
        }

        @unlink($stored);
        @unlink($stored . '.json');

        Log::info('[EDR response] File restored from quarantine', ['path' => $original]);

        return [
            'success' => true,
            'error' => null,
            'result' => ['restored_to' => $original, 'sha256' => $expectedDigest],
        ];
    }

    /**
     * @return array<int, array>
     */
    public function listQuarantined(): array
    {
        $entries = [];

        foreach ((array) @glob($this->directory . '/*.quarantined.json') as $meta) {
            $data = json_decode((string) @file_get_contents($meta), true);

            if (is_array($data)) {
                $data['exists'] = is_file((string) ($data['stored_path'] ?? ''));
                $entries[] = $data;
            }
        }

        return $entries;
    }

    /**
     * The deny list plus whatever each entry actually points at. Cached for
     * the life of the object; these do not move while we are running.
     *
     * @var array<int, string>|null
     */
    private ?array $resolvedDenyList = null;

    /**
     * @return array<int, string>
     */
    private function resolvedDenyList(): array
    {
        if ($this->resolvedDenyList !== null) {
            return $this->resolvedDenyList;
        }

        $entries = self::NEVER_QUARANTINE;

        foreach (self::NEVER_QUARANTINE as $entry) {
            $real = realpath($entry);
            if ($real !== false) {
                $entries[] = $real;
            }
        }

        return $this->resolvedDenyList = array_values(array_unique($entries));
    }

    private function ensureDirectory(): bool
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true)) {
            Log::error('[EDR response] Cannot create quarantine directory: ' . $this->directory);

            return false;
        }

        @chmod($this->directory, 0700);

        return true;
    }

    private function failure(string $reason): array
    {
        return [
            'success' => false,
            'error' => $reason,
            'restore_data' => null,
            'result' => null,
        ];
    }
}

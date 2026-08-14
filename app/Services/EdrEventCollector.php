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

    /** @var array<int, string> uid => username */
    private array $userCache = [];

    public function __construct(
        OsqueryEngine $engine,
        EdrRuleEngine $rules,
        EdrEventSpool $spool,
        EdrAlertFactory $factory
    ) {
        $this->engine = $engine;
        $this->rules = $rules;
        $this->spool = $spool;
        $this->factory = $factory;
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
                'by_rule' => [],
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

        $lines = $this->readNewLines($logPath);
        if ($lines === []) {
            return $empty;
        }

        $events = [];
        $alerts = [];
        $byRule = [];
        $findingsByEvent = [];

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

            $findingsByEvent[$eventIndex] = $findings;

            foreach ($findings as $finding) {
                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;
            }

            if (count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = ['event' => $event, 'findings' => $findings];
            }
        }

        $alerts = $this->collapseWrappers($alerts);

        // Cross-event rules run over the whole batch.
        foreach ($this->rules->evaluateBatch($events) as $batchHit) {
            foreach ($batchHit['findings'] as $finding) {
                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;
            }

            if (count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = $batchHit;
            }
        }

        arsort($byRule);

        // Persist the whole batch, not just the alerting slice. Retro-hunting
        // only over past alerts is pointless — you already have those. The
        // value is being able to answer "did this binary ever run here" when
        // the intel arrives a week later.
        $spooled = $options['spool_enabled'] ?? true
            ? $this->spool->store($events, $findingsByEvent)
            : 0;

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
                'by_rule' => $byRule,
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
     * Read whatever is new since last cycle, tracking the inode so a rotation
     * restarts cleanly instead of replaying or silently stalling.
     *
     * @return array<int, string>
     */
    private function readNewLines(string $logPath): array
    {
        $stateFile = storage_path('app/edr_log_position.json');
        $state = [];

        if (is_file($stateFile)) {
            $state = json_decode((string) @file_get_contents($stateFile), true) ?: [];
        }

        clearstatcache(true, $logPath);
        $stat = @stat($logPath);
        if ($stat === false) {
            return [];
        }

        $inode = (int) $stat['ino'];
        $size = (int) $stat['size'];
        $position = (int) ($state['position'] ?? 0);

        // New file (rotation) or truncation → start over from the top.
        if ((int) ($state['inode'] ?? 0) !== $inode || $size < $position) {
            $position = 0;
        }

        if ($size <= $position) {
            $this->saveState($stateFile, $inode, $position);

            return [];
        }

        // On a backlog, skip forward rather than trying to catch up: stale
        // process events are not worth blocking the sync cycle for.
        $skipped = 0;
        if ($size - $position > self::MAX_BYTES_PER_CYCLE) {
            $skipped = $size - $position - self::MAX_BYTES_PER_CYCLE;
            $position = $size - self::MAX_BYTES_PER_CYCLE;
            Log::warning('[EDR] Sensor backlog exceeded cycle budget, skipping ahead', [
                'skipped_bytes' => $skipped,
            ]);
        }

        $handle = @fopen($logPath, 'r');
        if ($handle === false) {
            return [];
        }

        fseek($handle, $position);

        // A skip-ahead almost certainly landed mid-line; drop the partial.
        if ($skipped > 0) {
            fgets($handle);
        }

        $lines = [];
        while (($line = fgets($handle)) !== false) {
            $line = trim($line);
            if ($line !== '') {
                $lines[] = $line;
            }
        }

        $newPosition = ftell($handle);
        fclose($handle);

        $this->saveState($stateFile, $inode, $newPosition === false ? $size : $newPosition);

        return $lines;
    }

    private function saveState(string $stateFile, int $inode, int $position): void
    {
        @file_put_contents($stateFile, json_encode([
            'inode' => $inode,
            'position' => $position,
            'updated_at' => now()->toIso8601String(),
        ]));
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

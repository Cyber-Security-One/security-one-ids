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
    private ?LogCursor $cursor = null;

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

        // Pass one: normalise everything. Attribution has to see the whole
        // batch before any rule runs, because a file event only becomes
        // meaningful once we have guessed which process caused it — and the
        // rule that matters most, a web account dropping a script into a web
        // root, is unreachable without that guess.
        foreach ($lines as $line) {
            $event = $this->normalize($line);

            if ($event !== null && !$this->isAgentNoise($event)) {
                $events[] = $event;
            }
        }

        $this->attributeFileEvents($events);
        $this->compareFileDigests($events);

        // Pass two: evaluate.
        foreach ($events as $eventIndex => $event) {
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
        $alerts = $this->collapseFileRepeats($alerts);

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

    /**
     * One write, one alert.
     *
     * A single `echo > file` produces a CREATED and one or more UPDATED
     * events, so the same finding on the same path arrives several times in a
     * cycle. Three identical criticals for one dropped webshell is noise
     * dressed as urgency, and the analyst still only has one file to look at.
     *
     * @param  array<int, array{event:array,findings:array}> $hits
     * @return array<int, array{event:array,findings:array}>
     */
    private function collapseFileRepeats(array $hits): array
    {
        $seen = [];
        $kept = [];

        foreach ($hits as $hit) {
            $action = (string) ($hit['event']['action'] ?? '');

            if (!str_starts_with($action, 'file_')) {
                $kept[] = $hit;
                continue;
            }

            $path = (string) ($hit['event']['path'] ?? '');

            $remaining = array_filter(
                $hit['findings'],
                static function (array $finding) use (&$seen, $path): bool {
                    $key = ($finding['rule'] ?? '') . '|' . $path;

                    if (isset($seen[$key])) {
                        return false;
                    }

                    $seen[$key] = true;

                    return true;
                }
            );

            if ($remaining !== []) {
                // Keep the richest copy: a later event in the sequence may
                // have picked up an attribution the first one lacked.
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
     * Follow the sensor log. The mechanics live in LogCursor, which is shared
     * with the identity collector — every bug in a log cursor is silent, and
     * this one has already had three of them found and fixed. Reimplementing
     * it per log source would be inviting them back one at a time.
     *
     * @return array{lines: array<int, string>, cursor: ?array}
     */
    private function readNewLines(string $logPath): array
    {
        return $this->cursor()->read($logPath);
    }

    private function commitCursor(?array $cursor): void
    {
        $this->cursor()->commit($cursor);
    }

    private function cursor(): LogCursor
    {
        return $this->cursor ??= new LogCursor(
            storage_path('app/edr_log_position.json'),
            self::MAX_BYTES_PER_CYCLE
        );
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

        if ($name === 'file_changes') {
            return $this->normalizeFileEvent($row, $columns);
        }

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
     * Map an inotify file event into the shared event shape.
     *
     * The important absence here is a pid. inotify reports what changed and
     * can hash it, but not who did it — so the process fields stay empty and
     * are filled in later by inference, clearly marked as inference. Claiming
     * an attribution we do not have would be worse than admitting the gap:
     * an analyst acts on the name of the process they are shown.
     */
    private function normalizeFileEvent(array $row, array $columns): ?array
    {
        $path = (string) ($columns['target_path'] ?? '');

        if ($path === '') {
            return null;
        }

        $action = match (strtoupper((string) ($columns['action'] ?? ''))) {
            'CREATED' => 'file_create',
            'UPDATED', 'ATTRIBUTES_MODIFIED', 'MOVED_TO' => 'file_write',
            'DELETED', 'MOVED_FROM' => 'file_delete',
            default => null,
        };

        // osquery emits directory-level and bookkeeping actions too; only
        // changes to file content or existence are worth carrying.
        if ($action === null) {
            return null;
        }

        $uid = isset($columns['uid']) && $columns['uid'] !== '' ? (int) $columns['uid'] : -1;

        return [
            'ts' => (int) ($row['unixTime'] ?? time()),
            'host' => (string) ($row['hostIdentifier'] ?? gethostname()),
            'action' => $action,
            'sensor' => 'osquery-fim',
            // Left unset on purpose — see the note above.
            'pid' => 0,
            'ppid' => 0,
            'uid' => $uid,
            'username' => $uid >= 0 ? $this->resolveUsername($uid) : '',
            'path' => $path,
            'cmdline' => '',
            'cwd' => dirname($path),
            'container_id' => '',
            'syscall' => strtolower((string) ($columns['action'] ?? '')),
            'file' => [
                'category' => (string) ($columns['category'] ?? ''),
                'size' => isset($columns['size']) && $columns['size'] !== '' ? (int) $columns['size'] : null,
                'mode' => (string) ($columns['mode'] ?? ''),
                'sha256' => (string) ($columns['sha256'] ?? ''),
                'inode' => (string) ($columns['inode'] ?? ''),
                'mtime' => isset($columns['mtime']) && $columns['mtime'] !== '' ? (int) $columns['mtime'] : null,
            ],
            'attribution' => null,
        ];
    }

    /**
     * Guess which process was responsible for each file change.
     *
     * inotify does not tell us, so this looks for a process that executed
     * close in time and whose command line or working directory points at the
     * path. It is inference: the confidence is recorded alongside it, and
     * nothing downstream is allowed to treat a `low` attribution as identity.
     *
     * @param array<int, array> $events the whole batch, in arrival order
     */
    private function attributeFileEvents(array &$events, int $windowSeconds = 5): void
    {
        $fileEvents = array_filter(
            $events,
            static fn (array $e): bool => str_starts_with((string) ($e['action'] ?? ''), 'file_')
        );

        if ($fileEvents === []) {
            return;
        }

        $inBatch = array_values(array_filter(
            $events,
            static fn (array $e): bool => ($e['action'] ?? '') === 'exec'
        ));

        // Candidates come from the spool as well as the current batch. File
        // events and process events are separate scheduled queries with
        // independent flush timing, so the process that did the writing has
        // usually been committed in an earlier cycle — looking only at the
        // batch in hand finds it almost never.
        $spooled = [];

        foreach ($fileEvents as $fileEvent) {
            foreach ($this->spool->execsAround((int) $fileEvent['ts'], $windowSeconds) as $row) {
                $spooled[(int) $row['id']] = [
                    'ts' => (int) $row['ts'],
                    'pid' => (int) $row['pid'],
                    'ppid' => (int) $row['ppid'],
                    'uid' => (int) $row['uid'],
                    'username' => (string) ($row['username'] ?? ''),
                    'path' => (string) ($row['path'] ?? ''),
                    'cmdline' => (string) ($row['cmdline'] ?? ''),
                ];
            }
        }

        $processes = array_merge($inBatch, array_values($spooled));

        if ($processes === []) {
            return;
        }

        foreach ($events as &$event) {
            if (!str_starts_with((string) ($event['action'] ?? ''), 'file_')) {
                continue;
            }

            $path = (string) $event['path'];
            $basename = basename($path);
            $best = null;

            foreach ($processes as $process) {
                $delta = abs((int) $process['ts'] - (int) $event['ts']);

                if ($delta > $windowSeconds) {
                    continue;
                }

                $cmdline = (string) $process['cmdline'];

                // Naming the full path is the strongest thing we can see
                // without kernel-side attribution.
                if ($path !== '' && str_contains($cmdline, $path)) {
                    $best = ['process' => $process, 'confidence' => 'high', 'basis' => 'cmdline_contains_path'];
                    break;
                }

                if ($basename !== '' && strlen($basename) > 3 && str_contains($cmdline, $basename)) {
                    $candidate = ['process' => $process, 'confidence' => 'medium', 'basis' => 'cmdline_contains_name'];
                } elseif ((int) $process['uid'] === (int) $event['uid'] && (int) $event['uid'] >= 0) {
                    $candidate = ['process' => $process, 'confidence' => 'low', 'basis' => 'same_user_same_window'];
                } else {
                    continue;
                }

                if ($best === null || $this->confidenceRank($candidate['confidence']) > $this->confidenceRank($best['confidence'])) {
                    $best = $candidate;
                }
            }

            if ($best === null) {
                continue;
            }

            $event['attribution'] = [
                'confidence' => $best['confidence'],
                'basis' => $best['basis'],
                'pid' => (int) $best['process']['pid'],
                'ppid' => (int) $best['process']['ppid'],
                'process_path' => (string) $best['process']['path'],
                'cmdline' => (string) $best['process']['cmdline'],
                'username' => (string) $best['process']['username'],
            ];

            // Carry the inferred user forward when inotify gave us nothing,
            // but never overwrite a uid the kernel actually reported.
            if (($event['username'] ?? '') === '' && $best['confidence'] !== 'low') {
                $event['username'] = (string) $best['process']['username'];
            }
        }
        unset($event);
    }

    /**
     * Compare each hashed file event against the digest we last saw.
     *
     * "This file changed" is a weak statement on its own — package updates
     * rewrite /etc/ssh/sshd_config regularly. "This no longer matches what it
     * has been since we started watching, and the previous digest was X" is
     * something an analyst can act on, and it is also what makes a restore
     * verifiable afterwards.
     *
     * @param array<int, array> $events
     */
    private function compareFileDigests(array &$events): void
    {
        foreach ($events as &$event) {
            if (!str_starts_with((string) ($event['action'] ?? ''), 'file_')) {
                continue;
            }

            $digest = (string) ($event['file']['sha256'] ?? '');
            $path = (string) ($event['path'] ?? '');

            // osquery only hashes when it can read the file at flush time; a
            // deletion or a file already replaced leaves this empty.
            if ($digest === '' || $path === '') {
                continue;
            }

            $comparison = $this->governor->compareFileDigest($path, $digest, $event['file']['size'] ?? null);

            $event['file']['baseline'] = [
                'known' => $comparison['known'],
                'changed' => $comparison['changed'],
                'previous_sha256' => $comparison['previous'],
                'established_at' => $comparison['established'],
                'prior_changes' => $comparison['changes'],
            ];
        }
        unset($event);
    }

    private function confidenceRank(string $confidence): int
    {
        return match ($confidence) {
            'high' => 3,
            'medium' => 2,
            default => 1,
        };
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

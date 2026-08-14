<?php

namespace App\Console\Commands;

use App\Services\Correlation\EdrActorScorer;
use App\Services\Correlation\EdrCorrelator;
use App\Services\Correlation\EdrCorrelatorStore;
use App\Services\Correlation\EdrIntentClassifier;
use App\Services\EdrEventSpool;
use Illuminate\Console\Command;
use PDO;

class EdrCorrelateCommand extends Command
{
    protected $signature = 'ids:edr-correlate
        {--status : Show warm-up progress, budget and state inventory}
        {--actors=15 : Show the top N actors by score}
        {--replay : Re-score the spooled history from scratch, with no warm-up concession}
        {--since= : Replay window start (unix ts or strtotime string)}
        {--until= : Replay window end}
        {--state= : Write replay state here instead of a throwaway file}
        {--reset : Wipe correlator state and restart the warm-up}';

    protected $description = 'Inspect and replay the EDR behaviour correlator (EDR-100)';

    public function handle(): int
    {
        if ($this->option('reset')) {
            return $this->reset();
        }

        if ($this->option('replay')) {
            return $this->replay();
        }

        return $this->status();
    }

    /* ------------------------------------------------------------------ */
    /* Status                                                              */
    /* ------------------------------------------------------------------ */

    private function status(): int
    {
        $options = $this->hubOptions();
        $correlator = EdrCorrelator::make($options);
        $store = $correlator->store();

        if (!$store->isAvailable()) {
            $this->error('Correlator state is not readable at ' . $store->getPath());

            return 1;
        }

        $stats = $store->stats();

        $this->info('EDR Behaviour Correlator (EDR-100)');
        $this->line(str_repeat('=', 62));
        $this->line(sprintf('  %-22s %s', 'enabled', !empty($options['correlator_enabled']) ? 'yes' : 'no'));
        $this->line(sprintf('  %-22s %s', 'state', $stats['path']));
        $this->line(sprintf('  %-22s %s', 'size', $this->humanBytes($stats['size_bytes'])));

        $scored = (int) ($store->getMeta('scored_events') ?? '0');
        $first = (int) ($store->getMeta('first_event_ts') ?? '0');
        $last = (int) ($store->getMeta('last_event_ts') ?? '0');
        $warmEvents = max(1000, min(5000000, (int) ($options['correlator_warm_events'] ?? 50000)));
        $warmDays = max(3, min(60, (int) ($options['correlator_warm_days'] ?? 14)));
        $spanDays = $first > 0 && $last > $first ? ($last - $first) / 86400 : 0.0;
        $mature = $correlator->isMature();

        $this->newLine();
        $this->info('Warm-up');
        $this->line(str_repeat('-', 62));
        $this->line(sprintf('  %-22s %s', 'mature', $mature ? 'yes — emitting' : 'no — silent by design'));
        $this->line(sprintf('  %-22s %d / %d', 'events scored', $scored, $warmEvents));
        $this->line(sprintf('  %-22s %.1f / %d days', 'observation span', $spanDays, $warmDays));

        if (!$mature) {
            $this->warn('  → Nothing will be raised until both gates are met. This is not a fault.');
        }

        $this->newLine();
        $this->info('Learned state');
        $this->line(str_repeat('-', 62));
        foreach (['facets', 'tombstones', 'procs', 'actors', 'sigs', 'incidents_seen'] as $key) {
            $this->line(sprintf('  %-22s %d', $key, $stats[$key]));
        }

        $anomalies = (int) ($store->getMeta('clock_anomaly_count') ?? '0');
        if ($anomalies > 0) {
            $this->warn(sprintf('  %-22s %d  (host clock moved unexpectedly)', 'clock anomalies', $anomalies));
        }

        if ($stats['state_reset_at'] !== null) {
            $this->warn(sprintf(
                '  %-22s %s  (%s)',
                'last state reset',
                date('Y-m-d H:i:s', (int) $stats['state_reset_at']),
                $store->getMeta('state_reset_reason') ?? 'unknown'
            ));
        }

        $this->newLine();
        $this->info('Emission budget');
        $this->line(str_repeat('-', 62));
        foreach ($correlator->stats()['budget'] as $key => $value) {
            $this->line(sprintf('  %-22s %s', $key, is_float($value) ? round($value, 2) : $value));
        }

        $this->showActors($store, $options);

        $correlator->close();

        return 0;
    }

    /**
     * The per-host coverage number.
     *
     * A chaotic host is genuinely less protected than a quiet one — its own
     * threshold rises with its own novelty. That has to be visible rather than
     * buried, because "this host is covered" and "this host is covered at a
     * bar three times higher than the fleet" are different statements.
     */
    private function showActors(EdrCorrelatorStore $store, array $options): void
    {
        $limit = max(1, min(200, (int) $this->option('actors')));

        try {
            $pdo = new PDO('sqlite:' . $store->getPath(), null, null, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]);
            $rows = $pdo->query('SELECT * FROM actors ORDER BY last_ts DESC LIMIT ' . ($limit * 4))->fetchAll();
        } catch (\Throwable $e) {
            return;
        }

        if ($rows === []) {
            return;
        }

        $scorer = new EdrActorScorer($options);
        $jitter = EdrActorScorer::jitterFor((string) ($options['host_id'] ?? gethostname() ?: 'unknown'));

        $table = [];

        foreach ($rows as $row) {
            $actor = [
                'acc' => (array) json_decode((string) $row['acc'], true),
                'class_first_ts' => (array) json_decode((string) $row['class_first_ts'], true),
                'nov' => (float) $row['nov'],
            ];

            $scored = $scorer->score($actor);
            $threshold = $scorer->threshold($actor, $jitter, $row['actor_key'] === EdrCorrelator::HOST_ACTOR);

            $table[] = [
                'actor' => $this->shorten((string) $row['actor_key'], 34),
                'score' => round($scored['score'], 2),
                'thr' => round($threshold, 2),
                'pct' => $threshold > 0 ? round(100 * $scored['score'] / $threshold) . '%' : '-',
                'classes' => implode(',', array_map(
                    static fn (int $c): string => substr(EdrIntentClassifier::name($c), 0, 4),
                    $scored['lit']
                )),
                'nov' => round((float) $row['nov'], 2),
                'last' => date('m-d H:i', (int) $row['last_ts']),
            ];
        }

        usort($table, static fn (array $a, array $b): int => $b['score'] <=> $a['score']);
        $table = array_slice($table, 0, $limit);

        $this->newLine();
        $this->info('Actors (by current score)');
        $this->table(['actor', 'score', 'threshold', '% of bar', 'classes lit', 'novelty/day', 'last seen'], array_map(
            static fn (array $r): array => array_values($r),
            $table
        ));
    }

    /* ------------------------------------------------------------------ */
    /* Replay                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * Re-score the retained history against a fresh model.
     *
     * This exists for one specific and very common situation: the agent was
     * installed on a host *because* something was already wrong. During the
     * warm-up the model learns whatever it sees, and an intrusion present at
     * install time therefore gets a permanent discount on its own tooling.
     * Replaying the spool with no warm-up concession is the only way to ask
     * "what would this have said if it had known what normal was" — and it is
     * the first thing to run the morning after an agent lands on a host
     * somebody already suspects.
     */
    private function replay(): int
    {
        $spool = app(EdrEventSpool::class);

        if (!$spool->isAvailable()) {
            $this->error('The event spool is not readable — there is nothing to replay.');

            return 1;
        }

        // Not /tmp. This command runs as root, and a predictable name in a
        // world-writable directory is a symlink someone else can plant — the
        // SQLite driver would follow it and write wherever it points. The
        // agent's own storage directory is 0750 and root-owned.
        $statePath = (string) ($this->option('state') ?: storage_path(
            'app/edr/replay-' . bin2hex(random_bytes(8)) . '.sqlite'
        ));
        $discard = $this->option('state') === null;

        if ($discard) {
            // A leftover file from an interrupted run would otherwise be
            // reused as a warm model, and the replay would report against
            // history it did not just read.
            foreach (['', '-wal', '-shm'] as $suffix) {
                @unlink($statePath . $suffix);
            }
        }

        $since = $this->timestampOption('since') ?? 0;
        $until = $this->timestampOption('until') ?? time();

        $options = $this->hubOptions();
        $options['correlator_enabled'] = true;
        // A replay has the whole corpus in front of it, so the warm-up gate
        // that protects a live agent from its own ignorance is not needed.
        $options['correlator_warm_events'] = 1000;
        $options['correlator_warm_days'] = 3;

        // The replay has to honour the same exclusions the live agent does, or
        // it reports incidents built from events the customer has told us to
        // ignore — and teaches its throwaway model from them too.
        $rules = new \App\Services\EdrRuleEngine();
        $rules->setExclusions(is_array($options['exclusions'] ?? null) ? $options['exclusions'] : []);

        $correlator = EdrCorrelator::make($options, $statePath, $spool, null, $rules);
        $correlator->setReplayMode(true);

        $this->info('Replaying spooled history with no warm-up concession');
        $this->line('  state:  ' . $statePath . ($discard ? '  (discarded afterwards)' : ''));
        $this->line('  window: ' . date('c', $since ?: time()) . '  ..  ' . date('c', $until));
        $this->newLine();

        $cursor = $since;
        $pages = 0;
        $events = 0;
        $incidents = [];

        while ($pages < 5000) {
            $rows = $spool->query(['since' => $cursor, 'until' => $until, 'limit' => 2000]);

            if ($rows === []) {
                break;
            }

            // The spool answers newest-first; the model must see the stream in
            // the order it happened or every lineage decision is wrong.
            usort($rows, static fn (array $a, array $b): int => [(int) $a['ts'], (int) $a['id']] <=> [(int) $b['ts'], (int) $b['id']]);

            $batch = [];
            $findings = [];
            $governance = [];

            foreach ($rows as $i => $row) {
                $batch[$i] = $this->eventFromRow($row);
                $hits = json_decode((string) ($row['rule_hits'] ?? ''), true);

                if (is_array($hits) && $hits !== []) {
                    $findings[$i] = $hits;

                    // Recover what governance decided at the time. The spool's
                    // `deliver` flag is exactly that record: 1 means the
                    // finding was raised, 0 means it was held back. Without
                    // this every replayed finding reads as unproven, so no
                    // replayed incident is ever rule-backed and all of them
                    // are metered by the token bucket — which is the opposite
                    // of what an incident responder needs from a replay.
                    $delivered = (bool) ($row['deliver'] ?? 0);
                    $governance[$i] = array_fill(0, count($hits), [
                        'emit' => $delivered,
                        'reason' => $delivered ? null : 'replayed_suppressed',
                        'allow_response' => false,
                    ]);
                }
            }

            foreach (array_chunk($batch, 200, true) as $chunk) {
                $keys = array_keys($chunk);
                $chunkFindings = array_intersect_key($findings, array_flip($keys));
                $chunkGovernance = array_intersect_key($governance, array_flip($keys));

                // No array_values() on the findings: the map is deliberately
                // sparse — only events that tripped a rule appear — and
                // re-packing it would slide every finding onto the wrong
                // event, so a replay would not reproduce the live run at all.
                $replayed = $correlator->correlate(
                    array_values($chunk),
                    $this->reindex($chunkFindings, $keys),
                    $this->reindex($chunkGovernance, $keys)
                );

                foreach ($replayed as $incident) {
                    $incidents[] = $incident;
                }
            }

            $events += count($rows);
            $pages++;

            $newest = (int) end($rows)['ts'];
            $cursor = $newest > $cursor ? $newest : $cursor + 1;

            if (count($rows) < 2000) {
                break;
            }
        }

        $this->line(sprintf('  replayed %d event(s) in %d page(s)', $events, $pages));
        $this->newLine();

        // "Nothing found" and "not enough history to have an opinion" are
        // completely different answers to an incident responder, and only one
        // of them means the host is clean. A replay over a window shorter than
        // the model needs to mature can only ever produce the second.
        $matured = $correlator->isMature();

        if (!$matured) {
            $this->warn('The replayed window was too small for the model to mature, so nothing could');
            $this->warn('have been reported regardless of what happened. This is NOT a clean result.');
            $this->line('  Widen it with --since, or raise edr_spool_retention_days so more history exists.');
            $this->newLine();
        }

        if ($incidents === []) {
            $this->info($matured
                ? 'No incidents in the replayed window.'
                : 'No incidents — but see the warning above before reading anything into that.');
        } else {
            $this->warn(count($incidents) . ' incident(s) found:');

            foreach ($incidents as $incident) {
                $finding = $incident['findings'][0];
                $detail = $finding['incident'];

                $this->newLine();
                $this->line(sprintf('  [%s] %s  score %.1f / %.1f', $finding['severity'], $finding['rule'], $detail['score'], $detail['threshold']));
                $this->line('    chain:    ' . $detail['chain_key']);
                $this->line('    stages:   ' . implode(' → ', $detail['classes']));
                $this->line('    evidence:');

                foreach ($detail['evidence'] as $row) {
                    $this->line(sprintf(
                        '      %s  %-8s %s',
                        date('m-d H:i:s', (int) $row['ts']),
                        '+' . round((float) $row['charge'], 1),
                        $this->shorten((string) $row['cmdline'], 96)
                    ));
                }
            }
        }

        $correlator->close();

        if ($discard) {
            foreach (['', '-wal', '-shm'] as $suffix) {
                @unlink($statePath . $suffix);
            }
        }

        return $incidents === [] ? 0 : 2;
    }

    /**
     * Re-key a sparse findings map onto the positional indexes of a chunk.
     */
    private function reindex(array $findings, array $keys): array
    {
        $out = [];

        foreach (array_values($keys) as $position => $key) {
            if (isset($findings[$key])) {
                $out[$position] = $findings[$key];
            }
        }

        return $out;
    }

    private function eventFromRow(array $row): array
    {
        $event = [
            'ts' => (int) ($row['ts'] ?? 0),
            'host' => $row['host'] ?? gethostname(),
            'action' => (string) ($row['action'] ?? 'exec'),
            'sensor' => $row['sensor'] ?? 'osquery',
            'pid' => (int) ($row['pid'] ?? 0),
            'ppid' => (int) ($row['ppid'] ?? 0),
            'uid' => (int) ($row['uid'] ?? -1),
            'username' => (string) ($row['username'] ?? ''),
            'path' => (string) ($row['path'] ?? ''),
            'cmdline' => (string) ($row['cmdline'] ?? ''),
            'cwd' => (string) ($row['cwd'] ?? ''),
            'container_id' => (string) ($row['container_id'] ?? ''),
            'syscall' => (string) ($row['syscall'] ?? ''),
        ];

        $extra = json_decode((string) ($row['extra'] ?? ''), true);

        return is_array($extra) ? $event + $extra : $event;
    }

    /* ------------------------------------------------------------------ */
    /* Reset                                                               */
    /* ------------------------------------------------------------------ */

    private function reset(): int
    {
        $store = new EdrCorrelatorStore();

        if (!$this->confirm('Wipe correlator state and restart the ' . ($this->hubOptions()['correlator_warm_days'] ?? 14) . '-day warm-up?', false)) {
            $this->line('Cancelled.');

            return 0;
        }

        $store->resetToCold('operator requested via ids:edr-correlate --reset');
        $store->close();

        $this->info('Correlator state wiped. It will stay silent until the warm-up completes again.');

        return 0;
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private function hubOptions(): array
    {
        $config = json_decode((string) @file_get_contents(storage_path('app/waf_config.json')), true) ?: [];
        $addons = $config['addons'] ?? [];

        $options = [
            'host_id' => gethostname() ?: 'unknown',
            'exclusions' => is_array($addons['edr_exclusions'] ?? null) ? $addons['edr_exclusions'] : [],
        ];

        foreach ($addons as $key => $value) {
            if (str_starts_with((string) $key, 'edr_correlator_')) {
                $options[substr((string) $key, 4)] = $value;
            }
        }

        return $options;
    }

    private function timestampOption(string $name): ?int
    {
        $raw = $this->option($name);

        if ($raw === null || $raw === '') {
            return null;
        }

        if (ctype_digit((string) $raw)) {
            return (int) $raw;
        }

        $parsed = strtotime((string) $raw);

        return $parsed === false ? null : $parsed;
    }

    private function shorten(string $value, int $limit): string
    {
        return mb_strlen($value) > $limit ? mb_substr($value, 0, $limit - 1) . '…' : $value;
    }

    private function humanBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $i = 0;

        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }

        return round($bytes, 1) . ' ' . $units[$i];
    }
}

<?php

namespace App\Services\Network;

use App\Services\EdrAlertFactory;
use App\Services\EdrEventSpool;
use App\Services\Quality\EdrRuleGovernor;
use Illuminate\Support\Facades\Log;

/**
 * Turns socket telemetry into connection summaries, rule hits and history.
 *
 * Takes rows that have already been read from the sensor log rather than
 * reading it itself. That is deliberate: a log cursor has to survive rotation,
 * truncate-and-rewrite and partial trailing lines, every failure in one is
 * silent, and the shared cursor has already had three such bugs found and
 * fixed. A second cursor over the same file would reintroduce them one at a
 * time, and two cursors that can drift apart turn "why did the network module
 * miss this" into a question about which of them was where.
 *
 * It exists as its own class instead of more branches in the process collector
 * because socket events have a genuinely different lifecycle. They must be
 * aggregated across a whole batch before any rule can look at them, they carry
 * their own long-lived baseline, and — measured on a real host — they arrive at
 * 6.5 times the rate of process events, so they need their own volume ceiling
 * rather than sharing one ring buffer with the events the process rules depend
 * on.
 *
 * What made that concrete, measured on the live spool: 391,067 raw `connect`
 * events, 78.1% of everything in it, and not one rule in the process engine
 * matches that action. Of those, 98,518 were loopback, 61,285 private, 39,453
 * had no address at all and 21,338 were AF_UNIX paths rather than addresses.
 *
 * The cost is not disk, it is history. That spool sits at 500,584 rows against
 * a 500,000 ceiling, and at the observed rate of 6.67 million connect events a
 * day the retained window has collapsed to 1.42 hours — for `exec` events too,
 * since they share the ceiling. `edr_spool_retention_days` defaults to seven
 * days, but the row cap bites 118 times sooner, so retro-hunt, chain
 * correlation and alert attribution all really reach back eighty-five minutes.
 * Identity events survive 52 to 64 hours in the same database, because those
 * were given their own ceiling for exactly this reason.
 *
 * Aggregating what survives the scope filter takes the same telemetry to
 * roughly 5,900 external relationships a day, which returns `exec` retention to
 * about 6.6 hours.
 */
class NetworkCollector
{
    private SocketEventNormalizer $normalizer;
    private ConnectionAggregator $aggregator;
    private NetworkRuleEngine $rules;
    private NetworkBaselineStore $baseline;
    private EdrEventSpool $spool;
    private EdrAlertFactory $factory;
    private EdrRuleGovernor $governor;
    private ?AsnAnnotator $annotator;

    public function __construct(
        SocketEventNormalizer $normalizer,
        ConnectionAggregator $aggregator,
        NetworkRuleEngine $rules,
        NetworkBaselineStore $baseline,
        EdrEventSpool $spool,
        EdrAlertFactory $factory,
        EdrRuleGovernor $governor,
        ?AsnAnnotator $annotator = null
    ) {
        $this->normalizer = $normalizer;
        $this->aggregator = $aggregator;
        $this->rules = $rules;
        $this->baseline = $baseline;
        $this->spool = $spool;
        $this->factory = $factory;
        $this->governor = $governor;
        $this->annotator = $annotator;
    }

    /**
     * Process one batch of socket and listener rows.
     *
     * @param array<int, array> $socketRows   decoded `process_socket` result rows
     * @param array<int, array> $listenerRows decoded `listeners` result rows
     * @param array             $options      sensor options from the Hub
     * @return array{alerts: array<int, array>, stats: array, events: array<int, array>}
     */
    public function collect(array $socketRows, array $listenerRows = [], array $options = []): array
    {
        $stats = [
            'raw' => count($socketRows) + count($listenerRows),
            'kept' => 0,
            'dropped_scope' => 0,
            'dropped_agent' => 0,
            'aggregated' => 0,
            'ratio' => 0.0,
            'alerts' => 0,
            'suppressed' => 0,
            'spooled' => 0,
            'by_rule' => [],
        ];

        if ($socketRows === [] && $listenerRows === []) {
            return ['alerts' => [], 'stats' => $stats, 'events' => []];
        }

        $normalized = $this->normalizeBatch($socketRows, $options, $stats);
        $aggregated = $this->aggregator->aggregate(
            $normalized,
            max(100, (int) ($options['network_max_connections'] ?? 5000))
        );

        $stats['kept'] = count($normalized);
        $stats['aggregated'] = count($aggregated);
        $ratio = $this->aggregator->ratio($normalized, $aggregated);
        $stats['ratio'] = $ratio['ratio'];

        // Listeners are a snapshot of state rather than a stream of events, so
        // they bypass aggregation entirely — there is nothing to collapse.
        $events = array_merge($aggregated, $this->normalizeListeners($listenerRows));

        if ($events === []) {
            return ['alerts' => [], 'stats' => $stats, 'events' => []];
        }

        $this->annotate($events);

        return $this->evaluate($events, $options, $stats);
    }

    /**
     * @param array<int, array> $rows
     * @return array<int, array>
     */
    private function normalizeBatch(array $rows, array $options, array &$stats): array
    {
        $normalized = [];

        foreach ($rows as $row) {
            $columns = $row['columns'] ?? null;

            if (!is_array($columns)) {
                continue;
            }

            $event = $this->normalizer->normalize($row, $columns);

            if ($event === null) {
                continue;
            }

            // Our own sensors talk to the network constantly. Counting that as
            // host behaviour would mean the product detecting itself, and on a
            // quiet host it would be most of what the rules see.
            if ($this->normalizer->isAgentNoise($event)) {
                $stats['dropped_agent']++;
                continue;
            }

            if ($this->normalizer->shouldDrop($event, $options)) {
                $stats['dropped_scope']++;
                continue;
            }

            $normalized[] = $event;
        }

        return $normalized;
    }

    /**
     * @param array<int, array> $rows
     * @return array<int, array>
     */
    private function normalizeListeners(array $rows): array
    {
        $listeners = [];

        foreach ($rows as $row) {
            $columns = $row['columns'] ?? null;

            if (!is_array($columns)) {
                continue;
            }

            $event = $this->normalizer->normalizeListener($row, $columns);

            if ($event !== null && !$this->normalizer->isAgentNoise($event)) {
                $listeners[] = $event;
            }
        }

        return $listeners;
    }

    /**
     * Attach ownership context to external destinations.
     *
     * One annotator instance for the whole batch, which is not a style
     * preference: the lookup is 223.7ms cold against 1.9ms warm, so a
     * per-event instance would spend minutes doing work it had already done.
     */
    private function annotate(array &$events): void
    {
        if ($this->annotator === null) {
            return;
        }

        foreach ($events as &$event) {
            if (($event['network']['scope'] ?? '') === 'external') {
                $event = $this->annotator->annotate($event);
            }
        }

        unset($event);
    }

    /**
     * @param array<int, array> $events
     * @return array{alerts: array<int, array>, stats: array}
     */
    private function evaluate(array $events, array $options, array $stats): array
    {
        $alerts = [];
        $spoolEvents = [];
        $spoolFindings = [];
        $spoolDeliverable = [];

        foreach ($events as $event) {
            $findings = $this->rules->evaluate($event);
            $allowed = [];

            foreach ($findings as $finding) {
                $decision = $this->governor->assess($finding, $event, $options);
                $this->governor->record($decision, $finding, $event, $options);

                // `emit`, not `deliver`. The first version of this line read a
                // key the governor does not return, and it produced no error
                // of any kind: every finding read as suppressed, the cycle
                // reported success, and nothing would ever have reached the
                // Hub. Read without a `??` default on purpose, so a future
                // rename fails loudly instead of silently disabling every
                // network alert.
                if ($decision['emit'] === true) {
                    $finding['stage'] = $decision['stage'];
                    $finding['allow_response'] = $decision['allow_response'];
                    $allowed[] = $finding;
                    $rule = (string) ($finding['rule'] ?? '?');
                    $stats['by_rule'][$rule] = ($stats['by_rule'][$rule] ?? 0) + 1;
                } else {
                    $stats['suppressed']++;
                }
            }

            $index = count($spoolEvents);
            $spoolEvents[] = $event;

            if ($findings !== []) {
                $spoolFindings[$index] = $findings;
                // Suppressed findings are still stored — rule tuning and
                // retro-hunt both need to see what was held back — but only an
                // allowed one may be queued for the Hub.
                $spoolDeliverable[$index] = $allowed !== [];
            }

            if ($allowed !== []) {
                $alerts[] = $this->factory->fromEvent($event, $allowed);
                $stats['alerts']++;
            }
        }

        // Learning happens after the whole batch is judged, not after each
        // event, and the difference is not cosmetic.
        //
        // Recording inside the loop means the first event of a batch teaches
        // the baseline that the second event is then judged against. On a host
        // with no listener history, the first cycle would find the first
        // listener unknowable and stay silent — correctly — and then report
        // every remaining listener on the host as new, because by then the
        // baseline was no longer empty. Measured on a two-listener batch:
        // one spurious NET-003.
        //
        // The deeper problem is that it made the outcome depend on the order
        // events happened to appear in the batch, which nothing guarantees.
        // Judging an entire cycle against the state at the start of that cycle
        // is what makes the result reproducible, and it is also what keeps the
        // first sighting of a C2 channel from establishing itself as normal in
        // the same cycle it is being evaluated in.
        foreach ($events as $event) {
            $this->rules->learn($event);
        }

        $stats['spooled'] = $this->spool->store($spoolEvents, $spoolFindings, $spoolDeliverable);

        // The aggregated connections are handed back so in-cycle consumers can
        // read them — the correlation engine lights its egress stage from them.
        //
        // These are summaries, not raw telemetry, and that distinction is the
        // whole point of the hand-off. One connection relationship stands for
        // every syscall that made it: measured, 12,813 raw socket rows reduce to
        // 261 relationships, of which 166 are external. At the observed rate
        // that is roughly 5,900 rows a day against 6.67 million raw, and it
        // still carries every field an egress question needs — executable path,
        // peer address and port, scope, and a `first_seen` that is the real
        // first connection on the kernel clock rather than the moment this
        // cycle ran.
        //
        // They are already stored above. A caller must not store them again.
        return ['alerts' => $alerts, 'stats' => $stats, 'events' => $events];
    }

    /**
     * Trim the connection baseline.
     *
     * Separate from the event spool's prune because the two answer different
     * questions over different horizons: the spool holds recent raw history for
     * retro-hunting, while the baseline holds a long, small summary of what is
     * normal. Ninety days of the latter is a few thousand rows.
     */
    public function pruneBaseline(array $options = []): int
    {
        try {
            return $this->baseline->prune(max(7, (int) ($options['network_baseline_days'] ?? 90)));
        } catch (\Throwable $e) {
            Log::warning('[EDR network] Baseline prune failed: ' . $e->getMessage());

            return 0;
        }
    }

    public function baselineStats(): array
    {
        try {
            return $this->baseline->stats();
        } catch (\Throwable $e) {
            return ['available' => false, 'error' => $e->getMessage()];
        }
    }
}

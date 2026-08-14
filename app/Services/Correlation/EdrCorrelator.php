<?php

namespace App\Services\Correlation;

use App\Services\EdrEventSpool;
use App\Services\EdrRuleEngine;
use App\Services\EdrSecretRedactor;
use Illuminate\Support\Facades\Log;

/**
 * EDR-100 — Lineage Novelty Budget.
 *
 * The eleven behaviour rules are memoryless functions of one command line, so
 * the only question they can answer is "is this string bad". An intrusion is
 * not a string. It is a set of stages reached by one actor over hours or days,
 * where every individual step is defensible on its own: a shell, a download, a
 * `whoami`, a `sudo`, a `tar`, an outbound connection. No rule catches that,
 * and no number of additional rules ever will, because the evidence is in the
 * *relationships* between events rather than in any one of them.
 *
 * This class adds the one stateful layer that can see those relationships:
 *
 *  1. **Lineage.** Every exec is attached to a durable actor — the entry point
 *     its causal chain descends from — which survives process death, cycle
 *     boundaries, daemonisation and pid reuse. See {@see EdrLineageResolver}.
 *
 *  2. **Novelty.** Each event is decomposed into six structural facets whose
 *     familiarity is learned from this host's own past, measured in *distinct
 *     calendar days*. Volume buys nothing. See {@see EdrFacetModel}.
 *
 *  3. **Stage coverage.** Charges land in ten capped kill-chain classes and
 *     the score is their capped sum plus a bounded ordering bonus. Two classes
 *     cannot reach the threshold at any event volume, ever. See
 *     {@see EdrActorScorer}.
 *
 *  4. **Economics.** Novelty-only incidents are spent from a token budget, so
 *     alert volume is a contract rather than an emergent property. See
 *     {@see EdrEmissionBudget}.
 *
 * ## What this component is not allowed to do
 *
 * It is a **consumer** of findings, never a mutator of them. If it throws, if
 * its state file is unwritable, if the Hub pushes a nonsensical weight table,
 * the eleven rules have already produced their findings and those findings
 * ship exactly as they do today. EDR-100 can only ever *add*. That is enforced
 * by the call site — the correlator runs after `$findingsByEvent` is complete
 * and inside its own try/catch — and asserted by a property test rather than
 * left to discipline.
 */
final class EdrCorrelator
{
    /** Upper bound on one event's contribution, however novel and however damning. */
    public const CHARGE_MAX = 16.0;

    /** What a rule finding is worth as evidence, by severity. */
    private const FINDING_CHARGE = [
        'critical' => 6.0,
        'high' => 4.0,
        'medium' => 2.0,
        'low' => 1.0,
    ];

    /** Exposure multiplier by entry point. */
    private const DEFAULT_EXPOSURE = [
        'web' => 1.6,
        'container' => 1.4,
        'cron' => 1.2,
        'ssh' => 1.0,
        'orphan' => 1.0,
        'unknown' => 1.0,
        'init' => 0.8,
        'desktop' => 0.7,
    ];

    /** Damping by host role — a build farm is legitimately chaotic. */
    private const DEFAULT_PROFILE_SCALE = [
        'build' => 0.7,
        'container_host' => 0.85,
        'dev' => 0.8,
    ];

    /** Package managers for the platform being watched; see the profile. */
    private array $packageManagers = [];

    /** How long after a package manager runs its collateral stays discounted. */
    private const PKG_WINDOW = 300;

    /** The pseudo-actor that sees every charge, for split detection. */
    public const HOST_ACTOR = '__host__';

    /** Evidence rows kept per actor. */
    private const EVIDENCE_SLOTS = 12;

    private EdrCorrelatorStore $store;
    private EdrLineageResolver $lineage;
    private EdrFacetModel $facets;
    private EdrIntentClassifier $classifier;
    private EdrActorScorer $scorer;
    private EdrEmissionBudget $budget;
    private EdrSecretRedactor $redactor;
    private ?EdrRuleEngine $rules;

    private array $config = [];
    private bool $enabled = false;
    private bool $clockAnomaly = false;

    /** Highest day the facet model is allowed to treat as "today" this cycle. */
    private int $learnDayCeiling = PHP_INT_MAX;
    private array $stats = [];

    /** Set when replaying history, which disables the bootstrap concession. */
    private bool $replayMode = false;

    public function __construct(
        EdrCorrelatorStore $store,
        EdrLineageResolver $lineage,
        EdrFacetModel $facets,
        EdrIntentClassifier $classifier,
        EdrActorScorer $scorer,
        EdrEmissionBudget $budget,
        ?EdrSecretRedactor $redactor = null,
        ?EdrRuleEngine $rules = null
    ) {
        $this->store = $store;
        $this->lineage = $lineage;
        $this->facets = $facets;
        $this->classifier = $classifier;
        $this->scorer = $scorer;
        $this->budget = $budget;
        $this->redactor = $redactor ?? new EdrSecretRedactor();
        $this->rules = $rules;
        $this->resetStats();
    }

    /**
     * Build a correlator from a Hub config blob, wiring every collaborator
     * with the same clamped settings.
     */
    public static function make(
        array $config = [],
        ?string $statePath = null,
        ?EdrEventSpool $spool = null,
        ?EdrSecretRedactor $redactor = null,
        ?EdrRuleEngine $rules = null
    ): self {
        $store = new EdrCorrelatorStore($statePath);
        $config['platform'] ??= \App\Services\Platform\EdrPlatformProfile::current();

        $correlator = new self(
            $store,
            new EdrLineageResolver($store, $spool, $config),
            new EdrFacetModel($store, $config),
            new EdrIntentClassifier($config),
            new EdrActorScorer($config),
            new EdrEmissionBudget($store, $config),
            $redactor,
            $rules
        );
        $correlator->setConfig($config);

        return $correlator;
    }

    /**
     * Accept Hub settings.
     *
     * Everything is clamped rather than rejected. A Hub typo must degrade the
     * detection, never disable it silently — a correlator that quietly stopped
     * scoring because someone sent `half_life_h: -1` is worse than one running
     * on the wrong constant, because nobody would notice.
     */
    public function setConfig(array $options): void
    {
        $this->enabled = (bool) ($options['correlator_enabled'] ?? false);

        // The platform vocabulary is set once per cycle and pushed into the
        // pure extractor, which has no constructor to inject it through.
        $platform = ($options['platform'] ?? null) instanceof \App\Services\Platform\EdrPlatformProfile
            ? $options['platform']
            : \App\Services\Platform\EdrPlatformProfile::current();

        $this->packageManagers = $platform->packageManagers();
        EdrFacetExtractor::usePlatform($platform);

        $this->config = [
            'absorb' => (bool) ($options['correlator_absorb'] ?? false),
            'warm_events' => max(1000, min(5000000, (int) ($options['correlator_warm_events'] ?? 50000))),
            'warm_days' => max(3, min(60, (int) ($options['correlator_warm_days'] ?? 14))),
            'min_classes' => max(2, min(6, (int) ($options['correlator_min_classes'] ?? 3))),
            'min_events' => max(1, min(10, (int) ($options['correlator_min_events'] ?? 3))),
            'solo' => max(6.0, min(30.0, (float) ($options['correlator_solo'] ?? 14.0))),
            'cooldown' => max(300, min(86400, (int) ($options['correlator_cooldown_s'] ?? 3600))),
            'escalation' => max(1.2, min(5.0, (float) ($options['correlator_escalation_mult'] ?? 1.6))),
            'incident_baseline_min' => max(2, min(50, (int) ($options['correlator_incident_baseline_min'] ?? 5))),
            'sig_ttl' => max(7, min(180, (int) ($options['correlator_sig_ttl_days'] ?? 30))) * 86400,
            'facet_cap' => max(10000, min(1000000, (int) ($options['correlator_facet_cap'] ?? 200000))),
            'maintenance_until' => max(0, (int) ($options['correlator_maintenance_until'] ?? 0)),
            'pkg_scale' => max(0.0, min(1.0, (float) ($options['correlator_pkg_scale'] ?? 0.3))),
            'profile' => (string) ($options['host_profile'] ?? ''),
            'web_roots' => array_slice(
                is_array($options['correlator_web_roots'] ?? null) ? $options['correlator_web_roots'] : [],
                0,
                32
            ),
            'host_id' => (string) ($options['host_id'] ?? gethostname() ?: 'unknown'),
            'weights' => $this->clampWeights($options['correlator_weights'] ?? null),
            'exposure' => $this->clampMap(
                $options['correlator_exposure'] ?? null,
                self::DEFAULT_EXPOSURE,
                0.0,
                3.0
            ),
            'profile_scale' => $this->clampMap(
                $options['correlator_profile_scale'] ?? null,
                self::DEFAULT_PROFILE_SCALE,
                0.25,
                1.5
            ),
        ];
    }

    public function setReplayMode(bool $replay): void
    {
        $this->replayMode = $replay;
    }

    public function isAvailable(): bool
    {
        return $this->enabled && $this->store->isAvailable();
    }

    public function close(): void
    {
        $this->store->close();
    }

    /**
     * Score a cycle's events and return any incidents worth raising.
     *
     * @param  array<int, array> $events           normalised, in arrival order
     * @param  array<int, array> $findingsByEvent  rule hits keyed by event index, INCLUDING suppressed ones
     * @param  array<int, array> $governanceByEvent per-finding governor decisions, keyed by event index
     * @return array<int, array{event_index:int, event:array, findings:array, absorbs:int[]}>
     */
    public function correlate(array $events, array $findingsByEvent = [], array $governanceByEvent = []): array
    {
        $this->resetStats();

        if (!$this->enabled || $events === []) {
            return [];
        }

        if (!$this->store->isAvailable()) {
            $this->stats['error'] = 'state_unavailable';

            return [];
        }

        $incidents = [];

        try {
            $this->store->begin();
            $incidents = $this->run($events, $findingsByEvent, $governanceByEvent);
            $this->store->commit();
        } catch (\Throwable $e) {
            $this->store->rollBack();
            $this->stats['error'] = $e->getMessage();

            // Not every failure means the state is broken.
            //
            // The watchdog will start a second `ids:sync-edr` while the first
            // is still inside its transaction, and SQLite answers that with a
            // lock error. Treating a transient lock as corruption threw away
            // weeks of learned behaviour and restarted the fortnight-long
            // warm-up — a self-inflicted outage of the entire detection, from
            // two processes overlapping by a second.
            //
            // Skipping the cycle is the right response to a busy database.
            // The events are still in the spool, and the next cycle picks up
            // where this one stopped.
            if ($this->isTransientStateError($e)) {
                Log::info('[EDR correlator] Cycle skipped, state busy: ' . $e->getMessage());

                return [];
            }

            // Genuine corruption. Fail closed: resetting puts the model back
            // behind the warm-up gate — silent — rather than into a state
            // where every facet looks novel and every actor is over threshold.
            $this->store->resetToCold('exception: ' . $e->getMessage());

            Log::warning('[EDR correlator] Cycle failed, state reset to cold: ' . $e->getMessage());

            return [];
        }

        return $incidents;
    }

    /**
     * Failures that mean "try again later", not "the state is broken".
     *
     * Contention, a read-only filesystem and a full disk are all conditions
     * that resolve themselves or need an operator — none of them is a reason
     * to destroy a model that took two weeks to build.
     */
    private function isTransientStateError(\Throwable $e): bool
    {
        $message = strtolower($e->getMessage());

        foreach ([
            'database is locked',
            'database table is locked',
            'database is busy',
            'attempt to write a readonly database',
            'disk i/o error',
            'database or disk is full',
            'unable to open database',
            'cannot create correlator directory',
        ] as $needle) {
            if (str_contains($message, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return array<int, array>
     */
    private function run(array $events, array $findingsByEvent, array $governanceByEvent): array
    {
        $cycleTs = $this->cycleClock($events);
        $this->applyClockGuard($cycleTs);

        $this->lineage->prime($events);
        $this->budget->refill($cycleTs);

        /** @var array<string, array> $actors */
        $actors = [];
        /** @var array<string, array> $touched  actor_key => context for emission */
        $touched = [];

        $hostKey = self::HOST_ACTOR;
        $actors[$hostKey] = $this->loadActor($hostKey, 'host', $cycleTs);

        $scoredEvents = 0;

        foreach ($events as $index => $event) {
            if (!is_array($event) || $this->isExcluded($event)) {
                $this->stats['excluded']++;

                continue;
            }

            $ts = (int) ($event['ts'] ?? 0);

            // An aggregated network relationship is stamped with the moment it
            // began, not the moment the aggregation ran — the producer sets
            // both `ts` and `network.first_seen` to the earliest wall clock in
            // the group, and pins that with a contract test. This is belt and
            // braces for any other producer that might not: the chain needs
            // the start of the relationship, because that is where the stage
            // actually lit, and taking an aggregation time instead would push
            // every egress to the end of the cycle and flatten the ordering
            // the score depends on.
            $relationStart = (int) ($event['network']['first_seen'] ?? 0);

            if ($relationStart > 0 && $relationStart < $ts) {
                $ts = $relationStart;
            }

            if ($ts <= 0) {
                continue;
            }

            $findings = $this->usableFindings($findingsByEvent[$index] ?? [], $governanceByEvent[$index] ?? []);

            $resolved = $this->lineage->resolve($event, $this->config['web_roots']);
            $actorKey = $resolved['actor_key'];

            // Only process and network events carry structural novelty.
            //
            // A file-integrity event describes a file, and the extractor reads
            // `path` as the thing that ran — so a file event would mint a
            // never-seen "image" and a never-seen "lineage" out of a *file
            // name*. On any host where users upload things, every upload would
            // be maximally novel forever. File events still reach the chain
            // through their rule findings, which is the signal they actually
            // provide.
            $action = (string) ($event['action'] ?? 'exec');
            $scorable = $action === 'exec' || EdrFacetExtractor::isNetworkAction($action);

            $facets = $scorable
                ? EdrFacetExtractor::facetsFor(
                    $event,
                    $resolved['parent'],
                    $this->config['web_roots'],
                    $this->config['weights']
                )
                : [];

            $fam = [];
            $eRaw = 0.0;

            if ($facets !== []) {
                $fids = array_column($facets, 'fid');
                $this->facets->prime($fids);
                $this->facets->applyTombstones($facets, $ts);
                $fam = $this->facets->familiarity($fids, $ts);

                foreach ($facets as $facet) {
                    $eRaw += (float) $facet['weight'] * (1.0 - ($fam[$facet['fid']] ?? 0.0));
                }
            }

            $actors[$actorKey] ??= $this->loadActor($actorKey, $resolved['anchor_kind'], $ts);

            // Roll the day before anything else touches the actor: the novelty
            // EWMA has to close out yesterday before today's charges land in
            // it, or a burst at midnight is counted against the wrong day.
            $day = intdiv($ts, 86400);
            $actors[$actorKey] = $this->scorer->rollDay($actors[$actorKey], $day);
            $actors[$hostKey] = $this->scorer->rollDay($actors[$hostKey], $day);

            // An event with no facets has no shape to remember, so it never
            // enters the charge-once ledger — otherwise every file event on
            // the host would collide on the same empty signature.
            $signature = $facets !== [] ? EdrFacetExtractor::signature($facets) : '';
            $chargedBefore = $signature !== '' && $this->isChargedRecently($actorKey, $signature, $ts);

            // Evaluated unconditionally for scorable events: arming the
            // package-manager window is a side effect, and `apt-get -y upgrade`
            // has a stable signature, so gating this behind the charge-once
            // check meant the window armed exactly once in the life of the host
            // and never again. File events are excluded for the same reason
            // they are excluded from facets — their `path` names a file, and a
            // document called `dpkg` is not a package manager.
            $pkgScale = $scorable ? $this->packageScale($actors[$actorKey], $event, $ts) : 1.0;

            $eTotal = $chargedBefore
                ? 0.0
                : $eRaw * $this->exposureFor($resolved['anchor_kind'], $ts)
                    * $this->profileScale()
                    * $pkgScale;

            $ruleCharge = $this->findingCharge($findings);
            $charge = min(self::CHARGE_MAX, $eTotal + $ruleCharge);

            $classIds = $this->classifier->classify($event, $facets, $fam, $findings, [
                'anchor_kind' => $resolved['anchor_kind'],
                'parent' => $resolved['parent'],
                'web_roots' => $this->config['web_roots'],
            ]);

            // Decay and re-evaluate on EVERY event, not only on charging ones.
            // A chain that stops has to cool down, and an actor whose events
            // have all become familiar produces no charge at all — so gating
            // the decay on "something happened" is exactly the case where the
            // score would freeze at its warm-up peak and sit there forever,
            // one unusual Tuesday away from an alert.
            foreach ([$actorKey, $hostKey] as $key) {
                $actors[$key] = $this->scorer->decay($actors[$key], $ts);
                $actors[$key] = $this->scorer->apply($actors[$key], $charge, $classIds, $ts);
            }

            if ($classIds !== [] || $charge > 0.0) {
                $actors[$hostKey] = $this->noteContributor($actors[$hostKey], $actorKey, $ts);
            }

            if ($charge > 0.0) {
                $actors[$actorKey] = $this->pushEvidence(
                    $actors[$actorKey],
                    $event,
                    $facets,
                    $fam,
                    $charge,
                    $classIds
                );
                $actors[$hostKey] = $this->pushEvidence(
                    $actors[$hostKey],
                    $event,
                    $facets,
                    $fam,
                    $charge,
                    $classIds
                );
            }

            $this->learn($actors, $actorKey, $facets, $fam, $eRaw, $findings, $resolved, $ts, $day);

            if (!$chargedBefore && $signature !== '') {
                $this->rememberSignature($actorKey, $signature, $ts);
            }

            // The incident is reported against the event that contributed most,
            // so the event itself has to travel with the index rather than
            // being overwritten by whatever happened to arrive last — an alert
            // whose index and body disagree is worse than either alone.
            $isStrongest = $charge >= (float) ($touched[$actorKey]['charge'] ?? 0.0);

            $touched[$actorKey] = [
                'event_index' => $index,
                'event' => $isStrongest ? $event : ($touched[$actorKey]['event'] ?? $event),
                'findings' => array_merge((array) ($touched[$actorKey]['findings'] ?? []), $findings),
                'ts' => $ts,
                'lineage' => $resolved['lineage'],
                'charge' => max((float) ($touched[$actorKey]['charge'] ?? 0.0), $charge),
                'top_index' => $isStrongest
                    ? $index
                    : (int) ($touched[$actorKey]['top_index'] ?? $index),
                'members' => array_merge((array) ($touched[$actorKey]['members'] ?? []), [$index]),
            ];

            $scoredEvents++;
            $this->stats['scored']++;
            $this->stats['charge_total'] += $charge;
        }

        $this->advanceCorpusCounters($scoredEvents, $events);

        $incidents = $this->emit($actors, $touched, $cycleTs);

        $this->persist($actors);
        $this->maintain($cycleTs);

        return $incidents;
    }

    /* ------------------------------------------------------------------ */
    /* Emission                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Decide which actors have crossed, and shape the incidents.
     *
     * @return array<int, array>
     */
    private function emit(array &$actors, array $touched, int $cycleTs): array
    {
        $mature = $this->isMature();
        $this->stats['mature'] = $mature;

        $jitter = EdrActorScorer::jitterFor($this->config['host_id']);
        $out = [];

        foreach ($touched as $actorKey => $context) {
            $candidate = $this->evaluate($actors, $actorKey, $context, $jitter, false, $mature);

            if ($candidate !== null) {
                $out[] = $candidate;
            }
        }

        // The host lane exists to catch an intrusion deliberately split across
        // several entry points, where no single actor accumulates enough.
        $hostContext = $this->hostContext($touched, $actors[self::HOST_ACTOR]);

        if ($hostContext !== null) {
            $candidate = $this->evaluate($actors, self::HOST_ACTOR, $hostContext, $jitter, true, $mature);

            if ($candidate !== null) {
                $out[] = $candidate;
            }
        }

        // Anything the budget held back earlier gets its turn as tokens refill.
        // A deferred actor is usually NOT part of the current cycle — that is
        // the normal case, not the exception — so it is reloaded from disk and
        // aged forward rather than skipped.
        $released = $this->budget->release(
            $cycleTs,
            function (array $candidate) use (&$actors, $touched, $cycleTs, $jitter, $mature): ?array {
                if (!$mature) {
                    return null;
                }

                $key = (string) $candidate['actor_key'];
                $hostLane = $key === self::HOST_ACTOR;

                if (!isset($actors[$key])) {
                    // Deliberately not `??= loadActor(...)`: that mints a blank
                    // actor when the row has been evicted, and persist() would
                    // then write an empty one back to disk for an incident
                    // that was never raised.
                    $stored = $this->store->loadActors([$key]);

                    if (!isset($stored[$key])) {
                        return null;
                    }

                    $actors[$key] = $this->loadActor($key, 'unknown', $cycleTs);
                }

                $actor = $this->scorer->decay($actors[$key], $cycleTs);
                $actor = $this->scorer->apply($actor, 0.0, [], $cycleTs);

                $scored = $this->scorer->score($actor);
                $threshold = $this->scorer->threshold($actor, $jitter, $hostLane);
                $minClasses = $hostLane ? max(4, $this->config['min_classes'] + 1) : $this->config['min_classes'];

                // It has to still be worth reporting now, not when it queued.
                if ($scored['classes'] < $minClasses || $scored['score'] < $threshold) {
                    return null;
                }

                // The host lane's foothold gate applies here too, or the queue
                // becomes a way around it.
                if ($hostLane && count($this->distinctFootholds($actor)) < 3) {
                    return null;
                }

                // And so do the cooldown and escalation gates. Deduping the
                // queue is not enough on its own: nothing removes a queued
                // entry when the same actor emits through the direct path in
                // the same cycle, so without these an actor that crossed while
                // the bucket was empty produced two byte-identical incidents —
                // and each one advanced the recurrence counter, so three such
                // cycles muted the chain permanently. Exactly the self-mute
                // the deferral rework exists to remove.
                if ((int) $actor['last_alert_ts'] > 0) {
                    if ($cycleTs - (int) $actor['last_alert_ts'] < $this->config['cooldown']) {
                        return null;
                    }

                    if ($scored['score'] < $this->config['escalation'] * (float) $actor['last_alert_score']) {
                        return null;
                    }
                }

                $context = $touched[$key] ?? [
                    'event_index' => 0,
                    'top_index' => 0,
                    'event' => ['ts' => (int) $actor['last_ts'], 'host' => $this->config['host_id']],
                    'findings' => [],
                    'ts' => $cycleTs,
                    'lineage' => 'deferred',
                    'members' => [],
                ];

                $incident = $this->shape($actor, $context, $threshold, $hostLane, true);

                if ($incident === null) {
                    return null;
                }

                // Gate 7 applies to the release path as well. Without it the
                // queue is a way around the recurrence baseline: a signature
                // already shown to the analyst enough times to be suppressed
                // on the direct path would still come out of the queue, and
                // advance its own counter while doing so.
                if ($this->store->incidentOccurrences($incident['signature']) >= $this->config['incident_baseline_min']
                    && $incident['finding']['severity'] !== 'critical'
                ) {
                    $this->stats['suppressed_recurring']++;

                    return null;
                }

                $actors[$key] = $actor;
                $actors[$key]['last_alert_ts'] = $cycleTs;
                $actors[$key]['last_alert_score'] = $scored['score'];
                $this->store->observeIncident($incident['signature'], $incident['sample'], $cycleTs);
                $this->stats['emitted']++;

                return $incident['payload'];
            }
        );

        foreach ($released as $incident) {
            $out[] = $incident;
        }

        $this->budget->persist();

        return $out;
    }

    /**
     * Run the nine emission gates for one actor.
     */
    private function evaluate(
        array &$actors,
        string $actorKey,
        array $context,
        float $jitter,
        bool $hostLane,
        bool $mature
    ): ?array {
        $actor = $actors[$actorKey];
        $scored = $this->scorer->score($actor);
        $threshold = $this->scorer->threshold($actor, $jitter, $hostLane);

        $minClasses = $hostLane ? max(4, $this->config['min_classes'] + 1) : $this->config['min_classes'];

        /* Gate 2 — stage coverage. This is the gate that makes the
         * false-positive bound arithmetic rather than tuned. */
        if ($scored['classes'] < $minClasses) {
            return null;
        }

        /* Gate 3 — the actor's own bar. */
        if ($scored['score'] < $threshold) {
            return null;
        }

        /* Gate 4 — enough independent events, or one event so far outside
         * anything this host has ever done that it stands alone. */
        if ((int) $actor['event_count'] < $this->config['min_events']
            && (float) $actor['max_charge'] < $this->config['solo']
        ) {
            return null;
        }

        /* Gate 1 — warm-up. Before the model has seen enough of this host to
         * know what normal looks like, every facet is novel and every actor
         * would cross on day one. Silence is the only honest output. */
        if (!$mature) {
            $this->stats['warmup_withheld']++;
            $this->stats['warmup_max_score'] = max($this->stats['warmup_max_score'], round($scored['score'], 2));

            return null;
        }

        $ts = (int) $context['ts'];

        /* Gate 5 — cooldown. */
        if ($ts - (int) $actor['last_alert_ts'] < $this->config['cooldown'] && (int) $actor['last_alert_ts'] > 0) {
            return null;
        }

        /* Gate 6 — escalate, do not repeat. A chain in progress keeps
         * accumulating; it only alerts again when it has got materially
         * worse. */
        if ((int) $actor['last_alert_ts'] > 0
            && $scored['score'] < $this->config['escalation'] * (float) $actor['last_alert_score']
        ) {
            return null;
        }

        $incident = $this->shape($actor, $context, $threshold, $hostLane, false);

        if ($incident === null) {
            return null;
        }

        /* Gate 7 — incident recurrence. The governance layer cannot do this
         * for us: its baseline suppression is skipped entirely at high and
         * critical severity, and it stops recording observations when its own
         * learning window closes — long before this model matures. */
        $signature = $incident['signature'];
        $occurrences = $this->store->incidentOccurrences($signature);

        if ($occurrences >= $this->config['incident_baseline_min']
            && $incident['finding']['severity'] !== 'critical'
        ) {
            $this->stats['suppressed_recurring']++;

            return null;
        }

        /* Gates 8 and 9 — the volume contract. */
        $ruleBacked = $incident['corroboration'] === 'strong';

        if (!$this->budget->admit(
            ['actor_key' => $actorKey, 'score' => $scored['score'], 'threshold' => $threshold, 'ts' => $ts],
            $ruleBacked,
            $ts
        )) {
            $this->stats['budget_deferred']++;

            return null;
        }

        // Counted only once the incident is genuinely raised.
        //
        // Counting on every *evaluation* was a way to mute a live intrusion:
        // an actor held back by the token budget is re-evaluated every cycle,
        // the agent runs every thirty seconds, and five cycles is two and a
        // half minutes — after which the chain looks "recurring" and is
        // suppressed permanently, while it is still in progress. The
        // recurrence baseline is about incidents an analyst has actually been
        // shown, so it may only advance when one is.
        $this->store->observeIncident($signature, $incident['sample'], $ts);

        $actors[$actorKey]['last_alert_ts'] = $ts;
        $actors[$actorKey]['last_alert_score'] = $scored['score'];

        // Reported, so anything queued for this actor is now redundant.
        $this->budget->forget($actorKey);

        $this->stats['emitted']++;

        return $incident['payload'];
    }

    /**
     * Build the incident payload, or null when it does not deserve one.
     *
     * @return array{payload:array, signature:string, sample:?string, corroboration:string, finding:array}|null
     */
    private function shape(array $actor, array $context, float $threshold, bool $hostLane, bool $released): ?array
    {
        $scored = $this->scorer->score($actor);

        if ($scored['lit'] === []) {
            return null;
        }

        $findings = $context['findings'] ?? [];
        $corroboration = $this->corroborationFor($findings);

        $hasCritical = false;
        foreach ($findings as $finding) {
            if (($finding['severity'] ?? '') === 'critical' && !empty($finding['_emitted'])) {
                $hasCritical = true;
            }
        }

        $severity = $this->scorer->severity($scored['score'], $threshold, $hasCritical);

        // An incident held up entirely by evidence this host has positive
        // proof is routine cannot escalate on its own. Structural novelty and
        // unproven-rule hits both count as genuine corroboration; a match the
        // governance layer demoted *because it recurs here* does not.
        if ($corroboration === 'baseline_only' && $severity !== 'medium') {
            $severity = 'medium';
        }

        $mitre = $this->classifier->mitreFor($scored['lit'], $findings);

        $incident = EdrIncident::fromActor(
            $actor,
            $scored,
            $this->evidenceOf($actor),
            [
                'rule' => $hostLane ? EdrIncident::RULE_HOST : EdrIncident::RULE_ACTOR,
                'lane' => $hostLane ? 'host' : 'actor',
                'severity' => $severity,
                'threshold' => $threshold,
                'mitre' => $mitre,
                'corroboration' => $corroboration,
                // True only when every contributing finding had already earned
                // the right to drive a response on its own. The caller ANDs
                // this with the incident rule's own stage, so an incident
                // assembled from three alert-stage rules cannot acquire
                // kill-a-process authority just because the total looks bad.
                'member_response_allowed' => $this->everyMemberAllowsResponse($findings),
                'lineage' => (string) ($context['lineage'] ?? 'linked'),
                'caps' => $this->scorer->caps(),
                'contributors' => $hostLane ? $this->recentContributors($actor) : [],
                'signature' => $this->incidentSignature($actor, $scored, $hostLane),
                'member_findings' => $findings,
                'anchor_event_index' => (int) ($context['top_index'] ?? $context['event_index']),
                'absorbed_event_indexes' => $this->config['absorb'] ? (array) ($context['members'] ?? []) : [],
            ]
        );

        $finding = $incident->toFinding();

        if ($released) {
            $finding['incident']['deferred_release'] = true;
        }

        return [
            'payload' => [
                'event_index' => (int) ($context['top_index'] ?? $context['event_index']),
                'event' => $context['event'],
                'findings' => [$finding],
                'absorbs' => $incident->absorbedEventIndexes(),
                'rule' => $incident->rule(),
                'severity' => $incident->severity(),
            ],
            'signature' => $incident->signature(),
            'sample' => $incident->payload()['classes'][0] ?? null,
            'corroboration' => $corroboration,
            'finding' => $finding,
        ];
    }

    /**
     * A stable description of "this kind of incident on this host".
     *
     * Coarse on purpose: the same actor reaching the same stages by the same
     * dominant novelty is the same story, and telling it every hour is how a
     * correlator becomes noise.
     */
    private function incidentSignature(array $actor, array $scored, bool $hostLane): string
    {
        $parts = explode('|', (string) $actor['actor_key']);

        return implode('|', [
            $hostLane ? EdrIncident::RULE_HOST : EdrIncident::RULE_ACTOR,
            (string) $actor['anchor_kind'],
            $parts[1] ?? '-',
            implode(',', $scored['lit']),
        ]);
    }

    /**
     * How much of this incident rests on findings that stand on their own.
     *
     *  - `strong`        — at least one finding the governance layer raised.
     *  - `unproven`      — findings exist but are all held back for reasons
     *                      that mean "we do not know yet" (an unproven rule, a
     *                      host still learning). Those are exactly the events
     *                      that make up the first half of a chain on a
     *                      freshly-installed agent, so they must count.
     *  - `baseline_only` — every finding was demoted because this host has
     *                      positive evidence the shape is routine.
     *  - `none`          — pure structural novelty, no rule involved.
     */
    private function corroborationFor(array $findings): string
    {
        if ($findings === []) {
            return 'none';
        }

        $sawUnproven = false;
        $sawBaseline = false;

        foreach ($findings as $finding) {
            if (!empty($finding['_emitted'])) {
                return 'strong';
            }

            if (($finding['_reason'] ?? null) === 'matches_baseline') {
                $sawBaseline = true;
            } else {
                $sawUnproven = true;
            }
        }

        if ($sawUnproven) {
            return 'unproven';
        }

        return $sawBaseline ? 'baseline_only' : 'none';
    }

    /**
     * Findings this component is allowed to reason about.
     *
     * A rule someone deliberately switched off is excluded outright. If a
     * disabled rule could still reach an analyst through correlation, the off
     * switch would not mean anything — and an off switch that does not work is
     * worse than a missed detection, because someone has already decided they
     * do not want to see it.
     */
    private function usableFindings(array $findings, array $governance): array
    {
        $out = [];

        foreach ($findings as $i => $finding) {
            if (!is_array($finding)) {
                continue;
            }

            $decision = $governance[$i] ?? null;

            $emitted = false;
            $reason = null;
            $allowResponse = false;

            if (is_array($decision)) {
                $emitted = (bool) ($decision['emit'] ?? false);
                $reason = $decision['reason'] ?? null;
                $allowResponse = (bool) ($decision['allow_response'] ?? false);
            } elseif (is_bool($decision)) {
                $emitted = $decision;
            }

            if ($reason === 'rule_disabled') {
                continue;
            }

            $finding['_emitted'] = $emitted;
            $finding['_reason'] = $reason;
            $finding['_allow_response'] = $allowResponse;
            $out[] = $finding;
        }

        return $out;
    }

    /**
     * Response authority is the AND of the members', never the OR.
     *
     * An incident is a statement about a *combination*; it is not evidence
     * that any of its parts has been proven trustworthy enough to act on
     * automatically. Taking the maximum here would turn correlation into a way
     * around the rule promotion process.
     */
    private function everyMemberAllowsResponse(array $findings): bool
    {
        if ($findings === []) {
            return false;
        }

        foreach ($findings as $finding) {
            if (empty($finding['_allow_response'])) {
                return false;
            }
        }

        return true;
    }

    private function findingCharge(array $findings): float
    {
        $charge = 0.0;

        foreach ($findings as $finding) {
            $charge = max($charge, self::FINDING_CHARGE[(string) ($finding['severity'] ?? 'low')] ?? 0.0);
        }

        return $charge;
    }

    /* ------------------------------------------------------------------ */
    /* Actor bookkeeping                                                   */
    /* ------------------------------------------------------------------ */

    private function loadActor(string $actorKey, string $anchorKind, int $ts): array
    {
        $rows = $this->store->loadActors([$actorKey]);

        if (!isset($rows[$actorKey])) {
            return $this->scorer->newActor($actorKey, $anchorKind, $ts);
        }

        $row = $rows[$actorKey];

        return [
            'actor_key' => $actorKey,
            'anchor_kind' => (string) $row['anchor_kind'],
            'acc' => $this->decodeMap($row['acc']),
            'class_first_ts' => $this->decodeMap($row['class_first_ts']),
            'first_ts' => (int) $row['first_ts'],
            'last_ts' => (int) $row['last_ts'],
            'nov' => (float) $row['nov'],
            'day_charges' => (float) $row['day_charges'],
            'day_key' => (int) $row['day_key'],
            'event_count' => (int) $row['event_count'],
            'max_charge' => (float) $row['max_charge'],
            'contributors' => $this->decodeList($row['contributors']),
            'evidence' => $this->decodeList($row['evidence']),
            'last_alert_ts' => (int) $row['last_alert_ts'],
            'last_alert_score' => (float) $row['last_alert_score'],
            'taught_today' => (int) $row['taught_today'],
            'taught_day' => (int) $row['taught_day'],
            'pkg_until' => (int) ($row['pkg_until'] ?? 0),
        ];
    }

    private function persist(array $actors): void
    {
        $rows = [];

        foreach ($actors as $actor) {
            $rows[] = [
                'actor_key' => $actor['actor_key'],
                'anchor_kind' => $actor['anchor_kind'],
                'acc' => json_encode($this->roundMap($actor['acc'])),
                'class_first_ts' => json_encode((object) $actor['class_first_ts']),
                'first_ts' => $actor['first_ts'],
                'last_ts' => $actor['last_ts'],
                'nov' => $actor['nov'],
                'day_charges' => $actor['day_charges'],
                'day_key' => $actor['day_key'],
                'event_count' => $actor['event_count'],
                'max_charge' => $actor['max_charge'],
                'contributors' => json_encode(array_values($actor['contributors'] ?? [])),
                'evidence' => $this->encodeEvidence($actor['evidence'] ?? []),
                'last_alert_ts' => $actor['last_alert_ts'],
                'last_alert_score' => $actor['last_alert_score'],
                'taught_today' => $actor['taught_today'],
                'taught_day' => $actor['taught_day'],
                'pkg_until' => $actor['pkg_until'] ?? 0,
            ];
        }

        $this->store->upsertActors($rows);
        $this->stats['facets_written'] = $this->facets->flush();
        $this->stats['procs_written'] = $this->lineage->flush();
    }

    /**
     * Track which actors fed the host lane, so a split can be described rather
     * than merely detected.
     */
    private function noteContributor(array $hostActor, string $actorKey, int $ts): array
    {
        if ($actorKey === self::HOST_ACTOR) {
            return $hostActor;
        }

        $contributors = [];

        foreach ($hostActor['contributors'] ?? [] as $entry) {
            if (!is_array($entry) || count($entry) < 2) {
                continue;
            }

            if ((string) $entry[0] === $actorKey) {
                continue;
            }

            $contributors[] = $entry;
        }

        $contributors[] = [$actorKey, $ts];

        // Keep the eight most recent. More than that is not a split, it is a
        // busy host.
        usort($contributors, static fn (array $a, array $b): int => $b[1] <=> $a[1]);
        $hostActor['contributors'] = array_slice($contributors, 0, 8);

        return $hostActor;
    }

    /**
     * Distinct actors that fed the host lane inside two score half-lives.
     */
    private function recentContributors(array $hostActor, int $window = 518400): array
    {
        $cutoff = (int) $hostActor['last_ts'] - $window;
        $out = [];

        foreach ($hostActor['contributors'] ?? [] as $entry) {
            if (is_array($entry) && count($entry) >= 2 && (int) $entry[1] >= $cutoff) {
                $out[] = ['actor' => (string) $entry[0], 'last_seen' => (int) $entry[1]];
            }
        }

        return $out;
    }

    /**
     * Genuinely separate footholds, for the host lane's gate.
     *
     * Not the same thing as the contributor list. Orphaned chains — the ones
     * whose parent the sensor never saw — are bucketed into five-minute
     * windows so that a double-forked payload still groups with itself. That
     * bucket is a *grouping* device, not an identity: a host with unresolvable
     * parents mints a new orphan key every five minutes, and counting those as
     * independent entry points would make the host lane fire on what is really
     * one actor drifting through time. Collapse the bucket before counting.
     *
     * @return array<string, true>
     */
    private function distinctFootholds(array $hostActor, int $window = 518400): array
    {
        $cutoff = (int) $hostActor['last_ts'] - $window;
        $out = [];

        foreach ($hostActor['contributors'] ?? [] as $entry) {
            if (!is_array($entry) || count($entry) < 2 || (int) $entry[1] < $cutoff) {
                continue;
            }

            $parts = explode('|', (string) $entry[0]);

            if (($parts[2] ?? '') === 'orphan') {
                $parts[3] = 'o';
            }

            $out[implode('|', $parts)] = true;
        }

        return $out;
    }

    /**
     * The host lane only reports when several independent actors contributed —
     * otherwise it is just a louder copy of the actor lane.
     */
    private function hostContext(array $touched, array $hostActor): ?array
    {
        if ($touched === []) {
            return null;
        }

        // The host lane exists for ONE case: an intrusion deliberately spread
        // across separate footholds so that no single actor accumulates
        // enough. Without this check it fires whenever the aggregate crosses,
        // which on a single-actor chain means every EDR-100 arrives with a
        // duplicate EDR-101 attached — the correlator's own alert-volume
        // contract broken by the correlator.
        if (count($this->distinctFootholds($hostActor)) < 3) {
            return null;
        }

        $best = null;

        foreach ($touched as $context) {
            if ($best === null || (float) $context['charge'] > (float) $best['charge']) {
                $best = $context;
            }
        }

        if ($best === null) {
            return null;
        }

        $best['lineage'] = 'multi';
        $best['findings'] = [];

        foreach ($touched as $context) {
            foreach ($context['findings'] as $finding) {
                $best['findings'][] = $finding;
            }
        }

        return $best;
    }

    /* ------------------------------------------------------------------ */
    /* Evidence                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Keep the strongest events, plus one for each class the moment it lights.
     *
     * The second half matters: ranking purely by charge drops the cheap event
     * that opened a stage — often the most explanatory one in the whole chain —
     * in favour of a louder event in a stage that was already lit.
     */
    private function pushEvidence(
        array $actor,
        array $event,
        array $facets,
        array $fam,
        float $charge,
        array $classIds
    ): array {
        $novel = [];

        foreach ($facets as $facet) {
            if (($fam[$facet['fid']] ?? 0.0) < 0.25) {
                $novel[] = $this->facetName((int) $facet['kind']);
            }
        }

        $row = [
            'ts' => (int) ($event['ts'] ?? 0),
            'pid' => (int) ($event['pid'] ?? 0),
            'user' => (string) ($event['username'] ?? ''),
            'path' => (string) ($event['path'] ?? ''),
            // Redacted here, not at the boundary. Evidence is the one place a
            // correlator naturally wants to quote a command line, and a secret
            // that reaches this array reaches the spool, the Hub and every
            // support bundle taken afterwards.
            'cmdline' => mb_substr((string) $this->redactor->redact($event['cmdline'] ?? ''), 0, 300),
            'charge' => round($charge, 3),
            'novel_facets' => $novel,
            'classes' => array_map(
                static fn (int $c): string => EdrIntentClassifier::name($c),
                $classIds
            ),
        ];

        if (($event['action'] ?? '') === 'connect') {
            $row['remote'] = (string) ($event['remote_address'] ?? '') . ':' . (int) ($event['remote_port'] ?? 0);
        }

        $existingClasses = [];
        foreach ($actor['evidence'] as $entry) {
            foreach ((array) ($entry['classes'] ?? []) as $name) {
                $existingClasses[$name] = true;
            }
        }

        $opensAStage = false;
        foreach ($row['classes'] as $name) {
            if (!isset($existingClasses[$name])) {
                $opensAStage = true;
                break;
            }
        }

        $row['opened_stage'] = $opensAStage;

        $evidence = $actor['evidence'];
        $evidence[] = $row;

        if (count($evidence) > self::EVIDENCE_SLOTS) {
            // Stage-opening rows are protected; among the rest, the weakest
            // charge is dropped.
            usort($evidence, static function (array $a, array $b): int {
                $aProtected = !empty($a['opened_stage']) ? 1 : 0;
                $bProtected = !empty($b['opened_stage']) ? 1 : 0;

                return [$bProtected, $b['charge']] <=> [$aProtected, $a['charge']];
            });

            $evidence = array_slice($evidence, 0, self::EVIDENCE_SLOTS);
        }

        $actor['evidence'] = $evidence;

        return $actor;
    }

    /** Evidence in chronological order — an analyst reads a narrative. */
    private function evidenceOf(array $actor): array
    {
        $evidence = $actor['evidence'] ?? [];

        usort($evidence, static fn (array $a, array $b): int => ($a['ts'] ?? 0) <=> ($b['ts'] ?? 0));

        return $evidence;
    }

    private function encodeEvidence(array $evidence): string
    {
        $json = json_encode(array_values($evidence), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        // A pathological command line must not be able to grow one actor row
        // without bound.
        while ($json !== false && strlen($json) > 8192 && count($evidence) > 1) {
            array_pop($evidence);
            $json = json_encode(array_values($evidence), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        return $json === false ? '[]' : $json;
    }

    /* ------------------------------------------------------------------ */
    /* Learning                                                            */
    /* ------------------------------------------------------------------ */

    private function learn(
        array &$actors,
        string $actorKey,
        array $facets,
        array $fam,
        float $eRaw,
        array $findings,
        array $resolved,
        int $ts,
        int $day
    ): void {
        $actor = $actors[$actorKey];

        if ((int) $actor['taught_day'] !== $day) {
            $actor['taught_today'] = 0;
            $actor['taught_day'] = $day;
        }

        $decisions = $this->facets->learnDecisions(
            $facets,
            $fam,
            $eRaw,
            $findings !== [],
            (int) $actor['taught_today'],
            $this->clockAnomaly,
            (int) $resolved['anchor_id'],
            $day
        );

        foreach ($facets as $facet) {
            $this->facets->noteAnchor($facet['fid'], (int) $resolved['anchor_id'], $ts);
        }

        // No bootstrap concession while replaying: a cold replay exists
        // precisely to re-score history *without* the discount an intrusion
        // present during warm-up would otherwise keep forever.
        $bootstrap = !$this->replayMode && !$this->isMature() && $findings === [];

        // The clock-guarded day, not the event's own: a timestamp that jumped
        // forward must not be able to buy a day of familiarity.
        $taught = $this->facets->stage($facets, $decisions, $ts, $bootstrap, min($day, $this->learnDayCeiling));

        $actor['taught_today'] = (int) $actor['taught_today'] + $taught;
        $actors[$actorKey] = $actor;

        $this->stats['facets_taught'] += $taught;
    }

    /* ------------------------------------------------------------------ */
    /* Charge-once ledger                                                  */
    /* ------------------------------------------------------------------ */

    /** @var array<string, int> */
    private array $sigCache = [];

    /** @var array<int, array> */
    private array $sigWrites = [];

    private function isChargedRecently(string $actorKey, string $signature, int $ts): bool
    {
        $key = $actorKey . "\x1f" . $signature;

        if (!array_key_exists($key, $this->sigCache)) {
            $rows = $this->store->loadSigs([[$actorKey, $signature]]);
            $this->sigCache[$key] = $rows[$key] ?? 0;
        }

        $lastSeen = $this->sigCache[$key];

        return $lastSeen > 0 && $lastSeen > $ts - $this->config['sig_ttl'];
    }

    private function rememberSignature(string $actorKey, string $signature, int $ts): void
    {
        $key = $actorKey . "\x1f" . $signature;
        $this->sigCache[$key] = $ts;
        $this->sigWrites[] = ['actor_key' => $actorKey, 'sig' => $signature, 'last_seen' => $ts];
    }

    /* ------------------------------------------------------------------ */
    /* Multipliers                                                         */
    /* ------------------------------------------------------------------ */

    private function exposureFor(string $anchorKind, int $ts): float
    {
        // An operator-declared maintenance window zeroes structural novelty.
        // A planned rollout produces hundreds of never-before-seen images in
        // an hour, and the honest answer is to charge nothing for it rather
        // than to explain away the alerts afterwards.
        if ($this->config['maintenance_until'] > 0 && $ts <= $this->config['maintenance_until']) {
            return 0.0;
        }

        return (float) ($this->config['exposure'][$anchorKind] ?? 1.0);
    }

    private function profileScale(): float
    {
        return (float) ($this->config['profile_scale'][$this->config['profile']] ?? 1.0);
    }

    /**
     * Discount everything a package manager drags in behind it.
     *
     * An upgrade of two hundred packages is the loudest legitimate event a
     * host ever produces: hundreds of new images, new lineages, new argument
     * shapes, all inside a few minutes. The window is tracked on the actor so
     * it survives the cycle boundary the upgrade will certainly cross.
     */
    private function packageScale(array &$actor, array $event, int $ts): float
    {
        $path = (string) ($event['path'] ?? '');
        $binary = $path !== '' ? basename($path) : '';

        // The name alone is not enough. Keying only on the basename made the
        // discount available to anyone who called their dropper `apt`: a 70%
        // cut on its own charge, plus a five-minute window in which everything
        // else the actor did was discounted too. A package manager lives in a
        // system directory; a payload in /tmp called `dpkg` is the opposite of
        // a reason to charge less.
        $trusted = in_array(
            EdrFacetExtractor::dirclass($path, $this->config['web_roots']),
            ['sys', 'pkg'],
            true
        );

        if ($binary !== '' && $trusted && in_array($binary, $this->packageManagers, true)) {
            $actor['pkg_until'] = $ts + self::PKG_WINDOW;

            return $this->config['pkg_scale'];
        }

        return $ts <= (int) ($actor['pkg_until'] ?? 0) ? $this->config['pkg_scale'] : 1.0;
    }

    /* ------------------------------------------------------------------ */
    /* Warm-up, clock and maintenance                                      */
    /* ------------------------------------------------------------------ */

    /**
     * Has the model seen enough of this host to be allowed to speak?
     *
     * Both gates are required, and the reason is the failure they each catch.
     * Event count alone lets a busy host mature in an afternoon, before any
     * facet has accumulated the distinct days familiarity needs. Wall clock
     * alone lets a nearly-idle host mature having learned nothing at all. The
     * combination is the only formulation where "mature" means the model
     * actually knows something.
     */
    public function isMature(): bool
    {
        $scored = (int) ($this->store->getMeta('scored_events') ?? '0');

        if ($scored < $this->config['warm_events']) {
            return false;
        }

        $first = (int) ($this->store->getMeta('first_event_ts') ?? '0');
        $last = (int) ($this->store->getMeta('last_event_ts') ?? '0');

        if ($first <= 0 || $last <= $first) {
            return false;
        }

        $span = $last - $first;

        // The model cannot be older than the agent has been watching.
        //
        // Bounding the observation span per *cycle* is not a bound: at one
        // cycle every thirty seconds, fourteen cycles is seven minutes. One
        // event stamped a day before the current start pulls the span open by
        // a day each time, and no branch of the clock guard fires, because the
        // cycle's own clock is perfectly normal. Holding the span to real
        // elapsed time closes that, costs an honest host nothing, and is
        // exempted in replay — where walking recorded history quickly is the
        // entire point of the exercise.
        if (!$this->replayMode) {
            $watchingSince = (int) ($this->store->getMeta('watching_since') ?? '0');

            if ($watchingSince > 0) {
                $span = min($span, time() - $watchingSince);
            }
        }

        return $span >= $this->config['warm_days'] * 86400;
    }

    private function advanceCorpusCounters(int $scoredEvents, array $events): void
    {
        // Stamped once, from the agent's own clock, the first time this model
        // scores anything. It is the reference the maturity span is held to.
        if ($this->store->getMeta('watching_since') === null) {
            $this->store->setMeta('watching_since', (string) time());
        }

        if ($scoredEvents > 0) {
            $this->store->bumpMeta('scored_events', $scoredEvents);
        }

        $timestamps = array_filter(array_map(
            static fn ($event): int => is_array($event) ? (int) ($event['ts'] ?? 0) : 0,
            $events
        ));

        if ($timestamps === []) {
            return;
        }

        $first = (int) ($this->store->getMeta('first_event_ts') ?? '0');
        $min = min($timestamps);
        $max = max($timestamps);

        // Both ends of the observation span need guarding, not just the newer
        // one. The maturity gate is `last - first >= warm_days`, so a single
        // back-dated event satisfies it just as effectively as a future-dated
        // one — and an event stamped 1970 is exactly what a container with no
        // clock produces on its first boot.
        //
        // The bound is relative rather than absolute: a cycle covers about
        // thirty seconds of real time, so its own events cannot legitimately
        // span more than a day, and the span cannot be pulled backwards faster
        // than a day per cycle afterwards.
        if (!$this->replayMode) {
            $min = $first > 0 ? max($min, $first - 86400) : max($min, $max - 86400);
        }

        if ($first <= 0 || $min < $first) {
            $this->store->setMeta('first_event_ts', (string) $min);
        }

        $last = (int) ($this->store->getMeta('last_event_ts') ?? '0');

        // The observation span may not jump. One event carrying a timestamp
        // years in the future — a broken RTC, a container without an NTP
        // client, or an attacker who noticed the maturity gate — would
        // otherwise satisfy the fourteen-day requirement outright and switch
        // the model on before it has learned anything. Advancing by at most a
        // day per cycle still catches up after any real outage: the agent runs
        // 2880 cycles a day.
        $ceiling = $last > 0 && !$this->replayMode ? $last + 86400 : $max;

        if ($max > $last) {
            $this->store->setMeta('last_event_ts', (string) min($max, $ceiling));
        }
    }

    /**
     * The cycle's clock is the newest event, never `time()`.
     *
     * Everything in this component ages against the event stream, which is
     * what makes a replay over the spool produce byte-identical results to the
     * live run that originally saw those events.
     */
    private function cycleClock(array $events): int
    {
        $max = 0;

        foreach ($events as $event) {
            if (is_array($event)) {
                $max = max($max, (int) ($event['ts'] ?? 0));
            }
        }

        return $max > 0 ? $max : time();
    }

    /**
     * Bound how fast the model's idea of "today" can move.
     *
     * Every age in this model comes from timestamps an attacker with root can
     * influence, and moving the clock forward would mature the facets they
     * just introduced. Two things matter here, and the first version of this
     * guard got the second one wrong.
     *
     * First, the guard has to actually bite. Clamping a marker in `meta` while
     * the day mask still advances on the raw event timestamp changes nothing;
     * the clamped day is now the ceiling that learning uses.
     *
     * Second, the limit is per *cycle*, and the agent runs every thirty
     * seconds. Allowing two days per cycle let an attacker advance the model a
     * decade in an afternoon — 5760 days a day — which is not a bound at all.
     * One day per cycle means a facet still needs distinct cycles to gain
     * distinct days.
     *
     * What this does NOT do, stated plainly: defeat a root attacker who moves
     * the system clock steadily. There is no in-band reference to check
     * against — `time()` moves too. What it does is remove the cheap version,
     * force the expensive one to take many cycles, and count every anomaly so
     * the Hub, which has an independent clock, can see a host whose timestamps
     * are misbehaving.
     */
    private function applyClockGuard(int $cycleTs): void
    {
        $this->clockAnomaly = false;

        $lastDay = (int) ($this->store->getMeta('day_of_last_cycle') ?? '0');
        $day = intdiv($cycleTs, 86400);

        // A replay is walking real history on purpose and is exempt outright:
        // (the marker is clamped on read below, for the live path)
        // the whole point of `--replay` is to age the model through weeks of
        // recorded events in one pass.
        if ($this->replayMode) {
            $this->learnDayCeiling = PHP_INT_MAX;
            $this->store->setMeta('day_of_last_cycle', (string) max($day, $lastDay));

            return;
        }

        // The reference is the agent's own wall clock, not the previous cycle.
        //
        // Bounding the advance *per cycle* was not a bound at all: the agent
        // runs every thirty seconds, so even one day per cycle is 2880 days a
        // day, and a stream advancing exactly 86400s per cycle never tripped
        // the check. Tying the model's idea of "today" to `time()` costs
        // nothing in replay (exempted above) and closes the whole class of
        // "the event timestamps say it is next year": a broken RTC, a
        // container with no NTP client, or a sensor an attacker is feeding.
        //
        // What it does NOT do, stated plainly: stop a root attacker who moves
        // the *system* clock, because `time()` moves with it. There is no
        // in-band reference for that. What survives is the anomaly counter,
        // which the Hub — which has its own clock — can alarm on.
        $wallDay = intdiv(time(), 86400);

        // The marker is clamped on read, not only on write.
        //
        // While a host's clock is running ahead, the future day is stored
        // legitimately — nothing looks wrong, because the event day and the
        // wall day agree. When NTP then corrects the clock, every subsequent
        // cycle reads as a backward jump against that stale future marker,
        // learning is frozen on every one of them, and the marker only ever
        // rises, so there is no path back: the host matures on span and event
        // count with a model that learned nothing, and then reports everything
        // as maximally novel. Letting a stale marker decay toward the wall day
        // still catches a genuinely backdated cycle.
        $lastDay = min($lastDay, $wallDay);

        if ($day > $wallDay) {
            $this->clockAnomaly = true;
            $this->store->bumpMeta('clock_anomaly_count');
            $this->stats['clock_anomaly'] = 'ahead_of_wall_clock';
        } elseif ($lastDay > 0 && $cycleTs < ($lastDay * 86400) - 300) {
            $this->clockAnomaly = true;
            $this->store->bumpMeta('clock_anomaly_count');
            $this->stats['clock_anomaly'] = 'backward_jump';
        }

        $this->learnDayCeiling = $wallDay;

        $this->store->setMeta('day_of_last_cycle', (string) max(min($day, $wallDay), $lastDay));
    }

    /**
     * Bounded state, enforced every cycle rather than by a cron job that might
     * not be running.
     */
    private function maintain(int $now): void
    {
        if ($this->sigWrites !== []) {
            $this->store->upsertSigs($this->sigWrites);
            $this->sigWrites = [];
        }

        // Eviction rewrites a lot of rows, so it runs at most hourly in event
        // time rather than on every cycle.
        $lastEvict = (int) ($this->store->getMeta('last_evict_ts') ?? '0');

        if ($now - $lastEvict >= 3600) {
            $this->stats['facets_evicted'] = $this->store->evictFacets($this->config['facet_cap'], $now);
            $this->lineage->prune($now);
            $this->store->pruneActors($now, 4096, self::HOST_ACTOR);
            $this->store->pruneSigs($now, $this->config['sig_ttl'], 50000);
            $this->store->setMeta('last_evict_ts', (string) $now);
        }

        $this->facets->forget();
        $this->sigCache = [];
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Honour Hub exclusions.
     *
     * An excluded event must not score and must not teach. Without this a
     * pattern the customer explicitly told us to ignore would still shape the
     * model — and worse, would still be able to contribute to an incident.
     */
    private function isExcluded(array $event): bool
    {
        if ($this->rules === null) {
            return false;
        }

        if (!is_callable([$this->rules, 'isExcluded'])) {
            return false;
        }

        return (bool) $this->rules->isExcluded($event);
    }

    private function facetName(int $kind): string
    {
        return match ($kind) {
            EdrFacetExtractor::KIND_LINEAGE => 'lineage',
            EdrFacetExtractor::KIND_IMAGE => 'image',
            EdrFacetExtractor::KIND_ARGSHAPE => 'argshape',
            EdrFacetExtractor::KIND_IDENTITY => 'identity',
            EdrFacetExtractor::KIND_PRIVTRANS => 'privtrans',
            EdrFacetExtractor::KIND_EGRESS => 'egress',
            default => 'facet' . $kind,
        };
    }

    private function clampWeights(mixed $weights): array
    {
        $out = EdrFacetExtractor::DEFAULT_WEIGHTS;

        if (!is_array($weights)) {
            return $out;
        }

        $byName = [
            'lineage' => EdrFacetExtractor::KIND_LINEAGE,
            'image' => EdrFacetExtractor::KIND_IMAGE,
            'argshape' => EdrFacetExtractor::KIND_ARGSHAPE,
            'identity' => EdrFacetExtractor::KIND_IDENTITY,
            'privtrans' => EdrFacetExtractor::KIND_PRIVTRANS,
            'egress' => EdrFacetExtractor::KIND_EGRESS,
        ];

        foreach ($weights as $name => $value) {
            $kind = $byName[$name] ?? (is_numeric($name) ? (int) $name : null);

            if ($kind !== null && isset($out[$kind])) {
                $out[$kind] = max(0.0, min(6.0, (float) $value));
            }
        }

        return $out;
    }

    private function clampMap(mixed $values, array $defaults, float $min, float $max): array
    {
        $out = $defaults;

        if (!is_array($values)) {
            return $out;
        }

        foreach ($values as $key => $value) {
            $out[(string) $key] = max($min, min($max, (float) $value));
        }

        return $out;
    }

    private function decodeMap(mixed $json): array
    {
        $decoded = json_decode((string) $json, true);
        $out = [];

        if (is_array($decoded)) {
            foreach ($decoded as $key => $value) {
                $out[(int) $key] = is_numeric($value) ? (float) $value : 0.0;
            }
        }

        return $out;
    }

    private function decodeList(mixed $json): array
    {
        $decoded = json_decode((string) $json, true);

        return is_array($decoded) ? $decoded : [];
    }

    private function roundMap(array $map): object
    {
        $out = [];

        foreach ($map as $key => $value) {
            // Below the lit floor by two orders of magnitude, an accumulation
            // is arithmetic dust: dropping it keeps the row small and cannot
            // change any decision.
            if ((float) $value >= 0.01) {
                $out[(string) $key] = round((float) $value, 6);
            }
        }

        return (object) $out;
    }

    private function resetStats(): void
    {
        $this->stats = [
            'scored' => 0,
            'excluded' => 0,
            'emitted' => 0,
            'warmup_withheld' => 0,
            'warmup_max_score' => 0.0,
            'suppressed_recurring' => 0,
            'budget_deferred' => 0,
            'facets_taught' => 0,
            'facets_written' => 0,
            'facets_evicted' => 0,
            'procs_written' => 0,
            'charge_total' => 0.0,
            'mature' => false,
            'clock_anomaly' => null,
            'error' => null,
        ];
    }

    /**
     * Per-cycle rollup, merged into the collector's stats.
     */
    public function stats(): array
    {
        $stats = $this->stats;
        $stats['charge_total'] = round((float) $stats['charge_total'], 2);
        $stats['budget'] = $this->budget->counters();
        $stats['spool_parent_lookups'] = $this->lineage->spoolLookupsUsed();

        $reset = $this->store->consumeResetReason();
        if ($reset !== null) {
            $stats['state_reset'] = $reset;
        }

        return $stats;
    }

    public function store(): EdrCorrelatorStore
    {
        return $this->store;
    }
}

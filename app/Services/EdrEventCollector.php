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

    /**
     * Events this collector did not read from the sensor log but must still
     * store: the anchoring event of an incident built on an aggregated network
     * relationship. Keyed by the spool index assigned to it.
     *
     * @var array<int, array>
     */
    private array $extraSpoolEvents = [];

    private ?\App\Services\Platform\EdrPlatformProfile $platform = null;

    private function platform(): \App\Services\Platform\EdrPlatformProfile
    {
        return $this->platform ??= \App\Services\Platform\EdrPlatformProfile::current();
    }

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
        $governanceByEvent = [];
        $deliverable = [];
        $bySuppression = [];
        $suppressed = 0;
        $correlatorStats = [];

        // Pass one: normalise everything. Attribution has to see the whole
        // batch before any rule runs, because a file event only becomes
        // meaningful once we have guessed which process caused it — and the
        // rule that matters most, a web account dropping a script into a web
        // root, is unreachable without that guess.
        $this->extraSpoolEvents = [];
        $socketRows = [];
        $listenerRows = [];

        foreach ($lines as $line) {
            // Network rows are not turned into per-connection events here.
            //
            // Raw socket events were 78% of the spool and had never produced a
            // single deliverable finding — three quarters of the retained
            // history was material no rule could evaluate, crowding out the
            // events that rules do use. The network module aggregates them
            // into relationships at roughly a thousand to one and spools those
            // itself, which takes this host's process-telemetry retention from
            // about 1.4 hours to 6.6.
            $row = $this->networkRow($line);

            if ($row !== null) {
                if ($row['kind'] === 'listener') {
                    $listenerRows[] = $row['row'];
                } else {
                    $socketRows[] = $row['row'];
                }

                continue;
            }

            $event = $this->normalize($line);

            if ($event !== null && !$this->isAgentNoise($event)) {
                $events[] = $event;
            }
        }

        // The aggregated relationships rejoin the stream as ordinary events so
        // the correlator can light its egress stage from them. They are NOT
        // re-spooled below: the network module has already stored them.
        $networkStats = [];
        $networkEvents = [];

        if ($socketRows !== [] || $listenerRows !== []) {
            try {
                $network = app(\App\Services\Network\NetworkCollector::class)
                    ->collect($socketRows, $listenerRows, $options);

                $networkStats = $network['stats'] ?? [];
                $networkEvents = $network['events'] ?? [];
            } catch (\Throwable $e) {
                // Once per cycle. A failure here must not cost the process
                // telemetry that shares this loop.
                Log::warning('[EDR] Network collection failed this cycle: ' . $e->getMessage());
                $networkStats = ['error' => $e->getMessage()];
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

            foreach ($findings as $findingIndex => $finding) {
                $decision = $this->governor->assess($finding, $event, $options);
                $this->governor->record($decision, $finding, $event, $options);

                // Count every hit, including suppressed ones — the suppression
                // rate per rule is exactly what tells you whether a rule is
                // earning its place.
                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;

                // Kept for the correlator, which needs to know not just that a
                // match was held back but *why*. "This rule is unproven" and
                // "this host does this every day" are opposite facts about the
                // same suppressed finding, and only one of them means the
                // event is uninteresting.
                $governanceByEvent[$eventIndex][$findingIndex] = [
                    'emit' => $decision['emit'],
                    'reason' => $decision['reason'],
                    'allow_response' => $decision['allow_response'],
                ];

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
            $batchDecisions = [];

            foreach ($batchHit['findings'] as $finding) {
                $decision = $this->governor->assess($finding, $batchHit['event'], $options);
                $this->governor->record($decision, $finding, $batchHit['event'], $options);

                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;

                $batchDecisions[] = [
                    'emit' => $decision['emit'],
                    'reason' => $decision['reason'],
                    'allow_response' => $decision['allow_response'],
                ];

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

            // Batch findings have to reach the spool like every other finding.
            //
            // Delivery runs off spool->pending(), and $alerts is explicitly
            // the dry-run view — so a cross-event rule that only ever pushed
            // into $alerts was counted, governed, logged, and then never sent
            // to the Hub at all. EDR-012 has never actually been delivered.
            $batchIndex = $this->indexOfEvent($events, $batchHit['event']);

            if ($batchIndex !== null) {
                $findingsByEvent[$batchIndex] = array_merge(
                    $findingsByEvent[$batchIndex] ?? [],
                    $batchHit['findings']
                );

                foreach ($batchHit['findings'] as $offset => $finding) {
                    $governanceByEvent[$batchIndex][] = $batchDecisions[$offset] ?? ['emit' => false, 'reason' => null];
                }

                if ($emitted !== []) {
                    $deliverable[$batchIndex] = true;
                }
            }

            if ($emitted !== [] && count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = ['event' => $batchHit['event'], 'findings' => $emitted];
            }
        }

        // Behaviour correlation. Runs last, sees everything, and is the only
        // stage that can look across events and across cycles.
        //
        // Structurally incapable of weakening what came before it: by the time
        // it runs, $alerts and $findingsByEvent are complete, it only ever
        // appends, and the whole call is inside one catch. If it throws, if
        // its state file is unwritable, if the Hub pushes a nonsensical weight
        // table, the eleven rules have already produced their findings and
        // those findings ship exactly as they do today.
        // Aggregated network relationships join the stream here, after the
        // command-line rules have run — those rules are written against exec
        // events and have nothing to say about a connection, while the network
        // module has already evaluated its own. The correlator does have
        // something to say: this is where its egress stage comes from.
        //
        // They are appended rather than merged in place so the indices the
        // rules and the spool already use stay valid.
        $spoolableCount = count($events);

        foreach ($networkEvents as $networkEvent) {
            $events[] = $networkEvent;
        }

        try {
            $correlatorStats = $this->correlate(
                $events,
                $findingsByEvent,
                $governanceByEvent,
                $options,
                $alerts,
                $deliverable,
                $byRule,
                $suppressed,
                $bySuppression,
                $spoolableCount
            );
        } catch (\Throwable $e) {
            // Once per cycle, never once per event.
            Log::warning('[EDR] Correlator disabled this cycle: ' . $e->getMessage());
            $correlatorStats = ['error' => $e->getMessage()];
        }

        arsort($byRule);

        // Persist the whole batch, not just the alerting slice. Retro-hunting
        // only over past alerts is pointless — you already have those. The
        // value is being able to answer "did this binary ever run here" when
        // the intel arrives a week later.
        // Only the events this collector owns. The network module has already
        // spooled its own, so re-storing them here would put the volume back
        // that the aggregation was introduced to remove. Keys are preserved,
        // so the findings and delivery maps stay aligned.
        $spoolable = array_slice($events, 0, $spoolableCount, true) + $this->extraSpoolEvents;

        $spoolEnabled = $options['spool_enabled'] ?? true;
        $spooled = $spoolEnabled ? $this->spool->store($spoolable, $findingsByEvent, $deliverable) : 0;

        // Advance the cursor only now. If the spool write failed we leave it
        // where it was and re-read the same window next cycle: duplicated
        // events are cheap, and a gap in the retro-hunt corpus is not
        // recoverable.
        // Judged on what this collector was responsible for storing. A cycle
        // carrying nothing but network rows has nothing of its own to spool,
        // and holding the cursor for that would re-read the same window
        // forever.
        if (!$spoolEnabled || $spoolable === [] || $spooled > 0) {
            $this->commitCursor($read['cursor']);
        } else {
            Log::warning('[EDR] Spool write failed, holding cursor to re-read next cycle', [
                'events' => count($spoolable),
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
                'correlator' => $correlatorStats,
                'network' => $networkStats,
                'backend' => $this->engine->resolveBackend(),
            ],
        ];
    }

    /**
     * Run the behaviour correlator over this cycle and fold its incidents in.
     *
     * The correlator is the only stage that can answer "do these eleven
     * separately-defensible events add up to an intrusion". It consumes
     * findings — including the ones governance held back, because on a
     * freshly-installed agent those are the entire first half of a chain — and
     * produces its own, which then go through exactly the same governance as
     * every other rule. Nothing here bypasses the rollout ladder.
     *
     * @param  array<int, array> $events
     * @param  array<int, array> $findingsByEvent    by reference: incidents are appended
     * @param  array<int, array> $governanceByEvent
     * @param  array<int, array> $alerts             by reference
     * @param  array<int, bool>  $deliverable        by reference
     * @return array the correlator's per-cycle rollup
     */
    private function correlate(
        array $events,
        array &$findingsByEvent,
        array $governanceByEvent,
        array $options,
        array &$alerts,
        array &$deliverable,
        array &$byRule,
        int &$suppressed,
        array &$bySuppression,
        int $spoolableCount = PHP_INT_MAX
    ): array {
        if (empty($options['correlator_enabled']) || $events === []) {
            return [];
        }

        $correlator = \App\Services\Correlation\EdrCorrelator::make(
            $options,
            // Relocatable so a test — and the replay command — can point it
            // somewhere other than the live agent's learned state.
            isset($options['correlator_state_path']) ? (string) $options['correlator_state_path'] : null,
            $this->spool,
            app(EdrSecretRedactor::class),
            $this->rules
        );

        $incidents = $correlator->correlate($events, $findingsByEvent, $governanceByEvent);

        // A correlated multi-stage score is exactly the kind of finding a human
        // should read before a process is killed, so EDR-100 and EDR-101 start
        // at the bottom of the rollout ladder and stay there until somebody
        // deliberately promotes them. The Hub can override this per rule; the
        // default is deliberately the cautious one.
        $governanceOptions = $options;
        $governanceOptions['rule_stages'] = array_merge(
            [
                \App\Services\Correlation\EdrIncident::RULE_ACTOR => \App\Services\Quality\EdrGovernanceStore::STAGE_OBSERVE,
                \App\Services\Correlation\EdrIncident::RULE_HOST => \App\Services\Quality\EdrGovernanceStore::STAGE_OBSERVE,
            ],
            is_array($options['rule_stages'] ?? null) ? $options['rule_stages'] : []
        );

        foreach ($incidents as $incident) {
            $index = (int) $incident['event_index'];
            $event = $incident['event'];

            // An incident anchored on an aggregated network relationship sits
            // past the range this collector spools, so its finding would be
            // built and then never stored — the delivery path reads the spool.
            // Give it a row of its own. One extra row per incident is nothing
            // against the volume the aggregation removed, and the Hub needs
            // the anchoring event to render the alert at all.
            if ($index >= $spoolableCount) {
                $index = $spoolableCount + count($this->extraSpoolEvents);
                $this->extraSpoolEvents[$index] = $event;
            }

            $emitted = [];

            foreach ($incident['findings'] as $finding) {
                $decision = $this->governor->assess($finding, $event, $governanceOptions);
                $this->governor->record($decision, $finding, $event, $governanceOptions);

                $byRule[$finding['rule']] = ($byRule[$finding['rule']] ?? 0) + 1;

                // Stored either way — a suppressed incident is still the best
                // record of what the correlator saw, and a retro-hunt needs it.
                $findingsByEvent[$index] = array_merge($findingsByEvent[$index] ?? [], [$finding]);

                if (!$decision['emit']) {
                    $suppressed++;
                    $bySuppression[$decision['reason'] ?? 'unknown'] =
                        ($bySuppression[$decision['reason'] ?? 'unknown'] ?? 0) + 1;

                    continue;
                }

                $finding['stage'] = $decision['stage'];
                // AND, not OR. An incident assembled from three alert-stage
                // rules must not acquire the right to kill a process just
                // because the total looks serious — that would make
                // correlation a way around the promotion process.
                $finding['allow_response'] = $decision['allow_response']
                    && $this->everyMemberAllowsResponse($incident);

                $emitted[] = $finding;
            }

            if ($emitted === []) {
                continue;
            }

            $deliverable[$index] = true;

            // Absorption is off by default, and when it is on the absorbed
            // findings travel inside the incident rather than being dropped.
            //
            // Marking a member undeliverable is what removes the duplicate
            // alert; without copying the findings across it also removed the
            // *detection*, because delivery runs off the spool and a
            // `deliver = 0` row is never uploaded. A rule hit that an analyst
            // would have seen must not vanish because a correlator decided to
            // summarise it.
            $absorbed = [];

            foreach ((array) ($incident['absorbs'] ?? []) as $memberIndex) {
                $memberIndex = (int) $memberIndex;

                if ($memberIndex === $index || empty($deliverable[$memberIndex])) {
                    continue;
                }

                foreach ($findingsByEvent[$memberIndex] ?? [] as $memberFinding) {
                    $absorbed[] = $memberFinding;
                }

                $deliverable[$memberIndex] = false;
            }

            if ($absorbed !== []) {
                foreach ($emitted as $position => $finding) {
                    if (isset($finding['incident'])) {
                        $emitted[$position]['incident']['absorbed_findings'] = $absorbed;
                        break;
                    }
                }

                // And into the spooled copy, which is what actually reaches
                // the Hub — $alerts is only the dry-run view.
                foreach ($findingsByEvent[$index] ?? [] as $position => $finding) {
                    if (isset($finding['incident'])) {
                        $findingsByEvent[$index][$position]['incident']['absorbed_findings'] = $absorbed;
                        break;
                    }
                }
            }

            if (count($alerts) < self::MAX_ALERTS_PER_CYCLE) {
                $alerts[] = ['event' => $event, 'findings' => $emitted];
            }
        }

        $stats = $correlator->stats();
        $correlator->close();

        return $stats;
    }

    /**
     * Is this sensor line a network row, and which kind?
     *
     * Routed by the scheduled query name rather than by inspecting columns:
     * the names are set by this agent in `OsqueryEngine::writeConfig()`, so
     * they are the one part of the sensor's output we control.
     *
     * @return array{kind:string, row:array}|null
     */
    private function networkRow(string $line): ?array
    {
        $row = json_decode($line, true);

        if (!is_array($row) || !is_array($row['columns'] ?? null)) {
            return null;
        }

        $name = (string) ($row['name'] ?? '');

        if ($name === 'listeners') {
            // A listener is a state, not an event: osquery reports both the
            // arrival and the departure of one, and only arrivals are of
            // interest here.
            return ($row['action'] ?? '') === 'added' ? ['kind' => 'listener', 'row' => $row] : null;
        }

        if (str_contains($name, 'socket')) {
            return ($row['action'] ?? '') === 'added' ? ['kind' => 'socket', 'row' => $row] : null;
        }

        return null;
    }

    /**
     * Where in this cycle's batch a cross-event rule's exemplar event sits.
     *
     * Matched on pid and timestamp rather than by value: the rule hands back
     * one of the events it was given, and those two fields identify it without
     * depending on every other field surviving unchanged.
     */
    private function indexOfEvent(array $events, array $needle): ?int
    {
        $pid = (int) ($needle['pid'] ?? -1);
        $ts = (int) ($needle['ts'] ?? -1);

        foreach ($events as $index => $event) {
            if ((int) ($event['pid'] ?? -2) === $pid && (int) ($event['ts'] ?? -2) === $ts) {
                return (int) $index;
            }
        }

        return null;
    }

    /**
     * True only when every finding that contributed to an incident had already
     * earned the right to drive a response on its own.
     */
    private function everyMemberAllowsResponse(array $incident): bool
    {
        // Computed by the correlator, which is the only thing that knows which
        // findings actually contributed. Absent or false means at least one
        // member had not earned response authority — including the pure
        // structural-novelty case, where no rule vouched for any of it.
        return !empty($incident['findings'][0]['incident']['member_response_allowed']);
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

        $flushedAt = (int) ($row['unixTime'] ?? time());
        $bootNs = (int) ($columns['ntime'] ?? 0);

        $event = [
            // When the event actually happened, to the second.
            //
            // `unixTime` is when osquery *flushed the batch*, not when the
            // event occurred: one value on this host was measured carrying
            // 8,820 exec rows, 54,491 execs in an hour shared 252 distinct
            // values, and the lag runs 3–297 seconds. Every age, ordering and
            // retention decision downstream reads this field, so it is worth
            // deriving properly from the kernel's own per-event clock.
            'ts' => $this->eventTime($bootNs, $flushedAt),
            // The raw kernel timestamp, named for what it is.
            //
            // It is nanoseconds since BOOT, not since the epoch. Reading it as
            // a unix timestamp puts this host's events in January 1970, off by
            // exactly its uptime — an error that is invisible on a freshly
            // booted test machine and three months wide on a server that has
            // been up three months. Useful unanchored only for differences,
            // where the constant offset cancels and the sub-second resolution
            // survives.
            'ntime_boot_ns' => $bootNs,
            'flushed_at' => $flushedAt,
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

    /**
     * Turn the kernel's boot-relative timestamp into wall-clock seconds.
     *
     * Anchored on `btime` from /proc/stat, which the kernel keeps as
     * "now minus uptime" and therefore re-derives if the system clock is
     * adjusted — so the anchor corrects itself rather than drifting.
     *
     * Falls back to the flush time whenever the result cannot be trusted:
     * no `ntime` column (the audit backend does not provide one), no
     * readable `btime`, or an anchored value that disagrees with the flush
     * time by more than the observed flush lag can explain. The fallback
     * matters more than the optimisation — a wrong event time is worse than a
     * coarse one, because everything downstream believes it.
     */
    private function eventTime(int $bootNs, int $flushedAt): int
    {
        if ($bootNs <= 0) {
            return $flushedAt;
        }

        // Some platforms report a per-event clock that cannot be converted to
        // wall time from here — macOS scales its by a ratio that differs
        // between Intel and Apple Silicon, so the naive conversion is right on
        // one and silently wrong on the other while differences stay correct
        // on both. The flush time is coarse; a fiction is worse.
        if (!$this->platform()->canAnchorEventClock()) {
            return $flushedAt;
        }

        $bootTime = $this->bootTime();

        if ($bootTime <= 0) {
            return $flushedAt;
        }

        $anchored = $bootTime + intdiv($bootNs, 1_000_000_000);

        // The event must precede its own flush, and by an amount a flush lag
        // can account for. Measured on this host: 3–297 seconds, median 14.
        if ($anchored > $flushedAt + 60 || $anchored < $flushedAt - 900) {
            return $flushedAt;
        }

        return $anchored;
    }

    /** Cached for the life of the process; it cannot change underneath us. */
    private ?int $bootTime = null;

    private function bootTime(): int
    {
        if ($this->bootTime !== null) {
            return $this->bootTime;
        }

        return $this->bootTime = $this->platform()->bootTime();
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

    /**
     * Cached for the life of the process, which is thirty seconds.
     *
     * Where the names come from is a platform question: /etc/passwd is the
     * whole answer on Linux and only the system accounts on macOS, where real
     * users live in Directory Services. Asking the wrong source there does not
     * fail — it returns a file that parses cleanly and is missing every human
     * on the machine, so every alert about a person would be labelled with a
     * bare uid.
     */
    private function loadUserCache(): void
    {
        $this->userCache = $this->platform()->users();
    }

}

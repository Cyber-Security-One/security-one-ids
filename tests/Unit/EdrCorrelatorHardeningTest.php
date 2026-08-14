<?php

namespace Tests\Unit;

use App\Services\Correlation\EdrActorScorer;
use App\Services\Correlation\EdrCorrelator;
use App\Services\Correlation\EdrCorrelatorStore;
use App\Services\Correlation\EdrFacetExtractor;
use App\Services\Correlation\EdrIntentClassifier;
use Tests\TestCase;

/**
 * Regressions for defects an adversarial review found in the first cut.
 *
 * Every one of these was a case where the code did something reasonable-
 * looking and the *documentation above it* was false. They are pinned here
 * individually because each would come back the moment somebody refactored
 * the surrounding code for a good reason and lost the constraint.
 */
class EdrCorrelatorHardeningTest extends TestCase
{
    private const T0 = 1700000000;
    private const HOST = 'hard-01';

    private string $path;
    private EdrCorrelator $correlator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-hard-' . uniqid() . '.sqlite';
        $this->correlator = EdrCorrelator::make([
            'correlator_enabled' => true,
            'host_id' => self::HOST,
            'correlator_web_roots' => ['/var/www/html'],
        ], $this->path);
    }

    protected function tearDown(): void
    {
        $this->correlator->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function event(array $overrides): array
    {
        return array_merge([
            'ts' => self::T0,
            'host' => self::HOST,
            'action' => 'exec',
            'sensor' => 'osquery',
            'pid' => 1000,
            'ppid' => 900,
            'uid' => 33,
            'username' => 'www-data',
            'path' => '/bin/sh',
            'cmdline' => 'sh',
            'cwd' => '/var/www/html',
            'container_id' => '',
        ], $overrides);
    }

    private function markMature(): void
    {
        $store = $this->correlator->store();
        $store->setMeta('scored_events', '60000');
        $store->setMeta('first_event_ts', (string) (self::T0 - 30 * 86400));
        $store->setMeta('last_event_ts', (string) (self::T0 - 3600));
        $store->setMeta('watching_since', (string) (time() - 60 * 86400));
    }

    /**
     * The two-class bound has to hold in the presence of sub-threshold residue
     * in every other class.
     *
     * Summing unlit accumulation as well made the documented ceiling of 16.0
     * false by up to ten points — more than half the threshold floor — while
     * every other part of the design still reported "two stages reached".
     */
    public function test_unlit_classes_contribute_nothing_to_the_score(): void
    {
        $scorer = new EdrActorScorer([]);

        $acc = [];

        // Two classes genuinely lit, at their caps.
        $acc[EdrIntentClassifier::PRIVESC] = 99.0;
        $acc[EdrIntentClassifier::CRED] = 99.0;

        // Every other class holding residue just below the lit floor.
        foreach (array_keys(EdrIntentClassifier::CLASSES) as $classId) {
            if (!isset($acc[$classId])) {
                $acc[$classId] = EdrActorScorer::LIT_MIN - 0.001;
            }
        }

        $scored = $scorer->score([
            'acc' => $acc,
            'class_first_ts' => [],
            'nov' => 0.0,
        ]);

        $this->assertSame(2, $scored['classes'], 'Residue is not a stage');
        $this->assertLessThanOrEqual(
            16.0 + 1e-9,
            $scored['score'],
            'Two lit classes must never score above the sum of the two heaviest caps'
        );
        $this->assertLessThan(
            EdrActorScorer::DEFAULT_T_FLOOR,
            $scored['score'],
            'Two classes must sit below the threshold floor, whatever else is accumulating'
        );
    }

    /**
     * The adaptive ceiling has to stay under what a real intrusion can score.
     *
     * A ceiling above the reachable maximum does not make a noisy host "less
     * sensitive" — it makes it structurally undetectable, because no chain the
     * attacker could run would ever clear its bar.
     */
    public function test_threshold_ceiling_is_below_a_reachable_score(): void
    {
        $scorer = new EdrActorScorer([]);

        // A thorough six-stage intrusion: entry, discovery, staging,
        // privilege, credentials, egress — every class at its cap.
        $reachable = $scorer->capFor(EdrIntentClassifier::ENTRY)
            + $scorer->capFor(EdrIntentClassifier::DISCOVERY)
            + $scorer->capFor(EdrIntentClassifier::STAGING)
            + $scorer->capFor(EdrIntentClassifier::PRIVESC)
            + $scorer->capFor(EdrIntentClassifier::CRED)
            + $scorer->capFor(EdrIntentClassifier::EGRESS)
            + EdrActorScorer::B_ORD_MAX;

        $this->assertLessThan(
            $reachable,
            EdrActorScorer::DEFAULT_T_CEIL,
            'A noisy actor must still be catchable by a full six-stage chain'
        );
        $this->assertLessThan(
            $reachable,
            EdrActorScorer::DEFAULT_T_CEIL_HOST,
            'The host lane must be catchable too'
        );

        // And no Hub value can push it above that either, at any jitter.
        //
        // Both halves of this mattered. The jitter used to multiply the
        // ceiling as well, re-inflating by up to 25% the number the clamp had
        // just bounded; and the earlier version of this assertion pinned
        // jitter at 1.0 — the one value production never passes, since
        // jitterFor() returns [1.0, 1.25). A test that only checks the
        // boundary nobody uses is how the regression got in.
        $hostile = [
            ['t_ceiling' => 999.0, 't_ceiling_host' => 999.0],
            ['t_floor' => 999.0, 't_floor_host' => 999.0],
            ['t_ceiling' => 38.0, 't_ceiling_host' => 40.0],
        ];

        $noisy = ['acc' => [], 'class_first_ts' => [], 'nov' => 1000.0];

        foreach ($hostile as $config) {
            $pushed = new EdrActorScorer($config);

            foreach ([1.0, 1.1, 1.2499] as $jitter) {
                $this->assertLessThan($reachable, $pushed->threshold($noisy, $jitter));
            }
        }
    }

    /**
     * The host lane has its own gate — four classes — so its ceiling has to be
     * measured against what four classes can reach, not against the actor
     * lane's six.
     */
    public function test_host_ceiling_is_below_what_four_classes_can_reach(): void
    {
        $scorer = new EdrActorScorer([]);

        $caps = $scorer->caps();
        rsort($caps);

        $fourClassMax = $caps[0] + $caps[1] + $caps[2] + $caps[3] + EdrActorScorer::B_ORD_MAX;
        $noisy = ['acc' => [], 'class_first_ts' => [], 'nov' => 1000.0];

        $configs = [[], ['t_ceiling_host' => 999.0], ['t_floor_host' => 999.0]];

        foreach ($configs as $config) {
            $pushed = new EdrActorScorer($config);

            foreach ([1.0, 1.1, 1.2499] as $jitter) {
                $this->assertLessThan(
                    $fourClassMax,
                    $pushed->threshold($noisy, $jitter, true),
                    'A four-class split intrusion must still be able to cross on the noisiest host'
                );
            }
        }
    }

    /**
     * The two-class bound must survive the Hub pushing the class caps up.
     *
     * A guarantee that holds only for the shipped defaults is not a guarantee;
     * two caps at 12 would put the pair at 24, above the threshold floor, and
     * the whole "cannot alert at any volume" claim would quietly stop being
     * true the first time somebody tuned a deployment.
     */
    public function test_pushed_class_caps_cannot_break_the_two_class_bound(): void
    {
        $scorer = new EdrActorScorer([
            'class_caps' => array_fill_keys(array_keys(EdrIntentClassifier::CLASSES), 12.0),
        ]);

        $caps = $scorer->caps();
        rsort($caps);

        $this->assertLessThan(
            EdrActorScorer::DEFAULT_T_FLOOR,
            $caps[0] + $caps[1],
            'The two heaviest caps must stay below the threshold floor whatever the Hub sends'
        );

        // And the bound holds end to end, not just on paper.
        $acc = [];
        foreach (array_keys(EdrIntentClassifier::CLASSES) as $classId) {
            $acc[$classId] = 0.0;
        }
        $acc[EdrIntentClassifier::PRIVESC] = 999.0;
        $acc[EdrIntentClassifier::CRED] = 999.0;

        $scored = $scorer->score(['acc' => $acc, 'class_first_ts' => [], 'nov' => 0.0]);

        $this->assertSame(2, $scored['classes']);
        $this->assertLessThan(
            $scorer->threshold(['acc' => $acc, 'class_first_ts' => [], 'nov' => 0.0], 1.0),
            $scored['score']
        );
    }

    /**
     * A class that has been charged past its cap must still cool down on the
     * documented half-life.
     *
     * Accumulating uncapped built a hidden reservoir: the score looked right,
     * but a chain the attacker abandoned went on reading as lit for a
     * fortnight instead of a few days.
     */
    public function test_accumulation_is_capped_on_write_so_chains_cool_down(): void
    {
        $scorer = new EdrActorScorer([]);
        $actor = $scorer->newActor('a', 'web', self::T0);

        // Charge one class far past its ceiling, repeatedly.
        for ($i = 0; $i < 20; $i++) {
            $actor = $scorer->apply($actor, EdrCorrelator::CHARGE_MAX, [EdrIntentClassifier::CRED], self::T0);
        }

        $this->assertLessThanOrEqual(
            $scorer->capFor(EdrIntentClassifier::CRED) + 1e-9,
            $actor['acc'][EdrIntentClassifier::CRED],
            'Stored accumulation must never exceed the class cap'
        );

        // Four half-lives later — twelve days — it must be below the lit floor.
        // Uncapped, the same twenty charges would have stored 320 and needed
        // nine half-lives, i.e. most of a month, to go quiet.
        $cold = $scorer->decay($actor, self::T0 + 4 * 259200);
        $cold = $scorer->apply($cold, 0.0, [], self::T0 + 4 * 259200);

        $this->assertSame(
            0,
            $scorer->score($cold)['classes'],
            'An abandoned chain must be cold four half-lives after the last charge'
        );
    }

    /**
     * Event timestamps ahead of the agent's own wall clock must buy nothing.
     *
     * This is the guarantee the code can actually make, and it covers the
     * realistic causes: a container with no NTP client, a broken RTC, a sensor
     * an attacker is feeding. It does NOT cover a root attacker who moves the
     * *system* clock — `time()` moves with it, there is no in-band reference,
     * and the code says so rather than pretending otherwise. What survives in
     * that case is the anomaly counter, which the Hub can alarm on because the
     * Hub has its own clock.
     *
     * The first version of this guard was worse than useless: it clamped a
     * marker in `meta` while the day mask still advanced on the raw event
     * timestamp, and it bounded the advance *per cycle* — at one cycle every
     * thirty seconds, "one day per cycle" is 2880 days a day.
     */
    public function test_timestamps_ahead_of_the_wall_clock_buy_no_familiarity(): void
    {
        $base = time();
        $store = $this->correlator->store();

        // Everything about the event is familiar except the image, so the
        // learn gate would happily teach it if the clock allowed.
        foreach ([
            [EdrFacetExtractor::KIND_LINEAGE, 'none:‹unknown›>sys:legit'],
            [EdrFacetExtractor::KIND_ARGSHAPE, EdrFacetExtractor::argShape('legit')],
            [EdrFacetExtractor::KIND_IDENTITY, '33:web'],
            [EdrFacetExtractor::KIND_PRIVTRANS, 'unknown'],
        ] as [$kind, $value]) {
            $store->upsertFacets([[
                'fid' => EdrFacetExtractor::fid($kind, $value),
                'kind' => $kind,
                'first_seen' => $base - 40 * 86400,
                'last_seen' => $base - 86400,
                'days_mask' => 0b11111,
                'occ' => 500,
                'bootstrap' => 0,
                'anchor_day' => 0,
                'anchor_set' => null,
            ]]);
        }

        $fid = EdrFacetExtractor::fid(EdrFacetExtractor::KIND_IMAGE, 'sys:legit');

        // Ten sightings, each a day further into the future than the last.
        for ($i = 1; $i <= 10; $i++) {
            $this->correlator->correlate([$this->event([
                'ts' => $base + $i * 86400,
                'pid' => 2000 + $i,
                'path' => '/usr/bin/legit',
                'cmdline' => 'legit',
            ])]);
        }

        $rows = $store->loadFacets([$fid]);
        $support = isset($rows[$fid])
            ? EdrCorrelatorStore::popcount((int) $rows[$fid]['days_mask'])
            : 0;

        $this->assertLessThan(
            5,
            $support,
            'Ten future-dated sightings must not buy the five distinct days familiarity needs'
        );
        $this->assertGreaterThan(
            0,
            (int) ($store->getMeta('clock_anomaly_count') ?? '0'),
            'The anomaly has to be counted so the Hub, which has its own clock, can see it'
        );
    }

    /**
     * And a future-dated sighting must not freeze the facet either.
     *
     * Storing the raw timestamp while the mask day arrived clamped left the
     * two permanently inconsistent, so the gap always computed as zero and the
     * value could never gain or lose support again — a silent, permanent hole
     * punched by one bad timestamp.
     */
    public function test_a_future_sighting_does_not_freeze_a_facet_mask(): void
    {
        $base = time();
        $store = $this->correlator->store();
        $fid = EdrFacetExtractor::fid(EdrFacetExtractor::KIND_IMAGE, 'sys:frozen');

        $store->upsertFacets([[
            'fid' => $fid,
            'kind' => EdrFacetExtractor::KIND_IMAGE,
            'first_seen' => $base - 40 * 86400,
            // A timestamp from the future, as an earlier bad event would have
            // left it.
            'last_seen' => $base + 3650 * 86400,
            'days_mask' => 0b1,
            'occ' => 1,
            'bootstrap' => 0,
            'anchor_day' => 0,
            'anchor_set' => null,
        ]]);

        $this->correlator->correlate([$this->event([
            'ts' => $base,
            'pid' => 2500,
            'path' => '/usr/bin/frozen',
            'cmdline' => 'frozen',
        ])]);

        $row = $store->loadFacets([$fid])[$fid] ?? null;

        $this->assertNotNull($row);
        $this->assertLessThanOrEqual(
            $base + 86400,
            (int) $row['last_seen'],
            'A stored future timestamp must be pulled back so the row can recover'
        );
    }

    /**
     * A single implausible timestamp must not satisfy the maturity gate.
     */
    public function test_one_future_timestamp_does_not_end_the_warmup(): void
    {
        $store = $this->correlator->store();
        $store->setMeta('scored_events', '60000');

        $this->correlator->correlate([$this->event(['ts' => self::T0, 'pid' => 3000])]);

        // A broken RTC, a container with no NTP, or somebody who read this file.
        $this->correlator->correlate([$this->event([
            'ts' => self::T0 + 3650 * 86400,
            'pid' => 3001,
        ])]);

        $this->assertFalse(
            $this->correlator->isMature(),
            'A decade-long jump in one event must not switch the model on'
        );
    }

    /**
     * File-integrity events describe files, not processes. Running them
     * through the process pricing path would mint permanent novelty out of
     * every uploaded filename.
     */
    public function test_file_events_do_not_mint_novelty_from_filenames(): void
    {
        $this->markMature();

        $this->correlator->correlate([
            $this->event([
                'ts' => self::T0,
                'pid' => 4000,
                'action' => 'file_create',
                'path' => '/var/www/html/uploads/invoice-9f2a7c.pdf',
                'cmdline' => '',
            ]),
            $this->event([
                'ts' => self::T0 + 1,
                'pid' => 4001,
                'action' => 'file_write',
                // A file that happens to share a name with a discovery binary.
                'path' => '/var/www/html/uploads/id',
                'cmdline' => '',
            ]),
        ]);

        $fids = [
            EdrFacetExtractor::fid(EdrFacetExtractor::KIND_IMAGE, 'web:invoice-9f2a7c.pdf'),
            EdrFacetExtractor::fid(EdrFacetExtractor::KIND_IMAGE, 'web:id'),
        ];

        $this->assertSame(
            [],
            $this->correlator->store()->loadFacets($fids),
            'A filename must never become a behaviour facet'
        );

        $actors = $this->correlator->store()->loadActors([self::HOST . '|33|orphan|o' . intdiv(self::T0, 300) . '|']);

        foreach ($actors as $actor) {
            $acc = (array) json_decode((string) $actor['acc'], true);

            $this->assertArrayNotHasKey(
                EdrIntentClassifier::DISCOVERY,
                $acc,
                'A file called "id" is not host reconnaissance'
            );
        }
    }

    /**
     * Classes lit at the same instant earn no ordering bonus.
     *
     * The sensor stamps every event in a flush batch with the *flush* time, so
     * "same timestamp" is the common case rather than a corner: 54,491 exec
     * events in one hour on this host shared 252 distinct timestamps, and a
     * single value carried 8,820 of them. Breaking ties by kill-chain position
     * therefore handed the full +3.0 to any burst that lit several classes
     * inside one batch — and three cheap classes plus that bonus is 19.0
     * against a floor of 18.0, so a bag of coincidences crossed.
     *
     * None of the other tests catch this, because they all construct events
     * with distinct per-event timestamps, which the real sensor does not.
     */
    public function test_simultaneous_classes_earn_no_ordering_bonus(): void
    {
        $scorer = new EdrActorScorer([]);

        $lit = [
            EdrIntentClassifier::ENTRY,
            EdrIntentClassifier::DISCOVERY,
            EdrIntentClassifier::STAGING,
        ];

        $burst = ['acc' => [], 'class_first_ts' => [], 'nov' => 0.0];
        $spread = ['acc' => [], 'class_first_ts' => [], 'nov' => 0.0];

        foreach ($lit as $offset => $classId) {
            $cap = $scorer->capFor($classId);
            $burst['acc'][$classId] = $cap;
            $spread['acc'][$classId] = $cap;

            // One flush batch: every class lights on the same timestamp.
            $burst['class_first_ts'][$classId] = self::T0;
            // A real chain: the stages are separated in time.
            $spread['class_first_ts'][$classId] = self::T0 + $offset * 3600;
        }

        $burstScore = $scorer->score($burst);
        $spreadScore = $scorer->score($spread);

        $this->assertSame(3, $burstScore['classes']);
        $this->assertEqualsWithDelta(
            0.0,
            $burstScore['ordering'],
            1e-9,
            'Simultaneous evidence is not evidence of progression'
        );
        $this->assertLessThan(
            EdrActorScorer::DEFAULT_T_FLOOR,
            $burstScore['score'],
            'Three cheap classes in one flush batch must not reach the threshold'
        );

        // The genuine chain still earns it.
        $this->assertEqualsWithDelta(EdrActorScorer::B_ORD_MAX, $spreadScore['ordering'], 1e-9);
        $this->assertGreaterThan(
            EdrActorScorer::DEFAULT_T_FLOOR,
            $spreadScore['score'],
            'A chain that actually progresses over time must still cross'
        );
    }

    /**
     * The egress stage must light on aggregated network relationships, not
     * only on raw connect events.
     *
     * The network module replaces 6.6 million raw connect events a day with a
     * few thousand aggregated relationships — a thousandfold reduction that
     * takes the spool's process-telemetry retention from 1.4 hours to about
     * 6.6. But it spells the action `net_connect`, and this classifier tested
     * for `connect`. Wiring the two together without this would have left the
     * last stage of every chain permanently dark: no error, no missing alert,
     * simply every intrusion scored one stage short and the whole model
     * quietly less sensitive.
     */
    public function test_aggregated_network_relationships_light_egress(): void
    {
        $this->markMature();

        $relation = [
            'ts' => self::T0 + 600,
            'host' => self::HOST,
            'action' => 'net_connect',
            'sensor' => 'osquery-net',
            'pid' => 3281271,
            'ppid' => 900,
            'uid' => 33,
            'username' => 'www-data',
            'path' => '/usr/bin/php',
            'cmdline' => '',
            'cwd' => '/var/www/html',
            'container_id' => '',
            'network' => [
                'remote_address' => '45.32.1.9',
                'remote_port' => 443,
                'scope' => 'external',
                'count' => 131,
                'first_seen' => self::T0,
                'last_seen' => self::T0 + 600,
                'pid_count' => 10,
            ],
        ];

        $this->correlator->correlate([$relation]);

        $key = self::HOST . '|33|orphan|o' . intdiv(self::T0 + 600, 300) . '|';
        $rows = $this->correlator->store()->loadActors([$key]);
        $acc = isset($rows[$key]) ? (array) json_decode((string) $rows[$key]['acc'], true) : [];

        $this->assertArrayHasKey(
            EdrIntentClassifier::EGRESS,
            $acc,
            'An aggregated outbound relationship to a novel public endpoint is egress'
        );

        // Inbound is not egress: an accepted connection is something arriving,
        // and counting it would put a web server's ordinary traffic in the
        // last stage of every chain.
        $inbound = $relation;
        $inbound['action'] = 'net_accept';
        $inbound['pid'] = 3281999;
        $inbound['ts'] = self::T0 + 700;
        $inbound['network']['first_seen'] = self::T0 + 700;
        $inbound['network']['remote_address'] = '203.0.113.5';

        $before = $this->correlator->store()->stats()['actors'];
        $this->correlator->correlate([$inbound]);

        $key = self::HOST . '|33|orphan|o' . intdiv(self::T0 + 700, 300) . '|';
        $rows = $this->correlator->store()->loadActors([$key]);
        $inboundAcc = isset($rows[$key]) ? (array) json_decode((string) $rows[$key]['acc'], true) : [];

        $this->assertArrayNotHasKey(
            EdrIntentClassifier::EGRESS,
            $inboundAcc,
            'An accepted connection is not data leaving'
        );
        $this->assertGreaterThan(0, $before);
    }

    /**
     * An aggregated relationship is attributed through the pids it names, not
     * through the one that happens to be listed first.
     *
     * The producer measured that only ~52% of relationships resolve through
     * the representative pid, against a ceiling of ~56% if any named pid may
     * be used — and pids are allocated in ascending order, so a numerically
     * sorted list hands over the oldest processes, which are exactly the ones
     * least likely to still have an exec on record. Trying them all is free
     * and keeps the connection attached to the chain that made it.
     */
    public function test_network_events_are_attributed_through_any_named_pid(): void
    {
        $this->markMature();

        // A shell under the web server. This is the process that will later be
        // named — but not first — by the aggregated relationship.
        $this->correlator->correlate([$this->event([
            'ts' => self::T0,
            'pid' => 5150,
            'ppid' => 900,
            'path' => '/bin/bash',
            'cmdline' => 'bash',
        ])]);

        $webActor = $this->correlator->store()->loadActors([self::HOST . '|33|orphan|o' . intdiv(self::T0, 300) . '|']);
        $this->assertNotEmpty($webActor, 'The fixture must have created an actor to attribute to');
        $key = array_key_first($webActor);

        $this->correlator->correlate([[
            'ts' => self::T0 + 120,
            'host' => self::HOST,
            'action' => 'net_connect',
            'sensor' => 'osquery-net',
            // A representative this host has never executed.
            'pid' => 4001,
            'ppid' => 4000,
            'uid' => 33,
            'username' => 'www-data',
            'path' => '/bin/bash',
            'cmdline' => '',
            'cwd' => '/var/www/html',
            'container_id' => '',
            'network' => [
                'remote_address' => '45.32.1.9',
                'remote_port' => 443,
                'scope' => 'external',
                'first_seen' => self::T0 + 120,
                'last_seen' => self::T0 + 180,
                // The resolvable one is not first.
                'pids' => [4001, 4002, 5150],
                'pid_count' => 3,
            ],
        ]]);

        $rows = $this->correlator->store()->loadActors([$key]);
        $acc = isset($rows[$key]) ? (array) json_decode((string) $rows[$key]['acc'], true) : [];

        $this->assertArrayHasKey(
            EdrIntentClassifier::EGRESS,
            $acc,
            'The connection must land on the chain that made it, not on a fresh orphan'
        );
    }

    /**
     * A busy database is not a broken one.
     *
     * The watchdog will start a second `ids:sync-edr` while the first is still
     * inside its transaction, and SQLite answers that with a lock error.
     * Treating it as corruption threw away weeks of learned behaviour and
     * restarted the fortnight-long warm-up — an outage of the whole detection,
     * caused by two processes overlapping by a second.
     */
    public function test_a_locked_database_skips_the_cycle_instead_of_wiping_it(): void
    {
        $this->markMature();

        $this->correlator->correlate([$this->event([
            'ts' => self::T0,
            'pid' => 7000,
            'path' => '/usr/bin/legit',
            'cmdline' => 'legit',
        ])]);

        $before = $this->correlator->store()->stats();
        $this->assertGreaterThan(0, $before['procs'], 'The fixture must have learned something first');

        // Another process holding the write lock, exactly as an overlapping
        // cycle would.
        $blocker = new \PDO('sqlite:' . $this->path);
        $blocker->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        $blocker->exec('PRAGMA busy_timeout = 0');
        $blocker->exec('BEGIN EXCLUSIVE');

        $this->correlator->close();
        $blocked = EdrCorrelator::make([
            'correlator_enabled' => true,
            'host_id' => self::HOST,
            'correlator_web_roots' => ['/var/www/html'],
        ], $this->path);

        $incidents = $blocked->correlate([$this->event([
            'ts' => self::T0 + 60,
            'pid' => 7001,
            'path' => '/usr/bin/legit',
            'cmdline' => 'legit',
        ])]);

        $blocked->close();
        $blocker->exec('ROLLBACK');
        $blocker = null;

        $this->assertSame([], $incidents, 'A blocked cycle produces nothing');

        $this->correlator = EdrCorrelator::make([
            'correlator_enabled' => true,
            'host_id' => self::HOST,
            'correlator_web_roots' => ['/var/www/html'],
        ], $this->path);

        $after = $this->correlator->store()->stats();

        $this->assertSame(
            $before['procs'],
            $after['procs'],
            'Contention must not destroy learned state'
        );
        $this->assertNull(
            $after['state_reset_at'],
            'A busy database must not be mistaken for a corrupt one'
        );
    }

    /**
     * Row-cap pressure must evict the dead, not the daemons.
     *
     * Trimming by sequence number deleted the oldest rows first — which are
     * systemd, php-fpm and sshd, the long-lived processes whose rows are
     * refreshed on use precisely so they survive. That reintroduced the
     * orphaning bug the liveness refresh exists to prevent, under row pressure
     * instead of on a timer.
     */
    public function test_row_pressure_evicts_dead_processes_not_live_daemons(): void
    {
        $store = $this->correlator->store();

        $store->begin();

        // Three daemons, born first, still alive.
        $rows = [];
        foreach ([['systemd', 1], ['php-fpm', 900], ['sshd', 700]] as $i => [$image, $pid]) {
            $rows[] = [
                'seq' => $i + 1, 'pid' => $pid, 'ts' => self::T0 - 90 * 86400,
                'uid' => 0, 'image' => 'sys:' . $image, 'anchor_id' => 0,
                'actor_key' => 'k', 'depth' => 0, 'last_seen' => self::T0,
            ];
        }

        // A thousand short-lived shells that have all exited.
        for ($i = 0; $i < 1000; $i++) {
            $rows[] = [
                'seq' => 100 + $i, 'pid' => 20000 + $i, 'ts' => self::T0 - 3600,
                'uid' => 33, 'image' => 'sys:sh', 'anchor_id' => 0,
                'actor_key' => 'k', 'depth' => 1, 'last_seen' => self::T0 - 3600,
            ];
        }

        $store->insertProcs($rows);
        $store->commit();

        $store->pruneProcs(self::T0, 604800, 500);

        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $survivors = $pdo->query("SELECT image FROM procs WHERE pid IN (1, 900, 700)")->fetchAll();

        $this->assertCount(
            3,
            $survivors,
            'systemd, php-fpm and sshd must survive row pressure — they are still running'
        );
    }

    /**
     * The signature ledger's row ceiling has to be enforceable.
     *
     * It was written against `rowid` on a WITHOUT ROWID table, so it threw
     * every time — and because the failure was caught and logged, the cap
     * silently did not exist.
     */
    public function test_the_signature_ledger_cap_is_actually_enforced(): void
    {
        $store = $this->correlator->store();

        $rows = [];
        for ($i = 0; $i < 300; $i++) {
            $rows[] = ['actor_key' => 'a' . ($i % 7), 'sig' => 'sig' . $i, 'last_seen' => self::T0 + $i];
        }

        $store->begin();
        $store->upsertSigs($rows);
        $store->commit();

        $removed = $store->pruneSigs(self::T0 + 1000, 86400, 100);

        $this->assertGreaterThan(0, $removed, 'The trim must actually delete rows');
        $this->assertSame(100, $store->stats()['sigs'], 'The ledger must be trimmed to its cap');
    }

    /**
     * Naming a payload after a package manager must not buy it a discount.
     */
    public function test_a_payload_named_apt_gets_no_package_discount(): void
    {
        $this->markMature();

        // Both events are equally novel; only the path differs.
        $this->correlator->correlate([$this->event([
            'ts' => self::T0,
            'pid' => 5000,
            'path' => '/tmp/apt',
            'cmdline' => 'apt install evil',
        ])]);

        $impostor = $this->actorCharge();

        $this->correlator->close();
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }
        $this->correlator = EdrCorrelator::make([
            'correlator_enabled' => true,
            'host_id' => self::HOST,
            'correlator_web_roots' => ['/var/www/html'],
        ], $this->path);
        $this->markMature();

        $this->correlator->correlate([$this->event([
            'ts' => self::T0,
            'pid' => 5000,
            'path' => '/usr/bin/apt',
            'cmdline' => 'apt install evil',
        ])]);

        $genuine = $this->actorCharge();

        $this->assertGreaterThan(
            $genuine,
            $impostor,
            'A dropper in /tmp called "apt" must be charged more than the real package manager'
        );
    }

    private function actorCharge(): float
    {
        $key = self::HOST . '|33|orphan|o' . intdiv(self::T0, 300) . '|';
        $rows = $this->correlator->store()->loadActors([$key]);

        return isset($rows[$key]) ? (float) $rows[$key]['max_charge'] : 0.0;
    }

    /**
     * The host lane exists for an intrusion split across several footholds.
     * Firing it on a single actor would attach a duplicate EDR-101 to every
     * EDR-100 — the correlator breaking its own alert-volume contract.
     */
    public function test_host_lane_needs_several_contributing_actors(): void
    {
        $this->markMature();

        // A real parent, so every event anchors to the same web actor rather
        // than drifting through orphan time buckets.
        $this->correlator->correlate([$this->event([
            'ts' => self::T0 - 60,
            'pid' => 900,
            'ppid' => 1,
            'uid' => 33,
            'path' => '/usr/sbin/nginx',
            'cmdline' => '/usr/sbin/nginx -g daemon off;',
            'cwd' => '/',
        ])]);

        $incidents = [];

        // One actor, hammering every class it can reach.
        for ($i = 0; $i < 40; $i++) {
            foreach ($this->correlator->correlate(
                [$this->event([
                    'ts' => self::T0 + $i * 120,
                    'pid' => 6000 + $i,
                    'path' => '/tmp/stage' . $i,
                    'cmdline' => '/tmp/stage' . $i . ' --run',
                ])],
                [0 => [
                    ['rule' => 'EDR-006', 'name' => 'x', 'severity' => 'critical', 'mitre' => 'T1552', 'reason' => 't'],
                    ['rule' => 'EDR-008', 'name' => 'x', 'severity' => 'high', 'mitre' => 'T1053', 'reason' => 't'],
                    ['rule' => 'EDR-002', 'name' => 'x', 'severity' => 'critical', 'mitre' => 'T1059', 'reason' => 't'],
                ]],
                [0 => [
                    ['emit' => true, 'reason' => null, 'allow_response' => false],
                    ['emit' => true, 'reason' => null, 'allow_response' => false],
                    ['emit' => true, 'reason' => null, 'allow_response' => false],
                ]]
            ) as $incident) {
                $incidents[] = $incident['rule'];
            }
        }

        $this->assertNotContains(
            'EDR-101',
            $incidents,
            'The host lane must not fire when only one actor contributed'
        );
    }
}

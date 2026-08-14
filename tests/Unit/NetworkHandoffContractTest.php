<?php

namespace Tests\Unit;

use App\Services\EdrAlertFactory;
use App\Services\EdrEventSpool;
use App\Services\Network\ConnectionAggregator;
use App\Services\Network\NetworkBaselineStore;
use App\Services\Network\NetworkCollector;
use App\Services\Network\NetworkRuleEngine;
use App\Services\Network\SocketEventNormalizer;
use App\Services\Quality\EdrGovernanceStore;
use App\Services\Quality\EdrRuleGovernor;
use Tests\TestCase;

/**
 * The contract the correlation engine consumes, tested before it is wired.
 *
 * Written this way on purpose. Both sides of this hand-off found a bug in the
 * same afternoon that no existing test could have caught, because both bugs
 * lived in code paths that do not execute until the wiring lands: on this side
 * the aggregator wrote a monotonic clock value into `ts`, giving every summary a
 * 1970 timestamp; on the correlator side a guard rejected anything that was not
 * `exec` or `connect`, so `net_connect` events were classified as file events
 * and left before reaching the network branch. Neither produced an error. Both
 * were caught only by asserting the post-wiring contract while the wiring did
 * not yet exist.
 *
 * So this file is not a unit test of the collector. It is the shape of the
 * hand-off, pinned, so that the day it is connected the failure is a red test
 * rather than a kill chain that is quietly one stage short.
 */
class NetworkHandoffContractTest extends TestCase
{
    private string $dir;
    private NetworkBaselineStore $baseline;
    private EdrEventSpool $spool;
    private NetworkCollector $collector;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/edr-handoff-' . uniqid();
        mkdir($this->dir, 0700, true);

        $this->baseline = new NetworkBaselineStore($this->dir . '/baseline.sqlite');
        $this->spool = new EdrEventSpool($this->dir . '/spool.sqlite');

        $this->collector = new NetworkCollector(
            new SocketEventNormalizer(),
            new ConnectionAggregator(),
            new NetworkRuleEngine($this->baseline),
            $this->baseline,
            $this->spool,
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov.sqlite'))
        );
    }

    protected function tearDown(): void
    {
        $this->baseline->close();
        $this->spool->close();

        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->dir);

        parent::tearDown();
    }

    private function opts(array $extra = []): array
    {
        return array_merge([
            'baseline_days' => 0,
            'default_stage' => EdrGovernanceStore::STAGE_OBSERVE,
        ], $extra);
    }

    private function row(
        string $syscall,
        string $path,
        string $remote,
        int $port,
        float $offset,
        int $pid
    ): array {
        return [
            'name' => 'process_socket',
            'hostIdentifier' => 'test-host',
            'unixTime' => 1786716927,
            'action' => 'added',
            'columns' => [
                'syscall' => $syscall,
                'path' => $path,
                'pid' => (string) $pid,
                'parent' => '900',
                'uid' => '0',
                'gid' => '0',
                'remote_address' => $remote,
                'remote_port' => (string) $port,
                'local_address' => '0.0.0.0',
                'local_port' => '0',
                'family' => '2',
                'protocol' => '6',
                'cid' => '',
                'ntime' => (string) ((int) ($offset * 1e9)),
            ],
        ];
    }

    /**
     * Every field the egress stage reads must be present and usable.
     *
     * The consumer's condition is: an outbound connection, to a public address,
     * whose shape (executable, port class, scope, direction) this host has not
     * produced before. Novelty is computed on the consumer's side from its own
     * store, so what has to arrive here is the shape itself.
     */
    public function test_an_aggregated_connection_carries_everything_the_egress_stage_needs(): void
    {
        $rows = [];

        // One relationship, several workers, several calls each — the php-fpm
        // pool case, which is what makes aggregation necessary in the first
        // place.
        foreach ([[8001, 0.0], [8002, 0.5], [8003, 1.1], [8001, 1.6], [8002, 2.2]] as [$pid, $at]) {
            $rows[] = $this->row('connect', '/usr/bin/php', '203.0.113.60', 443, $at, $pid);
        }

        $result = $this->collector->collect($rows, [], $this->opts());

        $this->assertArrayHasKey('events', $result, 'the hand-off key must exist');
        $this->assertCount(1, $result['events'], 'five calls, one relationship');

        $event = $result['events'][0];

        // The action string. The consumer accepts 'connect', 'net_connect' and
        // 'net_accept'; this side emits the net_ prefixed forms, and asserting
        // it here is what stops a silent rename from disconnecting the stage.
        $this->assertSame('net_connect', $event['action']);

        // image
        $this->assertSame('/usr/bin/php', $event['path']);

        // peer endpoint and scope
        $this->assertSame('203.0.113.60', $event['network']['remote_address']);
        $this->assertSame(443, $event['network']['remote_port']);
        $this->assertSame('external', $event['network']['scope']);

        // Timestamps on the wall clock. This is the assertion that would have
        // caught the aggregator writing a monotonic value into ts.
        foreach (['ts' => $event['ts'], 'first_seen' => $event['network']['first_seen']] as $field => $value) {
            $this->assertGreaterThan(1_600_000_000, $value, "{$field} must be a wall clock");
        }

        // The consumer scores on first_seen. For an aggregated summary it is by
        // construction the earliest event's own time, so it equals ts rather
        // than being later than it — a summary is stamped with when the
        // relationship started, never with when the cycle ran.
        $this->assertSame($event['ts'], $event['network']['first_seen']);
        $this->assertGreaterThanOrEqual($event['network']['first_seen'], $event['network']['last_seen']);

        // Attribution material for lineage resolution. The list matters more
        // than the representative: measured on a real host, no pid in the group
        // appeared in the exec stream at all for 43.7% of multi-pid
        // relationships, so a single representative is a guess and the consumer
        // needs candidates.
        $this->assertSame(3, $event['network']['pid_count']);
        $this->assertSame([8001, 8002, 8003], $event['network']['pids'], 'first-appearance order');
        $this->assertContains($event['pid'], $event['network']['pids']);

        $this->assertSame(5, $event['network']['count'], 'the calls behind the summary are counted');
    }

    /**
     * Inbound and outbound must stay distinguishable, because they are
     * different facts about a host. The consumer's novelty key includes
     * direction for that reason: a familiar outbound pattern must not vouch for
     * a listener that has never existed before, which is the shape of a bind
     * shell.
     */
    public function test_direction_survives_the_handoff(): void
    {
        $rows = [
            $this->row('connect', '/usr/bin/php', '203.0.113.61', 443, 0.0, 8100),
            $this->row('accept', '/usr/sbin/nginx', '203.0.113.62', 51000, 0.5, 8200),
        ];

        $result = $this->collector->collect($rows, [], $this->opts());

        $actions = array_column($result['events'], 'action');
        sort($actions);

        $this->assertSame(['net_accept', 'net_connect'], $actions);
    }

    /**
     * The summaries handed back are the same ones already written to the spool.
     * A consumer that stored them again would double every network row in the
     * database the hand-off exists to relieve.
     */
    public function test_handed_back_events_are_the_stored_events(): void
    {
        $rows = [
            $this->row('connect', '/usr/bin/curl', '203.0.113.63', 443, 0.0, 8300),
            $this->row('connect', '/usr/bin/wget', '203.0.113.64', 8443, 1.0, 8301),
        ];

        $result = $this->collector->collect($rows, [], $this->opts());

        $this->assertCount(2, $result['events']);
        $this->assertSame(2, $result['stats']['spooled'], 'stored once, by the collector');

        $stored = $this->spool->query(['limit' => 50]);
        $this->assertCount(2, $stored, 'and not again by anyone else');

        $handed = array_column($result['events'], 'path');
        $storedPaths = array_column($stored, 'path');
        sort($handed);
        sort($storedPaths);

        $this->assertSame($handed, $storedPaths);
    }

    /**
     * Internal traffic does not reach the consumer by default, and that is a
     * stated trade rather than an accident. It costs the consumer nothing today
     * because it has no lateral-movement stage; if one is added, this test is
     * where the coupling becomes visible again.
     */
    public function test_internal_traffic_is_absent_by_default_and_available_on_request(): void
    {
        $rows = [
            $this->row('connect', '/usr/bin/php', '172.18.0.5', 3306, 0.0, 8400),
            $this->row('connect', '/usr/bin/php', '203.0.113.65', 443, 1.0, 8401),
        ];

        $default = $this->collector->collect($rows, [], $this->opts());
        $this->assertCount(1, $default['events']);
        $this->assertSame('external', $default['events'][0]['network']['scope']);

        $widened = $this->collector->collect($rows, [], $this->opts(['include_private' => true]));
        $scopes = array_column(array_column($widened['events'], 'network'), 'scope');
        sort($scopes);
        $this->assertSame(['external', 'private'], $scopes);
    }

    /**
     * A cycle with nothing in it still has to answer with the hand-off key.
     * A consumer reading `$result['events']` on an absent key would take an
     * undefined index as an empty batch on a good day and a fatal on a bad one.
     */
    public function test_the_handoff_key_is_present_even_when_there_is_nothing_to_hand_over(): void
    {
        $empty = $this->collector->collect([], [], $this->opts());
        $this->assertSame([], $empty['events']);

        // Rows that all get dropped: same requirement.
        $dropped = $this->collector->collect(
            [$this->row('connect', '/usr/bin/osqueryd', '203.0.113.66', 443, 0.0, 8500)],
            [],
            $this->opts()
        );
        $this->assertSame([], $dropped['events']);
    }

    /**
     * Suppressed findings must not remove an event from the hand-off. The
     * consumer's stage lights from the connection itself, not from whether a
     * network rule chose to alert on it, so governance staging must not be able
     * to blind a kill chain.
     */
    public function test_governance_staging_does_not_withhold_events_from_the_consumer(): void
    {
        $rows = [$this->row('connect', '/bin/bash', '203.0.113.67', 443, 0.0, 8600)];

        $observing = $this->collector->collect($rows, [], $this->opts([
            'default_stage' => EdrGovernanceStore::STAGE_OBSERVE,
        ]));

        $this->assertSame(0, $observing['stats']['alerts'], 'nothing raised');
        $this->assertGreaterThan(0, $observing['stats']['suppressed']);
        $this->assertCount(1, $observing['events'], 'but the event still reaches the consumer');
    }
}

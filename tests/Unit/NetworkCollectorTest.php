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
 * The socket collection cycle end to end: rows in, rule hits and history out.
 *
 * The rule engine and the aggregator have their own tests. What is only
 * testable here is the order the collector does things in, and one of those
 * orderings decides whether a C2 channel is ever reported at all.
 */
class NetworkCollectorTest extends TestCase
{
    private string $dir;
    private NetworkBaselineStore $baseline;
    private EdrEventSpool $spool;
    private NetworkCollector $collector;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/edr-netcollect-' . uniqid();
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

    /**
     * Every rule is enforcing and the baseline window is off, so a finding that
     * fires is a finding that is delivered. Without this the governor holds
     * everything back for seven days and the test would pass on a host that
     * detects nothing.
     */
    private function opts(array $extra = []): array
    {
        return array_merge([
            'baseline_days' => 0,
            'default_stage' => EdrGovernanceStore::STAGE_ENFORCE,
        ], $extra);
    }

    private function row(
        string $syscall,
        string $path,
        ?string $remote,
        ?int $remotePort,
        float $offsetSeconds,
        int $pid = 4242
    ): array {
        return [
            'name' => 'process_socket',
            'hostIdentifier' => 'test-host',
            'unixTime' => 1786692601,
            'action' => 'added',
            'columns' => [
                'syscall' => $syscall,
                'path' => $path,
                'pid' => (string) $pid,
                'parent' => '1',
                'uid' => '0',
                'gid' => '0',
                'remote_address' => $remote,
                'remote_port' => $remotePort === null ? '0' : (string) $remotePort,
                'local_address' => '0.0.0.0',
                'local_port' => '0',
                'family' => '2',
                'protocol' => '6',
                'cid' => '',
                'ntime' => (string) ((int) ($offsetSeconds * 1e9)),
            ],
        ];
    }

    /**
     * The ordering that decides whether a C2 channel is ever reported.
     *
     * A connection has to be judged against the baseline before it is added to
     * it. Recording first would let the first sighting of a channel establish
     * itself as normal in the same cycle it is being evaluated in, so the rule
     * that exists to catch exactly that moment would find a destination the
     * host already "knows" and stay silent — permanently, because there is no
     * second first sighting.
     */
    public function test_a_destination_is_judged_before_it_is_learned(): void
    {
        $rows = [$this->row('connect', '/bin/bash', '203.0.113.10', 443, 1.0)];

        $first = $this->collector->collect($rows, [], $this->opts());

        $this->assertSame(1, $first['stats']['alerts'], 'a shell reaching the internet must alert on first sighting');
        $this->assertNotEmpty($first['alerts']);

        // And the learning did happen — the point is the order, not that
        // learning is skipped.
        $this->assertTrue(
            $this->baseline->destinationHistory('/bin/bash', '203.0.113.10', 443)['known'],
            'the destination should be in the baseline after the cycle'
        );
    }

    /**
     * Our own sensors talk to the network constantly. On a quiet host that
     * traffic would be most of what the rules ever see, and a product that
     * detects itself generates alerts forever.
     */
    public function test_agent_traffic_is_not_treated_as_host_behaviour(): void
    {
        $rows = [
            $this->row('connect', '/usr/bin/osqueryd', '203.0.113.20', 443, 1.0),
            $this->row('connect', '/usr/bin/suricata', '203.0.113.21', 443, 2.0),
            $this->row('connect', '/usr/bin/curl', '203.0.113.22', 443, 3.0),
        ];

        $result = $this->collector->collect($rows, [], $this->opts());

        $this->assertSame(2, $result['stats']['dropped_agent']);
        $this->assertSame(1, $result['stats']['kept'], 'only the non-agent connection survives');
    }

    /**
     * Loopback and private traffic is 48% of the measured stream. Dropping it
     * before aggregation is what keeps the module affordable; the option to
     * keep private traffic exists because lateral movement is internal.
     */
    public function test_local_traffic_is_dropped_before_it_reaches_the_rules(): void
    {
        $rows = [
            $this->row('connect', '/usr/sbin/nginx', '127.0.0.1', 8083, 1.0),
            $this->row('connect', '/usr/sbin/nginx', '172.18.0.5', 3306, 2.0),
            $this->row('connect', '/usr/bin/curl', '8.8.8.8', 53, 3.0),
        ];

        $default = $this->collector->collect($rows, [], $this->opts());
        $this->assertSame(2, $default['stats']['dropped_scope']);
        $this->assertSame(1, $default['stats']['kept']);

        $widened = $this->collector->collect($rows, [], $this->opts(['include_private' => true]));
        $this->assertSame(1, $widened['stats']['dropped_scope'], 'loopback still goes');
        $this->assertSame(2, $widened['stats']['kept']);
    }

    /**
     * The reason the module can exist at all. Socket events run at 4.1 million
     * a day on a real host; storing them raw wraps the spool's ring buffer in
     * about three hours, leaving no history to detect anything against.
     */
    public function test_repeated_connections_collapse_into_one_summary(): void
    {
        $rows = [];

        for ($i = 0; $i < 40; $i++) {
            $rows[] = $this->row('connect', '/usr/bin/app', '203.0.113.30', 443, 1.0 + $i * 0.5);
        }

        $result = $this->collector->collect($rows, [], $this->opts());

        $this->assertSame(40, $result['stats']['kept']);
        $this->assertSame(1, $result['stats']['aggregated']);
        $this->assertSame(40.0, $result['stats']['ratio']);
        $this->assertSame(1, $result['stats']['spooled'], 'one row stored, not forty');
    }

    /**
     * A suppressed finding is still history. Rule tuning needs to see what was
     * held back, and an analyst reviewing an incident needs the events that did
     * not qualify as alerts — but none of it may reach the Hub.
     */
    public function test_observed_rules_are_recorded_without_being_delivered(): void
    {
        $rows = [$this->row('connect', '/bin/bash', '203.0.113.40', 443, 1.0)];

        $result = $this->collector->collect($rows, [], $this->opts([
            'default_stage' => EdrGovernanceStore::STAGE_OBSERVE,
        ]));

        $this->assertSame(0, $result['stats']['alerts'], 'an observing rule must not raise');
        $this->assertGreaterThan(0, $result['stats']['suppressed']);
        $this->assertSame(1, $result['stats']['spooled'], 'the event is still stored');

        $stored = $this->spool->query(['limit' => 10]);
        $this->assertCount(1, $stored);
        $this->assertSame(0, (int) $stored[0]['deliver'], 'stored but not queued for the Hub');
        $this->assertNotSame('', (string) $stored[0]['rule_hits'], 'the finding is kept for tuning');
    }

    private function listenerRow(string $path, int $port, int $pid = 5150): array
    {
        return [
            'name' => 'listeners',
            'hostIdentifier' => 'test-host',
            'unixTime' => 1786692601,
            'action' => 'added',
            'columns' => [
                'pid' => (string) $pid,
                'port' => (string) $port,
                'protocol' => '6',
                'family' => '2',
                'address' => '0.0.0.0',
                'path' => $path,
                'name' => basename($path),
            ],
        ];
    }

    /**
     * Listeners come from a snapshot query, not the event stream: no syscall,
     * no aggregation, and — unlike socket events, where it is 0 on every row —
     * an actual port.
     *
     * The first cycle must be silent. With no record of what this host listens
     * on, "new" only means "not seen yet", and a freshly deployed agent would
     * alert on every service it found. Reporting a backdoor requires knowing
     * what normal looked like first, so the silence is the rule working rather
     * than the rule failing — and the difference between those two is only
     * visible by driving a second cycle.
     */
    public function test_a_listener_is_only_new_once_the_host_has_a_listener_set(): void
    {
        $known = [
            $this->listenerRow('/usr/sbin/nginx', 443),
            $this->listenerRow('/usr/sbin/sshd', 22),
        ];

        $first = $this->collector->collect([], $known, $this->opts());

        $this->assertSame(2, $first['stats']['spooled'], 'listeners are stored from the first cycle');
        $this->assertSame(0, $first['stats']['alerts'], 'nothing is new when nothing is known');

        // Same listeners again: now they are the recorded set, still silent.
        $second = $this->collector->collect([], $known, $this->opts());
        $this->assertSame(0, $second['stats']['alerts']);

        // A listener that is not in that set.
        $third = $this->collector->collect(
            [],
            array_merge($known, [$this->listenerRow('/tmp/.hidden/backdoor', 4444, 6666)]),
            $this->opts()
        );

        $this->assertSame(1, $third['stats']['alerts'], 'a port outside the recorded set is reportable');
        $this->assertSame(1, $third['stats']['by_rule']['NET-003'] ?? 0);

        // The port is asserted against the `rules` block, which is where the
        // EDR views read it. It is deliberately not asserted against
        // `detections`: that legacy summary line is built from the command
        // line, which a listener event does not have, so it falls back to the
        // path and a new-listener alert reads without its port in the old
        // alert list. Worth fixing in the alert factory — the port is the
        // single most useful fact about a new listener — but the data is
        // present, so this is a presentation gap, not a missing detection.
        $this->assertStringContainsString('4444', $third['alerts'][0]['rules'][0]['reason']);
        $this->assertSame('NET-003', $third['alerts'][0]['rules'][0]['rule']);
    }

    /**
     * The container escape primitive, and the rule that justifies keeping the
     * data it lives in.
     *
     * A writable handle on the Docker socket starts a privileged container with
     * the host root filesystem mounted, which is root by another name. On the
     * host this was written against that socket is mode 666, so every account
     * including www-data already holds the capability and only needs to use it.
     *
     * Novelty is the signal rather than access, because Docker's own CLI uses
     * that socket constantly and legitimately — and novelty needs a basis, so
     * with no recorded history the rule stays silent rather than reporting every
     * process on a freshly deployed host.
     */
    public function test_a_new_process_reaching_the_docker_socket_is_reported(): void
    {
        $sock = '/var/run/docker.sock';

        // No history: silent, because "not seen yet" is not "new".
        $first = $this->collector->collect(
            [$this->row('connect', '/usr/bin/php', $sock, null, 1.0, 7001)],
            [],
            $this->opts()
        );

        $this->assertSame(1, $first['stats']['kept'], 'the event is carried, unlike ordinary IPC');
        $this->assertSame(0, $first['stats']['alerts'], 'but nothing can be concluded without history');

        // Give the legitimate client three distinct days of history.
        $day = 86400;
        $base = 1786700000;

        for ($i = 0; $i < 4; $i++) {
            $this->collector->collect(
                [$this->row('connect', '/usr/bin/docker', $sock, null, 1.0, 7100 + $i)],
                [],
                $this->opts()
            );

            $this->baseline->recordDestination('/usr/bin/docker', $sock, null, 1, $base - $i * $day);
        }

        // The established client stays quiet.
        $known = $this->collector->collect(
            [$this->row('connect', '/usr/bin/docker', $sock, null, 2.0, 7200)],
            [],
            $this->opts()
        );
        $this->assertSame(0, $known['stats']['alerts'], 'the docker CLI using the docker socket is not news');

        // A different binary with its own history reaching it for the first
        // time. Deliberately not the one used in the no-history probe above:
        // that call learned the socket on its way out, so reusing it would be
        // testing a process that genuinely does have history now. The rule
        // being right is what made this test wrong.
        for ($i = 0; $i < 4; $i++) {
            $this->baseline->recordDestination('/usr/sbin/nginx', '203.0.113.90', 443, 1, $base - $i * $day);
        }

        $novel = $this->collector->collect(
            [$this->row('connect', '/usr/sbin/nginx', $sock, null, 3.0, 7300)],
            [],
            $this->opts()
        );

        $this->assertSame(1, $novel['stats']['alerts']);
        $this->assertSame(1, $novel['stats']['by_rule']['NET-006'] ?? 0);
        $this->assertStringContainsString('docker.sock', $novel['alerts'][0]['rules'][0]['reason']);
        $this->assertSame('high', $novel['alerts'][0]['rules'][0]['severity']);
    }

    /**
     * Ordinary local IPC does not reach the rules at all. It was 44.1% of
     * aggregated output and no rule could ever match it.
     */
    public function test_ordinary_unix_sockets_are_dropped(): void
    {
        $result = $this->collector->collect([
            $this->row('connect', '/usr/sbin/mysqld', '/var/run/nscd/socket', null, 1.0, 7400),
            $this->row('connect', '/usr/bin/agent', '/tmp/some-app.sock', null, 2.0, 7401),
        ], [], $this->opts());

        $this->assertSame(2, $result['stats']['dropped_scope']);
        $this->assertSame(0, $result['stats']['kept']);
    }

    /**
     * A cycle with nothing in it must touch nothing. This runs every 30 seconds
     * on every host, and most of the time there is no external traffic at all.
     */
    public function test_an_empty_batch_is_a_no_op(): void
    {
        $result = $this->collector->collect([], [], $this->opts());

        $this->assertSame([], $result['alerts']);
        $this->assertSame(0, $result['stats']['raw']);
        $this->assertSame(0, $result['stats']['spooled']);
    }

    /**
     * Malformed rows are the normal case, not the exception: osquery drops
     * string buffers under load, and a partially-written trailing line is
     * whatever the cursor happened to catch. None of it may abort the cycle.
     */
    public function test_malformed_rows_do_not_abort_the_cycle(): void
    {
        $rows = [
            ['name' => 'process_socket'],
            ['name' => 'process_socket', 'columns' => 'not-an-array'],
            ['name' => 'process_socket', 'action' => 'added', 'columns' => []],
            ['name' => 'process_socket', 'action' => 'removed', 'columns' => ['syscall' => 'connect']],
            $this->row('connect', '/usr/bin/curl', '203.0.113.50', 443, 1.0),
        ];

        $result = $this->collector->collect($rows, [], $this->opts());

        $this->assertSame(1, $result['stats']['kept'], 'the one good row is processed');
        $this->assertSame(1, $result['stats']['spooled']);
    }
}

<?php

namespace Tests\Unit;

use App\Services\Network\ConnectionAggregator;
use App\Services\Network\NetworkBaselineStore;
use App\Services\Network\NetworkRuleEngine;
use App\Services\Network\SocketEventNormalizer;
use Tests\TestCase;

/**
 * The socket telemetry pipeline: normalise, aggregate, evaluate.
 *
 * Three decisions in here were made by measuring a real host and would have
 * been made differently from the schema alone. Each has a test that fails if
 * it is undone, because each one silently disables a detection rather than
 * breaking anything visibly.
 */
class NetworkPipelineTest extends TestCase
{
    private SocketEventNormalizer $normalizer;
    private ConnectionAggregator $aggregator;
    private string $baselinePath;
    private NetworkBaselineStore $baseline;
    private NetworkRuleEngine $rules;

    protected function setUp(): void
    {
        parent::setUp();

        $this->normalizer = new SocketEventNormalizer();
        $this->aggregator = new ConnectionAggregator();

        $this->baselinePath = sys_get_temp_dir() . '/edr-netpipe-' . uniqid() . '.sqlite';
        $this->baseline = new NetworkBaselineStore($this->baselinePath);
        $this->rules = new NetworkRuleEngine($this->baseline);
    }

    protected function tearDown(): void
    {
        $this->baseline->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->baselinePath . $suffix);
        }

        parent::tearDown();
    }

    /**
     * Shaped exactly like a real osquery row, including the two fields whose
     * real values are counter-intuitive: `ntime` in nanoseconds and
     * `local_port` always zero.
     */
    private function row(
        string $syscall,
        string $path,
        ?string $remote,
        ?int $remotePort,
        int $ntimeNs,
        int $pid = 9999
    ): array {
        return [
            'name' => 'process_socket',
            'hostIdentifier' => 'test',
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
                // Measured: 0 on 100% of real rows, all four syscalls.
                'local_port' => '0',
                'family' => '2',
                'protocol' => '6',
                'cid' => '',
                'ntime' => (string) $ntimeNs,
            ],
        ];
    }

    private function normalize(array $row): ?array
    {
        return $this->normalizer->normalize($row, $row['columns']);
    }

    /**
     * 1,326 real events carried addresses in the compressed hex form
     * `::ffff:ac12:5`, which is 172.18.0.5 — a container address. PHP's
     * private-range filter does not recognise the mapped form as private and
     * its reserved-range filter rejects every mapped address, so relying on
     * either alone misclassifies in both directions.
     */
    public function test_ipv4_mapped_addresses_are_classified_by_their_ipv4_value(): void
    {
        // The compressed hex form real data actually uses.
        $this->assertSame('172.18.0.5', $this->normalizer->unmapIpv4('::ffff:ac12:5'));
        $this->assertSame('private', $this->normalizer->classifyScope('::ffff:ac12:5'));

        // The dotted form documentation shows.
        $this->assertSame('private', $this->normalizer->classifyScope('::ffff:172.18.0.5'));

        // And the case a reserved-range filter alone would wrongly hide: a
        // genuine public destination reached over a v6 socket.
        $this->assertSame('external', $this->normalizer->classifyScope('::ffff:808:808'));

        $this->assertSame('loopback', $this->normalizer->classifyScope('::1'));
        $this->assertSame('loopback', $this->normalizer->classifyScope('127.0.0.1'));
        $this->assertSame('external', $this->normalizer->classifyScope('8.8.8.8'));

        // AF_UNIX sockets put a filesystem path here — 2,424 real events.
        $this->assertSame('unknown', $this->normalizer->classifyScope('/var/run/nscd/socket'));
        $this->assertSame('unknown', $this->normalizer->classifyScope(''));
        $this->assertSame('unknown', $this->normalizer->classifyScope(null));
    }

    /**
     * Loopback is 28% of the measured stream and private 32%. Dropping private
     * by default is a stated trade — lateral movement is internal traffic — not
     * a claim that it does not matter.
     */
    public function test_scope_filtering_drops_local_plumbing_but_can_be_widened(): void
    {
        $loopback = $this->normalize($this->row('connect', '/usr/sbin/nginx', '127.0.0.1', 8083, 1_000_000_000));
        $this->assertTrue($this->normalizer->shouldDrop($loopback));
        $this->assertTrue($this->normalizer->shouldDrop($loopback, ['include_private' => true]), 'loopback always goes');

        $private = $this->normalize($this->row('connect', '/usr/sbin/nginx', '172.18.0.5', 80, 1_000_000_000));
        $this->assertTrue($this->normalizer->shouldDrop($private));
        $this->assertFalse($this->normalizer->shouldDrop($private, ['include_private' => true]));

        $external = $this->normalize($this->row('connect', '/usr/bin/curl', '8.8.8.8', 53, 1_000_000_000));
        $this->assertFalse($this->normalizer->shouldDrop($external));

        // An accept event often reports family -1 with a usable address;
        // dropping unknown scope would lose inbound visibility entirely.
        $unknown = $this->normalize($this->row('accept', '/usr/sbin/nginx', '/var/run/x.sock', null, 1_000_000_000));
        $this->assertFalse($this->normalizer->shouldDrop($unknown));
    }

    /**
     * The regression that made beacon detection possible.
     *
     * `unixTime` is the query flush time: 25,148 real events carried 18
     * distinct values of it. Intervals derived from it describe this sensor's
     * schedule, and reported fourteen false beacons out of twenty-seven
     * candidates.
     */
    public function test_intervals_come_from_the_kernel_clock_not_the_flush_clock(): void
    {
        $events = [];

        // Eleven connections roughly a minute apart with the jitter any real
        // round-trip carries, all sharing one flush timestamp — the situation
        // where the two clocks disagree completely. A flush-clock
        // implementation sees eleven identical times and no usable gaps.
        $jitter = [0.0, 60.3, 119.8, 180.4, 239.7, 300.2, 359.6, 420.5, 480.1, 539.8, 600.3];

        foreach ($jitter as $offset) {
            $events[] = $this->normalize(
                $this->row('connect', '/usr/bin/agent', '198.51.100.7', 443, (int) ($offset * 1e9))
            );
        }

        $this->assertCount(
            1,
            array_unique(array_map(static fn (array $e): int => (int) $e['unixTime'], [$this->row('connect', '/x', null, null, 0)])),
            'the fixture shares one flush timestamp, as real batches do'
        );

        $aggregated = $this->aggregator->aggregate($events);
        $this->assertCount(1, $aggregated);

        $intervals = $aggregated[0]['network']['intervals'];
        $this->assertCount(10, $intervals, 'ten gaps from eleven events');

        foreach ($intervals as $interval) {
            $this->assertEqualsWithDelta(60.0, $interval, 1.0, 'gaps must reflect the kernel clock');
        }

        $this->assertNotNull($this->rules->assessRegularity($intervals));
    }

    /**
     * Keying on the pid splits one logical relationship across every worker of
     * a pool. Measured: 1,574 groups at 7.7:1 with the pid against 263 at
     * 46.2:1 without — and, more importantly, it fragments the inter-arrival
     * gaps, so the same data yielded three periodic connections keyed by path
     * and only two keyed by pid. Including the pid hid one.
     */
    public function test_aggregation_groups_by_executable_not_by_worker_process(): void
    {
        $events = [];

        // One beacon, served round-robin by twelve workers — which is what a
        // php-fpm or nginx pool looks like.
        for ($i = 0; $i < 12; $i++) {
            $events[] = $this->normalize(
                $this->row('connect', '/usr/sbin/nginx', '198.51.100.7', 443, (int) (($i * 60) * 1e9), 1000 + $i)
            );
        }

        $aggregated = $this->aggregator->aggregate($events);

        $this->assertCount(1, $aggregated, 'twelve workers, one relationship');
        $this->assertSame(12, $aggregated[0]['network']['count']);
        $this->assertSame(12, $aggregated[0]['network']['pid_count'], 'attribution is kept, just not used to group');
        $this->assertCount(11, $aggregated[0]['network']['intervals'], 'gaps stay whole');
    }

    /**
     * An accepted connection's remote port is the client's ephemeral port and
     * differs on every event. Keying on it takes the aggregation ratio from
     * 51:1 to 2:1 — the difference between a shippable module and one that
     * writes millions of rows a day.
     */
    public function test_ephemeral_client_ports_do_not_split_accept_events(): void
    {
        $events = [];

        for ($i = 0; $i < 20; $i++) {
            $events[] = $this->normalize(
                $this->row('accept', '/usr/sbin/nginx', '203.0.113.9', 40000 + $i, (int) (($i * 5) * 1e9))
            );
        }

        $aggregated = $this->aggregator->aggregate($events);

        $this->assertCount(1, $aggregated, 'twenty ephemeral ports, one client relationship');
        $this->assertSame(20, $aggregated[0]['network']['count']);
        $this->assertNull($this->aggregator->servicePortFor($aggregated[0]), 'accept has no service port here');
    }

    public function test_outbound_connections_keep_the_service_port(): void
    {
        $https = $this->normalize($this->row('connect', '/usr/bin/curl', '8.8.8.8', 443, 1_000_000_000));
        $dns = $this->normalize($this->row('connect', '/usr/bin/curl', '8.8.8.8', 53, 2_000_000_000));

        $aggregated = $this->aggregator->aggregate([$https, $dns]);

        $this->assertCount(2, $aggregated, 'different services are different connections');
    }

    /**
     * Listener detection cannot come from the event stream at all: bind and
     * listen events carry local_port 0 and local_address 0.0.0.0. The snapshot
     * query is the only source with a port.
     */
    public function test_listeners_are_normalised_from_the_snapshot_query(): void
    {
        $row = [
            'name' => 'listeners',
            'hostIdentifier' => 'test',
            'unixTime' => 1786692601,
            'action' => 'added',
            'columns' => [
                'pid' => '3813',
                'port' => '18789',
                'protocol' => '6',
                'family' => '2',
                'address' => '0.0.0.0',
                'path' => '/usr/bin/node',
                'name' => 'node',
            ],
        ];

        $event = $this->normalizer->normalizeListener($row, $row['columns']);

        $this->assertNotNull($event);
        $this->assertSame('net_listener', $event['action']);
        $this->assertSame(18789, $event['network']['local_port']);
        $this->assertSame('/usr/bin/node', $event['path']);

        // A listener with no port is not a listener we can reason about.
        $row['columns']['port'] = '0';
        $this->assertNull($this->normalizer->normalizeListener($row, $row['columns']));
    }

    /**
     * The end-to-end check that the pipeline output shape is actually
     * compatible with the rules. NET-003 shipped once with an unsatisfiable
     * condition, and unit-testing the rule in isolation did not catch it —
     * only feeding it the pipeline's real output would have.
     */
    public function test_the_whole_pipeline_fires_on_attacks_and_stays_quiet_otherwise(): void
    {
        $second = 1_000_000_000;
        $rows = [
            // A shell holding an outbound socket.
            $this->row('connect', '/bin/bash', '203.0.113.99', 443, $second),
            // A C2-associated destination port.
            $this->row('connect', '/usr/bin/wget', '203.0.113.88', 4444, 2 * $second),
            // Container-internal chatter, and the mapped form of the same.
            $this->row('connect', '/usr/sbin/nginx', '172.18.0.5', 80, 3 * $second),
            $this->row('accept', '/usr/sbin/mysqld', '::ffff:ac12:5', null, 4 * $second),
        ];

        // Eleven connections roughly a minute apart, with the jitter a real
        // beacon carries: perfectly uniform timing is rejected as an artifact.
        foreach ([10.0, 70.4, 129.7, 190.2, 249.9, 310.3, 369.8, 430.1, 489.7, 550.4, 609.9] as $offset) {
            $rows[] = $this->row('connect', '/usr/bin/evilagent', '198.51.100.200', 443, (int) ($offset * 1e9));
        }

        $kept = [];
        foreach ($rows as $row) {
            $event = $this->normalize($row);

            if ($event !== null && !$this->normalizer->isAgentNoise($event) && !$this->normalizer->shouldDrop($event)) {
                $kept[] = $event;
            }
        }

        $fired = [];
        foreach ($this->aggregator->aggregate($kept) as $event) {
            foreach ($this->rules->evaluate($event) as $finding) {
                $fired[$finding['rule']] = $finding['severity'];
            }
        }

        $this->assertSame('critical', $fired['NET-001'] ?? null);
        $this->assertSame('high', $fired['NET-004'] ?? null);
        $this->assertSame('low', $fired['NET-005'] ?? null);

        // The two container-internal events never reached the rules.
        $this->assertCount(3, $this->aggregator->aggregate($kept));
    }
}

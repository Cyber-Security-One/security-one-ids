<?php

namespace Tests\Unit;

use App\Services\EdrEventSpool;
use App\Services\Network\SuricataCorrelator;
use Tests\TestCase;

/**
 * Naming the process behind a Suricata alert.
 *
 * Every test here covers something that, done wrong, produces a confident
 * answer rather than an error: an alert attributed to the wrong process, or an
 * "it did not happen" that really means "we did not look".
 */
class SuricataCorrelatorTest extends TestCase
{
    private string $path;
    private EdrEventSpool $spool;
    private SuricataCorrelator $correlator;
    private string $hostIp;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-suricorr-' . uniqid() . '.sqlite';
        $this->spool = new EdrEventSpool($this->path);
        $this->correlator = new SuricataCorrelator($this->spool);

        // The real host addresses, read the same way production does. Using a
        // fabricated address would make every orientation test vacuous.
        $addresses = array_keys($this->correlator->knownHostAddresses());
        $routable = array_values(array_filter(
            $addresses,
            static fn (string $a): bool => str_contains($a, '.') && !str_starts_with($a, '127.')
        ));

        $this->hostIp = $routable[0] ?? '127.0.0.1';
    }

    protected function tearDown(): void
    {
        $this->spool->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    /**
     * A socket event in the shape the network collector writes.
     */
    private function socket(
        string $action,
        string $path,
        string $remote,
        ?int $port,
        int $ts,
        int $pid = 3131
    ): array {
        return [
            'ts' => $ts,
            'host' => 'test-host',
            'action' => $action,
            'sensor' => 'osquery-socket',
            'pid' => $pid,
            'ppid' => 1,
            'uid' => 0,
            'username' => 'root',
            'path' => $path,
            'cmdline' => '',
            'cwd' => '',
            'container_id' => '',
            'syscall' => $action === 'net_connect' ? 'connect' : 'accept',
            'network' => ['remote_address' => $remote, 'remote_port' => $port],
        ];
    }

    /**
     * A socket event in the shape the process collector wrote before the
     * network module existed: one action for every syscall, address at the top
     * level of `extra`.
     */
    private function legacySocket(string $syscall, string $path, string $remote, ?int $port, int $ts): array
    {
        return [
            'ts' => $ts,
            'host' => 'test-host',
            'action' => 'connect',
            'sensor' => 'osquery',
            'pid' => 4242,
            'ppid' => 1,
            'uid' => 0,
            'username' => 'root',
            'path' => $path,
            'cmdline' => '',
            'cwd' => '',
            'container_id' => '',
            'syscall' => $syscall,
            'remote_address' => $remote,
            'remote_port' => $port,
        ];
    }

    private function alert(string $src, ?int $srcPort, string $dst, ?int $dstPort, int $ts): array
    {
        return [
            'timestamp' => date('c', $ts),
            'event_type' => 'alert',
            'src_ip' => $src,
            'src_port' => $srcPort,
            'dest_ip' => $dst,
            'dest_port' => $dstPort,
            'proto' => 'TCP',
            'alert' => ['signature' => 'TEST rule', 'severity' => 2, 'category' => 'Test'],
        ];
    }

    /**
     * The join the module exists for: an alert about a flow, answered with the
     * name of the process that opened it.
     */
    public function test_an_outbound_alert_names_the_process_that_connected(): void
    {
        $ts = 1786700000;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/curl', '203.0.113.5', 443, $ts),
        ]);

        $result = $this->correlator->attribute([
            $this->alert($this->hostIp, 51000, '203.0.113.5', 443, $ts + 1),
        ]);

        $attribution = $result['alerts'][0]['edr_attribution'];

        $this->assertSame('unique', $attribution['confidence']);
        $this->assertSame('outbound', $attribution['direction']);
        $this->assertSame('/usr/bin/curl', $attribution['processes'][0]['path']);
        $this->assertSame(1, $result['stats']['unique']);
    }

    /**
     * An inbound alert has to be matched against accepts, not connects.
     *
     * Measured on real telemetry, inbound attribution is unique 99.9% of the
     * time because the peer's ephemeral port never repeats — but only if the
     * accept side is what gets searched. Matching inbound alerts against
     * connects finds the host's own outbound traffic to the same peer, which is
     * a different flow with a different process.
     */
    public function test_an_inbound_alert_is_matched_against_accepts(): void
    {
        $ts = 1786700100;

        $this->spool->store([
            // What really handled the inbound connection.
            $this->socket('net_accept', '/usr/sbin/nginx', '198.51.100.9', 42123, $ts, 800),
            // The host also talking outbound to the same peer, on the same
            // ephemeral port number. Only the syscall tells them apart.
            $this->socket('net_connect', '/usr/bin/wget', '198.51.100.9', 42123, $ts, 900),
        ]);

        $result = $this->correlator->attribute([
            $this->alert('198.51.100.9', 42123, $this->hostIp, 8083, $ts),
        ]);

        $attribution = $result['alerts'][0]['edr_attribution'];

        $this->assertSame('inbound', $attribution['direction']);
        $this->assertSame('unique', $attribution['confidence']);
        $this->assertSame('/usr/sbin/nginx', $attribution['processes'][0]['path']);
    }

    /**
     * Two processes reaching the same destination is the normal case for a
     * worker pool, and the honest answer is both names — not a coin flip
     * dressed up as a finding.
     */
    public function test_several_candidates_are_reported_as_ambiguous(): void
    {
        $ts = 1786700200;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/php-fpm', '203.0.113.7', 443, $ts, 101),
            $this->socket('net_connect', '/usr/bin/node', '203.0.113.7', 443, $ts + 2, 202),
        ]);

        $result = $this->correlator->attribute([
            $this->alert($this->hostIp, 51001, '203.0.113.7', 443, $ts + 1),
        ]);

        $attribution = $result['alerts'][0]['edr_attribution'];

        $this->assertSame('ambiguous', $attribution['confidence']);
        $this->assertCount(2, $attribution['processes']);
        $this->assertSame(1, $result['stats']['ambiguous']);
        $this->assertSame(0, $result['stats']['unique']);

        $paths = array_column($attribution['processes'], 'path');
        $this->assertContains('/usr/bin/php-fpm', $paths);
        $this->assertContains('/usr/bin/node', $paths);
    }

    /**
     * The distinction an investigation acts on.
     *
     * "We hold telemetry for that moment and no process opened that
     * connection" is evidence. "We hold no telemetry for that moment" is a gap
     * in our own recording. Collapsing them into one empty answer is how a
     * correlator comes to assert that traffic did not originate on a host it
     * simply was not watching.
     */
    public function test_no_telemetry_and_no_match_are_different_answers(): void
    {
        $ts = 1786700300;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/curl', '203.0.113.8', 443, $ts),
        ]);

        // Covered by telemetry, but nothing reached that peer.
        $covered = $this->correlator->attribute([
            $this->alert($this->hostIp, 51002, '203.0.113.250', 443, $ts),
        ]);

        $this->assertSame('no_matching_connection', $covered['alerts'][0]['edr_attribution']['reason']);
        $this->assertSame(1, $covered['stats']['no_match']);
        $this->assertSame(0, $covered['stats']['no_telemetry']);

        // A day earlier — nothing recorded, so nothing can be concluded.
        $uncovered = $this->correlator->attribute([
            $this->alert($this->hostIp, 51003, '203.0.113.8', 443, $ts - 86400),
        ]);

        $this->assertSame('no_telemetry_for_window', $uncovered['alerts'][0]['edr_attribution']['reason']);
        $this->assertSame(1, $uncovered['stats']['no_telemetry']);
        $this->assertSame(0, $uncovered['stats']['no_match']);
    }

    /**
     * The spool holds two event shapes and a week-long retro-hunt spans both.
     *
     * Events written before the network module used action 'connect' for every
     * socket syscall with the real one in the `syscall` column, and put the
     * address at the top level of `extra`. Reading only the current shape makes
     * the older half of the retention window look like a host that never
     * touched the network.
     */
    public function test_both_stored_event_shapes_are_readable(): void
    {
        $ts = 1786700400;

        $this->spool->store([
            $this->legacySocket('connect', '/usr/bin/legacy-client', '203.0.113.11', 443, $ts),
            $this->legacySocket('accept', '/usr/sbin/legacy-server', '203.0.113.12', 33333, $ts),
        ]);

        $outbound = $this->correlator->attribute([
            $this->alert($this->hostIp, 51004, '203.0.113.11', 443, $ts),
        ]);

        $this->assertSame('unique', $outbound['alerts'][0]['edr_attribution']['confidence']);
        $this->assertSame('/usr/bin/legacy-client', $outbound['alerts'][0]['edr_attribution']['processes'][0]['path']);

        $inbound = $this->correlator->attribute([
            $this->alert('203.0.113.12', 33333, $this->hostIp, 8083, $ts),
        ]);

        $this->assertSame('unique', $inbound['alerts'][0]['edr_attribution']['confidence']);
        $this->assertSame('/usr/sbin/legacy-server', $inbound['alerts'][0]['edr_attribution']['processes'][0]['path']);
    }

    /**
     * Three alert shapes exist in this codebase and they disagree on field
     * names. Written against one, this class would have reported no peer
     * endpoint for every alert from the other two — a total failure that reads
     * exactly like a quiet network.
     */
    public function test_all_three_alert_shapes_are_understood(): void
    {
        $ts = 1786700500;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/curl', '203.0.113.20', 443, $ts),
        ]);

        $eve = $this->alert($this->hostIp, 51005, '203.0.113.20', 443, $ts);

        // What SuricataEngine::parseAlerts() returns.
        $parsed = [
            'timestamp' => $eve['timestamp'],
            'source_ip' => $this->hostIp,
            'source_port' => 51005,
            'destination_ip' => '203.0.113.20',
            'destination_port' => 443,
        ];

        // What the sync service actually ships: no ports of its own, the
        // destination folded into a string, the original JSON in raw_log.
        $shipped = [
            'source_ip' => $this->hostIp,
            'severity' => 'high',
            'detections' => '[SURICATA] SID:1 TEST rule',
            'raw_log' => json_encode($eve),
            'uri' => '203.0.113.20:443',
            'method' => 'TCP',
        ];

        foreach (['eve' => $eve, 'parsed' => $parsed, 'shipped' => $shipped] as $label => $alert) {
            $result = $this->correlator->attribute([$alert]);
            $attribution = $result['alerts'][0]['edr_attribution'];

            $this->assertSame('unique', $attribution['confidence'], "shape {$label} must attribute");
            $this->assertSame('/usr/bin/curl', $attribution['processes'][0]['path'], "shape {$label}");
            $this->assertSame('outbound', $attribution['direction'], "shape {$label}");
        }
    }

    /**
     * Container bridge gateways are host addresses. Leaving them out inverts
     * the direction of every alert involving container traffic, so an outbound
     * flow gets matched against accepts and finds nothing.
     */
    public function test_container_bridge_addresses_count_as_this_host(): void
    {
        $known = $this->correlator->knownHostAddresses();

        $this->assertArrayHasKey('127.0.0.1', $known);

        $expected = [];

        foreach (preg_split('/\R/', (string) shell_exec('ip -o -4 addr show 2>/dev/null')) ?: [] as $line) {
            if (preg_match('/inet\s+(\d+\.\d+\.\d+\.\d+)/', $line, $m)) {
                $expected[] = $m[1];
            }
        }

        if ($expected === []) {
            $this->markTestSkipped('no IPv4 addresses reported by ip(8)');
        }

        foreach ($expected as $address) {
            $this->assertArrayHasKey($address, $known, "{$address} is this host and must be recognised");
        }
    }

    /**
     * A flow with no local end cannot be attributed, and saying so is the
     * correct outcome rather than a failure. Container-to-container traffic on
     * a bridge lands here, as does anything the host merely forwards.
     */
    public function test_a_flow_with_no_local_end_is_reported_as_such(): void
    {
        $ts = 1786700600;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/curl', '203.0.113.30', 443, $ts),
        ]);

        $result = $this->correlator->attribute([
            $this->alert('198.51.100.1', 4000, '203.0.113.2', 443, $ts),
        ]);

        $attribution = $result['alerts'][0]['edr_attribution'];

        $this->assertSame('none', $attribution['confidence']);
        $this->assertSame('both_endpoints_local', $attribution['reason']);
        $this->assertSame(1, $result['stats']['not_orientable']);
    }

    /**
     * Suricata reports dotted quads; osquery reports the compressed hex form of
     * the same address. Without canonicalising both sides, the two halves of
     * the join describe one endpoint with two strings and never meet.
     */
    public function test_mapped_and_compressed_addresses_join_correctly(): void
    {
        $ts = 1786700700;

        $this->spool->store([
            // The form real osquery data uses.
            $this->socket('net_connect', '/usr/bin/app', '::ffff:cb00:7114', 8443, $ts),
        ]);

        $result = $this->correlator->attribute([
            // The form Suricata reports.
            $this->alert($this->hostIp, 51006, '203.0.113.20', 8443, $ts),
        ]);

        $this->assertSame('unique', $result['alerts'][0]['edr_attribution']['confidence']);
        $this->assertSame('/usr/bin/app', $result['alerts'][0]['edr_attribution']['processes'][0]['path']);
    }

    /**
     * The window is a measured trade, not a tunable to be widened on instinct.
     * Fifteen seconds attributes 79% of outbound alerts uniquely; sixty
     * attributes 32%, because a minute is long enough for several workers to
     * reach the same destination. Widening it finds more suspects, not more
     * culprits.
     */
    public function test_the_window_bounds_what_counts_as_related(): void
    {
        $ts = 1786700800;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/curl', '203.0.113.40', 443, $ts),
            $this->socket('net_connect', '/usr/bin/wget', '203.0.113.40', 443, $ts + 40, 555),
        ]);

        $alert = $this->alert($this->hostIp, 51007, '203.0.113.40', 443, $ts + 2);

        $tight = $this->correlator->attribute([$alert]);
        $this->assertSame('unique', $tight['alerts'][0]['edr_attribution']['confidence']);
        $this->assertSame('/usr/bin/curl', $tight['alerts'][0]['edr_attribution']['processes'][0]['path']);
        $this->assertSame(SuricataCorrelator::DEFAULT_WINDOW, $tight['stats']['window_seconds']);

        $wide = $this->correlator->attribute([$alert], ['suricata_attribution_window' => 60]);
        $this->assertSame('ambiguous', $wide['alerts'][0]['edr_attribution']['confidence']);
        $this->assertCount(2, $wide['alerts'][0]['edr_attribution']['processes']);
    }

    /**
     * An alert is never dropped for being unattributable. Suppressing it would
     * mean the EDR layer deciding which IDS alerts the Hub gets to see, and
     * "we could not name a process" is not a reason to withhold a detection.
     */
    public function test_alerts_are_never_dropped_or_reordered(): void
    {
        $ts = 1786700900;

        $this->spool->store([
            $this->socket('net_connect', '/usr/bin/curl', '203.0.113.50', 443, $ts),
        ]);

        $alerts = [
            $this->alert($this->hostIp, 1, '203.0.113.50', 443, $ts),
            $this->alert($this->hostIp, 2, '203.0.113.99', 443, $ts),
            ['no' => 'timestamp', 'src_ip' => $this->hostIp],
        ];

        $result = $this->correlator->attribute($alerts);

        $this->assertCount(3, $result['alerts']);
        $this->assertSame(3, $result['stats']['alerts']);
        $this->assertSame(1, $result['alerts'][0]['src_port'], 'order preserved');
        $this->assertSame(2, $result['alerts'][1]['src_port']);
        $this->assertSame('timestamp', $result['alerts'][2]['no'], 'the unusable alert still comes back');

        foreach ($result['alerts'] as $alert) {
            $this->assertArrayHasKey('edr_attribution', $alert);
        }
    }

    /**
     * An empty batch must not query anything: this runs on every sync cycle,
     * and most cycles have no new alerts at all.
     */
    public function test_an_empty_batch_is_a_no_op(): void
    {
        $result = $this->correlator->attribute([]);

        $this->assertSame([], $result['alerts']);
        $this->assertSame(0, $result['stats']['alerts']);
    }
}

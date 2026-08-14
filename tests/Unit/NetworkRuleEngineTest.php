<?php

namespace Tests\Unit;

use App\Services\Network\NetworkBaselineStore;
use App\Services\Network\NetworkRuleEngine;
use Tests\TestCase;

/**
 * Per-process network rules.
 *
 * The reason this module exists is one question packet inspection cannot
 * answer: which process made the connection. Suricata can tell you the host
 * talked to a bad address; it cannot tell you a bash process opened the
 * socket. Everything expressible from packets alone is deliberately absent
 * here, because it is already covered better upstream.
 *
 * Every threshold in these tests is checked against shapes measured on a real,
 * busy host rather than invented — including the one that was wrong.
 */
class NetworkRuleEngineTest extends TestCase
{
    private string $path;
    private NetworkBaselineStore $baseline;
    private NetworkRuleEngine $rules;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-net-' . uniqid() . '.sqlite';
        $this->baseline = new NetworkBaselineStore($this->path);
        $this->rules = new NetworkRuleEngine($this->baseline);
    }

    protected function tearDown(): void
    {
        $this->baseline->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function event(array $overrides = [], array $network = []): array
    {
        return array_merge([
            'ts' => time(),
            'action' => 'net_connect',
            'sensor' => 'osquery-socket',
            'host' => 'test',
            'pid' => 1234,
            'ppid' => 1,
            'uid' => 0,
            'username' => 'root',
            'path' => '/usr/bin/curl',
            'cmdline' => '',
            'cwd' => '',
            'container_id' => '',
            'syscall' => 'connect',
        ], $overrides, [
            'network' => array_merge([
                'remote_address' => '198.51.100.9',
                'remote_port' => 443,
                'local_address' => '10.0.0.5',
                'local_port' => 54321,
                'family' => '2',
                'protocol' => 6,
                'scope' => 'external',
                'count' => 1,
                'first_seen' => time(),
                'last_seen' => time(),
                'intervals' => [],
            ], $network),
        ]);
    }

    /** @return array<int, string> */
    private function fired(array $event): array
    {
        return array_column($this->rules->evaluate($event), 'rule');
    }

    /**
     * The network half of a reverse shell. Process telemetry catches the
     * `/dev/tcp/` form because the construct sits in argv; this catches the
     * payload that opens the socket itself, where there is nothing to read.
     */
    public function test_an_interpreter_opening_an_outbound_socket_is_critical(): void
    {
        $findings = $this->rules->evaluate($this->event(['path' => '/bin/bash']));

        $this->assertSame('NET-001', $findings[0]['rule']);
        $this->assertSame('critical', $findings[0]['severity']);

        // An ordinary client doing ordinary work is not this rule's business.
        $this->assertNotContains('NET-001', $this->fired($this->event(['path' => '/usr/sbin/nginx'])));

        // Nor is an interpreter talking to something inside the network — that
        // is a different rule's job and a different severity.
        $this->assertNotContains('NET-001', $this->fired(
            $this->event(['path' => '/bin/bash'], ['scope' => 'private'])
        ));
    }

    /**
     * Distinct from the process rule that catches a web account spawning curl:
     * this fires when the web runtime itself opens the socket, with no new
     * process to notice. But every PHP application that calls an API looks
     * like this, so it leans on the baseline rather than on the account.
     */
    public function test_web_tier_outbound_needs_history_before_it_alerts(): void
    {
        $webEvent = $this->event([
            'path' => '/usr/local/sbin/php-fpm',
            'username' => 'www-data',
        ], ['remote_address' => '203.0.113.50']);

        // Nothing known about this process yet: no basis, no claim.
        $this->assertNotContains('NET-002', $this->fired($webEvent));

        // Give it several days of history to a different destination.
        $day = 86400;
        for ($i = 0; $i < 4; $i++) {
            $this->baseline->recordDestination(
                '/usr/local/sbin/php-fpm',
                '198.51.100.1',
                443,
                10,
                time() - ($i * $day)
            );
        }

        $this->assertContains('NET-002', $this->fired($webEvent), 'a destination outside an established profile');

        // And once this destination is itself established, it stops alerting.
        for ($i = 0; $i < 4; $i++) {
            $this->baseline->recordDestination(
                '/usr/local/sbin/php-fpm',
                '203.0.113.50',
                443,
                10,
                time() - ($i * $day)
            );
        }

        $this->assertNotContains('NET-002', $this->fired($webEvent));
    }

    public function test_a_new_listening_port_is_reported_once_there_is_a_listener_set(): void
    {
        // Fed from the listening_ports snapshot, not from bind/listen socket
        // events: measured, those carry local_port = 0 on 100% of rows, so the
        // first version of this rule could never fire at all.
        $listen = $this->event(
            ['action' => 'net_listener', 'syscall' => 'listen', 'path' => '/tmp/backdoor'],
            ['local_port' => 31337, 'local_address' => '0.0.0.0', 'remote_address' => null, 'scope' => 'unknown']
        );

        // With no recorded listeners at all we cannot call anything new.
        $this->assertNotContains('NET-003', $this->fired($listen));

        $this->baseline->recordListener('/usr/sbin/nginx', 80, time());

        $this->assertContains('NET-003', $this->fired($listen));

        // A listener we already know about is the host working normally.
        $known = $this->event(
            ['action' => 'net_listener', 'syscall' => 'listen', 'path' => '/usr/sbin/nginx'],
            ['local_port' => 80, 'local_address' => '0.0.0.0', 'remote_address' => null, 'scope' => 'unknown']
        );
        $this->assertNotContains('NET-003', $this->fired($known));
    }

    /**
     * The regression that matters most in this module.
     *
     * Intervals were first derived from the osquery result row's `unixTime`.
     * Measured on a real host, 25,148 socket events carried only 18 distinct
     * values of that field, because it is the query flush time and every event
     * in a batch shares it — so the "beacons" it produced were this sensor's
     * own ten-second schedule, fourteen of them out of twenty-seven
     * candidates. The artifact was *more* regular than the one real periodic
     * connection on the box: CV 0.022 against 0.044.
     */
    public function test_perfectly_uniform_intervals_are_rejected_as_a_clock_artifact(): void
    {
        // What the flush clock produced: fifteen identical 20.1s gaps.
        $this->assertNull($this->rules->assessRegularity(array_fill(0, 15, 20.1)));
    }

    public function test_regularity_separates_beacons_from_application_traffic(): void
    {
        // The one genuine periodic connection found on the host: a Node
        // process polling an external API every ~31s.
        $beacon = $this->rules->assessRegularity(
            [31.2, 31.4, 31.1, 30.9, 31.3, 31.2, 31.5, 31.0, 31.2, 31.3, 31.1, 31.4]
        );
        $this->assertNotNull($beacon);
        $this->assertEqualsWithDelta(31.2, $beacon['period'], 0.3);

        // Measured application traffic: bursty, CV between 1.0 and 4.9.
        $this->assertNull($this->rules->assessRegularity([0.1, 0.05, 2.3, 0.02, 5.1, 0.3, 0.08, 1.2, 0.04, 3.3]));

        // A C2 beacon with ordinary network jitter.
        $this->assertNotNull($this->rules->assessRegularity([58, 62, 59, 61, 60, 63, 57, 60, 62, 59]));

        // Slower than an hour is indistinguishable from a cron job.
        $this->assertNull($this->rules->assessRegularity(array_fill(0, 10, 3600.5)));

        // Not enough samples for regularity to mean anything.
        $this->assertNull($this->rules->assessRegularity([60, 61, 59, 60]));
    }

    /**
     * A beacon to somewhere the process has settled into is infrastructure
     * doing its job. Measured: php-fpm reaches 8.8.8.8:53 199 times a day and
     * nginx polls its origins on a fixed cadence, all of it legitimate.
     */
    public function test_beaconing_to_an_established_destination_is_not_reported(): void
    {
        $intervals = [31.2, 31.4, 31.1, 30.9, 31.3, 31.2, 31.5, 31.0, 31.2, 31.3];

        $beaconing = $this->event(['path' => '/usr/bin/node'], [
            'remote_address' => '149.154.166.110',
            'intervals' => $intervals,
            'count' => 11,
        ]);

        $this->assertContains('NET-004', $this->fired($beaconing), 'unestablished destination');

        $day = 86400;
        for ($i = 0; $i < 4; $i++) {
            $this->baseline->recordDestination('/usr/bin/node', '149.154.166.110', 443, 11, time() - ($i * $day));
        }

        $this->assertNotContains('NET-004', $this->fired($beaconing), 'established over several days');
    }

    /**
     * 4444 is Metasploit's default and Selenium Grid's; 8888 is Jupyter. On
     * its own this is a coincidence, so it is graded to corroborate rather
     * than to wake anybody.
     */
    public function test_suspicious_destination_ports_are_graded_low(): void
    {
        $findings = $this->rules->evaluate($this->event(['path' => '/usr/bin/wget'], ['remote_port' => 4444]));

        $port = array_values(array_filter($findings, static fn (array $f): bool => $f['rule'] === 'NET-005'));

        $this->assertNotEmpty($port);
        $this->assertSame('low', $port[0]['severity']);
        $this->assertStringContainsString('Selenium', $port[0]['reason'], 'the false-positive source is named');
    }

    /**
     * For an accepted connection the remote port is the client's ephemeral
     * port and changes every time. Measured: using it as the aggregation key
     * collapses the ratio from 51:1 to 2:1, which is the difference between a
     * shippable module and one that stores 4.1 million rows a day.
     */
    public function test_service_port_is_the_stable_side_of_the_connection(): void
    {
        $outbound = $this->event(['action' => 'net_connect'], ['remote_port' => 443, 'local_port' => 54321]);
        $this->assertSame(443, $this->rules->servicePort($outbound));

        $inbound = $this->event(
            ['action' => 'net_accept', 'syscall' => 'accept'],
            ['remote_port' => 54321, 'local_port' => 443]
        );
        $this->assertSame(443, $this->rules->servicePort($inbound), 'the local port identifies the service');
    }

    /**
     * The baseline is a record of what happens here, so it has to include the
     * things that alerted — otherwise a genuine destination could never become
     * established and the alert would repeat forever.
     */
    public function test_learning_records_alerting_events_too(): void
    {
        $event = $this->event(['path' => '/bin/bash']);

        $this->assertContains('NET-001', $this->fired($event));

        $this->rules->learn($event);

        $history = $this->baseline->destinationHistory('/bin/bash', '198.51.100.9', 443);
        $this->assertTrue($history['known']);
        $this->assertSame(1, $history['days']);
    }

    /**
     * A busy afternoon is a deploy; the same destination on separate days is
     * infrastructure. Counting hits instead of days would let one burst vouch
     * for an address permanently.
     */
    public function test_established_counts_distinct_days_not_hits(): void
    {
        $now = time();

        for ($i = 0; $i < 500; $i++) {
            $this->baseline->recordDestination('/usr/bin/app', '203.0.113.7', 443, 1, $now);
        }

        $this->assertFalse(
            $this->baseline->isEstablishedDestination('/usr/bin/app', '203.0.113.7', 443),
            '500 hits in one day is not a routine'
        );

        $this->baseline->recordDestination('/usr/bin/app', '203.0.113.7', 443, 1, $now - 86400);
        $this->baseline->recordDestination('/usr/bin/app', '203.0.113.7', 443, 1, $now - (2 * 86400));

        $this->assertTrue($this->baseline->isEstablishedDestination('/usr/bin/app', '203.0.113.7', 443));
    }

    /**
     * The rule this replaced could never fire. It read `local_port` off
     * bind/listen socket events, and that field is 0 on 100% of
     * bpf_socket_events rows on this platform — all four syscalls. A rule that
     * silently never fires is worse than no rule, because the coverage appears
     * on the list either way.
     */
    public function test_listener_detection_does_not_depend_on_socket_event_ports(): void
    {
        $this->baseline->recordListener('/usr/sbin/nginx', 80, time());

        // What the socket event stream actually provides for a bind: no port.
        $fromSocketEvent = $this->event(
            ['action' => 'net_bind', 'syscall' => 'bind', 'path' => '/tmp/backdoor'],
            ['local_port' => 0, 'local_address' => '0.0.0.0', 'remote_address' => null, 'scope' => 'unknown']
        );
        $this->assertNotContains('NET-003', $this->fired($fromSocketEvent));

        // What the listening_ports snapshot provides: a real port.
        $fromSnapshot = $this->event(
            ['action' => 'net_listener', 'path' => '/tmp/backdoor'],
            ['local_port' => 31337, 'local_address' => '0.0.0.0', 'remote_address' => null, 'scope' => 'unknown']
        );
        $this->assertContains('NET-003', $this->fired($fromSnapshot));
    }

    public function test_non_network_events_are_ignored(): void
    {
        $this->assertSame([], $this->rules->evaluate($this->event(['action' => 'exec'])));
        $this->assertSame([], $this->rules->evaluate($this->event(['action' => 'file_write'])));
    }
}

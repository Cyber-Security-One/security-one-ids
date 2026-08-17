<?php

namespace Tests\Unit;

use App\Services\Detection\SuricataEngine;
use Tests\TestCase;

/**
 * The netfilter state that decides whether the IPS sees anything.
 *
 * Every test here corresponds to a way this host was found inspecting nothing
 * while reporting healthy. None of them were caught by the existing suite,
 * because the existing suite never asked what the firewall actually looked
 * like — it tested the code that writes the rules, not the rules.
 */
class SuricataNetfilterTest extends TestCase
{
    private SuricataEngine $engine;

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY !== 'Linux') {
            $this->markTestSkipped('Inline netfilter is Linux-only.');
        }

        $this->engine = new SuricataEngine();
    }

    /**
     * The binary is located by absolute path, not through PATH.
     *
     * The root watchdog runs with PATH=/usr/local/bin:/usr/bin:/bin and
     * iptables lives at /usr/sbin/iptables, so every invocation returned exit
     * 127 with stderr sent to /dev/null. The rules that feed inline IPS could
     * never be installed from the one process that installs them, and Suricata
     * sat with decoder.pkts 0 for 2.26 days while every health check passed.
     */
    public function test_iptables_is_resolved_without_the_path(): void
    {
        $original = getenv('PATH');

        try {
            putenv('PATH=/usr/local/bin:/usr/bin:/bin');

            $command = (new SuricataEngine())->iptablesCommand();

            $this->assertStringStartsWith('/', $command, 'an absolute path, not a bare name');
            $this->assertTrue(@is_executable($command));
        } finally {
            putenv('PATH=' . ($original === false ? '' : $original));
        }
    }

    /**
     * Both directions must be queued, and this is the assertion that would have
     * caught the second blindness.
     *
     * With only the inbound rules installed, measured on this host:
     * tcp.syn 41,252 and tcp.synack 0, so no session ever reached established
     * state; app_layer tx was http=0 tls=0 dns=0, meaning zero application-layer
     * transactions parsed; and the only alerts firing were stream anomalies like
     * "Packet with invalid ack", which are artefacts of seeing one direction
     * rather than detections. Every signature needing request or response
     * content could never match.
     *
     * After adding the reply direction, within sixty seconds: synack 859,
     * http 358, and eighteen content-based alerts.
     */
    public function test_the_reply_direction_is_queued_as_well_as_the_request(): void
    {
        $count = $this->engine->countQueueRules();

        if ($count < 0) {
            $this->markTestSkipped('iptables is not readable here.');
        }

        if ($count === 0) {
            $this->markTestSkipped('inline IPS is not configured on this host.');
        }

        $inbound = $this->rulesMatching('INPUT', 'dport');
        $outbound = $this->rulesMatching('OUTPUT', 'sport');

        $this->assertNotEmpty($inbound, 'the request direction must be queued');
        $this->assertNotEmpty(
            $outbound,
            'the reply direction must be queued too, or Suricata sees one half of every '
            . 'connection and can parse no application-layer content at all'
        );
        $this->assertSame(
            count($inbound),
            count($outbound),
            'every inspected port needs both directions'
        );
    }

    /**
     * Failure has to be fail-open. If Suricata dies or stops draining, packets
     * must be accepted rather than dropped — the alternative is that a crash in
     * the security product takes the site down.
     */
    public function test_every_queue_rule_degrades_to_accept(): void
    {
        $rules = array_merge($this->rulesMatching('INPUT', 'dport'), $this->rulesMatching('OUTPUT', 'sport'));

        if ($rules === []) {
            $this->markTestSkipped('inline IPS is not configured on this host.');
        }

        foreach ($rules as $rule) {
            $this->assertStringContainsString('--queue-bypass', $rule, 'a queue with no reader must not drop');
        }
    }

    /**
     * The queue rules must precede the conntrack bypass.
     *
     * `applyInlineNetfilter()` has always said so. Its own idempotency guard
     * defeated it: `-C` skips a rule that exists anywhere in the chain, while
     * the bypass is inserted at position 1 every time, so the queue rules drift
     * behind it and nothing moves them back. Measured on this host after the
     * rules were restored — bypass at 1, queue at 11 and 12 — which accepts
     * every packet of an established flow before it can be inspected.
     */
    public function test_queue_rules_precede_the_conntrack_bypass(): void
    {
        foreach (['INPUT', 'OUTPUT'] as $chain) {
            $order = $this->engine->inspectRuleOrder($chain);

            if ($order['queue_positions'] === [] || $order['bypass_position'] === null) {
                continue;
            }

            $this->assertTrue(
                $order['ordered'],
                "{$chain}: queue rules at " . implode(',', $order['queue_positions'])
                . " sit after the bypass at {$order['bypass_position']}"
            );
        }

        $this->addToAssertionCount(1);
    }

    /**
     * @return array<int, string>
     */
    private function rulesMatching(string $chain, string $portMatch): array
    {
        $command = escapeshellarg($this->engine->iptablesCommand());
        $output = (string) @shell_exec("{$command} -S {$chain} 2>/dev/null");

        return array_values(array_filter(
            preg_split('/\R/', $output) ?: [],
            static fn (string $line): bool => str_starts_with($line, "-A {$chain} ")
                && str_contains($line, 'NFQUEUE')
                && str_contains($line, "--{$portMatch} ")
        ));
    }
}

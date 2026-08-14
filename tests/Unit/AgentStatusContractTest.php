<?php

namespace Tests\Unit;

use App\Console\Commands\AgentStatus;
use Tests\TestCase;

/**
 * The contract the menu bar console reads.
 *
 * The console is a separate program in a separate language that cannot be
 * compiled or run from here, so the only thing standing between a renamed key
 * and a permanently blank menu is this test. That is the same shape as every
 * cross-module handoff on this branch: the consumer's failure is silent, and
 * the only place to catch it is a contract assertion written before the two
 * halves ever meet.
 *
 * It also pins the two properties that make the snapshot safe to hand to an
 * unprivileged UI: it never carries the Hub token, and a subsystem that cannot
 * be read reports "unknown" rather than being absent — because a console that
 * paints a missing key green is worse than one that shows nothing.
 */
class AgentStatusContractTest extends TestCase
{
    private function snapshot(): array
    {
        return (new AgentStatus())->snapshot();
    }

    public function test_every_section_the_console_reads_is_present(): void
    {
        $s = $this->snapshot();

        foreach (['generated_at', 'host', 'edr', 'correlator', 'suricata', 'clamav', 'hub', 'overall'] as $key) {
            $this->assertArrayHasKey($key, $s, "The console reads {$key}");
        }

        foreach (['name', 'os', 'arch', 'platform'] as $key) {
            $this->assertArrayHasKey($key, $s['host']);
        }

        $this->assertArrayHasKey('state', $s['overall']);
        $this->assertArrayHasKey('reasons', $s['overall']);
        $this->assertIsArray($s['overall']['reasons']);
    }

    /**
     * Every section reports a state, and it is one the console knows how to
     * colour. An unrecognised value renders as unknown, which is safe — but a
     * missing one would render as nothing at all.
     */
    public function test_every_section_reports_a_known_state(): void
    {
        $known = ['ok', 'warming', 'degraded', 'down', 'disabled', 'unsupported', 'unknown'];

        foreach (['edr', 'correlator', 'suricata', 'clamav', 'hub'] as $section) {
            $s = $this->snapshot()[$section];

            $this->assertArrayHasKey('state', $s, "{$section} must report a state");
            $this->assertContains(
                $s['state'],
                $known,
                "{$section} reported '{$s['state']}', which the console cannot colour"
            );
        }
    }

    /**
     * The retention window is the number an investigation actually asks for,
     * and it must stay per class. Averaged over the whole spool it reported 67
     * hours on a host whose process telemetry reached back 1.8 — the long tail
     * of a small, separately-capped class presented as the window everything
     * else has.
     */
    public function test_retention_is_reported_per_class(): void
    {
        $spool = $this->snapshot()['edr']['spool'] ?? null;

        if ($spool === null) {
            $this->markTestSkipped('No spool on this host');
        }

        $this->assertArrayHasKey('retention', $spool);

        foreach (['process', 'network', 'identity'] as $class) {
            $this->assertArrayHasKey($class, $spool['retention'], "The console renders the {$class} window");
            $this->assertArrayHasKey('events', $spool['retention'][$class]);
            $this->assertArrayHasKey('hours', $spool['retention'][$class]);
        }
    }

    /**
     * The correlator spends its first fortnight warming, and the console shows
     * progress rather than a fault. The fields it needs to do that have to be
     * there even before there is anything to report.
     */
    public function test_the_warmup_fields_are_always_present(): void
    {
        $c = $this->snapshot()['correlator'];

        if (($c['state'] ?? '') === 'unknown') {
            $this->markTestSkipped('Correlator state is not readable here');
        }

        $this->assertArrayHasKey('warmup', $c);

        foreach (['events', 'events_required', 'days_observed', 'days_required', 'progress'] as $key) {
            $this->assertArrayHasKey($key, $c['warmup']);
        }

        $this->assertIsNumeric($c['warmup']['progress']);
    }

    /**
     * The snapshot is meant to be read by an unprivileged UI, so it has to be
     * safe to leave lying around. The agent token must never appear in it.
     */
    public function test_the_snapshot_carries_no_credentials(): void
    {
        $encoded = json_encode($this->snapshot());
        $config = app(\App\Services\WafSyncService::class)->getConnectionConfig();

        if ($config['token'] !== '') {
            $this->assertStringNotContainsString(
                $config['token'],
                (string) $encoded,
                'The Hub token must never reach a console'
            );
        }

        $this->assertStringNotContainsString('AGENT_TOKEN', (string) $encoded);
    }

    /**
     * One broken subsystem must not take the snapshot with it. A console that
     * shows nothing because ClamAV is missing is a console nobody trusts.
     *
     * Reflection rather than a subclass, because the probes are private: a
     * subclass "overriding" one would change nothing and the test would pass
     * having exercised the real code path zero times.
     */
    public function test_a_failing_probe_becomes_a_reported_state(): void
    {
        $method = new \ReflectionMethod(AgentStatus::class, 'section');
        $method->setAccessible(true);

        $result = $method->invoke(new AgentStatus(), function (): array {
            throw new \RuntimeException('simulated failure');
        });

        $this->assertSame('unknown', $result['state'], 'A failed probe reports unknown, not ok');
        $this->assertStringContainsString('simulated failure', $result['detail']);
    }

    /**
     * And a failed probe must not be scored as healthy once it reaches the
     * rollup. "Unknown" is the state the overall verdict is most likely to get
     * wrong, because absence of bad news reads like good news.
     */
    public function test_an_unknown_section_degrades_the_overall_verdict(): void
    {
        $method = new \ReflectionMethod(AgentStatus::class, 'overall');
        $method->setAccessible(true);

        $overall = $method->invoke(new AgentStatus(), [
            'edr' => ['state' => 'ok'],
            'correlator' => ['state' => 'ok'],
            'suricata' => ['state' => 'ok'],
            'clamav' => ['state' => 'ok'],
            'hub' => ['state' => 'unknown', 'detail' => 'root-only'],
        ]);

        $this->assertSame('degraded', $overall['state'], 'An unreadable subsystem is not a healthy one');
        $this->assertNotEmpty($overall['reasons']);
    }

    /**
     * Warming and disabled are designed states, not faults. A console that
     * paints the correlator red for its first fortnight teaches people that
     * red means nothing.
     */
    public function test_designed_states_do_not_raise_an_alarm(): void
    {
        $method = new \ReflectionMethod(AgentStatus::class, 'overall');
        $method->setAccessible(true);

        $overall = $method->invoke(new AgentStatus(), [
            'edr' => ['state' => 'ok'],
            'correlator' => ['state' => 'warming'],
            'suricata' => ['state' => 'ok'],
            'clamav' => ['state' => 'ok'],
            'hub' => ['state' => 'ok'],
        ]);

        $this->assertSame('ok', $overall['state']);
        $this->assertSame([], $overall['reasons']);
    }
}

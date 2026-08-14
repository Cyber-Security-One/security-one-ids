<?php

namespace Tests\Unit;

use App\Services\Response\NetworkContainment;
use Tests\TestCase;

/**
 * Containment is the one response that can destroy the channel its own undo
 * command would arrive on, so the tests care less about "does it block
 * traffic" and more about "can we always get back in".
 *
 * The apply/release cycle runs inside a throwaway network namespace. Running
 * it against the host would be an outage, and leaving it untested would ship
 * the most dangerous code in the product on hope.
 */
class NetworkContainmentTest extends TestCase
{
    private const NAMESPACE_NAME = 'edrtest_phpunit';

    private NetworkContainment $host;
    private ?NetworkContainment $namespaced = null;
    private bool $namespaceCreated = false;

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY !== 'Linux') {
            $this->markTestSkipped('Containment is Linux-only.');
        }

        $this->host = new NetworkContainment();

        if (!$this->host->isSupported()) {
            $this->markTestSkipped('iptables unavailable.');
        }
    }

    protected function tearDown(): void
    {
        if ($this->namespaceCreated) {
            exec('ip netns delete ' . self::NAMESPACE_NAME . ' 2>/dev/null');
        }

        parent::tearDown();
    }

    private function inNamespace(): NetworkContainment
    {
        if ($this->namespaced !== null) {
            return $this->namespaced;
        }

        exec('ip netns add ' . self::NAMESPACE_NAME . ' 2>/dev/null', $out, $code);

        if ($code !== 0) {
            $this->markTestSkipped('Cannot create a network namespace here.');
        }

        $this->namespaceCreated = true;
        exec('ip netns exec ' . self::NAMESPACE_NAME . ' ip link set lo up');

        return $this->namespaced = new NetworkContainment(
            'ip netns exec ' . self::NAMESPACE_NAME . ' iptables'
        );
    }

    public function test_allowlist_covers_every_hub_address_and_the_resolvers(): void
    {
        $allow = $this->host->resolveAllowlist('https://198.51.100.9:8443');

        $this->assertContains('198.51.100.9', $allow['addresses'], 'a literal IP host must be preserved');

        // DNS has to keep working, because the Hub's address may change while
        // the host is contained and we would have no way to follow it.
        $this->assertNotEmpty($allow['dns'], 'resolvers must be preserved');

        $unresolvable = $this->host->resolveAllowlist('https://no-such-host-abc123xyz.invalid');
        $this->assertSame([], $unresolvable['addresses']);
    }

    /**
     * The most important refusal in the codebase: isolating a host we cannot
     * reach afterwards produces an endpoint that is off the network with no
     * way to be told to come back.
     */
    public function test_refuses_to_isolate_when_the_hub_cannot_be_resolved(): void
    {
        $result = $this->host->isolate('https://no-such-host-abc123xyz.invalid', [], false);

        $this->assertFalse($result['success']);
        $this->assertSame('hub_unresolvable', $result['error']);
        $this->assertFalse($this->host->isActive(), 'nothing may be installed on a refused isolation');
    }

    public function test_isolate_installs_a_survivable_rule_set(): void
    {
        $containment = $this->inNamespace();

        $this->assertFalse($containment->isActive());

        $result = $containment->isolate('https://198.51.100.9', ['203.0.113.7'], false);

        $this->assertTrue($result['success'], json_encode($result));
        $this->assertTrue($containment->isActive());
        $this->assertContains('203.0.113.7', $result['restore_data']['allowed']);

        $rules = (string) shell_exec('ip netns exec ' . self::NAMESPACE_NAME . ' iptables -S 2>&1');

        $this->assertStringContainsString('-A OUTPUT -j ' . NetworkContainment::CHAIN_OUT, $rules);
        $this->assertStringContainsString('-o lo -j RETURN', $rules, 'loopback must survive');
        $this->assertStringContainsString('-d 203.0.113.7/32 -j RETURN', $rules);
        $this->assertStringContainsString('--dport 53 -j RETURN', $rules, 'DNS must survive');
        $this->assertStringContainsString('-A ' . NetworkContainment::CHAIN_OUT . ' -j DROP', $rules);

        // Deliberately asymmetric: letting established connections out would
        // leave an attacker's existing C2 session running, which is exactly
        // what containment is for. Inbound needs it so Hub replies arrive.
        $this->assertDoesNotMatchRegularExpression(
            '/-A ' . NetworkContainment::CHAIN_OUT . '.*ESTABLISHED/',
            $rules,
            'outbound must not permit established connections'
        );
        $this->assertMatchesRegularExpression(
            '/-A ' . NetworkContainment::CHAIN_IN . '.*ESTABLISHED/',
            $rules
        );
    }

    public function test_isolate_is_not_applied_twice(): void
    {
        $containment = $this->inNamespace();
        $containment->isolate('https://198.51.100.9', [], false);

        $second = $containment->isolate('https://198.51.100.9', [], false);

        $this->assertFalse($second['success']);
        $this->assertSame('already_isolated', $second['error']);
    }

    public function test_release_removes_everything_and_is_idempotent(): void
    {
        $containment = $this->inNamespace();
        $containment->isolate('https://198.51.100.9', [], false);

        $this->assertTrue($containment->release()['success']);
        $this->assertFalse($containment->isActive());

        $rules = (string) shell_exec('ip netns exec ' . self::NAMESPACE_NAME . ' iptables -S 2>&1');
        $this->assertStringNotContainsString('SECONE_EDR', $rules, 'chains must be gone, not just empty');

        // Releasing something that is not there is the desired end state.
        $this->assertTrue($containment->release()['success']);
    }

    /**
     * Rules live in dedicated chains so removing them never touches whatever
     * firewall policy the customer already had.
     */
    public function test_the_host_firewall_is_never_modified_by_namespaced_work(): void
    {
        $this->inNamespace()->isolate('https://198.51.100.9', [], false);

        $hostRules = (string) shell_exec('iptables -S 2>&1');

        $this->assertStringNotContainsString('SECONE_EDR', $hostRules);
        $this->assertFalse($this->host->isActive());
    }
}

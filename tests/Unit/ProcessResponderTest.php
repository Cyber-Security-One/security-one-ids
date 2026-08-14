<?php

namespace Tests\Unit;

use App\Services\Response\ProcessResponder;
use Tests\TestCase;

/**
 * Killing the wrong process is the failure mode that matters here. These
 * tests spawn real processes, because the guarantees being checked — PID
 * reuse detection, confirmed death, refusing to act on the host's own
 * plumbing — only exist against a live /proc.
 */
class ProcessResponderTest extends TestCase
{
    private ProcessResponder $responder;

    /** @var array<int, int> */
    private array $spawned = [];

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY !== 'Linux' || !function_exists('posix_kill')) {
            $this->markTestSkipped('Process response is Linux-only and needs ext-posix.');
        }

        $this->responder = new ProcessResponder();
    }

    protected function tearDown(): void
    {
        foreach ($this->spawned as $pid) {
            @posix_kill($pid, SIGKILL);
        }

        parent::tearDown();
    }

    /**
     * setsid detaches the child completely, so the returned pid is the target
     * itself rather than a shell wrapper, and nothing is left waiting on it.
     */
    private function spawn(): int
    {
        $pid = (int) trim((string) shell_exec('setsid sleep 25 >/dev/null 2>&1 & echo $!'));
        usleep(150000);

        $this->spawned[] = $pid;

        return $pid;
    }

    private function state(int $pid): ?string
    {
        $status = (string) @file_get_contents("/proc/{$pid}/status");

        return preg_match('/^State:\s*(\S)/m', $status, $m) ? $m[1] : null;
    }

    public function test_inspects_a_live_process(): void
    {
        $pid = $this->spawn();
        $info = $this->responder->inspect($pid);

        $this->assertNotNull($info);
        $this->assertSame($pid, $info['pid']);
        $this->assertIsInt($info['start_time']);
        $this->assertGreaterThan(0, $info['start_time']);
        $this->assertFalse($info['kernel_thread']);

        $this->assertNull($this->responder->inspect(4194303), 'a dead pid must not look alive');
    }

    /**
     * The single most important guarantee: a recycled PID must not be
     * mistaken for the original target.
     */
    public function test_refuses_to_act_when_the_start_time_does_not_match(): void
    {
        $pid = $this->spawn();
        $info = $this->responder->inspect($pid);

        $this->assertTrue($this->responder->verifyIdentity($pid, $info['start_time'])['ok']);

        $mismatch = $this->responder->verifyIdentity($pid, $info['start_time'] + 999);
        $this->assertFalse($mismatch['ok']);
        $this->assertSame('pid_reused', $mismatch['reason']);

        $result = $this->responder->kill($pid, $info['start_time'] + 999);
        $this->assertFalse($result['success']);
        $this->assertSame('pid_reused', $result['error']);
        $this->assertNotNull($this->responder->inspect($pid), 'the process must be untouched');
    }

    /**
     * Suspend is the response you can take back: the process stops but its
     * memory, handles and sockets survive for investigation.
     */
    public function test_suspend_and_resume_round_trip(): void
    {
        $pid = $this->spawn();
        $info = $this->responder->inspect($pid);

        $this->assertTrue($this->responder->suspend($pid, $info['start_time'])['success']);
        usleep(200000);
        $this->assertSame('T', $this->state($pid), 'process should be stopped');

        $this->assertTrue($this->responder->resume($pid, $info['start_time'])['success']);
        usleep(200000);
        $this->assertContains($this->state($pid), ['S', 'R'], 'process should be running again');
    }

    /**
     * A delivered signal is not a dead process. Reporting "killed" for
     * something still running is a lie the analyst acts on.
     */
    public function test_kill_confirms_the_process_actually_died(): void
    {
        $pid = $this->spawn();
        $info = $this->responder->inspect($pid);

        $result = $this->responder->kill($pid, $info['start_time']);

        $this->assertTrue($result['success']);
        $this->assertTrue($result['confirmed_dead']);
        $this->assertNull($this->responder->inspect($pid));

        $again = $this->responder->kill($pid, $info['start_time']);
        $this->assertFalse($again['success']);
        $this->assertSame('process_gone', $again['error']);
    }

    public function test_never_acts_on_critical_system_processes(): void
    {
        $init = ['pid' => 1, 'name' => 'systemd', 'path' => '/usr/lib/systemd/systemd', 'kernel_thread' => false];

        $guard = $this->responder->checkGuardrails($init);
        $this->assertFalse($guard['allowed']);
        $this->assertFalse($guard['requires_force'], 'panicking the kernel must not be a forceable option');

        $this->assertFalse($this->responder->checkGuardrails($init, true)['allowed']);

        $kthread = ['pid' => 99999, 'name' => 'kthreadd', 'path' => null, 'kernel_thread' => true];
        $this->assertSame('kernel_thread', $this->responder->checkGuardrails($kthread, true)['reason']);
    }

    /**
     * There is no legitimate response action that turns the EDR off.
     */
    public function test_never_acts_on_its_own_lineage(): void
    {
        $self = ['pid' => getmypid(), 'name' => 'php', 'path' => '/usr/bin/php', 'kernel_thread' => false];

        $guard = $this->responder->checkGuardrails($self, true);

        $this->assertFalse($guard['allowed']);
        $this->assertSame('agent_process', $guard['reason']);
    }

    /**
     * Cutting sshd on a remote server strands the administrator who has to
     * clean up — plausible during a real intrusion, but never automatic.
     */
    public function test_protected_processes_require_an_explicit_force(): void
    {
        $sshd = ['pid' => 99998, 'name' => 'sshd', 'path' => '/usr/sbin/sshd', 'kernel_thread' => false];

        $guard = $this->responder->checkGuardrails($sshd);
        $this->assertFalse($guard['allowed']);
        $this->assertSame('protected_process', $guard['reason']);
        $this->assertTrue($guard['requires_force']);

        $this->assertTrue($this->responder->checkGuardrails($sshd, true)['allowed']);

        $sensor = ['pid' => 99997, 'name' => 'osqueryd', 'path' => '/opt/osquery/bin/osqueryd', 'kernel_thread' => false];
        $this->assertTrue($this->responder->checkGuardrails($sensor)['requires_force']);
    }
}

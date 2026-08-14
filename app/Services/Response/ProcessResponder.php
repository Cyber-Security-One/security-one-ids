<?php

namespace App\Services\Response;

use Illuminate\Support\Facades\Log;

/**
 * Terminates or freezes a process on this endpoint.
 *
 * Two ideas drive the design.
 *
 * **PID reuse is the way this goes wrong.** By the time a command reaches the
 * agent the target may already be gone and the kernel may have handed its
 * number to something innocent. A PID alone is not an identity; the kernel's
 * own identity for a process is (pid, start time), so the caller must supply
 * the start time it observed and we refuse to act if it does not match. An
 * EDR that kills the wrong process because of a recycled number is worse than
 * one that does nothing.
 *
 * **Suspend before kill.** SIGSTOP freezes a process without destroying it:
 * the memory, open files and sockets all survive for forensics, and it is
 * reversible if the detection turns out to be wrong. SIGKILL is the option
 * you cannot take back, so it is never the automatic choice.
 */
class ProcessResponder
{
    /**
     * Killing these breaks the host or blinds us. No override exists —
     * a response feature that can panic a customer's kernel is not a feature.
     */
    private const NEVER_KILL_PIDS = [1, 2];

    /**
     * Killing these is plausible during a real intrusion but costly enough to
     * demand an explicit `force`. sshd in particular: cutting the SSH daemon
     * on a remote server strands the very administrator who has to clean up.
     */
    private const PROTECTED_NAMES = [
        'systemd', 'init', 'sshd', 'dbus-daemon', 'dbus-broker',
        'containerd', 'dockerd', 'kubelet', 'agetty', 'login',
        // Our own moving parts: killing these turns the EDR off.
        'osqueryd', 'suricata', 'clamd',
    ];

    /**
     * Inspect a process without touching it. Returns null when the pid does
     * not exist.
     */
    public function inspect(int $pid): ?array
    {
        if ($pid <= 0 || !is_dir("/proc/{$pid}")) {
            return null;
        }

        $startTime = $this->startTime($pid);
        if ($startTime === null) {
            return null;
        }

        $cmdlineRaw = (string) @file_get_contents("/proc/{$pid}/cmdline");
        $exe = @readlink("/proc/{$pid}/exe");
        $status = (string) @file_get_contents("/proc/{$pid}/status");

        preg_match('/^PPid:\s*(\d+)/m', $status, $ppidMatch);
        preg_match('/^Uid:\s*(\d+)/m', $status, $uidMatch);
        preg_match('/^Name:\s*(.+)$/m', $status, $nameMatch);
        preg_match('/^State:\s*(\S)/m', $status, $stateMatch);

        $state = $stateMatch[1] ?? null;

        return [
            'pid' => $pid,
            'ppid' => isset($ppidMatch[1]) ? (int) $ppidMatch[1] : null,
            'uid' => isset($uidMatch[1]) ? (int) $uidMatch[1] : null,
            'name' => isset($nameMatch[1]) ? trim($nameMatch[1]) : null,
            'state' => $state,
            'path' => $exe !== false ? $exe : null,
            'cmdline' => trim(str_replace("\0", ' ', $cmdlineRaw)),
            'start_time' => $startTime,
            // A kernel thread has no command line — but neither does a
            // zombie, whose argv is torn down when it exits. Classifying a
            // zombie as a kernel thread would put it behind the never-touch
            // guardrail, so a process that has already exited could never be
            // reported as dead.
            'kernel_thread' => $cmdlineRaw === '' && $state !== 'Z',
            'exited' => $state === 'Z',
        ];
    }

    /**
     * Whether a process is still running. A zombie has exited and is only
     * waiting to be reaped, so it counts as gone.
     */
    public function isAlive(int $pid, ?int $expectedStartTime = null): bool
    {
        $check = $this->verifyIdentity($pid, $expectedStartTime);

        if (!$check['ok']) {
            return false;
        }

        return ($check['process']['state'] ?? null) !== 'Z';
    }

    /**
     * The kernel's start time for a process, in clock ticks since boot
     * (field 22 of /proc/pid/stat).
     *
     * Parsing starts after the last ')' on purpose: the comm field is wrapped
     * in parentheses and may itself contain spaces and parentheses, so
     * splitting the line on whitespace gives the wrong field for any process
     * whose name is `(sd-pam)` or similar.
     */
    public function startTime(int $pid): ?int
    {
        $stat = @file_get_contents("/proc/{$pid}/stat");
        if ($stat === false) {
            return null;
        }

        $close = strrpos($stat, ')');
        if ($close === false) {
            return null;
        }

        $fields = preg_split('/\s+/', trim(substr($stat, $close + 1)));
        if ($fields === false) {
            return null;
        }

        // After the comm field, field 3 of /proc/pid/stat is index 0 here, so
        // starttime (field 22) sits at index 19.
        return isset($fields[19]) ? (int) $fields[19] : null;
    }

    /**
     * Confirm the running process is still the one that was observed.
     *
     * @return array{ok:bool, reason:?string, process:?array}
     */
    public function verifyIdentity(int $pid, ?int $expectedStartTime): array
    {
        $process = $this->inspect($pid);

        if ($process === null) {
            return ['ok' => false, 'reason' => 'process_gone', 'process' => null];
        }

        if ($expectedStartTime !== null && $process['start_time'] !== $expectedStartTime) {
            // Same number, different process. This is exactly the case the
            // check exists for.
            return ['ok' => false, 'reason' => 'pid_reused', 'process' => $process];
        }

        return ['ok' => true, 'reason' => null, 'process' => $process];
    }

    /**
     * Whether we are allowed to act on this process.
     *
     * @return array{allowed:bool, reason:?string, requires_force:bool}
     */
    public function checkGuardrails(array $process, bool $force = false): array
    {
        $pid = (int) $process['pid'];

        if (in_array($pid, self::NEVER_KILL_PIDS, true)) {
            return ['allowed' => false, 'reason' => 'pid_is_critical_system_process', 'requires_force' => false];
        }

        if (!empty($process['kernel_thread'])) {
            return ['allowed' => false, 'reason' => 'kernel_thread', 'requires_force' => false];
        }

        // Killing ourselves, our watchdog, or anything we are a descendant of
        // turns the EDR off. There is no legitimate response action that does
        // that, so it is not forceable.
        if ($this->isOwnLineage($pid)) {
            return ['allowed' => false, 'reason' => 'agent_process', 'requires_force' => false];
        }

        $name = (string) ($process['name'] ?? '');
        $binary = $process['path'] !== null ? basename((string) $process['path']) : $name;

        if (in_array($name, self::PROTECTED_NAMES, true) || in_array($binary, self::PROTECTED_NAMES, true)) {
            if (!$force) {
                return ['allowed' => false, 'reason' => 'protected_process', 'requires_force' => true];
            }

            Log::warning('[EDR response] Acting on a protected process under force', [
                'pid' => $pid,
                'name' => $name,
            ]);
        }

        return ['allowed' => true, 'reason' => null, 'requires_force' => false];
    }

    /**
     * True when the pid is this agent, or an ancestor of it.
     */
    private function isOwnLineage(int $pid): bool
    {
        if ($pid === getmypid()) {
            return true;
        }

        // Walk our own ancestry rather than the target's: it terminates at
        // PID 1 in a handful of steps and cannot be fooled by a process that
        // reparents itself.
        $current = getmypid();
        $guard = 0;

        while ($current > 1 && $guard++ < 32) {
            if ($current === $pid) {
                return true;
            }

            $status = (string) @file_get_contents("/proc/{$current}/status");
            if (!preg_match('/^PPid:\s*(\d+)/m', $status, $m)) {
                break;
            }

            $current = (int) $m[1];
        }

        return false;
    }

    /**
     * Freeze a process with SIGSTOP.
     *
     * The preferred first response: the process stops executing immediately
     * but its memory, file handles and sockets stay intact for investigation,
     * and a wrong call costs nothing permanent.
     *
     * @return array{success:bool, error:?string, process:?array}
     */
    public function suspend(int $pid, ?int $expectedStartTime, bool $force = false): array
    {
        return $this->signal($pid, $expectedStartTime, SIGSTOP, 'suspend', $force);
    }

    public function resume(int $pid, ?int $expectedStartTime): array
    {
        // Resuming is the undo of a suspend; guardrails do not apply because
        // letting a process run again cannot damage the host.
        return $this->signal($pid, $expectedStartTime, SIGCONT, 'resume', true, false);
    }

    /**
     * Terminate a process.
     *
     * SIGKILL by default rather than SIGTERM: a handled signal gives malware
     * the chance to run its own cleanup, unlink itself, or hand off to a
     * child before dying. Graceful termination is available for the cases
     * where an analyst wants the process to shut down properly.
     *
     * @return array{success:bool, error:?string, process:?array}
     */
    public function kill(int $pid, ?int $expectedStartTime, bool $force = false, bool $graceful = false): array
    {
        $result = $this->signal($pid, $expectedStartTime, $graceful ? SIGTERM : SIGKILL, 'kill', $force);

        if (!$result['success']) {
            return $result;
        }

        // Confirm it actually died. A signal that returns success only means
        // it was delivered; an uninterruptible-sleep process may outlive it,
        // and reporting "killed" for a process still running would be a lie
        // the analyst acts on.
        $gone = $this->waitForExit($pid, $expectedStartTime, $graceful ? 5.0 : 2.0);

        if (!$gone && $graceful) {
            Log::info('[EDR response] Graceful termination timed out, escalating to SIGKILL', ['pid' => $pid]);
            $this->signal($pid, $expectedStartTime, SIGKILL, 'kill', $force);
            $gone = $this->waitForExit($pid, $expectedStartTime, 2.0);
        }

        $result['confirmed_dead'] = $gone;

        if (!$gone) {
            $result['success'] = false;
            $result['error'] = 'signal_delivered_but_process_still_running';
        }

        return $result;
    }

    private function waitForExit(int $pid, ?int $expectedStartTime, float $seconds): bool
    {
        $deadline = microtime(true) + $seconds;

        while (microtime(true) < $deadline) {
            $check = $this->verifyIdentity($pid, $expectedStartTime);

            // Gone, or the number now belongs to something else — either way
            // the process we targeted is no longer running.
            if (!$check['ok']) {
                return true;
            }

            // A zombie has exited; it is just waiting to be reaped.
            if (($check['process']['state'] ?? null) === 'Z') {
                return true;
            }

            usleep(100000);
        }

        return false;
    }

    /**
     * @return array{success:bool, error:?string, process:?array}
     */
    private function signal(
        int $pid,
        ?int $expectedStartTime,
        int $signal,
        string $operation,
        bool $force = false,
        bool $applyGuardrails = true
    ): array {
        $check = $this->verifyIdentity($pid, $expectedStartTime);

        if (!$check['ok']) {
            return [
                'success' => false,
                'error' => $check['reason'],
                'process' => $check['process'],
            ];
        }

        $process = $check['process'];

        if ($applyGuardrails) {
            $guard = $this->checkGuardrails($process, $force);

            if (!$guard['allowed']) {
                Log::warning('[EDR response] Refused to act on process', [
                    'pid' => $pid,
                    'operation' => $operation,
                    'reason' => $guard['reason'],
                ]);

                return [
                    'success' => false,
                    'error' => $guard['reason'],
                    'requires_force' => $guard['requires_force'],
                    'process' => $process,
                ];
            }
        }

        if (!function_exists('posix_kill')) {
            return ['success' => false, 'error' => 'posix_extension_missing', 'process' => $process];
        }

        // Re-verify immediately before signalling. The window between the
        // check and the syscall is where a race would put a different
        // process behind this number.
        if ($expectedStartTime !== null && $this->startTime($pid) !== $expectedStartTime) {
            return ['success' => false, 'error' => 'pid_reused', 'process' => $process];
        }

        $sent = @posix_kill($pid, $signal);

        if (!$sent) {
            $errno = posix_get_last_error();

            return [
                'success' => false,
                'error' => 'signal_failed_' . posix_strerror($errno),
                'process' => $process,
            ];
        }

        Log::info('[EDR response] Signal delivered', [
            'pid' => $pid,
            'operation' => $operation,
            'signal' => $signal,
            'name' => $process['name'],
        ]);

        return ['success' => true, 'error' => null, 'process' => $process];
    }
}

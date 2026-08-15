<?php

namespace App\Services\Detection;

use App\Traits\DetectsPlatform;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Suricata IDS/IPS Detection Engine
 *
 * Manages Suricata process lifecycle, parses EVE JSON alerts, and provides status.
 * Supports IDS (passive) and IPS (inline) modes across Linux, macOS, and Windows.
 * On Windows, uses WinDivert (EV code-signed) instead of Npcap.
 */
class SuricataEngine
{
    use DetectsPlatform;

    private string $suricataPath;
    private string $configPath;
    /// errno for "operation not permitted" — see isProcessRunning().
    private const EPERM = 1;

    private string $alertLogPath;
    private string $pidFile;
    private string $logDir;
    private string $rulesDir;
    private ?string $cachedInterface = null;

    public function __construct()
    {
        $this->suricataPath = $this->detectSuricataPath();
        $this->configPath = $this->detectConfigPath();
        $this->logDir = $this->detectLogDir();
        $this->rulesDir = $this->detectRulesDir();
        $this->alertLogPath = $this->logDir . DIRECTORY_SEPARATOR . 'eve.json';
        $this->pidFile = $this->logDir . DIRECTORY_SEPARATOR . 'suricata.pid';

        // On Windows, ensure CYGWIN env var is set system-wide (prevents TP_NUM_C_BUFS crash)
        if ($this->isWindows()) {
            $currentCygwin = getenv('CYGWIN');
            if (empty($currentCygwin) || !str_contains($currentCygwin, 'tls_num_c_bufs')) {
                try {
                    Process::run('setx /M CYGWIN "tls_num_c_bufs:8192" 2>nul');
                    putenv('CYGWIN=tls_num_c_bufs:8192');
                    Log::info('[SuricataEngine] Set CYGWIN=tls_num_c_bufs:8192 system-wide');
                } catch (\Exception $e) {
                    Log::debug('[SuricataEngine] Could not set CYGWIN env: ' . $e->getMessage());
                }
            }
        }
    }

    /**
     * Check if Suricata is installed on this system
     */
    public function isInstalled(): bool
    {
        return !empty($this->suricataPath) && file_exists($this->suricataPath);
    }

    /**
     * Get the Suricata binary path
     */
    public function getSuricataPath(): string
    {
        return $this->suricataPath;
    }

    /**
     * Get the alert log file path (eve.json)
     */
    public function getAlertLogPath(): string
    {
        return $this->alertLogPath;
    }

    /**
     * Get installed Suricata version
     */
    public function getVersion(): ?string
    {
        if (!$this->isInstalled()) {
            return null;
        }

        try {
            $result = Process::timeout(10)->run("\"{$this->suricataPath}\" --build-info 2>&1");
            $output = $result->output() . $result->errorOutput();

            // "This is Suricata version 7.0.8 RELEASE"
            if (preg_match('/Suricata version\s+([\d.]+)/i', $output, $matches)) {
                return $matches[1];
            }

            // Fallback: try -V
            $result = Process::timeout(10)->run("\"{$this->suricataPath}\" -V 2>&1");
            $output = $result->output() . $result->errorOutput();
            // Require at least X.Y format to avoid matching single digits
            if (preg_match('/(\d+\.\d[\d.]*)/i', $output, $matches)) {
                return $matches[1];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to get Suricata version: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Check if Suricata process is currently running.
     *
     * Has to handle three deployment shapes that all appear in the wild:
     *   - Suricata started by `$this->start()` — pidfile in $this->logDir.
     *   - Suricata run under the distribution systemd unit — pidfile in
     *     /run/suricata.pid (Debian/Ubuntu/RHEL default) and the main
     *     thread's `comm` name is "Suricata-Main", NOT "suricata", so a
     *     plain `pgrep -x suricata` misses it.
     *   - Suricata run under Homebrew (macOS) — pidfile under
     *     /opt/homebrew/var/run/suricata.pid, comm=`suricata`.
     */
    public function isRunning(): bool
    {
        foreach ($this->candidatePidFiles() as $pidFile) {
            if (!file_exists($pidFile)) {
                continue;
            }
            $pid = (int) trim((string) @file_get_contents($pidFile));
            if ($pid > 0 && $this->isProcessRunning($pid)) {
                return true;
            }
        }

        // Systemd bus check — works even when we can't read the pidfile.
        if (!$this->isWindows() && PHP_OS !== 'Darwin') {
            try {
                $result = Process::run('systemctl is-active suricata 2>/dev/null');
                if (trim($result->output()) === 'active') {
                    return true;
                }
            } catch (\Exception $e) {
                // Ignore — fall through to pgrep.
            }
        }

        // Process-name fallback: match both `suricata` and `Suricata-Main`.
        return $this->isSuricataProcessActive();
    }

    /**
     * Detect what mode the currently-running Suricata process was started in,
     * by inspecting its command-line. Returns 'ips' if `-q`/NFQUEUE was used,
     * 'ids' if `--af-packet`/`--pcap`/`-i` only, or null if not running /
     * mode can't be determined (e.g. Windows WMIC unavailable).
     *
     * Used by the WAF sync layer to decide whether a running Suricata needs
     * to be restarted because the desired mode has changed.
     */
    public function getRunningMode(): ?string
    {
        if (!$this->isRunning()) {
            return null;
        }

        // Linux: /proc/<pid>/cmdline is the most reliable source.
        if (!$this->isWindows() && PHP_OS !== 'Darwin') {
            foreach ($this->candidatePidFiles() as $pidFile) {
                if (!file_exists($pidFile)) {
                    continue;
                }
                $pid = (int) trim((string) @file_get_contents($pidFile));
                if ($pid <= 0) {
                    continue;
                }
                $cmdlineRaw = @file_get_contents("/proc/{$pid}/cmdline");
                if ($cmdlineRaw === false || $cmdlineRaw === '') {
                    continue;
                }
                // cmdline is NUL-separated argv.
                $args = explode("\0", $cmdlineRaw);
                foreach ($args as $arg) {
                    if ($arg === '-q' || str_starts_with($arg, '--nfqueue') || preg_match('/^-q\d+$/', $arg)) {
                        return 'ips';
                    }
                }
                // No -q seen but process is alive → IDS (af-packet / pcap).
                return 'ids';
            }
            // Pidfile not readable but process is alive — fall back to pgrep.
            $result = Process::run("pgrep -af '[Ss]uricata' 2>/dev/null");
            if ($result->successful()) {
                $out = $result->output();
                if (preg_match('/\s-q(\s|\d|$)/', $out)) {
                    return 'ips';
                }
                if (str_contains($out, '--af-packet') || str_contains($out, '-i ')) {
                    return 'ids';
                }
            }
        }

        // Windows: best-effort via WMIC. Absent = unknown.
        if ($this->isWindows()) {
            try {
                $result = Process::timeout(5)->run('wmic process where "name=\'suricata.exe\'" get CommandLine /value 2>nul');
                $out = $result->output();
                if (str_contains($out, '--windivert-forward')) {
                    return 'ips';
                }
                if (str_contains($out, '--windivert')) {
                    return 'ids';
                }
            } catch (\Exception $e) {
                // ignore
            }
        }

        return null;
    }

    /**
     * @return array<string> Pidfile paths to probe, most specific first.
     */
    private function candidatePidFiles(): array
    {
        $paths = [$this->pidFile];
        if (!$this->isWindows()) {
            $paths[] = '/run/suricata.pid';
            $paths[] = '/var/run/suricata.pid';
            $paths[] = '/var/run/suricata/suricata.pid';
            $paths[] = '/opt/homebrew/var/run/suricata.pid';
            $paths[] = '/usr/local/var/run/suricata.pid';
        }
        return array_values(array_unique(array_filter($paths)));
    }

    /**
     * Start Suricata in the specified mode
     *
     * @param string $mode 'ids' or 'ips'
     * @param string|null $interface Network interface to monitor
     */
    public function start(string $mode = 'ids', ?string $interface = null): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Suricata is not installed'];
        }

        if ($this->isRunning()) {
            // Suricata may have been started by systemd or by the watchdog
            // before we got here. In that case we skip the process-launch
            // path but still need to sync iptables state — the NFQUEUE
            // rule the inline-IPS mode depends on is installed here, not
            // by systemd.
            //
            // We used to gate the iptables apply on `getRunningMode() ===
            // $mode`, but that opened a race window: when a stop()+start()
            // mode-switch raced with watchdog re-detection, start()'s
            // isRunning() would see the new process but getRunningMode()
            // might still read the old pidfile's /proc/cmdline (or an
            // in-flight transition), report 'ids', and skip installing
            // the IPS NFQUEUE rules. Result: Suricata running in IPS but
            // no packets routed to its queue — silent IPS failure.
            //
            // Apply unconditionally. It's idempotent (`iptables -C` guard),
            // and if the live process really is in the wrong mode, the
            // installed NFQUEUE rules route to a queue that nothing reads,
            // which --queue-bypass on each rule degrades gracefully to
            // plain ACCEPT — so the worst case is "no inspection yet",
            // not "dropped packets".
            $this->applyInlineNetfilter($mode);
            return ['success' => true, 'message' => 'Suricata is already running'];
        }

        // Serialize concurrent start() calls. The daemon takes several
        // seconds (rule loading) to write its pidfile / show up in pgrep,
        // so two callers — e.g. the watchdog's Scan and Sync threads — can
        // both see isRunning() === false and each spawn a daemon. Observed
        // result: two af-packet instances on the same interface, doubled
        // log volume. flock is cross-process; re-check isRunning() once the
        // lock is held, since the winner may have finished starting by then.
        $startLock = @fopen(sys_get_temp_dir() . '/security-one-suricata-start.lock', 'c');
        if ($startLock) {
            flock($startLock, LOCK_EX);
            if ($this->isRunning()) {
                flock($startLock, LOCK_UN);
                fclose($startLock);
                $this->applyInlineNetfilter($mode);
                return ['success' => true, 'message' => 'Suricata is already running'];
            }
        }

        // isRunning() returned false, so any pidfile still on disk is stale
        // (process died without cleanup). Suricata refuses to start when a
        // stale pidfile exists, so remove it here.
        if (file_exists($this->pidFile)) {
            @unlink($this->pidFile);
            Log::info('Removed stale Suricata pidfile before start', [
                'pidfile' => $this->pidFile,
            ]);
        }

        $interface = $interface ?? $this->detectDefaultInterface();

        // Ensure log directory exists
        if (!is_dir($this->logDir)) {
            @mkdir($this->logDir, 0755, true);
        }

        // Ensure a valid config file exists
        $this->ensureConfig();

        // Windows (Cygwin): limit rules before startup to prevent TP_NUM_C_BUFS crash
        if ($this->isWindows()) {
            $this->limitRulesForWindows();
        }

        // Build the Suricata command
        $cmd = $this->buildStartCommand($mode, $interface);

        try {
            Log::info("Starting Suricata in {$mode} mode on interface {$interface}", [
                'platform' => PHP_OS_FAMILY,
                'suricata_path' => $this->suricataPath,
                'config_path' => $this->configPath,
                'command' => $cmd,
            ]);

            if ($this->isWindows()) {
                // Windows: launch as background process via .bat wrapper to set CYGWIN env var
                $logFile = $this->logDir . '\\suricata_stdout.log';
                $errFile = $this->logDir . '\\suricata_stderr.log';
                // Extract arguments: remove the quoted executable path from the full command
                $args = trim(str_replace("\"{$this->suricataPath}\"", '', $cmd));

                // Create a .bat launcher that sets CYGWIN env var to prevent TP_NUM_C_BUFS crash
                $batFile = $this->logDir . '\\suricata_launcher.bat';
                $batContent = "@echo off\r\n" .
                    "set CYGWIN=tls_num_c_bufs:8192\r\n" .
                    "\"{$this->suricataPath}\" {$args}\r\n";
                file_put_contents($batFile, $batContent);

                // Launch the .bat wrapper as a hidden background process
                $psCommand = "\$proc = Start-Process -FilePath 'cmd.exe' " .
                    "-ArgumentList '/c','\"{$batFile}\"' " .
                    "-WindowStyle Hidden -PassThru " .
                    "-RedirectStandardOutput '{$logFile}' " .
                    "-RedirectStandardError '{$errFile}'; " .
                    "\$proc.Id | Set-Content '{$this->pidFile}'";
                $result = Process::timeout(15)->run("powershell -NonInteractive -Command \"{$psCommand}\"");
            } else {
                // Linux/macOS: run as daemon
                $stderrFile = sys_get_temp_dir() . '/suricata_start_stderr_' . uniqid() . '.log';
                $result = Process::timeout(15)->run("{$cmd} 2>{$stderrFile}");
            }

            // Wait for Suricata to initialize
            sleep(3);

            // Check PID file
            if (file_exists($this->pidFile)) {
                $daemonPid = trim(file_get_contents($this->pidFile));
                if (is_numeric($daemonPid) && $this->isProcessRunning((int) $daemonPid)) {
                    $this->fixLogPermissions();
                    $this->applyInlineNetfilter($mode);
                    Log::info('Suricata daemon started successfully', [
                        'platform' => PHP_OS_FAMILY,
                        'daemon_pid' => $daemonPid,
                    ]);
                    @unlink($stderrFile ?? '');
                    return ['success' => true, 'message' => "Suricata started in {$mode} mode"];
                }
            }

            // Fallback: check process list
            if ($this->isRunning()) {
                $this->fixLogPermissions();
                $this->applyInlineNetfilter($mode);
                Log::info('Suricata started successfully', ['platform' => PHP_OS_FAMILY]);
                @unlink($stderrFile ?? '');
                return ['success' => true, 'message' => "Suricata started in {$mode} mode"];
            }

            // Start failed — capture error output
            $errorOutput = '';
            if ($this->isWindows()) {
                $winErrFile = $this->logDir . '\\suricata_stderr.log';
                $winOutFile = $this->logDir . '\\suricata_stdout.log';
                if (file_exists($winErrFile)) {
                    $errorOutput = trim(file_get_contents($winErrFile));
                }
                // Suricata may write errors to stdout on Windows
                if (empty($errorOutput) && file_exists($winOutFile)) {
                    $errorOutput = trim(file_get_contents($winOutFile));
                }
            } elseif (isset($stderrFile) && file_exists($stderrFile)) {
                $errorOutput = file_get_contents($stderrFile);
                @unlink($stderrFile);
            }

            Log::warning('Suricata failed to start', [
                'platform' => PHP_OS_FAMILY,
                'exit_code' => $result->exitCode(),
                'stderr' => substr($errorOutput, 0, 500),
            ]);

            return ['success' => false, 'error' => 'Suricata started but not running: ' . substr($errorOutput, 0, 200)];
        } catch (\Exception $e) {
            Log::error('Failed to start Suricata: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        } finally {
            if ($startLock) {
                flock($startLock, LOCK_UN);
                fclose($startLock);
            }
        }
    }

    /**
     * Stop Suricata process
     */
    public function stop(): array
    {
        if (!$this->isRunning()) {
            // Still clear any NFQUEUE rules we may have left behind from a
            // prior IPS run — otherwise packets go to a queue with nobody
            // listening. --queue-bypass in the rule means the kernel then
            // accepts them, but removing the rule outright is cleaner.
            $this->removeInlineNetfilter();
            return ['success' => true, 'message' => 'Suricata is not running'];
        }

        // Remove NFQUEUE rules BEFORE killing Suricata. If we kill first and
        // the rule is still present without --queue-bypass, packets would be
        // dropped in the window between kill and rule removal.
        $this->removeInlineNetfilter();

        try {
            if ($this->isWindows()) {
                if (file_exists($this->pidFile)) {
                    $pid = trim(file_get_contents($this->pidFile));
                    Process::run("taskkill /PID {$pid} /F 2>nul");
                    @unlink($this->pidFile);
                } else {
                    Process::run("taskkill /IM suricata.exe /F 2>nul");
                }
                Log::info('Suricata stopped');
                return ['success' => true, 'message' => 'Suricata stopped'];
            }

            // Linux/macOS: a Suricata process can have been launched by any
            // of: this engine, systemd (distro package), or a previous run
            // that used a different pidfile path. We must handle all three
            // or stop() will silently no-op and the mode-switch restart
            // loop will see `isRunning()==true` and bail out.
            //
            // 1. systemctl stop (covers distro-package systemd unit)
            // 2. kill every PID in every candidate pidfile
            // 3. pkill -f suricata as a last resort (Ubuntu's Suricata main
            //    thread reports its comm as "Suricata-Main", so `pkill -x
            //    suricata` misses it — `-f` matches the full cmdline.)
            if (!$this->isWindows() && PHP_OS !== 'Darwin') {
                Process::run('systemctl stop suricata 2>/dev/null');
            }

            foreach ($this->candidatePidFiles() as $pidFile) {
                if (!file_exists($pidFile)) {
                    continue;
                }
                $pid = (int) trim((string) @file_get_contents($pidFile));
                if ($pid <= 0) {
                    continue;
                }
                Process::run("kill {$pid} 2>/dev/null");
                for ($i = 0; $i < 5 && $this->isProcessRunning($pid); $i++) {
                    usleep(200000);
                }
                if ($this->isProcessRunning($pid)) {
                    Process::run("kill -9 {$pid} 2>/dev/null");
                }
                @unlink($pidFile);
            }

            // Catch-all for processes whose pidfile we couldn't find.
            if ($this->isRunning()) {
                Process::run("pkill -f '^/usr/[s]?bin/suricata' 2>/dev/null");
                sleep(1);
                if ($this->isRunning()) {
                    Process::run("pkill -9 -f '^/usr/[s]?bin/suricata' 2>/dev/null");
                }
            }

            Log::info('Suricata stopped');
            return ['success' => true, 'message' => 'Suricata stopped'];
        } catch (\Exception $e) {
            Log::error('Failed to stop Suricata: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Get comprehensive Suricata status information
     */
    public function getStatus(): array
    {
        $installed = $this->isInstalled();

        // Read the desired mode from the same config file WafSyncService
        // writes Hub's heartbeat payload into — `waf_config.json`.
        // (The old implementation read from `hub_config.json`, which is
        // never created by any code path, so `$suricataMode` always fell
        // through to the 'ids' default. That made this value useless for
        // Hub-side displays that derived UI from `system_info.suricata.
        // suricata_mode`: it always reported 'ids' regardless of the
        // actual Hub-commanded mode.)
        $suricataMode = 'ids';
        foreach (['waf_config.json', 'hub_config.json'] as $name) {
            $p = storage_path('app/' . $name);
            if (!file_exists($p)) continue;
            try {
                $config = json_decode(file_get_contents($p), true);
                if (is_array($config)) {
                    $suricataMode = $config['addons']['suricata_mode']
                        ?? $config['addons']['snort_mode']
                        ?? 'ids';
                    break;
                }
            } catch (\Exception $e) {
                // ignore; try next candidate
            }
        }

        return [
            'installed' => $installed,
            'version' => $installed ? $this->getVersion() : null,
            'running' => $installed ? $this->isRunning() : false,
            'path' => $this->suricataPath,
            'config_path' => $this->configPath,
            'log_dir' => $this->logDir,
            // `suricata_mode`: the *intended* mode Hub last told us to run
            // as, mirrored from storage/app/hub_config.json.
            'suricata_mode' => $suricataMode,
            // `running_mode`: the mode the live process is actually
            // running in, derived from /proc/<pid>/cmdline (-q → ips,
            // --af-packet/-i → ids). Diverges from `suricata_mode` when
            // the agent just booted and systemd's IDS unit starts before
            // Hub sync flips it, or when a rule reload failed mid-switch.
            // Hub UI should prefer this for status display.
            'running_mode' => $installed ? $this->getRunningMode() : null,
            'stats' => $installed ? $this->getStats() : null,
        ];
    }

    /**
     * Get Suricata statistics
     */
    public function getStats(): ?array
    {
        if (!$this->isInstalled()) {
            return null;
        }

        $stats = [
            'alerts_today' => $this->countAlertsToday(),
            'rules_loaded' => $this->countLoadedRules(),
        ];

        // Collect packet stats from OS network interface counters
        $interface = $this->detectDefaultInterface();
        if (!$this->isWindows() && PHP_OS === 'Darwin') {
            $this->collectMacPacketStats($stats, $interface);
        } elseif (!$this->isWindows()) {
            $this->collectLinuxPacketStats($stats, $interface);
        }

        return $stats;
    }

    /**
     * Parse recent alerts from Suricata's EVE JSON log
     *
     * @param int $limit Number of alerts to return
     * @return array Parsed alert entries
     */
    public function parseAlerts(int $limit = 50): array
    {
        $logPath = $this->alertLogPath;
        if (!file_exists($logPath)) {
            return [];
        }

        $alerts = [];

        try {
            // Escalating byte window rather than a line count, because eve.json
            // is not mostly alerts. Suricata writes a stats record every ~8
            // seconds and each one is around 8KB on this host, so a quiet
            // period is a solid wall of them: measured, the last 2,000 lines of
            // a live eve.json contained 2,000 stats records and zero alerts,
            // and the last 16MB contained none either because 5.5 hours of
            // quiet is ~21MB of stats alone.
            //
            // The previous implementation read `tail -n (limit * 2)`, which with
            // the default limit meant 100 lines — about twelve minutes of stats.
            // On any host without an alert in the last few minutes it returned
            // an empty array, indistinguishable from a host with nothing to
            // report. It has no callers today, which is the only reason this was
            // latent rather than a live blind spot.
            //
            // Filtering with grep before parsing keeps the cost flat: a 256MB
            // window over a 3.4GB log measured 0.18s.
            $lines = [];

            foreach ([32, 64, 128, 256] as $megabytes) {
                $result = Process::run(sprintf(
                    'tail -c %dM %s | grep -a %s',
                    $megabytes,
                    escapeshellarg($logPath),
                    escapeshellarg('"event_type":"\(alert\|drop\)"')
                ));

                $lines = explode("\n", trim($result->output()));

                if (count(array_filter($lines)) >= $limit) {
                    break;
                }
            }

            foreach (array_reverse($lines) as $line) {
                if (empty($line)) {
                    continue;
                }

                $entry = @json_decode($line, true);
                $eventType = $entry['event_type'] ?? '';
                if (!$entry || !in_array($eventType, ['alert', 'drop'])) {
                    continue;
                }

                $alert = $entry['alert'] ?? $entry['drop'] ?? [];
                $alerts[] = [
                    'timestamp' => $entry['timestamp'] ?? null,
                    'source_ip' => $entry['src_ip'] ?? 'unknown',
                    'source_port' => $entry['src_port'] ?? null,
                    'destination_ip' => $entry['dest_ip'] ?? null,
                    'destination_port' => $entry['dest_port'] ?? null,
                    'protocol' => $entry['proto'] ?? null,
                    'sid' => $alert['signature_id'] ?? null,
                    'gid' => $alert['gid'] ?? 1,
                    'rev' => $alert['rev'] ?? null,
                    'signature' => $alert['signature'] ?? 'Unknown',
                    'category' => $alert['category'] ?? 'Unknown',
                    'severity' => $this->severityToLabel($alert['severity'] ?? 3),
                    'action' => $alert['action'] ?? 'alert',
                ];

                if (count($alerts) >= $limit) {
                    break;
                }
            }
        } catch (\Exception $e) {
            Log::warning('Failed to parse Suricata alerts: ' . $e->getMessage());
        }

        return $alerts;
    }

    /**
     * Reload Suricata rules (SIGUSR2 triggers rule reload)
     */
    public function reload(): array
    {
        if (!$this->isRunning()) {
            return ['success' => false, 'error' => 'Suricata is not running'];
        }

        try {
            if ($this->isWindows()) {
                // Windows: stop + start
                $this->stop();
                sleep(2);
                return $this->start();
            }

            // Unix: send SIGUSR2 for live rule reload
            if (file_exists($this->pidFile)) {
                $pid = trim(file_get_contents($this->pidFile));
                Process::run("kill -USR2 {$pid} 2>/dev/null");
                Log::info('Suricata rule reload signal sent (SIGUSR2)');
                return ['success' => true, 'message' => 'Rule reload signal sent'];
            }

            Process::run("pkill -USR2 -f suricata 2>/dev/null");
            return ['success' => true, 'message' => 'Rule reload signal sent'];
        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Apply custom rules content to Suricata rules file
     */
    public function applyCustomRules(string $rulesContent): bool
    {
        $rulesFile = $this->rulesDir . '/custom.rules';

        if (!is_dir($this->rulesDir)) {
            @mkdir($this->rulesDir, 0755, true);
        }

        file_put_contents($rulesFile, $rulesContent);
        Log::info('Applied custom Suricata rules', ['rules_file' => $rulesFile]);

        // Hub-synced rulesets can contain Snort-syntax rules Suricata cannot
        // parse (e.g. sticky-buffer `http_uri;` before any `content`). They
        // never load, and every engine start / rule reload dumps the full
        // error list into suricata.log — thousands of lines per pass, which
        // once filled /var/log to 200+ GB. Disable unparseable rules before
        // signaling the reload.
        $sanitizer = '/usr/local/bin/suricata-rule-sanitize';
        if (!$this->isWindows() && PHP_OS !== 'Darwin' && is_executable($sanitizer)) {
            try {
                $result = Process::timeout(300)->run($sanitizer);
                if (!$result->successful()) {
                    Log::warning('Suricata rule sanitize failed', [
                        'exit_code' => $result->exitCode(),
                        'output' => substr($result->output(), -500),
                    ]);
                }
            } catch (\Exception $e) {
                Log::warning('Suricata rule sanitize error: ' . $e->getMessage());
            }
        }

        // Live-reload rules
        if ($this->isRunning()) {
            $this->reload();
        }

        return true;
    }

    /**
     * Convert rule actions for IPS mode: alert → drop
     */
    public function applyIpsMode(string $rulesContent): string
    {
        $lines = explode("\n", $rulesContent);
        $converted = 0;

        foreach ($lines as &$line) {
            $trimmed = trim($line);
            if (empty($trimmed) || $trimmed[0] === '#') {
                continue;
            }
            if (preg_match('/^alert\s/', $trimmed)) {
                $line = preg_replace('/^alert\s/', 'drop ', $trimmed);
                $converted++;
            }
        }
        unset($line);

        if ($converted > 0) {
            Log::info("Suricata IPS mode: converted {$converted} alert rules to drop");
        }

        return implode("\n", $lines);
    }

    /**
     * Update Suricata to the latest version
     */
    public function updateSuricata(): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Suricata is not installed'];
        }

        $oldVersion = $this->getVersion();
        $wasRunning = $this->isRunning();

        if ($wasRunning) {
            $this->stop();
        }

        try {
            Log::info('Updating Suricata...', ['current_version' => $oldVersion]);

            if (PHP_OS === 'Darwin') {
                $this->updateSuricataMac();
            } elseif ($this->isWindows()) {
                $this->updateSuricataWindows();
            } else {
                $this->updateSuricataLinux();
            }

            $this->suricataPath = $this->detectSuricataPath();
            $newVersion = $this->getVersion();

            if ($wasRunning) {
                $this->start();
            }

            if ($newVersion && $newVersion !== $oldVersion) {
                Log::info('Suricata updated', ['old' => $oldVersion, 'new' => $newVersion]);
                return ['success' => true, 'version' => $newVersion, 'previous' => $oldVersion];
            }

            return ['success' => true, 'version' => $newVersion ?? $oldVersion, 'message' => 'Already at latest version'];
        } catch (\Exception $e) {
            Log::error('Suricata update failed: ' . $e->getMessage());
            if ($wasRunning) {
                $this->start();
            }
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Get the detected rules directory
     */
    public function getDetectedRulesDir(): string
    {
        return $this->rulesDir;
    }

    // ─── Private helpers ──────────────────────────────────────────

    /**
     * Build the Suricata start command based on platform and mode
     */
    private function buildStartCommand(string $mode, string $interface): string
    {
        $cmd = "\"{$this->suricataPath}\"";
        $cmd .= " -c \"{$this->configPath}\"";
        $cmd .= " --pidfile \"{$this->pidFile}\"";
        $cmd .= " -l \"{$this->logDir}\"";

        if ($this->isWindows()) {
            // Windows: use WinDivert for packet capture
            if ($mode === 'ips') {
                // IPS inline mode: WinDivert forward (can drop packets)
                $cmd .= " --windivert-forward";
            } else {
                // IDS passive mode: WinDivert monitor
                $cmd .= " --windivert \"{$interface}\"";
            }
        } else {
            // Linux/macOS
            if ($mode === 'ips' && PHP_OS !== 'Darwin') {
                // IPS inline on Linux via NFQUEUE only. `-q` and `--af-packet`
                // are mutually exclusive run modes; combining them makes
                // Suricata exit with "more than one run mode has been
                // specified". No `-i` — NFQUEUE packets come from the kernel
                // queue, not a NIC.
                //
                // Multi-queue (0:3 = queues 0-3) lets Suricata spawn 4
                // RX-NFQ threads, matched on the iptables side by
                // `--queue-balance 0:3`. A single queue was the throughput
                // bottleneck that caused rule-reload windows to back up
                // into kernel drops, even with fail-open set.
                $cmd .= " -q 0:3";
            } else {
                // IDS passive: af-packet on Linux, pcap on macOS.
                $cmd .= " -i {$interface}";
                if (PHP_OS !== 'Darwin') {
                    $cmd .= " --af-packet";
                }
            }

            // Daemon mode
            $cmd .= " -D";
        }

        return $cmd;
    }

    /**
     * Ensure a valid Suricata config (suricata.yaml) exists
     */
    private function ensureConfig(): void
    {
        $this->configPath = $this->detectConfigPath();

        if (file_exists($this->configPath)) {
            // Ensure eve.json output is configured
            $content = file_get_contents($this->configPath);
            if (!str_contains($content, 'eve-log')) {
                Log::info('Existing suricata.yaml missing eve-log, will use default');
            }
            // Self-heal interface misconfig.
            // Distribution packages ship suricata.yaml with `interface: eth0`,
            // but many modern hosts expose the NIC under a different name
            // (enp*, enP*, ens*, wlan*). When Suricata is told to capture on
            // a non-existent device its worker threads die immediately
            // ("af-packet: eth0: failed to find interface type: No such
            // device") and the Hub UI reports the engine as stopped even
            // though systemd says active. Rewrite the interface in-place to
            // whatever the OS says is the real default.
            $this->healInterfaceMisconfig();
            // Ensure NFQ safety settings (fail-open: yes, mode: accept) are
            // present so a future IPS mode switch doesn't black-hole
            // packets the moment Suricata is overloaded or crashes.
            $this->healNfqConfig();
            // Ensure Hub-synced custom.rules is actually loaded. Without
            // this, applyCustomRules() writes to <rulesDir>/custom.rules
            // but Suricata silently ignores it because the file isn't
            // listed in `rule-files:` — every Hub rule sync becomes a
            // no-op and no Hub signature can ever fire.
            $this->healCustomRulesInclude();
            return;
        }

        try {
            $configDir = dirname($this->configPath);
            if (!is_dir($configDir)) {
                @mkdir($configDir, 0755, true);
            }

            $this->generateDefaultConfig();
            Log::info('Generated default Suricata config', ['path' => $this->configPath]);
        } catch (\Exception $e) {
            Log::warning('Failed to generate Suricata config: ' . $e->getMessage());
        }
    }

    /**
     * Rewrite any `af-packet:` / `pcap:` interface lines that point at a
     * non-existent NIC so that Suricata's workers can actually attach.
     * Linux-only; no-op if the configured interface already exists or the
     * OS doesn't expose a usable default.
     */
    private function healInterfaceMisconfig(): void
    {
        if ($this->isWindows() || PHP_OS === 'Darwin') {
            return;
        }

        $content = @file_get_contents($this->configPath);
        if ($content === false) {
            return;
        }

        if (!preg_match_all('/^\s*(?:-\s*)?interface:\s*([A-Za-z0-9_\-]+)\s*$/m', $content, $m)) {
            return;
        }

        $available = $this->listNetworkInterfaces();
        $default = $this->detectDefaultInterface();

        // If detection falls back to the literal 'eth0' but eth0 isn't on the
        // box, we have no good replacement — bail rather than rewrite into
        // another bad value.
        if (!in_array($default, $available, true)) {
            Log::warning('[Suricata] Cannot self-heal interface: no working default detected', [
                'detected' => $default,
                'available' => $available,
            ]);
            return;
        }

        $replacements = 0;
        foreach (array_unique($m[1]) as $iface) {
            // Skip keyword / PCI-addressed entries, and anything that already
            // names an existing NIC.
            if ($iface === 'default' || str_contains($iface, ':') || in_array($iface, $available, true)) {
                continue;
            }
            $escaped = preg_quote($iface, '/');
            $content = preg_replace(
                "/^(\s*(?:-\s*)?interface:\s*){$escaped}(\s*)\$/m",
                '${1}' . $default . '${2}',
                $content,
                -1,
                $n
            );
            $replacements += (int) $n;
        }

        if ($replacements === 0) {
            return;
        }

        // Keep a timestamped backup so an operator can diff what changed.
        $backup = $this->configPath . '.bak.' . date('Ymd-His');
        @copy($this->configPath, $backup);
        if (@file_put_contents($this->configPath, $content) === false) {
            Log::warning('[Suricata] Could not write healed config (permission?)', [
                'path' => $this->configPath,
            ]);
            return;
        }

        Log::warning('[Suricata] Healed interface misconfig in ' . $this->configPath, [
            'replacements' => $replacements,
            'new_interface' => $default,
            'backup' => $backup,
        ]);
    }

    /**
     * @return array<string> Names of network interfaces visible to the
     *                       kernel (excluding `lo`).
     */
    private function listNetworkInterfaces(): array
    {
        $ifaces = [];
        foreach (@scandir('/sys/class/net') ?: [] as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === 'lo') {
                continue;
            }
            $ifaces[] = $entry;
        }
        return $ifaces;
    }

    /**
     * Generate a minimal working suricata.yaml
     */
    private function generateDefaultConfig(): void
    {
        if (!is_dir($this->rulesDir)) {
            @mkdir($this->rulesDir, 0755, true);
        }

        // Create custom.rules placeholder
        $customRules = $this->rulesDir . '/custom.rules';
        if (!file_exists($customRules)) {
            file_put_contents($customRules, "# Security One IDS - Custom Suricata Rules\n");
        }

        $rulesDir = str_replace('\\', '/', $this->rulesDir);
        $logDir = str_replace('\\', '/', $this->logDir);

        $config = <<<YAML
%YAML 1.1
---
# Auto-generated Suricata config by Security One IDS

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    GENEVE_PORTS: 6081
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: {$logDir}

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: no
            metadata: yes
            http-body: yes
            http-body-printable: yes
        - stats:
            totals: yes
            threads: no
            deltas: yes

  - stats:
      enabled: yes
      filename: stats.log
      append: yes
      totals: yes
      threads: no

af-packet:
  - interface: default

pcap:
  - interface: default

app-layer:
  protocols:
    http:
      enabled: yes
    tls:
      enabled: yes
    dns:
      enabled: yes
    smtp:
      enabled: yes
    ssh:
      enabled: yes

default-rule-path: {$rulesDir}
rule-files:
  - custom.rules

YAML;

        file_put_contents($this->configPath, $config);
    }

    /**
     * Detect Suricata binary path
     */
    private function detectSuricataPath(): string
    {
        $paths = $this->isWindows()
            ? [
                'C:\\Program Files\\Suricata\\suricata.exe',
                'C:\\Suricata\\suricata.exe',
                'C:\\Program Files (x86)\\Suricata\\suricata.exe',
            ]
            : [
                '/usr/bin/suricata',
                '/usr/local/bin/suricata',
                '/usr/sbin/suricata',
                '/opt/suricata/bin/suricata',
                '/opt/homebrew/bin/suricata',
            ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        // Try which/where
        try {
            $cmd = $this->isWindows() ? 'where suricata 2>nul' : 'which suricata 2>/dev/null';
            $result = Process::run($cmd);
            $path = trim($result->output());
            if (!empty($path) && file_exists($path)) {
                return $path;
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return '';
    }

    /**
     * Detect Suricata config path
     */
    private function detectConfigPath(): string
    {
        $paths = $this->isWindows()
            ? [
                'C:\\Program Files\\Suricata\\suricata.yaml',
                'C:\\Suricata\\suricata.yaml',
                storage_path('app/suricata/suricata.yaml'),
            ]
            : [
                '/etc/suricata/suricata.yaml',
                '/usr/local/etc/suricata/suricata.yaml',
                '/opt/homebrew/etc/suricata/suricata.yaml',
                '/opt/suricata/etc/suricata.yaml',
                storage_path('app/suricata/suricata.yaml'),
            ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        // Default: use standard location or storage fallback
        if ($this->isWindows()) {
            return 'C:\\Suricata\\suricata.yaml';
        }

        return file_exists('/etc/suricata') ? '/etc/suricata/suricata.yaml' : storage_path('app/suricata/suricata.yaml');
    }

    /**
     * Detect log directory
     */
    private function detectLogDir(): string
    {
        $paths = $this->isWindows()
            ? ['C:\\Suricata\\log', 'C:\\Program Files\\Suricata\\log']
            : ['/var/log/suricata', '/opt/homebrew/var/log/suricata', '/usr/local/var/log/suricata'];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                return $path;
            }
        }

        return $this->isWindows() ? 'C:\\Suricata\\log' : '/var/log/suricata';
    }

    /**
     * Detect rules directory
     */
    private function detectRulesDir(): string
    {
        // Prefer the directory Suricata's config actually loads from, i.e.
        // whatever `default-rule-path:` in suricata.yaml points at. Writing
        // custom.rules anywhere else is a silent no-op — Suricata parses
        // only files listed in `rule-files:`, resolved relative to
        // default-rule-path. On Debian/Ubuntu packages this is
        // /var/lib/suricata/rules (suricata-update's target), while
        // /etc/suricata/rules only holds static decoder rules and configs.
        $configPath = $this->configPath ?? $this->detectConfigPath();
        if (is_string($configPath) && file_exists($configPath)) {
            $content = @file_get_contents($configPath);
            if ($content !== false && preg_match('/^\s*default-rule-path:\s*([^\s#]+)/m', $content, $m)) {
                $configured = trim($m[1], " \"'");
                if ($configured !== '' && is_dir($configured)) {
                    return $configured;
                }
            }
        }

        $paths = $this->isWindows()
            ? ['C:\\Suricata\\rules', 'C:\\Program Files\\Suricata\\rules']
            : ['/var/lib/suricata/rules', '/etc/suricata/rules', '/usr/local/etc/suricata/rules'];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                return $path;
            }
        }

        return $this->isWindows() ? 'C:\\Suricata\\rules' : '/var/lib/suricata/rules';
    }

    /**
     * Detect the default network interface
     */
    private function detectDefaultInterface(): string
    {
        if ($this->cachedInterface !== null) {
            return $this->cachedInterface;
        }

        if ($this->isWindows()) {
            // On Windows with WinDivert, we use a filter string (not an interface name)
            // Default filter captures all IPv4/IPv6 traffic
            $this->cachedInterface = 'true';
            return $this->cachedInterface;
        }

        // macOS
        if (PHP_OS === 'Darwin') {
            try {
                $result = Process::run("route -n get default 2>/dev/null | grep 'interface:' | awk '{print \$2}'");
                $iface = trim($result->output());
                if (!empty($iface)) {
                    $this->cachedInterface = $iface;
                    return $this->cachedInterface;
                }
            } catch (\Exception $e) {
                // Ignore
            }
            $this->cachedInterface = 'en0';
            return $this->cachedInterface;
        }

        // Linux
        try {
            $result = Process::run("ip route show default 2>/dev/null | awk '{print \$5}' | head -1");
            $iface = trim($result->output());
            if (!empty($iface)) {
                $this->cachedInterface = $iface;
                return $this->cachedInterface;
            }
        } catch (\Exception $e) {
            // Ignore
        }

        $this->cachedInterface = 'eth0';
        return $this->cachedInterface;
    }

    private function updateSuricataMac(): void
    {
        // Find Homebrew
        $brewPaths = ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'];
        $brew = '';
        foreach ($brewPaths as $p) {
            if (file_exists($p)) {
                $brew = $p;
                break;
            }
        }
        if (empty($brew)) {
            throw new \RuntimeException('Homebrew not found');
        }

        Process::timeout(120)->run("{$brew} update 2>&1");
        Process::timeout(600)->run("{$brew} upgrade suricata 2>&1");
    }

    private function updateSuricataLinux(): void
    {
        $distro = $this->detectLinuxDistro();

        if (in_array($distro, ['debian', 'ubuntu', 'linuxmint', 'pop', 'kali'])) {
            Process::timeout(120)->run('apt-get update -qq 2>&1');
            Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade suricata 2>&1');
        } elseif (in_array($distro, ['centos', 'rhel', 'rocky', 'alma', 'fedora'])) {
            if (in_array($distro, ['fedora'])) {
                Process::timeout(600)->run('dnf upgrade -y suricata 2>&1');
            } else {
                Process::timeout(600)->run('yum update -y suricata 2>&1');
            }
        }
    }

    private function updateSuricataWindows(): void
    {
        // Windows: try WinGet or Chocolatey
        try {
            $result = Process::timeout(600)->run('winget upgrade OISF.Suricata --silent --accept-source-agreements 2>&1');
            if ($result->successful()) {
                return;
            }
        } catch (\Exception $e) {
            // Ignore
        }

        try {
            Process::timeout(600)->run('choco upgrade suricata -y 2>&1');
        } catch (\Exception $e) {
            Log::warning('Suricata Windows update failed: ' . $e->getMessage());
        }
    }

    /**
     * Count alerts from today in eve.json
     */
    /**
     * How much of the end of eve.json countAlertsToday() will look at.
     *
     * eve.json carries every event Suricata emits, not only alerts, so on a
     * busy sensor it grows by gigabytes a day; the host this was found on had
     * reached 79 GB. Any full scan of it has to be bounded by something, and
     * a timeout is not something: see countAlertsToday().
     */
    private const ALERT_SCAN_BYTES = 33554432; // 32 MiB

    /**
     * Count today's alert and drop events near the end of eve.json.
     *
     * This reads a fixed window from the end of the file. What it replaced ran
     * `grep -cE ... eve.json` under `Process::timeout(10)`, which on a file
     * this size failed in a way that was worse than not running at all. The
     * timeout stopped the shell but not the grep underneath it, so every call
     * left behind an orphaned full-file scan: 424 of them had accumulated on
     * that host, the oldest three days old, load average in the hundreds. Each
     * one also held the stdout it had inherited, which is what made the macOS
     * console hang — it was waiting for end-of-file on a pipe kept open by a
     * process it had never heard of.
     *
     * And it never worked even once: the timeout arrived as an exception, so
     * the function returned 0 on every call it had ever made.
     *
     * A window is a ceiling on work, so this returns a floor rather than a
     * total — if today is busier than the window, it counts what is in the
     * window. That is the honest shape of the answer, it arrives in
     * milliseconds, and it leaves nothing running behind it.
     */
    private function countAlertsToday(): int
    {
        if (!file_exists($this->alertLogPath)) {
            return 0;
        }

        $size = @filesize($this->alertLogPath);
        if ($size === false || $size === 0) {
            return 0;
        }

        $handle = @fopen($this->alertLogPath, 'rb');
        if ($handle === false) {
            return 0;
        }

        try {
            if ($size > self::ALERT_SCAN_BYTES) {
                fseek($handle, -self::ALERT_SCAN_BYTES, SEEK_END);
                fgets($handle); // discard the partial line the seek landed in
            }

            $today = preg_quote(date('Y-m-d'), '/');
            $matched = 0;
            $dated = 0;
            $sawTimestamp = false;

            while (($line = fgets($handle)) !== false) {
                if (strpos($line, '"event_type"') === false) {
                    continue;
                }

                if (preg_match('/"event_type"\s*:\s*"(?:alert|drop)"/', $line) !== 1) {
                    continue;
                }

                $matched++;

                if (strpos($line, '"timestamp"') === false) {
                    continue;
                }

                $sawTimestamp = true;

                if (preg_match('/"timestamp"\s*:\s*"' . $today . '/', $line) === 1) {
                    $dated++;
                }
            }

            // If nothing in the window carried a timestamp at all, the format
            // has changed rather than the traffic having stopped. Reporting
            // the window's alert count says something true about a different
            // question, which beats reporting "none today" about this one.
            return $sawTimestamp ? $dated : $matched;
        } finally {
            fclose($handle);
        }
    }

    /**
     * Count loaded rules from rules directory
     */
    private function countLoadedRules(): int
    {
        $count = 0;
        $rulesFiles = glob($this->rulesDir . '/*.rules');

        foreach ($rulesFiles as $file) {
            try {
                $content = file_get_contents($file);
                // Count non-comment, non-empty lines
                $lines = explode("\n", $content);
                foreach ($lines as $line) {
                    $trimmed = trim($line);
                    if (!empty($trimmed) && $trimmed[0] !== '#') {
                        $count++;
                    }
                }
            } catch (\Exception $e) {
                // Ignore
            }
        }

        return $count;
    }

    /**
     * Collect packet stats on macOS via netstat
     */
    private function collectMacPacketStats(array &$stats, string $interface): void
    {
        try {
            $result = Process::timeout(5)->run("netstat -I {$interface} -b 2>/dev/null | tail -1");
            $output = trim($result->output());
            $parts = preg_split('/\s+/', $output);
            if (count($parts) >= 7) {
                $stats['packets_received'] = (int) ($parts[4] ?? 0);
                $stats['packets_sent'] = (int) ($parts[6] ?? 0);
            }
        } catch (\Exception $e) {
            // Ignore
        }
    }

    /**
     * Collect packet stats on Linux via /sys/class/net
     */
    private function collectLinuxPacketStats(array &$stats, string $interface): void
    {
        $rxFile = "/sys/class/net/{$interface}/statistics/rx_packets";
        $txFile = "/sys/class/net/{$interface}/statistics/tx_packets";

        if (file_exists($rxFile)) {
            $stats['packets_received'] = (int) trim(file_get_contents($rxFile));
        }
        if (file_exists($txFile)) {
            $stats['packets_sent'] = (int) trim(file_get_contents($txFile));
        }
    }

    /**
     * Map Suricata severity number to label
     */
    private function severityToLabel(int $severity): string
    {
        return match ($severity) {
            1 => 'critical',
            2 => 'high',
            3 => 'medium',
            default => 'low',
        };
    }

    private function detectLinuxDistro(): string
    {
        if (!file_exists('/etc/os-release')) {
            return 'unknown';
        }
        $content = file_get_contents('/etc/os-release');
        if (preg_match('/^ID=(.+)$/m', $content, $matches)) {
            return trim($matches[1], '"\'');
        }
        return 'unknown';
    }

    /**
     * Fix log directory permissions for non-root PHP agent
     */
    private function fixLogPermissions(): void
    {
        if ($this->isWindows()) {
            return;
        }

        try {
            Process::run("chmod -R o+r {$this->logDir} 2>/dev/null");
            if (file_exists($this->alertLogPath)) {
                Process::run("chmod o+r {$this->alertLogPath} 2>/dev/null");
            }
        } catch (\Exception $e) {
            // Ignore
        }
    }

    private function isProcessRunning(int $pid): bool
    {
        if ($pid <= 0) {
            return false;
        }

        if ($this->isWindows()) {
            try {
                $result = Process::run("tasklist /FI \"PID eq {$pid}\" /NH 2>nul");
                return str_contains($result->output(), (string) $pid);
            } catch (\Exception $e) {
                return false;
            }
        }

        if (posix_kill($pid, 0)) {
            return true;
        }

        // EPERM is not "no such process". It is the kernel confirming the
        // process exists and declining to let us signal it, and it is the
        // ordinary case here rather than the exotic one: Suricata runs as
        // root while the agent's console runs unprivileged. Reading it as
        // absence reported a running sensor as down and told the operator to
        // start a second copy of it.
        return posix_get_last_error() === self::EPERM;
    }

    private function isSuricataProcessActive(): bool
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run('tasklist /FI "IMAGENAME eq suricata.exe" /NH 2>nul');
                return str_contains($result->output(), 'suricata.exe');
            }

            // `pgrep -x suricata` fails under systemd-packaged Suricata because
            // the main thread's comm name is "Suricata-Main". Use -f with a
            // regex anchored on the binary path so we match both shapes
            // (`/usr/bin/suricata ...` and `/opt/homebrew/bin/suricata ...`)
            // without catching grep / editor windows containing the word.
            //
            // The trailing boundary is a POSIX class rather than `\b`, which
            // is a GNU extension: BSD regex does not know it, so on macOS the
            // pattern matched nothing at all and this fallback — the one that
            // covers the case where the pid file cannot be trusted — silently
            // never fired. `suricata-update` stays excluded either way.
            $pattern = '(^|/)suricata(-Main)?([[:space:]]|$)';
            $result = Process::run('pgrep -f ' . escapeshellarg($pattern) . ' 2>/dev/null');
            return !empty(trim($result->output()));
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Limit rules files on Windows to prevent Cygwin TP_NUM_C_BUFS crash.
     * The Cygwin runtime used by Suricata on Windows cannot handle thousands of rules.
     */
    private function limitRulesForWindows(int $maxRules = 500): void
    {
        if (!is_dir($this->rulesDir)) {
            return;
        }

        $rulesFiles = glob($this->rulesDir . DIRECTORY_SEPARATOR . '*.rules');
        foreach ($rulesFiles as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", trim($content));
            $ruleCount = count(array_filter($lines, fn($l) => !empty(trim($l)) && !str_starts_with(trim($l), '#')));

            if ($ruleCount > $maxRules) {
                // Keep only active rules up to the limit
                $kept = [];
                foreach ($lines as $line) {
                    if (empty(trim($line)) || str_starts_with(trim($line), '#')) {
                        $kept[] = $line; // Keep comments/blanks
                        continue;
                    }
                    if (count(array_filter($kept, fn($l) => !empty(trim($l)) && !str_starts_with(trim($l), '#'))) < $maxRules) {
                        $kept[] = $line;
                    }
                }
                file_put_contents($file, implode("\n", $kept) . "\n");
                Log::info("Windows: Trimmed {$file} from {$ruleCount} to {$maxRules} rules (Cygwin TLS limit)");

                // Clear hash to force re-sync with the limited set
                $hashFile = storage_path('app/suricata_rules_hash.txt');
                if (file_exists($hashFile)) {
                    @unlink($hashFile);
                }
            }
        }
    }

    /**
     * Fix the Cygwin DLL in the Suricata Windows installation.
     *
     * The OISF Suricata Windows MSI bundles an old cygwin1.dll with TP_NUM_C_BUFS=10.
     * This method downloads a newer cygwin1.dll from official Cygwin mirrors and replaces
     * the bundled one, fixing the fatal startup crash.
     */
    public function fixCygwinDll(): bool
    {
        if (!$this->isWindows()) {
            return false;
        }

        // Find the Suricata installation directory
        $suricataDir = dirname($this->suricataPath);
        if (!is_dir($suricataDir)) {
            Log::error('[Suricata] Cannot find Suricata directory: ' . $suricataDir);
            return false;
        }

        $cygwinDll = $suricataDir . '\\cygwin1.dll';
        $fixedMarker = storage_path('app/suricata_cygwin_fixed.txt');

        // Skip if already fixed
        if (file_exists($fixedMarker)) {
            Log::info('[Suricata] Cygwin DLL was already fixed previously');
            return true;
        }

        Log::info("[Suricata] Attempting to fix cygwin1.dll in: {$suricataDir}");

        try {
            $tempDir = sys_get_temp_dir() . '\\suricata_cygwin_fix';
            if (!is_dir($tempDir)) {
                mkdir($tempDir, 0755, true);
            }

            // Use PowerShell to download the Cygwin setup and install just the runtime DLL
            // Strategy: Download setup-x86_64.exe and use it in quiet mode to install cygwin to a temp dir,
            // then copy the cygwin1.dll from there.
            $psScript = <<<'POWERSHELL'
$ErrorActionPreference = 'Stop'
$tempDir = 'TEMP_DIR_PLACEHOLDER'
$setupExe = "$tempDir\setup-x86_64.exe"
$cygwinInstallDir = "$tempDir\cygwin64"

# Download Cygwin setup if not present
if (-not (Test-Path $setupExe)) {
    Write-Host "Downloading Cygwin setup..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri 'https://www.cygwin.com/setup-x86_64.exe' -OutFile $setupExe -UseBasicParsing
}

# Install just the base package (includes cygwin1.dll) to temp directory
Write-Host "Installing Cygwin base package to temp directory..."
$setupArgs = @(
    '--quiet-mode',
    '--no-admin',
    '--root', $cygwinInstallDir,
    '--local-package-dir', "$tempDir\packages",
    '--site', 'https://mirrors.kernel.org/sourceware/cygwin/',
    '--packages', 'cygwin',
    '--no-shortcuts',
    '--no-desktop',
    '--no-startmenu'
)
$proc = Start-Process -FilePath $setupExe -ArgumentList $setupArgs -Wait -PassThru -NoNewWindow

if (Test-Path "$cygwinInstallDir\bin\cygwin1.dll") {
    Write-Host "SUCCESS: cygwin1.dll found at $cygwinInstallDir\bin\cygwin1.dll"
    exit 0
} else {
    Write-Host "ERROR: cygwin1.dll not found after install"
    exit 1
}
POWERSHELL;

            $psScript = str_replace('TEMP_DIR_PLACEHOLDER', $tempDir, $psScript);
            $scriptPath = $tempDir . '\\fix_cygwin.ps1';
            file_put_contents($scriptPath, $psScript);

            Log::info('[Suricata] Running Cygwin download and install script...');
            $result = Process::timeout(300)->run("powershell -ExecutionPolicy Bypass -File \"{$scriptPath}\" 2>&1");
            Log::info('[Suricata] Cygwin setup output: ' . substr($result->output(), -1000));

            $newDll = $tempDir . '\\cygwin64\\bin\\cygwin1.dll';
            if (!file_exists($newDll)) {
                Log::error('[Suricata] New cygwin1.dll not found after download');
                return false;
            }

            // Backup old DLL
            if (file_exists($cygwinDll)) {
                $backupPath = $cygwinDll . '.bak.' . date('Ymd_His');
                @copy($cygwinDll, $backupPath);
                Log::info("[Suricata] Backed up old cygwin1.dll to: {$backupPath}");
            }

            // Copy new DLL (need to kill any suricata process first)
            Process::run('taskkill /F /IM suricata.exe 2>nul');
            sleep(1);

            if (@copy($newDll, $cygwinDll)) {
                Log::info('[Suricata] Successfully replaced cygwin1.dll');
                file_put_contents($fixedMarker, date('Y-m-d H:i:s') . "\n");
                return true;
            }

            Log::error('[Suricata] Failed to copy new cygwin1.dll');
            return false;

        } catch (\Exception $e) {
            Log::error('[Suricata] fixCygwinDll failed: ' . $e->getMessage());
            return false;
        }
    }

    // ─── NFQUEUE netfilter management (Linux IPS inline) ──────────────
    //
    // Suricata inline blocking on Linux requires packets to be delivered to
    // its NFQUEUE socket. That only happens if iptables has a rule like
    //   -j NFQUEUE --queue-num 0
    // without such a rule, packets flow straight through the kernel and
    // Suricata sees nothing — it can only log alerts from passive reads.
    //
    // We add --queue-bypass so that if Suricata dies or is stopped, the
    // kernel treats the queue as absent and ACCEPTs packets instead of
    // dropping them. This pairs with `fail-open: yes` in suricata.yaml
    // which covers the case where Suricata is alive but overloaded.
    //
    // Rules are tagged with a comment so future starts/stops can identify
    // and clean up only the rules this engine owns, leaving any admin-added
    // NFQUEUE rules alone.

    private const NFQ_COMMENT = 'security-one-ids IPS';
    private const BYPASS_COMMENT = 'security-one-ids bypass';

    /**
     * Narrow the inspection surface to what the WAF actually protects
     * (HTTP/HTTPS). A previous catch-all NFQUEUE on every inbound packet
     * saturated the single RX-NFQ thread during rule-reload windows and
     * killed the host network. Restricting to WAF ports keeps queue
     * pressure manageable.
     */
    private const INSPECT_PORTS = [80, 443];

    private function applyInlineNetfilter(string $mode): void
    {
        if ($mode !== 'ips' || $this->isWindows() || PHP_OS === 'Darwin') {
            return;
        }

        $this->installBypassRules();

        // `--queue-balance 0:3` hashes packets across 4 NFQUEUE queues so
        // Suricata's 4 RX-NFQ threads share the load (Suricata is started
        // with `-q 0:3`). A single queue was the previous outage's root
        // cause: one RX thread couldn't drain the queue during rule
        // reloads and the kernel started dropping.
        $target = 'NFQUEUE --queue-balance 0:3 --queue-bypass';
        $comment = "-m comment --comment " . escapeshellarg(self::NFQ_COMMENT);

        // INPUT: only WAF-protected ports. All other inbound (SSH, DNS
        // replies, conntrack ESTABLISHED replies) is left to the bypass
        // rules installed by installBypassRules().
        //
        // CRITICAL: the NFQUEUE rules MUST sit BEFORE the conntrack
        // ESTABLISHED,RELATED bypass. installBypassRules() inserts the
        // conntrack rule at position 1, so a plain `-A INPUT` here would
        // land the NFQUEUE rule AFTER it, and every packet in an already-
        // established HTTP flow (including the PSH+ACK carrying the
        // request payload) would be bypassed before reaching inspection.
        // Suricata would then only see empty-payload handshake packets
        // and nothing content: match would ever fire.
        $insertPos = $this->findConntrackBypassLineNo('INPUT');
        foreach (self::INSPECT_PORTS as $port) {
            $spec = "-p tcp --dport {$port} -j {$target} {$comment}";
            $check = Process::run("iptables -C INPUT {$spec} 2>/dev/null");
            if ($check->successful()) {
                continue;
            }
            $cmd = $insertPos !== null
                ? "iptables -I INPUT {$insertPos} {$spec} 2>&1"
                : "iptables -A INPUT {$spec} 2>&1";
            $add = Process::run($cmd);
            if ($add->successful()) {
                Log::info("[Suricata] Added NFQUEUE rule to INPUT :{$port}" . ($insertPos !== null ? " at line {$insertPos}" : ""));
                // Each insert before the conntrack rule shifts it down by
                // one; next port needs to insert at the same effective
                // position (which is now the original + N inserted).
                if ($insertPos !== null) {
                    $insertPos++;
                }
            } else {
                Log::warning("[Suricata] Failed to add NFQUEUE rule for :{$port}: " . trim($add->output() . $add->errorOutput()));
            }
        }

        // FORWARD: catch-all after DOCKER-USER/DOCKER-FORWARD terminate
        // legit container traffic. This inspects routed traffic only —
        // container-to-container goes through the bridge and never hits
        // iptables unless br_netfilter is loaded.
        $forwardSpec = "-j {$target} {$comment}";
        $check = Process::run("iptables -C FORWARD {$forwardSpec} 2>/dev/null");
        if (!$check->successful()) {
            $add = Process::run("iptables -A FORWARD {$forwardSpec} 2>&1");
            if ($add->successful()) {
                Log::info("[Suricata] Added NFQUEUE rule to FORWARD");
            } else {
                Log::warning("[Suricata] Failed to add FORWARD NFQUEUE: " . trim($add->output() . $add->errorOutput()));
            }
        }
    }

    private function removeInlineNetfilter(): void
    {
        if ($this->isWindows() || PHP_OS === 'Darwin') {
            return;
        }

        // Delete by matching the security-one-ids IPS comment rather than
        // a specific rule spec, since the spec varies (per-port on INPUT,
        // catch-all on FORWARD, and older versions used --queue-num 0).
        foreach (['INPUT', 'FORWARD'] as $chain) {
            for ($i = 0; $i < 10; $i++) {
                $result = Process::run("iptables -L {$chain} -n --line-numbers 2>/dev/null");
                $lines = explode("\n", $result->output());
                $targetLine = null;
                foreach ($lines as $line) {
                    if (preg_match('/^(\d+)\s+NFQUEUE\b.*security-one-ids IPS/', $line, $m)) {
                        $targetLine = (int) $m[1];
                        break;
                    }
                }
                if ($targetLine === null) {
                    break;
                }
                $del = Process::run("iptables -D {$chain} {$targetLine} 2>/dev/null");
                if (!$del->successful()) {
                    break;
                }
                Log::info("[Suricata] Removed NFQUEUE rule from iptables {$chain} (line {$targetLine})");
            }
        }

        // Bypass rules are left in place on stop. Leaving loopback /
        // ESTABLISHED / docker ACCEPTs installed is harmless when no
        // NFQUEUE rule exists, and ensures the admin SSH session doesn't
        // flap if Suricata is restarted.
    }

    private function installBypassRules(): void
    {
        $rules = [
            // Loopback — never inspect localhost (breaks language_server,
            // docker-proxy, unix-socket-over-TCP IPC).
            '-i lo',
            // Reply packets for any already-established outbound connection
            // (Hub heartbeat, Claude API calls, apt update, etc.) plus
            // ongoing inbound sessions (current SSH). Without this, the
            // moment IPS flips, every reply packet for already-open
            // connections gets inspected and potentially dropped.
            '-m conntrack --ctstate ESTABLISHED,RELATED',
            // SSH — the admin management plane. If IPS drops this we lose
            // the ability to recover the box remotely, so it is a hard
            // fail-safe carve-out. Brute-force protection belongs in
            // fail2ban/sshd_config, not inline NFQUEUE.
            '-p tcp --dport 22',
            // DNS — an authoritative PowerDNS runs on this host. Delaying
            // UDP/53 via NFQUEUE causes client-side resolver timeouts long
            // before any signature match completes, which cascades into
            // every service that does a DNS lookup.
            '-p udp --dport 53',
            '-p tcp --dport 53',
        ];

        // Docker bridge interfaces — container-to-host traffic is trusted
        // by definition (our own services calling us). External traffic
        // to containers via port-publish goes through FORWARD+DOCKER-*
        // chains which terminally ACCEPT before reaching our NFQUEUE rule.
        if (is_dir('/sys/class/net/docker0')) {
            $rules[] = '-i docker0';
        }
        // `br+` is an iptables wildcard matching any interface starting
        // with `br`, which is Docker's naming convention for user-defined
        // bridges (`br-xxxxxxxxxxxx`).
        $brGlob = glob('/sys/class/net/br-*');
        if (!empty($brGlob)) {
            $rules[] = '-i br+';
        }

        foreach ($rules as $match) {
            $commentArg = "-m comment --comment " . escapeshellarg(self::BYPASS_COMMENT);
            $check = Process::run("iptables -C INPUT {$match} -j ACCEPT {$commentArg} 2>/dev/null");
            if ($check->successful()) {
                continue;
            }
            // -I 1 so bypass rules always sit above our NFQUEUE rule at
            // the bottom. Order among bypass rules doesn't matter — they
            // all terminally ACCEPT.
            $add = Process::run("iptables -I INPUT 1 {$match} -j ACCEPT {$commentArg} 2>&1");
            if ($add->successful()) {
                Log::info("[Suricata] Installed iptables bypass: INPUT {$match}");
            } else {
                Log::warning("[Suricata] Failed to install bypass rule '{$match}': " . trim($add->output() . $add->errorOutput()));
            }
        }
    }

    /**
     * Locate the line number of our conntrack ESTABLISHED,RELATED bypass
     * rule in the given chain so applyInlineNetfilter() can insert the
     * WAF-port NFQUEUE rules *above* it. Returns null if no such rule
     * exists yet — the caller then falls back to `-A` (append).
     */
    private function findConntrackBypassLineNo(string $chain): ?int
    {
        $result = Process::run("iptables -L {$chain} -n --line-numbers 2>/dev/null");
        if (!$result->successful()) {
            return null;
        }
        foreach (explode("\n", $result->output()) as $line) {
            if (preg_match('/^(\d+)\s+ACCEPT\b.*ctstate\s+RELATED,ESTABLISHED.*security-one-ids bypass/', $line, $m)) {
                return (int) $m[1];
            }
        }
        return null;
    }

    /**
     * Ensure the `nfq:` block has `fail-open: yes` and `mode: accept`.
     * Distro packages ship these commented, so a fresh install flips
     * IPS and then has the kernel drop packets the moment Suricata
     * can't keep up — looks exactly like the host network dying.
     */
    private function healNfqConfig(): void
    {
        if ($this->isWindows() || PHP_OS === 'Darwin') {
            return;
        }
        $content = @file_get_contents($this->configPath);
        if ($content === false) {
            return;
        }
        if (!preg_match('/^(nfq:\s*\n)((?:(?:[ \t]+.*|#.*)\n)*)/m', $content, $m, PREG_OFFSET_CAPTURE)) {
            return;
        }
        $blockStart = $m[0][1];
        $blockText = $m[0][0];
        $updated = $blockText;

        $required = ['fail-open' => 'yes', 'mode' => 'accept'];
        foreach ($required as $key => $value) {
            if (preg_match('/^[ \t]+' . preg_quote($key, '/') . ':/m', $updated)) {
                continue;
            }
            $uncommented = preg_replace(
                '/^#([ \t]*' . preg_quote($key, '/') . ':[ \t]*' . preg_quote($value, '/') . '[ \t]*)$/m',
                '$1',
                $updated,
                1,
                $count
            );
            if ($count > 0) {
                $updated = $uncommented;
                continue;
            }
            $updated = preg_replace('/^nfq:\s*\n/', "nfq:\n  {$key}: {$value}\n", $updated, 1);
        }

        if ($updated === $blockText) {
            return;
        }
        $backup = $this->configPath . '.bak.' . date('Ymd-His');
        @copy($this->configPath, $backup);
        $newContent = substr_replace($content, $updated, $blockStart, strlen($blockText));
        if (@file_put_contents($this->configPath, $newContent) === false) {
            Log::warning('[Suricata] Could not write healed nfq config (permission?)', ['path' => $this->configPath]);
            return;
        }
        Log::warning('[Suricata] Healed nfq config (fail-open/mode) in ' . $this->configPath, ['backup' => $backup]);
    }

    /**
     * Ensure `custom.rules` is listed under `rule-files:` in suricata.yaml.
     * Without this, applyCustomRules() writes Hub rules to disk but
     * Suricata never parses them — every sync is a silent no-op.
     */
    private function healCustomRulesInclude(): void
    {
        $content = @file_get_contents($this->configPath);
        if ($content === false) {
            return;
        }
        if (!preg_match('/^(rule-files:\s*\n)((?:[ \t]+-[ \t].*\n)*)/m', $content, $m, PREG_OFFSET_CAPTURE)) {
            Log::debug('[Suricata] No rule-files: block in suricata.yaml, skipping custom.rules heal');
            return;
        }
        $blockStart = $m[0][1];
        $blockText = $m[0][0];
        if (preg_match('/^\s*-\s+["\']?(?:[^"\'\n]*\/)?custom\.rules["\']?\s*$/m', $blockText)) {
            return;
        }
        $indent = '  ';
        if (preg_match_all('/^([ \t]+)-/m', $blockText, $mm) && !empty($mm[1])) {
            $indent = end($mm[1]);
        }
        $newBlock = $blockText . "{$indent}- custom.rules\n";
        $backup = $this->configPath . '.bak.' . date('Ymd-His');
        @copy($this->configPath, $backup);
        $newContent = substr_replace($content, $newBlock, $blockStart, strlen($blockText));
        if (@file_put_contents($this->configPath, $newContent) === false) {
            Log::warning('[Suricata] Could not write healed rule-files config (permission?)', ['path' => $this->configPath]);
            return;
        }
        Log::warning('[Suricata] Added custom.rules to rule-files in ' . $this->configPath, ['backup' => $backup]);
    }
}

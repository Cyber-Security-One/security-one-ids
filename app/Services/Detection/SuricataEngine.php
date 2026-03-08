<?php

namespace App\Services\Detection;

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
    use \App\Traits\DetectsPlatform;

    private string $suricataPath;
    private string $configPath;
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
     * Check if Suricata process is currently running
     */
    public function isRunning(): bool
    {
        // Check PID file first
        if (file_exists($this->pidFile)) {
            $pid = trim(file_get_contents($this->pidFile));
            if ($this->isProcessRunning((int) $pid)) {
                return true;
            }
        }

        // Fallback: check process list
        return $this->isSuricataProcessActive();
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
            return ['success' => true, 'message' => 'Suricata is already running'];
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
        }
    }

    /**
     * Stop Suricata process
     */
    public function stop(): array
    {
        if (!$this->isRunning()) {
            return ['success' => true, 'message' => 'Suricata is not running'];
        }

        try {
            if (file_exists($this->pidFile)) {
                $pid = trim(file_get_contents($this->pidFile));
                if ($this->isWindows()) {
                    Process::run("taskkill /PID {$pid} /F 2>nul");
                } else {
                    Process::run("kill {$pid} 2>/dev/null");
                    sleep(1);
                    if ($this->isProcessRunning((int) $pid)) {
                        Process::run("kill -9 {$pid} 2>/dev/null");
                    }
                }
                @unlink($this->pidFile);
            } else {
                if ($this->isWindows()) {
                    Process::run("taskkill /IM suricata.exe /F 2>nul");
                } else {
                    Process::run("pkill -f suricata 2>/dev/null");
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

        $suricataMode = 'ids';
        $settingsPath = storage_path('app/hub_config.json');
        if (file_exists($settingsPath)) {
            try {
                $config = json_decode(file_get_contents($settingsPath), true);
                $suricataMode = $config['addons']['suricata_mode'] ?? 'ids';
            } catch (\Exception $e) {
                // ignore
            }
        }

        return [
            'installed' => $installed,
            'version' => $installed ? $this->getVersion() : null,
            'running' => $installed ? $this->isRunning() : false,
            'path' => $this->suricataPath,
            'config_path' => $this->configPath,
            'log_dir' => $this->logDir,
            'suricata_mode' => $suricataMode,
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
            // Read last N lines (eve.json can be large)
            $result = Process::run("tail -n " . ($limit * 2) . " " . escapeshellarg($logPath));
            $lines = explode("\n", trim($result->output()));

            foreach (array_reverse($lines) as $line) {
                if (empty($line)) {
                    continue;
                }

                $entry = @json_decode($line, true);
                if (!$entry || ($entry['event_type'] ?? '') !== 'alert') {
                    continue;
                }

                $alert = $entry['alert'] ?? [];
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
            $cmd .= " -i {$interface}";

            if ($mode === 'ips' && PHP_OS !== 'Darwin') {
                // IPS inline on Linux via nfqueue
                $cmd .= " --af-packet -q 0";
            } else {
                // IDS passive via af-packet (Linux) or pcap (macOS)
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
        $paths = $this->isWindows()
            ? ['C:\\Suricata\\rules', 'C:\\Program Files\\Suricata\\rules']
            : ['/etc/suricata/rules', '/var/lib/suricata/rules', '/usr/local/etc/suricata/rules'];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                return $path;
            }
        }

        return $this->isWindows() ? 'C:\\Suricata\\rules' : '/etc/suricata/rules';
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
    private function countAlertsToday(): int
    {
        if (!file_exists($this->alertLogPath)) {
            return 0;
        }

        $today = date('Y-m-d');

        try {
            // Use grep for performance
            // Note: Suricata eve.json may use either compact or spaced JSON format
            // e.g., "event_type":"alert" or "event_type": "alert"
            $result = Process::timeout(10)->run(
                "grep -cE '\"event_type\"\\s*:\\s*\"alert\"' " . escapeshellarg($this->alertLogPath) . " 2>/dev/null"
            );
            $total = (int) trim($result->output());

            // For a more accurate today count, filter by date
            $result = Process::timeout(10)->run(
                "grep -E '\"event_type\"\\s*:\\s*\"alert\"' " . escapeshellarg($this->alertLogPath) .
                " | grep -c '\"timestamp\".*" . $today . "' 2>/dev/null"
            );
            $count = (int) trim($result->output());

            return $count > 0 ? $count : $total;
        } catch (\Exception $e) {
            return 0;
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

        return posix_kill($pid, 0);
    }

    private function isSuricataProcessActive(): bool
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run('tasklist /FI "IMAGENAME eq suricata.exe" /NH 2>nul');
                return str_contains($result->output(), 'suricata.exe');
            }

            $result = Process::run("pgrep -f suricata 2>/dev/null");
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
}

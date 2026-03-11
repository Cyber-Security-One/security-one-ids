<?php

namespace App\Services\Detection;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Snort 3 IPS Detection Engine
 *
 * Manages Snort 3 process lifecycle, parses alerts, and provides status information.
 * Supports IDS (passive) and IPS (inline) modes across Linux, macOS, and Windows.
 */
class SnortEngine
{
    private string $snortPath;
    private string $configPath;
    private string $alertLogPath;
    private string $pidFile;
    private string $logDir;

    public function __construct()
    {
        $this->snortPath = $this->detectSnortPath();
        $this->configPath = $this->detectConfigPath();
        $this->logDir = $this->detectLogDir();
        $this->alertLogPath = $this->logDir . '/alert_json.txt';
        $this->pidFile = $this->logDir . '/snort.pid';
    }

    /**
     * Check if Snort is installed on this system
     */
    public function isInstalled(): bool
    {
        return !empty($this->snortPath) && file_exists($this->snortPath);
    }

    /**
     * Get the Snort binary path
     */
    public function getSnortPath(): string
    {
        return $this->snortPath;
    }

    /**
     * Get the alert log file path (auto-detects Snort 2 vs Snort 3)
     */
    public function getAlertLogPath(): string
    {
        // Snort 3: alert_json.txt
        if (file_exists($this->alertLogPath)) {
            return $this->alertLogPath;
        }

        // Snort 2: check multiple possible filenames
        $snort2Paths = [
            $this->logDir . '/alert',           // Default -A fast output
            $this->logDir . '/alert.ids',       // Alternative filename
            $this->logDir . '/snort.alert.fast', // Named fast output
        ];
        foreach ($snort2Paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        return $this->alertLogPath;
    }

    /**
     * Get installed Snort version
     */
    public function getVersion(): ?string
    {
        if (!$this->isInstalled()) {
            return null;
        }

        try {
            $result = Process::run("{$this->snortPath} -V 2>&1");
            $output = $result->output() . $result->errorOutput();

            // Snort 3 outputs: ",,_ -*> Snort++ <*- ... Version 3.x.x.x"
            if (preg_match('/Version\s+([\d.]+)/i', $output, $matches)) {
                return $matches[1];
            }

            // Snort 2 fallback
            if (preg_match('/Snort\s+([\d.]+)/i', $output, $matches)) {
                return $matches[1];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to get Snort version: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Check if Snort process is currently running
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
        return $this->isSnortProcessActive();
    }

    /**
     * Start Snort in the specified mode
     *
     * @param string $mode 'ids' or 'ips'
     * @param string|null $interface Network interface to monitor
     */
    public function start(string $mode = 'ids', ?string $interface = null): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Snort is not installed'];
        }

        if ($this->isRunning()) {
            // One-time fix: if Snort 3 is running but alert_json.txt doesn't exist,
            // it's using old config without file=true. Restart to pick up --lua flag.
            $restartMarker = storage_path('app/snort_alert_restart_done.txt');
            if (!$this->isSnort2()
                && !file_exists($this->alertLogPath)
                && !file_exists($restartMarker)
            ) {
                Log::info('Snort running without alert file output, restarting with --lua alert_json config');
                file_put_contents($restartMarker, date('c'));
                $this->stop();
                sleep(2);
                // Fall through to start with new --lua config
            } else {
                return ['success' => true, 'message' => 'Snort is already running'];
            }
        }

        $interface = $interface ?? $this->detectDefaultInterface();

        // On Windows, if no valid interface was found (Npcap missing), don't attempt start
        if ($this->isWindows() && $interface === '1') {
            // Ensure Npcap DLLs are findable (PATH may not be updated in this process)
            $npcapDir = 'C:\\Windows\\System32\\Npcap';
            if (is_dir($npcapDir) && !str_contains(getenv('PATH') ?: '', 'Npcap')) {
                putenv('PATH=' . getenv('PATH') . ';' . $npcapDir);
            }
            // Verify interface 1 actually exists
            try {
                $result = Process::timeout(10)->run('"' . $this->snortPath . '" -W 2>&1');
                $output = $result->output();
                Log::debug('snort -W verify in start()', [
                    'output_length' => strlen($output),
                    'output_preview' => substr($output, 0, 500),
                ]);
                if (!preg_match('/\d+\s+\S+\s+\d+\.\d+\.\d+\.\d+/', $output)) {
                    // Try starting Npcap services before giving up
                    Log::info('No interfaces found, attempting to start Npcap services...');
                    Process::timeout(10)->run('net start npcap 2>&1');
                    Process::timeout(10)->run('net start npf 2>&1');
                    sleep(2);

                    // Re-check interfaces after service start
                    $retryResult = Process::timeout(10)->run('"' . $this->snortPath . '" -W 2>&1');
                    $retryOutput = $retryResult->output();
                    Log::debug('snort -W retry after service start', [
                        'output_preview' => substr($retryOutput, 0, 500),
                    ]);

                    if (preg_match('/\d+\s+\S+\s+\d+\.\d+\.\d+\.\d+/', $retryOutput)) {
                        Log::info('Npcap services started successfully, interfaces now available');
                        // Re-detect interface now that Npcap is running
                        $this->cachedInterface = null;
                        $interface = $this->detectDefaultInterface();
                        Log::info('Re-detected interface after Npcap start', ['interface' => $interface]);
                    } else {
                        // Invalidate Npcap cache so ensureNpcapInstalled() retries
                        @unlink(storage_path('app/pcap_ok_v3.txt'));
                        @unlink(storage_path('app/npcap_attempt_v2.txt'));
                        return [
                            'success' => false,
                            'error' => 'No network interfaces found. Please install Npcap from https://npcap.com and restart the system.',
                            'snort_w_output' => substr($retryOutput, 0, 500),
                        ];
                    }
                }
            } catch (\Exception $e) {
                // Continue with attempt
            }
        }

        // Ensure log directory exists
        if (!is_dir($this->logDir)) {
            @mkdir($this->logDir, 0755, true);
        }

        // Ensure a valid config file exists (generate default if missing)
        $this->ensureSnortConfig();

        // Build the Snort command (auto-detects Snort 2 vs 3)
        $cmd = $this->buildStartCommand($mode, $interface);

        try {
            Log::info("Starting Snort in {$mode} mode on interface {$interface}", [
                'platform' => PHP_OS_FAMILY,
                'snort_path' => $this->snortPath,
                'config_path' => $this->configPath,
                'command' => $cmd,
            ]);

            if ($this->isWindows()) {
                // Windows: Snort 2.9 doesn't have -D daemon mode
                // Use Start-Process to launch Snort as a detached background process
                $logFile = $this->logDir . '\\snort_stdout.log';
                $errFile = $this->logDir . '\\snort_stderr.log';
                $pidFile = $this->logDir . '\\snort.pid';
                $psCommand = "\$proc = Start-Process -FilePath '{$this->snortPath}' " .
                    "-ArgumentList '" . str_replace($this->snortPath . ' ', '', $cmd) . "' " .
                    "-WindowStyle Hidden -PassThru " .
                    "-RedirectStandardOutput '{$logFile}' " .
                    "-RedirectStandardError '{$errFile}'; " .
                    "\$proc.Id | Set-Content '{$pidFile}'";
                $result = Process::timeout(15)->run("powershell -NonInteractive -Command \"{$psCommand}\"");
            } else {
                // Linux/macOS: Snort -D (daemon mode) forks and detaches itself
                // No need for nohup (causes errors when no TTY, e.g. launchd)
                $stderrFile = sys_get_temp_dir() . '/snort_start_stderr_' . uniqid() . '.log';
                $result = Process::timeout(15)->run("{$cmd} 2>{$stderrFile}");
                // Snort -D forks: parent exits immediately, daemon PID is in --pid-path/snort.pid
            }

            // Wait for Snort daemon to fork and write its PID file
            sleep(3);

            // For daemon mode (-D), check the Snort-written PID file first
            // because the shell PID (from echo $!) is the parent that already exited
            $snortPidFile = $this->logDir . '/snort.pid';
            if (!$this->isWindows() && file_exists($snortPidFile)) {
                $daemonPid = trim(file_get_contents($snortPidFile));
                if (is_numeric($daemonPid)) {
                    // Verify the daemon process exists
                    $checkResult = Process::run("kill -0 {$daemonPid} 2>/dev/null && echo running");
                    if (str_contains($checkResult->output(), 'running')) {
                        // Update our PID file with the real daemon PID
                        file_put_contents($this->pidFile, $daemonPid);
                        // Fix log dir permissions so non-root PHP agent can read alerts
                        $this->fixLogPermissions();
                        Log::info('Snort daemon started successfully', [
                            'platform' => PHP_OS_FAMILY,
                            'daemon_pid' => $daemonPid,
                        ]);
                        @unlink($stderrFile ?? '');
                        return ['success' => true, 'message' => "Snort started in {$mode} mode"];
                    }
                }
            }

            // Fallback: check process list
            if ($this->isRunning()) {
                $this->fixLogPermissions();
                Log::info('Snort started successfully', ['platform' => PHP_OS_FAMILY]);
                @unlink($stderrFile ?? '');
                return ['success' => true, 'message' => "Snort started in {$mode} mode"];
            }

            // Start failed — capture error output for debugging
            $errorOutput = '';
            if ($this->isWindows()) {
                // Windows: read the stderr redirect file
                $winErrFile = $this->logDir . '\\snort_stderr.log';
                if (file_exists($winErrFile)) {
                    $errorOutput = file_get_contents($winErrFile);
                }
                $winOutFile = $this->logDir . '\\snort_stdout.log';
                if (empty($errorOutput) && file_exists($winOutFile)) {
                    $errorOutput = file_get_contents($winOutFile);
                }
            } elseif (isset($stderrFile) && file_exists($stderrFile)) {
                $errorOutput = file_get_contents($stderrFile);
                @unlink($stderrFile);
            }
            $stdOutput = $result->output() ?? '';
            Log::warning('Snort failed to start', [
                'platform' => PHP_OS_FAMILY,
                'exit_code' => $result->exitCode(),
                'stdout' => substr($stdOutput, 0, 500),
                'stderr_start' => substr($errorOutput, 0, 500),
                'stderr_end' => substr($errorOutput, -2000),
                'stderr_length' => strlen($errorOutput),
            ]);

            return ['success' => false, 'error' => 'Snort started but not running: ' . substr($errorOutput ?: $stdOutput, 0, 200)];
        } catch (\Exception $e) {
            Log::error('Failed to start Snort: ' . $e->getMessage(), [
                'platform' => PHP_OS_FAMILY,
            ]);
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Start Snort with automatic retry: if startup fails due to a rule error,
     * proactively find ALL rules with the same error pattern and comment them out.
     *
     * Snort only reports ONE error per run then quits. So instead of fixing
     * just the reported line, we analyze the error type and fix ALL similar
     * rules in one pass. This turns 50+ retries into 2-3 retries.
     *
     * Error types handled:
     *  - Unknown ClassType: X → comment out ALL rules with classtype:X
     *  - dce_iface invalid uuid → comment out ALL rules with dce_iface
     *  - !any is not allowed: !$VAR → comment out ALL rules referencing $VAR
     *  - Other errors → comment out just the reported line
     */
    public function startWithRetry(string $mode = 'ids', ?string $interface = null, int $maxRetries = 10): array
    {
        $rulesFile = $this->getDetectedRulesDir() . '/hub_custom.rules';
        $totalDisabled = 0;

        for ($attempt = 1; $attempt <= $maxRetries + 1; $attempt++) {
            $result = $this->start($mode, $interface);

            if ($result['success']) {
                if ($attempt > 1) {
                    Log::info("Snort started successfully after {$attempt} attempts", [
                        'total_disabled' => $totalDisabled,
                    ]);
                }
                return $result;
            }

            // Don't retry if rules file doesn't exist or max retries reached
            if ($attempt > $maxRetries || !file_exists($rulesFile)) {
                return $result;
            }

            // Read FULL stderr from the log file
            $stderrContent = '';
            if ($this->isWindows()) {
                $stderrFile = $this->logDir . '\\snort_stderr.log';
                if (file_exists($stderrFile)) {
                    $stderrContent = file_get_contents($stderrFile);
                }
            } else {
                $tmpDir = sys_get_temp_dir();
                $stderrFiles = glob($tmpDir . '/snort_start_stderr_*.log');
                if (!empty($stderrFiles)) {
                    usort($stderrFiles, fn($a, $b) => filemtime($b) - filemtime($a));
                    $stderrContent = file_get_contents($stderrFiles[0]);
                }
            }

            // Only match ERROR: lines (not WARNING:)
            if (!preg_match('/ERROR:.*?hub_custom\.rules\((\d+)\)[:\s]+(.+?)(?:\r?\n|$)/i', $stderrContent, $match)) {
                Log::warning('Snort startWithRetry: could not parse error from stderr', [
                    'attempt' => $attempt,
                    'stderr_length' => strlen($stderrContent),
                    'stderr_tail' => substr($stderrContent, -500),
                ]);
                return $result;
            }

            $errorLine = (int) $match[1];
            $errorMsg = trim($match[2]);

            // Proactively find ALL rules with the same error pattern
            $lines = file($rulesFile, FILE_IGNORE_NEW_LINES);
            $disabledCount = 0;
            $pattern = $this->buildProactivePattern($errorMsg);

            if ($pattern) {
                // Comment out ALL matching rules (not just the one Snort reported)
                foreach ($lines as $idx => &$line) {
                    if (!str_starts_with($line, '#') && preg_match($pattern, $line)) {
                        $line = '# [auto-disabled] ' . $line;
                        $disabledCount++;
                    }
                }
                unset($line);
            } else {
                // Unknown error type — just comment out the specific line
                $idx = $errorLine - 1;
                if (isset($lines[$idx]) && !str_starts_with($lines[$idx], '# [auto-disabled]')) {
                    $lines[$idx] = '# [auto-disabled] ' . $lines[$idx];
                    $disabledCount = 1;
                }
            }

            $totalDisabled += $disabledCount;
            Log::info("Snort startup retry: disabled {$disabledCount} rules matching error pattern", [
                'attempt' => $attempt,
                'trigger_line' => $errorLine,
                'error' => $errorMsg,
                'pattern' => $pattern ?? 'single-line',
                'total_disabled' => $totalDisabled,
            ]);

            file_put_contents($rulesFile, implode("\n", $lines));
            continue;
        }

        return ['success' => false, 'error' => "Max retries exceeded (disabled {$totalDisabled} rules total)"];
    }

    /**
     * Build a regex pattern to find ALL rules with the same error as the one Snort reported.
     * Returns null if the error type is unknown (fallback to single-line disable).
     */
    private function buildProactivePattern(string $errorMsg): ?string
    {
        // "Unknown ClassType: kickass-porn" → match all rules with classtype:kickass-porn
        if (preg_match('/Unknown ClassType:\s*(\S+)/i', $errorMsg, $m)) {
            $classtype = preg_quote($m[1], '/');
            return '/classtype\s*:\s*' . $classtype . '/i';
        }

        // "dce_iface" rule option → match all rules with dce_iface
        if (str_contains($errorMsg, 'dce_iface')) {
            return '/\bdce_iface\b/';
        }

        // "dce_opnum" or "dce_stub_data" → match all rules with that keyword
        if (str_contains($errorMsg, 'dce_opnum')) {
            return '/\bdce_opnum\b/';
        }
        if (str_contains($errorMsg, 'dce_stub_data')) {
            return '/\bdce_stub_data\b/';
        }

        // "!any is not allowed: !$DNS_SERVERS" → match all rules referencing that variable
        if (preg_match('/!\$(\w+)/', $errorMsg, $m)) {
            $varName = preg_quote($m[1], '/');
            return '/\$' . $varName . '/';
        }

        // "Undefined variable name: $SHELLCODE_PORTS" → match all rules using that variable
        if (preg_match('/Undefined.*?\$(\w+)/i', $errorMsg, $m)) {
            $varName = preg_quote($m[1], '/');
            return '/\$' . $varName . '/';
        }

        return null; // Unknown error type, fall back to single-line
    }

    /**
     * Convert rule actions for IPS mode: alert → drop.
     *
     * In IDS mode, rules only generate alerts. In IPS mode, rules should
     * actively block traffic by using the 'drop' action.
     */
    public function applyIpsMode(string $rulesContent): string
    {
        $lines = explode("\n", $rulesContent);
        $converted = 0;

        foreach ($lines as &$line) {
            $trimmed = trim($line);
            // Skip comments and blank lines
            if (empty($trimmed) || $trimmed[0] === '#') {
                continue;
            }
            // Convert alert → drop (preserve other actions like pass, reject)
            if (preg_match('/^alert\s/', $trimmed)) {
                $line = preg_replace('/^alert\s/', 'drop ', $trimmed);
                $converted++;
            }
        }
        unset($line);

        if ($converted > 0) {
            Log::info("IPS mode: converted {$converted} alert rules to drop");
        }

        return implode("\n", $lines);
    }

    /**
     * Ensure a valid Snort config file exists.
     * If no config is found, generate a minimal working config.
     */
    private function ensureSnortConfig(): void
    {
        // Re-detect config path in case it was created after constructor
        $this->configPath = $this->detectConfigPath();

        // Clean up wrong config format from previous runs
        if ($this->isSnort2()) {
            // Snort 2 can't use .lua configs — remove if exists alongside .conf
            $wrongConfig = str_replace('.conf', '.lua', $this->configPath);
            if ($wrongConfig !== $this->configPath && file_exists($wrongConfig)) {
                @unlink($wrongConfig);
                Log::info('Removed incorrect snort.lua config (Snort 2.9 uses .conf)');
            }
        }

        if (file_exists($this->configPath)) {
            // For Snort 3: ensure alert_json output is enabled in existing config
            if (!$this->isSnort2() && str_ends_with($this->configPath, '.lua')) {
                $configContent = file_get_contents($this->configPath);
                $needsRewrite = false;

                // Fix: remove previously injected bad alert_json with fields string
                // (Snort 3 fields must be a Lua table, not a space-separated string)
                if (str_contains($configContent, "fields = 'timestamp")) {
                    $configContent = preg_replace(
                        '/\n?-- Added by Security One IDS[^\n]*\nalert_json\s*=\s*\{[^}]+\}\s*\n?/',
                        '',
                        $configContent
                    );
                    $needsRewrite = true;
                    Log::info('Removed bad alert_json config with fields string from snort.lua');
                }

                if (!str_contains($configContent, 'alert_json')) {
                    $alertJsonBlock = "\n-- Added by Security One IDS for alert file output\nalert_json = {\n  file = true,\n  limit = 100,\n}\n";
                    $configContent .= $alertJsonBlock;
                    $needsRewrite = true;
                    Log::info('Injected alert_json config into existing snort.lua', ['path' => $this->configPath]);
                }

                if ($needsRewrite) {
                    file_put_contents($this->configPath, $configContent);
                    // Restart Snort to pick up the new config
                    if ($this->isRunning()) {
                        $this->stop();
                    }
                }
            }

            // For Windows Snort 2: fix Linux paths in snort.conf
            if ($this->isWindows() && $this->isSnort2()) {
                $configContent = file_get_contents($this->configPath);
                $originalContent = $configContent;

                // Replace Linux dynamic library paths with Windows equivalents
                // Include both with and without trailing slashes
                $linuxToWindows = [
                    '/usr/local/lib/snort_dynamicpreprocessor/' => 'C:\\Snort\\lib\\snort_dynamicpreprocessor',
                    '/usr/local/lib/snort_dynamicpreprocessor' => 'C:\\Snort\\lib\\snort_dynamicpreprocessor',
                    '/usr/local/lib/snort_dynamicengine/' => 'C:\\Snort\\lib\\snort_dynamicengine',
                    '/usr/local/lib/snort_dynamicengine' => 'C:\\Snort\\lib\\snort_dynamicengine',
                    '/usr/local/lib/snort_dynamicrules/' => 'C:\\Snort\\lib\\snort_dynamicrules',
                    '/usr/local/lib/snort_dynamicrules' => 'C:\\Snort\\lib\\snort_dynamicrules',
                    '/usr/local/lib64/' => 'C:\\Snort\\lib\\',
                    '/usr/local/etc/snort/' => 'C:\\Snort\\etc\\',
                    '/etc/snort/' => 'C:\\Snort\\etc\\',
                ];
                foreach ($linuxToWindows as $linux => $windows) {
                    $configContent = str_replace($linux, $windows, $configContent);
                }

                // Comment out ANY dynamic* directive that references a non-existent path
                $configContent = preg_replace_callback(
                    '/^(dynamic(?:preprocessor|engine|detection)\s+(?:directory\s+)?(.+))$/m',
                    function ($m) {
                        $path = trim($m[2]);
                        if (!empty($path) && !is_dir($path) && !file_exists($path)) {
                            Log::debug("Commenting out missing dynamic path: {$path}");
                            return '# ' . $m[1] . ' # Commented by Security One IDS (not found)';
                        }
                        return $m[1];
                    },
                    $configContent
                );

                // Comment out include lines for missing rule files
                $configDir = dirname($this->configPath);
                $configContent = preg_replace_callback(
                    '/^(include\s+(.+))$/m',
                    function ($m) use ($configDir) {
                        $rulePath = trim($m[2]);
                        // Resolve relative paths against config directory
                        if (!preg_match('/^[A-Z]:\\\\/i', $rulePath) && $rulePath[0] !== '/') {
                            $fullPath = $configDir . '/' . $rulePath;
                        } else {
                            $fullPath = $rulePath;
                        }
                        // Normalize path separators
                        $fullPath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $fullPath);
                        if (!file_exists($fullPath)) {
                            return '# ' . $m[1] . ' # Commented by Security One IDS (file not found)';
                        }
                        return $m[1];
                    },
                    $configContent
                );

                // Create empty placeholder files for any referenced but missing files
                // (e.g., white_list.rules, black_list.rules for Reputation preprocessor)
                $rulesDir = $this->detectRulesDir();
                if (!is_dir($rulesDir)) {
                    @mkdir($rulesDir, 0755, true);
                }
                $placeholderFiles = [
                    'white_list.rules',
                    'black_list.rules',
                    'local.rules',
                    'hub_custom.rules',
                ];
                foreach ($placeholderFiles as $file) {
                    $filePath = $rulesDir . DIRECTORY_SEPARATOR . $file;
                    if (!file_exists($filePath)) {
                        file_put_contents($filePath, "# Auto-created by Security One IDS\n");
                        Log::debug("Created placeholder rule file: {$filePath}");
                    }
                }

                // Ensure snort.conf includes Hub rules and local rules
                // (original include lines may have been commented out due to missing files)
                $includeFiles = [
                    $rulesDir . DIRECTORY_SEPARATOR . 'hub_custom.rules',
                    $rulesDir . DIRECTORY_SEPARATOR . 'local.rules',
                ];
                foreach ($includeFiles as $includeFile) {
                    $normalizedInclude = str_replace('/', '\\', $includeFile);
                    // Check if this include already exists (active, not commented)
                    if (!str_contains($configContent, "include {$normalizedInclude}")
                        && !str_contains($configContent, "include {$includeFile}")) {
                        $configContent .= "\n# Security One IDS - Hub rules\ninclude {$normalizedInclude}\n";
                        Log::info("Added include for rules file in snort.conf: {$normalizedInclude}");
                    }
                }

                if ($configContent !== $originalContent) {
                    file_put_contents($this->configPath, $configContent);
                    Log::info('Fixed Windows snort.conf: commented out missing paths');
                    // Restart Snort to pick up the new config (includes, path fixes)
                    if ($this->isRunning()) {
                        Log::info('Restarting Snort to load updated snort.conf');
                        $this->stop();
                    }
                }
            }

            return;
        }

        try {
            $configDir = dirname($this->configPath);
            if (!is_dir($configDir)) {
                @mkdir($configDir, 0755, true);
            }

            if ($this->isSnort2()) {
                $this->generateSnort2Config();
            } else {
                $this->generateSnort3Config();
            }

            Log::info('Generated default Snort config', ['path' => $this->configPath]);
        } catch (\Exception $e) {
            Log::warning('Failed to generate Snort config: ' . $e->getMessage());
        }
    }

    /**
     * Generate a minimal Snort 2.9 config
     */
    private function generateSnort2Config(): void
    {
        $rulesDir = $this->detectRulesDir();
        $config = <<<CONF
# Auto-generated Snort 2.9 config by Security One IDS
var HOME_NET any
var EXTERNAL_NET any
var RULE_PATH {$rulesDir}

config logdir: {$this->logDir}
config detection: search-method ac-full

output alert_fast: snort.alert.fast

include \$RULE_PATH/local.rules
CONF;

        file_put_contents($this->configPath, $config);

        // Ensure local.rules exists
        $localRules = $rulesDir . '/local.rules';
        if (!file_exists($localRules)) {
            if (!is_dir($rulesDir)) {
                @mkdir($rulesDir, 0755, true);
            }
            file_put_contents($localRules, "# Security One IDS - Local Rules\n");
        }
    }

    /**
     * Generate a minimal Snort 3 config (Lua)
     */
    private function generateSnort3Config(): void
    {
        $rulesDir = $this->detectRulesDir();
        $config = <<<'LUA'
-- Auto-generated Snort 3 config by Security One IDS
HOME_NET = 'any'
EXTERNAL_NET = 'any'

ips = {
    variables = default_variables,
}

alert_json = {
    file = true,
    limit = 100,
}
LUA;

        file_put_contents($this->configPath, $config);
    }

    /**
     * Update Snort to the latest version
     *
     * @return array{success: bool, version?: string, error?: string}
     */
    public function updateSnort(): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Snort is not installed'];
        }

        $oldVersion = $this->getVersion();
        $wasRunning = $this->isRunning();

        // Stop Snort before updating
        if ($wasRunning) {
            $this->stop();
        }

        try {
            Log::info('Updating Snort...', ['current_version' => $oldVersion, 'platform' => PHP_OS_FAMILY]);

            if (PHP_OS === 'Darwin') {
                $result = $this->updateSnortMac();
            } elseif ($this->isWindows()) {
                $result = $this->updateSnortWindows();
            } else {
                $result = $this->updateSnortLinux();
            }

            // Re-detect paths after update
            $this->snortPath = $this->detectSnortPath();
            $newVersion = $this->getVersion();

            // Restart if was running
            if ($wasRunning) {
                $this->start();
            }

            if ($newVersion && $newVersion !== $oldVersion) {
                Log::info('Snort updated', ['old' => $oldVersion, 'new' => $newVersion]);
                return ['success' => true, 'version' => $newVersion, 'previous' => $oldVersion];
            }

            return ['success' => true, 'version' => $newVersion ?? $oldVersion, 'message' => 'Already at latest version'];
        } catch (\Exception $e) {
            Log::error('Snort update failed: ' . $e->getMessage());
            // Try to restart if it was running
            if ($wasRunning) {
                $this->start();
            }
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Update Snort on macOS via Homebrew
     */
    private function updateSnortMac(): \Illuminate\Process\ProcessResult
    {
        $brewPath = $this->findBrewPath();
        $brewCmd = $this->getBrewCommand($brewPath);

        Process::timeout(120)->run("{$brewCmd} update 2>&1");
        return Process::timeout(600)->run("{$brewCmd} upgrade snort 2>&1");
    }

    /**
     * Update Snort on Linux via package manager (prefers Snort 3)
     */
    private function updateSnortLinux(): \Illuminate\Process\ProcessResult
    {
        $distro = $this->detectLinuxDistro();

        if (in_array($distro, ['debian', 'ubuntu', 'linuxmint', 'pop', 'kali'])) {
            Process::timeout(120)->run('apt-get update -qq 2>&1');
            // Try upgrading snort3 first, fallback to snort (Snort 2)
            $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade snort3 2>&1');
            if (!$result->successful()) {
                $result = Process::timeout(600)->run('DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade snort 2>&1');
            }
            return $result;
        }

        if (in_array($distro, ['rhel', 'centos', 'rocky', 'almalinux', 'ol', 'fedora'])) {
            $result = Process::timeout(600)->run('yum update -y snort3 2>&1');
            if (!$result->successful()) {
                $result = Process::timeout(600)->run('yum update -y snort 2>&1');
            }
            return $result;
        }

        $result = Process::timeout(600)->run('apt-get update -qq && apt-get install -y --only-upgrade snort3 2>&1');
        if (!$result->successful()) {
            $result = Process::timeout(600)->run('apt-get update -qq && apt-get install -y --only-upgrade snort 2>&1');
        }
        return $result;
    }

    /**
     * Update Snort on Windows
     */
    private function updateSnortWindows(): \Illuminate\Process\ProcessResult
    {
        $chocoPath = $this->findChocoPath();
        if ($chocoPath) {
            $result = Process::timeout(600)->run("\"{$chocoPath}\" upgrade snort -y 2>&1");
            // Clean up AutoHotkey that Chocolatey's Npcap dependency installs
            try {
                Process::timeout(120)->run("\"{$chocoPath}\" uninstall autohotkey.install autohotkey -y --force 2>&1");
            } catch (\Exception $e) {
                // Non-critical cleanup
            }
            return $result;
        }

        $wingetPath = $this->findWingetPath();
        if ($wingetPath) {
            return Process::timeout(600)->run("\"{$wingetPath}\" upgrade Snort.Snort --accept-package-agreements 2>&1");
        }

        return Process::timeout(1)->run('echo No package manager found for update');
    }

    /**
     * Find Homebrew binary path
     */
    private function findBrewPath(): string
    {
        foreach (['/opt/homebrew/bin/brew', '/usr/local/bin/brew'] as $bp) {
            if (file_exists($bp)) {
                return $bp;
            }
        }
        return 'brew';
    }

    /**
     * Get the Homebrew command, handling root execution by detecting real user
     */
    private function getBrewCommand(string $brewPath): string
    {
        if (!function_exists('posix_getuid') || posix_getuid() !== 0) {
            $home = getenv('HOME') ?: '/tmp';
            return "HOME={$home} {$brewPath}";
        }

        // Homebrew refuses to run as root — detect the real user
        $realUser = getenv('SUDO_USER') ?: '';
        if (empty($realUser) && $brewPath !== 'brew') {
            $ownerInfo = posix_getpwuid(fileowner($brewPath));
            $realUser = $ownerInfo['name'] ?? '';
        }
        if (empty($realUser)) {
            $users = @scandir('/Users') ?: [];
            foreach ($users as $u) {
                if ($u !== '.' && $u !== '..' && $u !== 'Shared' && $u !== '.localized') {
                    $realUser = $u;
                    break;
                }
            }
        }

        if (!empty($realUser)) {
            return "sudo -u {$realUser} HOME=/Users/{$realUser} {$brewPath}";
        }

        return $brewPath;
    }

    /**
     * Detect Linux distro from /etc/os-release
     */
    private function detectLinuxDistro(): string
    {
        if (file_exists('/etc/os-release')) {
            $osRelease = file_get_contents('/etc/os-release');
            if (preg_match('/^ID=(.+)$/m', $osRelease, $m)) {
                return strtolower(trim($m[1], '"'));
            }
        }
        return 'unknown';
    }

    /**
     * Find Chocolatey path on Windows
     */
    private function findChocoPath(): ?string
    {
        $chocoPath = 'C:\\ProgramData\\chocolatey\\bin\\choco.exe';
        if (file_exists($chocoPath)) {
            return $chocoPath;
        }
        $result = Process::run('where choco 2>&1');
        return $result->successful() ? trim($result->output()) : null;
    }

    /**
     * Find WinGet path on Windows
     */
    private function findWingetPath(): ?string
    {
        $paths = [
            'C:\\Users\\' . get_current_user() . '\\AppData\\Local\\Microsoft\\WindowsApps\\winget.exe',
        ];
        foreach ($paths as $wp) {
            $found = glob($wp);
            if (!empty($found)) {
                return $found[0];
            }
        }
        $result = Process::run('where winget 2>&1');
        return $result->successful() ? trim($result->output()) : null;
    }

    /**
     * Stop Snort process
     */
    public function stop(): array
    {
        if (!$this->isRunning()) {
            return ['success' => true, 'message' => 'Snort is not running'];
        }

        try {
            if (file_exists($this->pidFile)) {
                $pid = trim(file_get_contents($this->pidFile));
                if ($this->isWindows()) {
                    Process::run("taskkill /PID {$pid} /F 2>nul");
                } else {
                    Process::run("kill {$pid} 2>/dev/null");
                    sleep(1);
                    // Force kill if still running
                    if ($this->isProcessRunning((int) $pid)) {
                        Process::run("kill -9 {$pid} 2>/dev/null");
                    }
                }
                @unlink($this->pidFile);
            } else {
                // Kill all snort processes
                if ($this->isWindows()) {
                    Process::run("taskkill /IM snort.exe /F 2>nul");
                } else {
                    Process::run("pkill -f snort 2>/dev/null");
                }
            }

            Log::info('Snort stopped');
            return ['success' => true, 'message' => 'Snort stopped'];
        } catch (\Exception $e) {
            Log::error('Failed to stop Snort: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Get comprehensive Snort status information
     */
    public function getStatus(): array
    {
        $installed = $this->isInstalled();

        // Determine current Snort mode from Hub config
        $snortMode = config('ids.snort_mode', 'ids');
        // Also check if stored in cache/settings
        if ($snortMode === 'ids') {
            $settingsPath = storage_path('app/hub_config.json');
            if (file_exists($settingsPath)) {
                try {
                    $config = json_decode(file_get_contents($settingsPath), true);
                    $snortMode = $config['addons']['snort_mode'] ?? 'ids';
                } catch (\Exception $e) {
                    // ignore
                }
            }
        }

        return [
            'installed' => $installed,
            'version' => $installed ? $this->getVersion() : null,
            'running' => $installed ? $this->isRunning() : false,
            'path' => $this->snortPath,
            'config_path' => $this->configPath,
            'log_dir' => $this->logDir,
            'snort_mode' => $snortMode,
            'stats' => $installed ? $this->getStats() : null,
        ];
    }

    /**
     * Get Snort statistics (packets analyzed, alerts, etc.)
     */
    public function getStats(): array
    {
        $stats = [
            'packets_analyzed' => 0,
            'alerts_total' => 0,
            'alerts_today' => 0,
            'rules_loaded' => 0,
            'uptime' => null,
        ];

        // Fix log permissions on every stats collection (Snort runs as root)
        $this->fixLogPermissions();

        // Count alerts from log file
        if (file_exists($this->alertLogPath)) {
            $stats['alerts_total'] = $this->countLines($this->alertLogPath);
            $stats['alerts_today'] = $this->countAlertsToday();
        }

        // Also check Snort 2 fast alert format (multiple possible filenames)
        if ($stats['alerts_total'] === 0) {
            $snort2AlertPaths = [
                $this->logDir . '/alert',           // Default Snort 2 -A fast output
                $this->logDir . '/alert.ids',       // Alternative Snort 2 filename
                $this->logDir . '/snort.alert.fast', // Named fast output
            ];
            foreach ($snort2AlertPaths as $snort2AlertPath) {
                if (file_exists($snort2AlertPath)) {
                    $lineCount = $this->countLines($snort2AlertPath);
                    $fileSize = @filesize($snort2AlertPath);
                    Log::info('[Snort Alert Debug] Checking Snort 2 alert file', [
                        'path' => $snort2AlertPath,
                        'size_bytes' => $fileSize,
                        'line_count' => $lineCount,
                        'readable' => is_readable($snort2AlertPath),
                    ]);
                    $stats['alerts_total'] = $lineCount;
                    if ($stats['alerts_total'] > 0) {
                        // Count today's alerts from this file
                        $stats['alerts_today'] = $this->countSnort2AlertsToday($snort2AlertPath);
                        break;
                    }
                }
            }

            // Debug: list all files in log directory to find alert file
            if ($stats['alerts_total'] === 0 && is_dir($this->logDir)) {
                $logFiles = @scandir($this->logDir);
                if ($logFiles) {
                    $logFiles = array_filter($logFiles, fn($f) => $f !== '.' && $f !== '..');
                    $fileSizes = [];
                    foreach ($logFiles as $f) {
                        $fileSizes[$f] = @filesize($this->logDir . '/' . $f);
                    }
                    Log::info('[Snort Alert Debug] Files in log dir', [
                        'log_dir' => $this->logDir,
                        'files_with_sizes' => $fileSizes,
                        'alert_json_exists' => file_exists($this->alertLogPath),
                    ]);
                }
            }
        }

        // Try to get packet stats from Snort
        $this->collectPacketStats($stats);

        // Count rules
        $stats['rules_loaded'] = $this->countLoadedRules();

        // Calculate uptime from PID file
        if ($this->isRunning() && file_exists($this->pidFile)) {
            $pidCreated = filemtime($this->pidFile);
            if ($pidCreated) {
                $stats['uptime'] = time() - $pidCreated;
            }
        }

        return $stats;
    }

    /**
     * Collect packet statistics from Snort
     */
    private function collectPacketStats(array &$stats): void
    {
        // Get the network interface Snort is listening on
        $interface = $this->detectDefaultInterface();

        if ($this->isWindows()) {
            // Windows: use PowerShell Get-NetAdapterStatistics
            $this->collectWindowsPacketStats($stats, $interface);
        } elseif (PHP_OS === 'Darwin') {
            // macOS: use netstat -ib
            $this->collectMacPacketStats($stats, $interface);
        } else {
            // Linux: use /sys/class/net stats
            $this->collectLinuxPacketStats($stats, $interface);
        }
    }

    /**
     * Collect packet stats on macOS via netstat
     */
    private function collectMacPacketStats(array &$stats, string $interface): void
    {
        try {
            $result = Process::timeout(5)->run("/usr/sbin/netstat -ib 2>/dev/null");
            if ($result->successful()) {
                $lines = explode("\n", $result->output());
                foreach ($lines as $line) {
                    // Match interface line: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                    if (preg_match('/^' . preg_quote($interface, '/') . '\s+/', $line)) {
                        $parts = preg_split('/\s+/', trim($line));
                        // Ipkts is typically at index 4 for the first matching line (with <Link#> and MAC)
                        if (count($parts) >= 7 && is_numeric($parts[4])) {
                            $stats['packets_analyzed'] = (int) $parts[4];
                            Log::info('[Snort Stats] macOS packets from netstat', [
                                'interface' => $interface,
                                'packets' => $parts[4],
                            ]);
                            return;
                        }
                    }
                }
                // If we get here, no matching interface found
                Log::warning('[Snort Stats] No matching interface in netstat -ib', [
                    'interface' => $interface,
                    'line_count' => count($lines),
                    'first_10_lines' => implode("\n", array_slice($lines, 0, 10)),
                ]);
            } else {
                Log::warning('[Snort Stats] netstat -ib failed', ['exit_code' => $result->exitCode()]);
            }
        } catch (\Exception $e) {
            Log::warning('[Snort Stats] Failed to get macOS packet stats: ' . $e->getMessage());
        }
    }

    /**
     * Collect packet stats on Linux via /sys/class/net
     */
    private function collectLinuxPacketStats(array &$stats, string $interface): void
    {
        $rxPath = "/sys/class/net/{$interface}/statistics/rx_packets";
        if (file_exists($rxPath)) {
            $rxPackets = (int) trim(file_get_contents($rxPath));
            $stats['packets_analyzed'] = $rxPackets;
            return;
        }

        // Fallback: try /proc/net/dev
        if (file_exists('/proc/net/dev')) {
            $content = file_get_contents('/proc/net/dev');
            foreach (explode("\n", $content) as $line) {
                if (str_contains($line, $interface . ':')) {
                    $parts = preg_split('/\s+/', trim($line));
                    if (count($parts) > 1) {
                        // rx_packets is the 2nd field (after interface:rx_bytes)
                        $stats['packets_analyzed'] = (int) ($parts[2] ?? 0);
                        return;
                    }
                }
            }
        }
    }

    /**
     * Collect packet stats on Windows via PowerShell
     */
    private function collectWindowsPacketStats(array &$stats, string $interface): void
    {
        try {
            // Sum ReceivedUnicastPackets across all active adapters
            $result = Process::timeout(10)->run(
                "powershell -NoProfile -Command \"(Get-NetAdapterStatistics | Measure-Object -Property ReceivedUnicastPackets -Sum).Sum\" 2>&1"
            );
            if ($result->successful()) {
                $sum = trim($result->output());
                if (is_numeric($sum) && (int) $sum > 0) {
                    $stats['packets_analyzed'] = (int) $sum;
                    return;
                }
            }

            // Fallback: netstat -e
            $result = Process::timeout(5)->run('netstat -e 2>&1');
            if ($result->successful()) {
                if (preg_match('/Unicast Packets\s+(\d+)/i', $result->output(), $m)) {
                    $stats['packets_analyzed'] = (int) $m[1];
                }
            }
        } catch (\Exception $e) {
            Log::debug('Failed to get Windows packet stats: ' . $e->getMessage());
        }
    }

    /**
     * Parse recent alerts from Snort's JSON alert log
     *
     * @param int $limit Number of alerts to return
     * @return array Parsed alert entries
     */
    public function parseAlerts(int $limit = 50): array
    {
        if (!file_exists($this->alertLogPath)) {
            return [];
        }

        $alerts = [];

        try {
            // Read last N lines efficiently
            $lines = $this->tailFile($this->alertLogPath, $limit);

            foreach ($lines as $line) {
                $line = trim($line);
                if (empty($line)) {
                    continue;
                }

                $decoded = json_decode($line, true);
                if (!$decoded) {
                    continue;
                }

                $alerts[] = [
                    'timestamp' => $decoded['timestamp'] ?? $decoded['seconds'] ?? null,
                    'signature' => $decoded['msg'] ?? $decoded['rule'] ?? 'Unknown',
                    'signature_id' => $decoded['sid'] ?? $decoded['gid'] ?? null,
                    'priority' => $decoded['priority'] ?? 3,
                    'severity' => $this->priorityToSeverity($decoded['priority'] ?? 3),
                    'protocol' => $decoded['proto'] ?? $decoded['protocol'] ?? 'unknown',
                    'source_ip' => $decoded['src_addr'] ?? $decoded['src_ap'] ?? null,
                    'source_port' => $decoded['src_port'] ?? null,
                    'dest_ip' => $decoded['dst_addr'] ?? $decoded['dst_ap'] ?? null,
                    'dest_port' => $decoded['dst_port'] ?? null,
                    'classification' => $decoded['class'] ?? $decoded['classtype'] ?? null,
                    'action' => $decoded['action'] ?? 'alert',
                    'raw' => $decoded,
                ];
            }
        } catch (\Exception $e) {
            Log::warning('Failed to parse Snort alerts: ' . $e->getMessage());
        }

        return array_reverse($alerts); // Most recent first
    }

    /**
     * Update Snort rules (community/ET rules)
     */
    public function updateRules(): array
    {
        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'Snort is not installed'];
        }

        try {
            Log::info('Updating Snort rules...');

            // Try PulledPork3 first (official rule updater for Snort 3)
            $ppPath = $this->detectPulledPorkPath();
            if ($ppPath) {
                $result = Process::timeout(300)->run("{$ppPath} -c /etc/snort/pulledpork.conf 2>&1");
                if ($result->successful()) {
                    Log::info('Snort rules updated via PulledPork');
                    return ['success' => true, 'method' => 'pulledpork', 'output' => $result->output()];
                }
            }

            // Fallback: download community rules manually
            $rulesDir = $this->detectRulesDir();
            $tempFile = sys_get_temp_dir() . '/snort3-community-rules.tar.gz';
            $url = 'https://www.snort.org/downloads/community/snort3-community-rules.tar.gz';

            if ($this->isWindows()) {
                Process::run("curl -fsSL -o \"{$tempFile}\" \"{$url}\"");
            } else {
                Process::run("wget -q -O '{$tempFile}' '{$url}' 2>/dev/null || curl -fsSL -o '{$tempFile}' '{$url}'");
            }

            if (file_exists($tempFile) && filesize($tempFile) > 1000) {
                if (!$this->isWindows()) {
                    Process::run("tar xzf '{$tempFile}' -C '{$rulesDir}' --strip-components=1 2>/dev/null");
                }
                @unlink($tempFile);

                // Reload Snort if running
                if ($this->isRunning()) {
                    $this->reload();
                }

                Log::info('Snort community rules updated');
                return ['success' => true, 'method' => 'community', 'message' => 'Community rules downloaded'];
            }

            return ['success' => false, 'error' => 'Failed to download rules'];
        } catch (\Exception $e) {
            Log::error('Failed to update Snort rules: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Reload Snort configuration (SIGHUP on Unix, stop+start on Windows)
     */
    public function reload(): bool
    {
        if (!$this->isRunning()) {
            return false;
        }

        try {
            // Windows: SIGHUP not available, do full stop+start
            if ($this->isWindows()) {
                Log::info('Reloading Snort on Windows via stop+start (SIGHUP not available)');
                $this->stop();
                sleep(2); // Wait for Snort to fully stop
                $this->start();
                return true;
            }

            if (file_exists($this->pidFile)) {
                $pid = trim(file_get_contents($this->pidFile));
                Process::run("kill -HUP {$pid}");
                return true;
            }
        } catch (\Exception $e) {
            Log::warning('Failed to reload Snort: ' . $e->getMessage());
        }

        return false;
    }

    /**
     * Apply custom rules content to Snort
     */
    public function applyCustomRules(string $rulesContent): array
    {
        $customRulesFile = $this->detectRulesDir() . '/local.rules';

        try {
            file_put_contents($customRulesFile, $rulesContent);

            // Reload if running
            if ($this->isRunning()) {
                $this->reload();
            }

            return ['success' => true, 'rules_file' => $customRulesFile];
        } catch (\Exception $e) {
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    // ─── Private Helpers ─────────────────────────────────────────

    /**
     * Detect if this is Snort 2.x (vs Snort 3.x)
     * Snort 2 and 3 have different CLI flags and rule syntax.
     */
    public function isSnort2(): bool
    {
        $version = $this->getVersion();
        if ($version) {
            return version_compare($version, '3.0.0', '<');
        }

        // Version detection failed — fall back to platform heuristic:
        // Windows almost always has Snort 2 (Snort 3 has no official Windows build)
        // macOS/Linux with Homebrew/apt typically have Snort 3
        if ($this->isWindows()) {
            Log::debug('Snort version undetectable on Windows, assuming Snort 2');
            return true;
        }

        Log::debug('Snort version undetectable on Unix, assuming Snort 3');
        return false;
    }

    /**
     * Build Snort start command, auto-detecting Snort 2 vs 3 flags
     */
    private function buildStartCommand(string $mode, string $interface): string
    {
        $cmd = "{$this->snortPath}";

        if ($this->isSnort2()) {
            return $this->buildSnort2Command($cmd, $mode, $interface);
        }

        return $this->buildSnort3Command($cmd, $mode, $interface);
    }

    /**
     * Build command for Snort 2.9.x
     */
    private function buildSnort2Command(string $cmd, string $mode, string $interface): string
    {
        if (file_exists($this->configPath)) {
            $cmd .= " -c {$this->configPath}";
        }

        $cmd .= " -i {$interface}";
        $cmd .= " -l {$this->logDir}";

        // Snort 2: Use fast alert output (text format parsed by collectSnortAlerts)
        $cmd .= " -A fast";

        if ($mode === 'ips' && !$this->isWindows()) {
            // -Q (inline) requires DAQ support not available on Windows (WinPcap/Npcap is passive)
            $cmd .= " -Q";
        }

        // Run as daemon on Unix
        if (!$this->isWindows()) {
            $cmd .= " -D";
        }

        return $cmd;
    }

    /**
     * Build command for Snort 3.x
     */
    private function buildSnort3Command(string $cmd, string $mode, string $interface): string
    {
        if (file_exists($this->configPath)) {
            $cmd .= " -c {$this->configPath}";
        }

        $cmd .= " -i {$interface}";
        $cmd .= " -l {$this->logDir}";
        $cmd .= " --alert-before-pass";

        // JSON alert output — use --lua to force file=true
        // Without file=true, alerts go to stdout (lost when daemonized with -D)
        // Don't specify fields — Snort 3 default fields include all necessary info
        $cmd .= " --lua 'alert_json = { file = true, limit = 100 }'";

        // Load rules files
        $rulesDir = $this->detectRulesDir();
        $localRules = $rulesDir . '/local.rules';

        // Hub rules are converted from Snort 2→3 format during sync
        $hubRules = $rulesDir . '/hub_custom.rules';
        $hasHubRules = file_exists($hubRules) && filesize($hubRules) > 0;
        if ($hasHubRules) {
            $cmd .= " -R {$hubRules}";
        }

        // Only load local.rules when hub_custom.rules is absent (avoids duplicate SID errors)
        if (!$hasHubRules) {
            $this->ensureLocalRules($rulesDir);
            if (file_exists($localRules)) {
                $cmd .= " -R {$localRules}";
            }
        }

        if ($mode === 'ips') {
            // -Q (inline) requires DAQ support (afpacket/nfq) which only works on Linux
            // macOS only has pcap DAQ (passive/read-only), so skip -Q on macOS
            if (PHP_OS !== 'Darwin') {
                $cmd .= " -Q"; // Inline/IPS mode (Linux only)
            } else {
                Log::debug('Skipping -Q flag on macOS (no inline DAQ support), running in passive IDS mode');
            }
        }

        // Enable perf_monitor stats output is unreliable across platforms
        // Packet stats are collected from OS network interface counters instead

        // Run as daemon on Unix
        if (!$this->isWindows()) {
            $cmd .= " -D";
            $cmd .= " --create-pidfile"; // PID file created in log dir (-l)
        }

        return $cmd;
    }

    private function detectSnortPath(): string
    {
        $paths = $this->isWindows()
            ? [
                'C:\\Snort\\bin\\snort.exe',
                'C:\\Program Files\\Snort\\bin\\snort.exe',
                'C:\\Program Files (x86)\\Snort\\bin\\snort.exe',
            ]
            : [
                '/usr/local/bin/snort',
                '/usr/local/bin/snort3',
                '/usr/sbin/snort',
                '/usr/sbin/snort3',
                '/usr/bin/snort',
                '/usr/bin/snort3',
                '/opt/snort/bin/snort',
                '/opt/homebrew/bin/snort',
            ];

        foreach ($paths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        // Try which/where command
        try {
            $cmd = $this->isWindows() ? 'where snort 2>nul' : 'which snort3 2>/dev/null || which snort 2>/dev/null';
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

    private function detectConfigPath(): string
    {
        $isSnort2 = $this->isSnort2();

        if ($this->isWindows()) {
            $confPaths = [
                'C:\\Snort\\etc\\snort.conf',
                'C:\\Snort\\etc\\snort\\snort.conf',
                'C:\\Program Files\\Snort\\etc\\snort.conf',
            ];
            $luaPaths = [
                'C:\\Snort\\etc\\snort\\snort.lua',
                'C:\\Snort\\etc\\snort.lua',
                'C:\\Program Files\\Snort\\etc\\snort\\snort.lua',
            ];
        } else {
            $confPaths = [
                '/etc/snort/snort.conf',
                '/usr/local/etc/snort/snort.conf',
                '/opt/homebrew/etc/snort/snort.conf',
            ];
            $luaPaths = [
                '/etc/snort/snort.lua',
                '/usr/local/etc/snort/snort.lua',
                '/opt/homebrew/etc/snort/snort.lua',
                '/opt/snort/etc/snort/snort.lua',
                '/opt/snort/etc/snort.lua',
            ];
        }

        // Prioritize the correct format based on Snort version
        $primaryPaths = $isSnort2 ? $confPaths : $luaPaths;
        $secondaryPaths = $isSnort2 ? $luaPaths : $confPaths;

        foreach ($primaryPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }
        foreach ($secondaryPaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        // Return platform-appropriate default
        if ($this->isWindows()) {
            return $isSnort2 ? 'C:\\Snort\\etc\\snort.conf' : 'C:\\Snort\\etc\\snort.lua';
        }
        return $isSnort2 ? '/etc/snort/snort.conf' : '/etc/snort/snort.lua';
    }

    private function detectLogDir(): string
    {
        if ($this->isWindows()) {
            $dir = 'C:\\Snort\\log';
        } elseif (PHP_OS === 'Darwin') {
            $dir = '/var/log/snort';
        } else {
            $dir = '/var/log/snort';
        }

        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        return $dir;
    }

    public function getDetectedRulesDir(): string
    {
        return $this->detectRulesDir();
    }

    public function detectRulesDir(): string
    {
        $paths = $this->isWindows()
            ? ['C:\\Snort\\rules', 'C:\\Snort\\etc\\snort\\rules']
            : ['/opt/homebrew/etc/snort/rules', '/etc/snort/rules', '/usr/local/etc/snort/rules', '/opt/snort/rules'];

        foreach ($paths as $path) {
            if (is_dir($path)) {
                return $path;
            }
        }

        $default = $this->isWindows() ? 'C:\\Snort\\rules' : '/etc/snort/rules';
        @mkdir($default, 0755, true);

        return $default;
    }

    private ?string $cachedInterface = null;

    private function detectDefaultInterface(): string
    {
        if ($this->cachedInterface !== null) {
            return $this->cachedInterface;
        }

        if ($this->isWindows()) {
            // Windows Snort uses device index from `snort -W`
            // Try to detect the active adapter
            // Ensure Npcap DLLs are findable (PATH may not be updated in this PHP process)
            $npcapDir = 'C:\\Windows\\System32\\Npcap';
            if (is_dir($npcapDir) && !str_contains(getenv('PATH') ?: '', 'Npcap')) {
                putenv('PATH=' . getenv('PATH') . ';' . $npcapDir);
            }
            try {
                $cmd = '"' . $this->snortPath . '" -W 2>&1';
                $result = Process::timeout(10)->run($cmd);
                $output = $result->output();
                Log::debug('snort -W result', [
                    'cmd' => $cmd,
                    'exit_code' => $result->exitCode(),
                    'output_length' => strlen($output),
                    'output_preview' => substr($output, 0, 800),
                ]);
                // Parse the interface list — look for an adapter with an IP address
                // Format: "1  \Device\NPF_...   192.168.1.x   Description"
                if (preg_match_all('/^\s*(\d+)\s+\S+\s+(\d+\.\d+\.\d+\.\d+)/m', $output, $matches)) {
                    $firstAvailableIndex = $matches[1][0] ?? null;
                    foreach ($matches[2] as $idx => $ip) {
                        // Skip loopback, zero, and link-local (169.254.x.x) IPs
                        if ($ip !== '0.0.0.0' && $ip !== '127.0.0.1' && !str_starts_with($ip, '169.254.')) {
                            Log::debug('Detected Windows Snort interface', [
                                'index' => $matches[1][$idx],
                                'ip' => $ip,
                            ]);
                            $this->cachedInterface = $matches[1][$idx];
                            return $this->cachedInterface;
                        }
                    }
                    // No interface with a routable IP — use first available interface
                    if ($firstAvailableIndex !== null) {
                        Log::info('No routable IP found, using first available interface', [
                            'index' => $firstAvailableIndex,
                        ]);
                        $this->cachedInterface = $firstAvailableIndex;
                        return $this->cachedInterface;
                    }
                }
                // No interfaces found — likely Npcap not installed
                Log::warning('No Snort network interfaces detected (Npcap may not be installed). Install from https://npcap.com');
            } catch (\Exception $e) {
                Log::debug('Failed to detect Windows interface: ' . $e->getMessage());
            }
            $this->cachedInterface = '1';
            return $this->cachedInterface;
        }

        $isMac = PHP_OS === 'Darwin';

        // macOS: try route command first
        if ($isMac) {
            try {
                $result = Process::run("route -n get default 2>/dev/null | grep 'interface:' | awk '{print \$2}'");
                $iface = trim($result->output());
                if (!empty($iface)) {
                    return $iface;
                }
            } catch (\Exception $e) {
                // Ignore
            }

            // macOS fallback: get first active network service interface
            try {
                $result = Process::run("networksetup -listallhardwareports 2>/dev/null | awk '/Device:/{print \$2}' | head -1");
                $iface = trim($result->output());
                if (!empty($iface)) {
                    return $iface;
                }
            } catch (\Exception $e) {
                // Ignore
            }

            return 'en0'; // macOS default
        }

        // Linux: try to find the default interface
        try {
            $result = Process::run("ip route show default 2>/dev/null | awk '{print \$5}' | head -1");
            $iface = trim($result->output());
            if (!empty($iface)) {
                return $iface;
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return 'eth0';
    }

    private function detectPulledPorkPath(): ?string
    {
        $paths = ['/usr/local/bin/pulledpork3.py', '/usr/local/bin/pulledpork.py', '/opt/pulledpork/pulledpork3.py'];
        foreach ($paths as $path) {
            if (file_exists($path)) {
                return "python3 {$path}";
            }
        }

        return null;
    }

    private function isWindows(): bool
    {
        return PHP_OS_FAMILY === 'Windows';
    }

    /**
     * Fix log directory permissions so non-root PHP agent can read alert files.
     * Snort runs as root (needed for pcap), creating root-owned files.
     */
    public function fixLogPermissions(): void
    {
        if ($this->isWindows()) {
            return; // Windows doesn't have this issue
        }

        try {
            // Make log directory and all files world-readable
            Process::run("sudo chmod -R o+rX {$this->logDir} 2>/dev/null");
            Log::debug('Fixed Snort log permissions', ['dir' => $this->logDir]);
        } catch (\Exception $e) {
            Log::debug('Could not fix log permissions: ' . $e->getMessage());
        }
    }

    private function isProcessRunning(int $pid): bool
    {
        if ($this->isWindows()) {
            try {
                $result = Process::run("tasklist /FI \"PID eq {$pid}\" /NH 2>nul");
                return str_contains($result->output(), (string) $pid);
            } catch (\Exception $e) {
                return false;
            }
        }

        return file_exists("/proc/{$pid}") || (posix_kill($pid, 0) === true);
    }

    private function isSnortProcessActive(): bool
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run('tasklist /FI "IMAGENAME eq snort.exe" /NH 2>nul');
                return str_contains($result->output(), 'snort');
            }

            $result = Process::run('pgrep -f snort 2>/dev/null');
            return !empty(trim($result->output()));
        } catch (\Exception $e) {
            return false;
        }
    }

    private function priorityToSeverity(int $priority): string
    {
        return match (true) {
            $priority <= 1 => 'critical',
            $priority === 2 => 'high',
            $priority === 3 => 'medium',
            default => 'low',
        };
    }

    private function countLines(string $file): int
    {
        try {
            if (!file_exists($file) || filesize($file) === 0) {
                return 0;
            }

            // Stream line-by-line to avoid loading entire file into memory
            // (alert files can be 100K+ lines, file() caused OOM on macOS)
            $count = 0;
            $handle = @fopen($file, 'r');
            if ($handle === false) {
                return 0;
            }
            while (fgets($handle) !== false) {
                $count++;
            }
            fclose($handle);

            return $count;
        } catch (\Exception $e) {
            return 0;
        }
    }

    private function countAlertsToday(): int
    {
        if (!file_exists($this->alertLogPath)) {
            return 0;
        }

        // Snort 2 fast format: "02/09-23:55:24.812484 [**] ..."
        // Snort 3 JSON: contains "2026-02-09" in timestamp
        $todayYmd = date('Y-m-d');      // 2026-02-09
        $todayMd = date('m/d');         // 02/09
        $count = 0;

        try {
            $lines = $this->tailFile($this->alertLogPath, 500);
            foreach ($lines as $line) {
                if (str_contains($line, $todayYmd) || str_starts_with(trim($line), $todayMd)) {
                    $count++;
                }
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return $count;
    }

    /**
     * Count Snort 2 fast-format alerts for today.
     * Snort 2 fast alert format: MM/DD-HH:MM:SS.SSSSSS [**] [gid:sid:rev] msg [**] ...
     */
    private function countSnort2AlertsToday(string $alertFile): int
    {
        if (!file_exists($alertFile)) {
            return 0;
        }

        // Snort 2 uses MM/DD format, e.g. "02/09-12:30:45.123456"
        $todayPrefix = date('m/d');
        $count = 0;

        try {
            $lines = $this->tailFile($alertFile, 500);
            foreach ($lines as $line) {
                if (str_starts_with(trim($line), $todayPrefix)) {
                    $count++;
                }
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return $count;
    }

    private function countLoadedRules(): int
    {
        $rulesDir = $this->detectRulesDir();

        if (!is_dir($rulesDir)) {
            return 0;
        }

        $count = 0;
        $files = glob($rulesDir . '/*.rules');
        foreach ($files ?: [] as $file) {
            $content = @file_get_contents($file);
            if ($content) {
                // Count non-comment, non-empty lines
                $lines = explode("\n", $content);
                foreach ($lines as $line) {
                    $line = trim($line);
                    if (!empty($line) && $line[0] !== '#') {
                        $count++;
                    }
                }
            }
        }

        return $count;
    }

    /**
     * Read last N lines of a file efficiently
     */
    private function tailFile(string $file, int $lines): array
    {
        try {
            if ($this->isWindows()) {
                $result = Process::run("powershell -Command \"Get-Content '{$file}' -Tail {$lines}\"");
            } else {
                $result = Process::run("tail -n {$lines} '{$file}' 2>/dev/null");
            }

            return array_filter(explode("\n", $result->output()));
        } catch (\Exception $e) {
            return [];
        }
    }
    /**
     * Ensure local.rules exists with at least a test rule (Snort 3 compatible)
     */
    private function ensureLocalRules(string $rulesDir): void
    {
        $localRules = $rulesDir . '/local.rules';
        if (file_exists($localRules) && filesize($localRules) > 50) {
            return; // Already has content
        }

        if (!is_dir($rulesDir)) {
            @mkdir($rulesDir, 0755, true);
        }

        // Write Snort 3 compatible test rules
        $rules = <<<'RULES'
# Security One IDS - Local Rules (Snort 3 compatible)
# Test rule: triggers on any ICMP traffic (ping)
alert icmp any any -> any any (msg:"Security One IDS Test - ICMP Detected"; sid:9999001; rev:1;)
# Test rule: triggers on HTTP response containing "uid=0(root)"
alert tcp any any -> any any (msg:"Security One IDS Test - Root UID Response"; content:"uid=0(root)"; sid:9999002; rev:1;)
RULES;

        file_put_contents($localRules, $rules);
        Log::info('Created local.rules with test rules', ['path' => $localRules]);
    }

    /**
     * Convert Hub rules for Snort 3 compatibility.
     *
     * Hub rules are a mix of:
     * - Snort 3 IPS format (comma-separated: content:"x",nocase,depth N;) — ~3600 rules
     * - Snort 2 text format (semicolon-separated: content:"x"; nocase; depth:N;) — ~1400 rules
     *
     * Snort 3 REJECTS the semicolon-separated content modifier format.
     * This converter folds "; nocase;", "; depth:N;", "; offset:N;" etc.
     * back into the preceding content option using comma-separated format.
     * It also strips Snort 2-only pcre modifiers (U, P, H, D, I, B, C, K).
     *
     * @return array{content: string, stats: array}
     */
    public function convertRulesForSnort3(string $rulesContent): array
    {
        $lines = explode("\n", $rulesContent);
        $result = [];
        $converted = 0;
        $removed = 0;
        $kept = 0;

        // Rules with these features CANNOT be converted — skip entirely
        $skipPatterns = [
            '/\bftpbounce\b/',
            '/\bbase_protect\b/',
            '/\basn1\s*:/',
            '/\bcvs\s*:/',
            '/\bsameip\b/',           // Snort 2-only, no Snort 3 equivalent
            '/\btag\s*:/',            // Snort 3 tag syntax incompatible
        ];

        // Variables undefined in Snort 3 default config
        $undefinedVars = ['$SHELLCODE_PORTS', '$AIM_SERVERS', '$DNS_SERVERS'];

        foreach ($lines as $line) {
            $trimmed = trim($line);

            // Keep comments and empty lines
            if (empty($trimmed) || $trimmed[0] === '#') {
                $result[] = $line;
                continue;
            }

            // Only process actual rule lines
            if (!preg_match('/^(alert|drop|pass|reject|log|sdrop)\s/', $trimmed)) {
                $result[] = $line;
                continue;
            }

            // Check for undefined variables and unconvertible features
            $skip = false;
            foreach ($undefinedVars as $var) {
                if (str_contains($trimmed, $var)) {
                    $skip = true;
                    break;
                }
            }
            if (!$skip) {
                foreach ($skipPatterns as $pattern) {
                    if (preg_match($pattern, $trimmed)) {
                        $skip = true;
                        break;
                    }
                }
            }
            if ($skip) {
                $removed++;
                $result[] = '# [Snort2-only] ' . $line;
                continue;
            }

            $rule = $trimmed;
            $wasConverted = false;

            // 1. Remove rawbytes; (no Snort 3 equivalent)
            $rule = preg_replace('/\s*rawbytes\s*;/', '', $rule, -1, $c);
            if ($c) { $wasConverted = true; }

            // 2. Remove fast_pattern_offset/length (removed in Snort 3)
            //    Handles both semicolon format: fast_pattern_offset:N;
            //    and comma format inside content: ,fast_pattern_offset:N,
            $rule = preg_replace('/\s*fast_pattern_offset\s*:\s*\d+\s*;/', '', $rule, -1, $c);
            if ($c) { $wasConverted = true; }
            $rule = preg_replace('/,\s*fast_pattern_offset\s*:\s*\d+/', '', $rule, -1, $c);
            if ($c) { $wasConverted = true; }
            $rule = preg_replace('/\s*fast_pattern_length\s*:\s*\d+\s*;/', '', $rule, -1, $c);
            if ($c) { $wasConverted = true; }
            $rule = preg_replace('/,\s*fast_pattern_length\s*:\s*\d+/', '', $rule, -1, $c);
            if ($c) { $wasConverted = true; }

            // 3. Remove urilen; (not supported in Snort 3)
            $rule = preg_replace('/\s*urilen\s*:[^;]*;/', '', $rule, -1, $c);
            if ($c) { $wasConverted = true; }

            // 4. Convert Snort 2 threshold → detection_filter
            $rule = preg_replace(
                '/\bthreshold\s*:\s*type\s+(?:both|limit|threshold)\s*,\s*track\s+(by_src|by_dst)\s*,\s*count\s+(\d+)\s*,\s*seconds\s+(\d+)\s*;/',
                'detection_filter: track $1, count $2, seconds $3;',
                $rule, -1, $c
            );
            if ($c) { $wasConverted = true; }

            // 5. Convert uricontent: → content: (Snort 2-only keyword)
            $rule = preg_replace('/\buricontent\s*:/', 'content:', $rule, -1, $c);
            if ($c) { $wasConverted = true; }

            // 6. Fold Snort 2 semicolon-separated content modifiers into
            //    Snort 3 comma-separated format. Uses a single-pass approach
            //    to capture content:"..." followed by its modifiers.
            //
            //    Before: content:"YMSG"; depth:4; nocase; content:"|00 01|"; depth:2; offset:10;
            //    After:  content:"YMSG",depth 4,nocase; content:"|00 01|",depth 2,offset 10;
            $rule = preg_replace_callback(
                '/content\s*:\s*"([^"]*)"(\s*;\s*(?:nocase|depth\s*:\s*-?\d+|offset\s*:\s*-?\d+|distance\s*:\s*-?\d+|within\s*:\s*-?\d+|fast_pattern)\s*)+;/',
                function ($match) {
                    $full = $match[0];
                    if (!preg_match('/content\s*:\s*"([^"]*)"/', $full, $cm)) {
                        return $full;
                    }
                    $contentVal = $cm[1];
                    $afterContent = substr($full, strlen($cm[0]));
                    $modifiers = [];

                    preg_match_all('/(\w+)(?:\s*:\s*(-?\d+))?/', $afterContent, $mods, PREG_SET_ORDER);
                    foreach ($mods as $mod) {
                        $name = $mod[1];
                        if (in_array($name, ['nocase', 'fast_pattern'])) {
                            $modifiers[] = $name;
                        } elseif (in_array($name, ['depth', 'offset', 'distance', 'within']) && isset($mod[2])) {
                            $modifiers[] = $name . ' ' . $mod[2];
                        }
                    }

                    if (empty($modifiers)) {
                        return $full;
                    }

                    return 'content:"' . $contentVal . '",' . implode(',', $modifiers) . ';';
                },
                $rule, -1, $c
            );
            if ($c) { $wasConverted = true; }

            // 7. Strip Snort 2-only pcre HTTP modifiers (U, P, H, D, I, B, C, K)
            //    pcre:"/regex/Ui" → pcre:"/regex/i"
            //    Uses strrpos to reliably find the closing / delimiter
            $rule = preg_replace_callback(
                '/pcre\s*:\s*"(\/[^"]*)"/',
                function ($match) {
                    $pcreVal = $match[1]; // e.g. /path=(https?|ftp)/Ui
                    $lastSlash = strrpos($pcreVal, '/');
                    if ($lastSlash === false || $lastSlash === 0) {
                        return $match[0]; // Only one slash = no modifiers
                    }
                    $pattern = substr($pcreVal, 0, $lastSlash + 1); // includes closing /
                    $mods = substr($pcreVal, $lastSlash + 1);
                    if (empty($mods)) {
                        return $match[0]; // no modifiers to strip
                    }
                    // Remove Snort 2-only modifiers, keep standard ones (i, m, s, x, g)
                    $cleanMods = preg_replace('/[UPHDIBRCK]/', '', $mods);
                    return 'pcre:"' . $pattern . $cleanMods . '"';
                },
                $rule, -1, $c
            );
            if ($c) { $wasConverted = true; }

            // 8. Normalize flow values to lowercase (Snort 3 is case-sensitive)
            //    e.g. flow:to_Server → flow:to_server
            $rule = preg_replace_callback(
                '/flow\s*:\s*([^;]+);/',
                function ($match) {
                    return 'flow:' . strtolower($match[1]) . ';';
                },
                $rule, -1, $c
            );
            if ($c) { $wasConverted = true; }

            // 9. Clean up double semicolons and trailing commas before semicolons
            $rule = preg_replace('/;\s*;/', ';', $rule);
            $rule = preg_replace('/,\s*;/', ';', $rule);

            // 10. Safety fallback: if rule STILL has standalone Snort 2 content
            //     modifiers or fast_pattern_offset that we couldn't remove,
            //     comment it out rather than let Snort 3 fail on it
            if (preg_match('/;\s*(?:nocase|depth\s*:\s*-?\d+|offset\s*:\s*-?\d+|within\s*:\s*-?\d+|distance\s*:\s*-?\d+)\s*;/', $rule)
                || preg_match('/fast_pattern_offset/', $rule)) {
                $removed++;
                $result[] = '# [Snort2-unfoldable] ' . $rule;
                continue;
            }

            if ($wasConverted) {
                $converted++;
            } else {
                $kept++;
            }

            $result[] = $rule;
        }

        $stats = [
            'total' => $kept + $converted + $removed,
            'kept_as_is' => $kept,
            'converted' => $converted,
            'removed' => $removed,
        ];

        Log::info('Converted Hub rules for Snort 3', $stats);

        return [
            'content' => implode("\n", $result),
            'stats' => $stats,
        ];
    }

    /**
     * Validate and clean rules for Snort 2 compatibility.
     *
     * Snort 2's parser is strict about certain syntax that might be
     * present in community or custom rules. This method comments out
     * rules that would cause Snort 2 to crash on startup.
     *
     * @return array{content: string, stats: array}
     */
    public function validateRulesForSnort2(string $rulesContent): array
    {
        $lines = explode("\n", $rulesContent);
        $result = [];
        $removed = 0;
        $kept = 0;

        foreach ($lines as $line) {
            $trimmed = trim($line);

            // Pass through comments and blank lines
            if (empty($trimmed) || $trimmed[0] === '#') {
                $result[] = $line;
                continue;
            }

            // Only validate actual rules
            if (!preg_match('/^(alert|drop|pass|reject|log|sdrop)\s/', $trimmed)) {
                $result[] = $line;
                continue;
            }

            // Check for malformed hex: unmatched pipe characters in content
            // Snort uses |XX XX| for hex — odd pipe count = unterminated hex
            $skip = false;
            if (preg_match_all('/content\s*:\s*"([^"]*)"/i', $trimmed, $matches)) {
                foreach ($matches[1] as $val) {
                    $pipeCount = substr_count($val, '|');
                    if ($pipeCount % 2 !== 0) {
                        $skip = true;
                        break;
                    }
                }
            }

            // Check for content with literal semicolon (confuses parser)
            if (preg_match('/content\s*:\s*";"\s*;/', $trimmed)) {
                $skip = true;
            }

            // Check for Snort 3-only comma-separated content modifiers
            // e.g. content:"foo",nocase; — Snort 2 needs content:"foo"; nocase;
            if (preg_match('/content\s*:\s*"[^"]*"\s*,\s*(nocase|depth|offset|distance|within|fast_pattern)/', $trimmed)) {
                $skip = true;
            }

            // Check for Snort 3-only keywords that don't exist in Snort 2
            if (preg_match('/\b(service\s*:|sticky_buffer|http2_header|http_trailer|js_data|vba_data|file_data\s*;)/', $trimmed)) {
                $skip = true;
            }

            // Check for DCE/RPC keywords with Snort 3 syntax (invalid UUID format, etc.)
            // These cause "Invalid uuid" errors in Snort 2 — safer to strip all dce_ rules
            if (preg_match('/\b(dce_iface|dce_opnum|dce_stub_data)\b/', $trimmed)) {
                $skip = true;
            }

            // Check for http_uri/http_header BEFORE content (Snort 3 "sticky buffer" syntax)
            // Snort 2 requires: content:"foo"; http_uri; (modifier AFTER content)
            // Snort 3 allows: http_uri; content:"foo"; (sticky buffer BEFORE content)
            if (preg_match('/;\s*http_(uri|header|cookie|method|stat_code|stat_msg|raw_uri|raw_header|raw_cookie|client_body)\s*;\s*content\s*:/', $trimmed)) {
                $skip = true;
            }

            // Check for negated variables that resolve to !any in Snort 2
            // When $HOME_NET = any, then $DNS_SERVERS = $HOME_NET = any, and !$DNS_SERVERS = !any
            // Snort 2 fatally rejects "!any" with: "!any is not allowed"
            if (preg_match('/!\$(?:DNS_SERVERS|SMTP_SERVERS|SQL_SERVERS|HTTP_SERVERS|TELNET_SERVERS|AIM_SERVERS|SIP_SERVERS|ENIP_CLIENT|ENIP_SERVER)/', $trimmed)) {
                $skip = true;
            }

            if ($skip) {
                $removed++;
                $result[] = '# [Snort2-invalid] ' . $trimmed;
            } else {
                $kept++;
                $result[] = $trimmed;
            }
        }

        $stats = [
            'total' => $kept + $removed,
            'kept' => $kept,
            'removed' => $removed,
        ];

        if ($removed > 0) {
            Log::info('Validated rules for Snort 2', $stats);
        }

        return [
            'content' => implode("\n", $result),
            'stats' => $stats,
        ];
    }
}

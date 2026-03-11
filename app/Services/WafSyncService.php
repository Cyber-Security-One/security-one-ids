<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Artisan;
use Symfony\Component\Process\Process as SymfonyProcess;

class WafSyncService
{
    protected string $wafUrl;
    protected string $agentToken;
    protected string $agentName;
    protected bool $codeUpdated = false;

    public function __construct()
    {
        $this->wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');
        
        // Prefer cached WAF-assigned token over .env token (registration returns correct token)
        $cachedToken = cache()->get('waf_agent_token');
        $envToken = config('ids.agent_token') ?? env('AGENT_TOKEN', '');
        $this->agentToken = !empty($cachedToken) ? $cachedToken : $envToken;
        
        $this->agentName = config('ids.agent_name') ?? env('AGENT_NAME', gethostname());

        // Fallback: directly parse .env file if values are still empty
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            $envFile = base_path('.env');
            if (file_exists($envFile)) {
                $envValues = parse_ini_file($envFile);
                if ($envValues) {
                    if (empty($this->wafUrl) && !empty($envValues['WAF_URL'])) {
                        $this->wafUrl = rtrim($envValues['WAF_URL'], '/');
                    }
                    if (empty($this->agentToken) && !empty($envValues['AGENT_TOKEN'])) {
                        $this->agentToken = $envValues['AGENT_TOKEN'];
                    }
                    if (empty($this->agentName) && !empty($envValues['AGENT_NAME'])) {
                        $this->agentName = $envValues['AGENT_NAME'];
                    }
                }
            }
        }
    }

    /**
     * Get HTTP client with SSL configuration for Windows
     */
    protected function getHttpClient(int $timeout = 30): \Illuminate\Http\Client\PendingRequest
    {
        $http = Http::timeout($timeout)
            ->withHeaders([
                'Content-Type' => 'application/json; charset=utf-8',
                'Accept' => 'application/json',
            ]);
        
        // On Windows, configure SSL certificate path at runtime
        if (PHP_OS_FAMILY === 'Windows') {
            $cacertPath = $this->getCaCertPath();
            if ($cacertPath) {
                $http = $http->withOptions([
                    'verify' => $cacertPath,
                ]);
            } else {
                // No cacert.pem found — disable SSL verification as fallback
                $http = $http->withoutVerifying();
            }
        }
        
        return $http;
    }

    /**
     * Register this agent with the central WAF
     */
    public function register(): bool
    {
        // Debug logging
        Log::debug('WafSync register() called', [
            'wafUrl' => $this->wafUrl,
            'agentToken' => substr($this->agentToken, 0, 10) . '...',
            'agentName' => $this->agentName,
        ]);

        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured', [
                'wafUrl_empty' => empty($this->wafUrl),
                'agentToken_empty' => empty($this->agentToken),
                'env_WAF_URL' => env('WAF_URL'),
                'config_ids.waf_url' => config('ids.waf_url'),
            ]);
            return false;
        }

        try {
            // Use INSTALL_TOKEN if set, otherwise fall back to AGENT_TOKEN
            $installToken = config('ids.install_token') ?? env('INSTALL_TOKEN', '');
            if (empty($installToken)) {
                $installToken = $this->agentToken;
            }
            // Fallback: parse .env directly if install_token is empty
            if (empty($installToken)) {
                $envFile = base_path('.env');
                if (file_exists($envFile)) {
                    $envValues = parse_ini_file($envFile);
                    $installToken = $envValues['INSTALL_TOKEN'] ?? '';
                }
            }
            $response = $this->getHttpClient(30)
                ->withHeaders(['X-Install-Token' => $installToken])
                ->post("{$this->wafUrl}/api/ids/agents/register", [
                'token' => $this->agentToken,
                'name' => $this->agentName,
                'ip_address' => $this->getPublicIp(),
                'hostname' => gethostname(),
                'version' => config('app.version', '1.0.0'),
                'platform' => $this->detectPlatform(),
                'system_info' => $this->getSystemInfo(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::info('Successfully registered with WAF', $data);
                
                // Store the WAF-assigned token for future use
                if (!empty($data['token'])) {
                    cache()->put('waf_agent_token', $data['token'], now()->addDays(30));
                }
                
                // Store the agent ID for alert syncing
                if (!empty($data['agent_id'])) {
                    cache()->put('ids_agent_id', $data['agent_id'], now()->addDays(30));
                }
                
                return true;
            }

            Log::error('Failed to register with WAF', [
                'status' => $response->status(),
                'body' => $response->body(),
                'headers' => $response->headers(),
            ]);
            return false;
        } catch (\Exception $e) {
            Log::error('Exception during WAF registration', [
                'message' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return false;
        }
    }

    /**
     * Send heartbeat to WAF
     */
    public function heartbeat(): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            Log::warning('WAF_URL or AGENT_TOKEN not configured for heartbeat');
            return false;
        }

        $maxRetries = 3;
        $retryDelay = 2; // seconds
        
        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
            try {
                $response = $this->getHttpClient(30)->post("{$this->wafUrl}/api/ids/agents/heartbeat", [
                    'token' => $this->agentToken,
                    'name' => $this->agentName,
                    'version' => config('app.version', '1.0.0'),
                    'version_updated_at' => $this->getLastGitPullTime(),
                    'system_info' => $this->getSystemInfo(),
                    'discovered_logs' => $this->getDiscoveredLogPaths(),
                    'recent_logs' => $this->collectRecentLogs(),
                ]);

                if ($response->successful()) {
                    $data = $response->json();
                    Log::debug('Heartbeat sent successfully', $data);
                    
                    // Sync config from WAF Hub (including Ollama settings)
                    if (isset($data['config'])) {
                        $this->syncConfigFromHub($data['config']);
                    }
                    
                    return true;
                }

                // If agent not found (404), try to register
                if ($response->status() === 404) {
                    Log::info('Agent not found, attempting registration...');
                    return $this->register();
                }

                Log::warning('Heartbeat failed', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                    'attempt' => $attempt,
                ]);
                
            } catch (\Exception $e) {
                Log::error("Heartbeat exception (attempt {$attempt}/{$maxRetries}): " . $e->getMessage());
                
                if ($attempt < $maxRetries) {
                    Log::info("Retrying heartbeat in {$retryDelay} seconds...");
                    sleep($retryDelay);
                    continue;
                }
                
                // On final failure, log connection error
                if (str_contains($e->getMessage(), 'Connection') || str_contains($e->getMessage(), 'cURL')) {
                    Log::info('Connection error, will try registration on next sync');
                }
            }
        }
        
        return false;
    }

    /**
     * Sync config received from WAF Hub (save only, tasks dispatched by sub-commands)
     */
    private function syncConfigFromHub(array $config): void
    {
        $configPath = storage_path('app/waf_config.json');
        
        // Read existing config
        $existingConfig = [];
        if (file_exists($configPath)) {
            $existingConfig = json_decode(file_get_contents($configPath), true) ?: [];
        }
        
        // Merge with new config
        $mergedConfig = array_merge($existingConfig, $config);
        
        // Backwards compatibility: map Hub snort_* keys → suricata_*
        if (isset($mergedConfig['addons'])) {
            $addons = &$mergedConfig['addons'];
            if (isset($addons['snort_enabled']) && !isset($addons['suricata_enabled'])) {
                $addons['suricata_enabled'] = $addons['snort_enabled'];
            }
            if (isset($addons['snort_mode']) && !isset($addons['suricata_mode'])) {
                $addons['suricata_mode'] = $addons['snort_mode'];
            }
            if (isset($addons['snort_rules_hash']) && !isset($addons['suricata_rules_hash'])) {
                $addons['suricata_rules_hash'] = $addons['snort_rules_hash'];
            }
            // Remove legacy snort keys from stored config
            unset($addons['snort_enabled'], $addons['snort_mode'], $addons['snort_rules_hash']);
            unset($addons);
        }

        // Save to storage
        file_put_contents($configPath, json_encode($mergedConfig, JSON_PRETTY_PRINT));

        Log::info('Config synced from WAF Hub', [
            'ollama_url' => $config['ollama']['url'] ?? 'not set',
            'ollama_model' => $config['ollama']['model'] ?? 'not set',
            'clamav_enabled' => $config['addons']['clamav_enabled'] ?? false,
            'suricata_enabled' => $config['addons']['suricata_enabled'] ?? $config['addons']['snort_enabled'] ?? false,
            'suricata_mode' => $config['addons']['suricata_mode'] ?? $config['addons']['snort_mode'] ?? 'ids',
            'update_ids' => $config['addons']['update_ids'] ?? false,
            'update_definitions' => $config['addons']['update_definitions'] ?? false,
            'scan_now' => $config['addons']['scan_now'] ?? false,
            'scan_type' => $config['addons']['scan_type'] ?? 'quick',
        ]);
    }

    /**
     * Get saved WAF config from storage
     */
    public function getWafConfig(): array
    {
        $configPath = storage_path('app/waf_config.json');
        if (!file_exists($configPath)) {
            return [];
        }

        return json_decode(file_get_contents($configPath), true) ?: [];
    }

    /**
     * Run quick sync tasks: rules, signatures, alerts, blocked IPs
     */
    public function runQuickSync(): void
    {
        $config = $this->getWafConfig();
        $addons = $config['addons'] ?? [];


        // Suricata rules & alerts (only if Suricata enabled)
        if (!empty($addons['suricata_enabled'])) {
            // Ensure Suricata is running if enabled but not active
            $this->ensureSuricataRunning($addons);

            if (!empty($addons['suricata_rules_hash'])) {
                $this->syncSuricataRules($addons['suricata_rules_hash'], $addons['suricata_mode'] ?? 'ids');
            }
            $this->collectSuricataAlerts();
        }

        // Blocked IPs
        if (!empty($config['blocked_ips'])) {
            $this->handleBlockedIps($config['blocked_ips']);
        }

        // Fetch rules from WAF and sync to local DB
        $rules = $this->fetchRules();
        if ($rules && isset($rules['rules']) && count($rules['rules']) > 0) {
            $synced = $this->syncRulesToDatabase($rules['rules']);
            Log::info("Synced {$synced} rules from WAF to local database");
            cache()->put('ids_rules', $rules['rules'], now()->addHour());
        }

        // Upload local signatures
        $this->uploadSignatures();
    }

    /**
     * Run Snort management tasks (deprecated — redirects to Suricata)
     */
    public function runSnortSync(): void
    {
        Log::debug('[SyncSnort] Deprecated — redirecting to Suricata sync');
        $this->runSuricataSync();
    }

    /**
     * Run maintenance tasks: ClamAV, updates, definitions, scan, system signals
     */
    public function runMaintenanceSync(): void
    {
        $config = $this->getWafConfig();
        $addons = $config['addons'] ?? [];

        // ClamAV
        if (!empty($addons['clamav_enabled'])) {
            $this->handleClamavAddon();
        }

        // IDS update (manual or auto)
        if (!empty($addons['update_ids'])) {
            $this->handleIdsUpdate();
        } else {
            $this->checkAndAutoUpdate();
        }

        // Virus definitions update
        if (!empty($addons['update_definitions'])) {
            $this->handleDefinitionsUpdate();
        }

        // Scan now
        if (!empty($addons['scan_now'])) {
            $this->handleScanNow();
        }

        // System signals (reboot, lock, unlock, login controls)
        if (!empty($addons['reboot'])) {
            Log::warning('Reboot signal received from WAF Hub');
            $this->handleSystemReboot();
        }

        if (!empty($addons['lock'])) {
            Log::warning('Lock signal received from WAF Hub');
            $this->handleSystemLock();
        }

        if (!empty($addons['unlock'])) {
            Log::warning('Unlock signal received from WAF Hub');
            $this->handleSystemUnlock();
        }

        if (!empty($addons['disable_login'])) {
            Log::warning('Disable login signal received from WAF Hub');
            $this->handleDisableLogin();
        }

        if (!empty($addons['enable_login'])) {
            Log::warning('Enable login signal received from WAF Hub');
            $this->handleEnableLogin();
        }
    }
    
    /**
     * Handle ClamAV add-on installation
     */
    private function handleClamavAddon(): void
    {
        try {
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::info('ClamAV enabled but not installed, starting installation...');
                $result = $clamav->install();
                
                if ($result['success']) {
                    Log::info('ClamAV installed successfully');
                } else {
                    Log::error('ClamAV installation failed: ' . ($result['message'] ?? 'Unknown error'));
                }
            }
            
            // Report status to Hub - but don't include scan_status to avoid overwriting active scan
            $status = $clamav->getStatus();
            $status['skip_scan_status'] = true;  // Flag to tell Hub to not update scan_status
            $clamav->reportToHub($status);
            
        } catch (\Exception $e) {
            Log::error('ClamAV addon handling failed: ' . $e->getMessage());
        }
    }

    /**
     * Ensure Suricata is running if enabled.
     * Auto-installs if missing, auto-starts if not running.
     */
    private function ensureSuricataRunning(array $addons): void
    {
        try {
            $suricata = app(\App\Services\Detection\SuricataEngine::class);
            $mode = $addons['suricata_mode'] ?? 'ids';

            if (!$suricata->isInstalled()) {
                Log::info('[Suricata] Enabled but not installed, triggering install...');
                $this->installSuricata();
                // Re-detect after install
                $suricata = app(\App\Services\Detection\SuricataEngine::class);
                if (!$suricata->isInstalled()) {
                    Log::error('[Suricata] Installation failed, cannot start');
                    return;
                }
            }

            if (!$suricata->isRunning()) {
                Log::info("[Suricata] Enabled but not running, starting in {$mode} mode...");
                $result = $suricata->start($mode);
                if (!empty($result['success'])) {
                    Log::info('[Suricata] Started successfully');
                    $this->reportAgentEvent('suricata_started', "Suricata 已自動啟動（{$mode} 模式）");
                } else {
                    Log::error('[Suricata] Failed to start', $result);
                    $this->reportAgentEvent('error', 'Suricata 自動啟動失敗: ' . ($result['error'] ?? 'unknown'));
                }
            }
        } catch (\Exception $e) {
            Log::error('[Suricata] ensureSuricataRunning failed: ' . $e->getMessage());
        }
    }

    private function syncSuricataRules(string $hubHash, string $mode = 'ids'): void
    {
        try {
            if ($this->codeUpdated) {
                Log::info('Skipping Suricata rule sync — code was just updated');
                return;
            }

            $suricata = app(\App\Services\Detection\SuricataEngine::class);
            if (!$suricata->isInstalled()) {
                return;
            }

            // Compare local hash with Hub hash
            $hashPath = storage_path('app/suricata_rules_hash.txt');
            $localHash = file_exists($hashPath) ? trim(file_get_contents($hashPath)) : '';
            if ($localHash === $hubHash) {
                Log::debug('Suricata rules hash matches Hub, no sync needed');
                return;
            }

            Log::info('Suricata rules hash mismatch, syncing from Hub...', [
                'local_hash' => $localHash,
                'hub_hash' => $hubHash,
            ]);

            if (empty($this->wafUrl) || empty($this->agentToken)) {
                Log::warning('Cannot sync Suricata rules: Hub URL or token not configured');
                return;
            }

            // Fetch rules from Hub
            $response = $this->getHttpClient(120)
                ->withHeaders(['Authorization' => "Bearer {$this->agentToken}"])
                ->get("{$this->wafUrl}/api/ids/agents/suricata-rules", [
                    'token' => $this->agentToken,
                ]);

            if (!$response->successful()) {
                Log::error('Failed to fetch Suricata rules from Hub', ['status' => $response->status()]);
                $this->reportAgentEvent('error', 'Suricata 規則同步失敗：無法從 Hub 下載', [
                    'http_status' => $response->status(),
                ]);
                return;
            }

            $data = $response->json();
            $rulesContent = '';
            $ruleCount = 0;

            if (!empty($data['rules_text'])) {
                $rulesContent = $data['rules_text'] . "\n";
                $ruleCount = $data['rules_count'] ?? substr_count($rulesContent, "\n");
            } else {
                Log::info('No Suricata rules received from Hub');
                return;
            }

            // Windows (Cygwin build): limit rules to prevent TP_NUM_C_BUFS crash
            // The Cygwin runtime can't handle thousands of rules due to TLS buffer limits
            if (PHP_OS_FAMILY === 'Windows' && $ruleCount > 500) {
                $lines = explode("\n", trim($rulesContent));
                $lines = array_slice($lines, 0, 500);
                $rulesContent = implode("\n", $lines) . "\n";
                $originalCount = $ruleCount;
                $ruleCount = count($lines);
                Log::info("Windows: Limited Suricata rules from {$originalCount} to {$ruleCount} (Cygwin TLS limit)");
            }

            // IPS mode: convert alert → drop for inline blocking
            if ($mode === 'ips') {
                $rulesContent = $suricata->applyIpsMode($rulesContent);
            }

            // Write rules and reload
            $suricata->applyCustomRules($rulesContent);

            // Store the new hash locally
            file_put_contents($hashPath, $data['rules_hash'] ?? $hubHash);

            // Reload rules (SIGUSR2 for live reload, or restart)
            if ($suricata->isRunning()) {
                $reloadResult = $suricata->reload();
                if (!($reloadResult['success'] ?? false)) {
                    Log::warning('Suricata reload failed, restarting...', $reloadResult);
                    $suricata->stop();
                    $suricata->start($mode);
                }
            }

            Log::info("Synced {$ruleCount} Suricata rules from Hub");
            $this->reportAgentEvent('suricata_rule_sync', "已從 Hub 同步 {$ruleCount} 條 Suricata 規則", [
                'rule_count' => $ruleCount,
                'rules_hash' => $data['rules_hash'] ?? $hubHash,
            ]);

        } catch (\Exception $e) {
            Log::error('Suricata rules sync failed: ' . $e->getMessage());
            $this->reportAgentEvent('error', 'Suricata 規則同步例外：' . $e->getMessage());
        }
    }

    /**
     * Collect alerts from Suricata EVE JSON log and upload to Hub
     */
    private function collectSuricataAlerts(): void
    {
        try {
            $suricata = app(\App\Services\Detection\SuricataEngine::class);
            if (!$suricata->isInstalled() || !$suricata->isRunning()) {
                return;
            }

            $alertLogPath = $suricata->getAlertLogPath();
            if (!$alertLogPath || !file_exists($alertLogPath)) {
                Log::debug('Suricata EVE log not found', ['path' => $alertLogPath]);
                return;
            }

            // Fix permissions if needed
            if (!is_readable($alertLogPath) && PHP_OS_FAMILY !== 'Windows') {
                $logDir = dirname($alertLogPath);
                Process::run("sudo chmod -R o+rX {$logDir} 2>/dev/null");
                clearstatcache(true, $alertLogPath);
                if (!is_readable($alertLogPath)) {
                    Log::warning('Suricata EVE log not readable', ['path' => $alertLogPath]);
                    return;
                }
            }

            // Track file position
            $positionFile = storage_path('app/suricata_alert_position.txt');
            $lastPosition = 0;
            if (file_exists($positionFile)) {
                $lastPosition = (int) file_get_contents($positionFile);
            }

            $fileSize = filesize($alertLogPath);
            if ($fileSize < $lastPosition) {
                $lastPosition = 0; // Log rotated
            }
            if ($fileSize <= $lastPosition) {
                return; // No new data
            }

            $handle = fopen($alertLogPath, 'r');
            if (!$handle) {
                return;
            }

            fseek($handle, $lastPosition);
            $newAlerts = [];
            $maxAlerts = 50;

            while (!feof($handle) && count($newAlerts) < $maxAlerts) {
                $line = fgets($handle);
                if ($line === false) {
                    break;
                }

                $line = trim($line);
                if (empty($line)) {
                    continue;
                }

                // Parse EVE JSON format
                $event = json_decode($line, true);
                if (!$event || ($event['event_type'] ?? '') !== 'alert') {
                    continue;
                }

                $alert = $event['alert'] ?? [];
                $sourceIp = $event['src_ip'] ?? null;
                if (!$sourceIp || !filter_var($sourceIp, FILTER_VALIDATE_IP)) {
                    continue;
                }

                $severity = match ((int) ($alert['severity'] ?? 3)) {
                    1 => 'critical',
                    2 => 'high',
                    3 => 'medium',
                    default => 'low',
                };

                $sid = $alert['signature_id'] ?? 0;
                $msg = $alert['signature'] ?? 'Unknown';
                $category = $alert['category'] ?? 'suricata-detection';
                $proto = strtoupper($event['proto'] ?? 'unknown');

                $newAlerts[] = [
                    'source_ip' => $sourceIp,
                    'severity' => $severity,
                    'category' => $category,
                    'source' => 'suricata',
                    'detections' => "[SURICATA] SID:{$sid} {$msg} (Severity: " . ($alert['severity'] ?? '?') . ')',
                    'raw_log' => $line,
                    'uri' => ($event['dest_ip'] ?? '') . ':' . ($event['dest_port'] ?? ''),
                    'method' => $proto,
                ];
            }

            // Save position
            file_put_contents($positionFile, (string) ftell($handle));
            fclose($handle);

            // Upload to Hub
            if (!empty($newAlerts) && !empty($this->wafUrl) && !empty($this->agentToken)) {
                $response = $this->getHttpClient(30)
                    ->withHeaders(['Authorization' => "Bearer {$this->agentToken}"])
                    ->post("{$this->wafUrl}/api/ids/agents/alerts", [
                        'token' => $this->agentToken,
                        'alerts' => $newAlerts,
                    ]);

                if ($response->successful()) {
                    Log::info('Uploaded ' . count($newAlerts) . ' Suricata alerts to Hub');
                } else {
                    Log::warning('Failed to upload Suricata alerts', ['status' => $response->status()]);
                }
            }

        } catch (\Exception $e) {
            Log::error('Suricata alert collection failed: ' . $e->getMessage());
        }
    }

    /**
     * Auto-update Suricata (checks once per day)
     */
    private function autoUpdateSuricata(\App\Services\Detection\SuricataEngine $suricata): void
    {
        $updateFile = storage_path('app/suricata_last_update_check.txt');

        if (file_exists($updateFile)) {
            $lastCheck = (int) file_get_contents($updateFile);
            if (time() - $lastCheck < 86400) {
                return;
            }
        }

        file_put_contents($updateFile, (string) time());

        try {
            Log::info('Running daily Suricata auto-update check...');
            $result = $suricata->updateSuricata();

            if ($result['success'] ?? false) {
                $version = $result['version'] ?? 'unknown';
                $previous = $result['previous'] ?? null;

                if ($previous && $previous !== $version) {
                    Log::info("Suricata updated: {$previous} → {$version}");
                    $this->reportAgentEvent('suricata_updated', "Suricata 已更新：{$previous} → {$version}", [
                        'old_version' => $previous,
                        'new_version' => $version,
                    ]);
                } else {
                    Log::info("Suricata is up to date: {$version}");
                }
            }
        } catch (\Exception $e) {
            Log::warning('Suricata auto-update check failed: ' . $e->getMessage());
        }
    }

    /**
     * Install Suricata on the current platform
     */
    private function installSuricata(): array
    {
        $platform = $this->detectPlatform();
        Log::info("Installing Suricata on {$platform}...");

        try {
            switch ($platform) {
                case 'linux':
                case 'server':
                    return $this->installSuricataLinux();
                case 'macos':
                    return $this->installSuricataMac();
                case 'windows':
                    return $this->installSuricataWindows();
                default:
                    return ['success' => false, 'error' => "Unsupported platform: {$platform}"];
            }
        } catch (\Exception $e) {
            Log::error("Suricata installation failed: " . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Install Suricata on Linux
     */
    private function installSuricataLinux(): array
    {
        // Detect distro from os-release
        $distro = 'unknown';
        if (file_exists('/etc/os-release')) {
            $content = file_get_contents('/etc/os-release');
            if (preg_match('/^ID=(.+)$/m', $content, $m)) {
                $distro = trim($m[1], '"\'');
            }
        }

        Log::info("[Suricata] Linux distro detected: {$distro}");

        // Determine sudo prefix
        $sudo = (posix_getuid() !== 0) ? 'sudo ' : '';
        Log::info("[Suricata] Running as " . (posix_getuid() === 0 ? 'root' : 'user (uid=' . posix_getuid() . ')'));

        if (in_array($distro, ['debian', 'ubuntu', 'linuxmint', 'pop', 'kali'])) {
            // Add OISF PPA only on Ubuntu variants (PPA not supported on Debian)
            if (in_array($distro, ['ubuntu', 'linuxmint', 'pop'])) {
                Log::info('[Suricata] Adding OISF PPA for latest Suricata...');
                Process::timeout(60)->run("{$sudo}DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common 2>&1");
                Process::timeout(60)->run("{$sudo}add-apt-repository -y ppa:oisf/suricata-stable 2>&1");
            }

            Log::info('[Suricata] Running apt-get update...');
            Process::timeout(120)->run("{$sudo}apt-get update -qq 2>&1");

            Log::info('[Suricata] Installing suricata via apt-get...');
            $result = Process::timeout(600)->run("{$sudo}DEBIAN_FRONTEND=noninteractive apt-get install -y suricata 2>&1");
            if ($result->successful()) {
                // Run suricata-update to fetch ET Open rules
                Log::info('[Suricata] Running suricata-update...');
                Process::timeout(120)->run("{$sudo}suricata-update 2>&1");
                $version = null;
                try {
                    $vResult = Process::run('suricata -V 2>&1');
                    if (preg_match('/([\d.]+)/', $vResult->output(), $m)) {
                        $version = $m[1];
                    }
                } catch (\Exception $e) {
                    // Ignore
                }
                Log::info("[Suricata] Installation successful, version: {$version}");
                return ['success' => true, 'version' => $version];
            }
            $error = 'apt-get install suricata failed: ' . substr($result->output(), -500);
            Log::error("[Suricata] {$error}");
            return ['success' => false, 'error' => $error];
        }

        if (in_array($distro, ['centos', 'rhel', 'rocky', 'alma', 'fedora'])) {
            if ($distro === 'fedora') {
                $result = Process::timeout(600)->run("{$sudo}dnf install -y suricata 2>&1");
            } else {
                // Enable EPEL first
                Process::timeout(120)->run("{$sudo}yum install -y epel-release 2>&1");
                $result = Process::timeout(600)->run("{$sudo}yum install -y suricata 2>&1");
            }

            if ($result->successful()) {
                Process::timeout(120)->run("{$sudo}suricata-update 2>&1");
                return ['success' => true];
            }
            return ['success' => false, 'error' => 'Package install failed: ' . substr($result->output(), -500)];
        }

        return ['success' => false, 'error' => "Unsupported Linux distribution: {$distro}"];
    }

    /**
     * Install Suricata on macOS via Homebrew
     */
    private function installSuricataMac(): array
    {
        $brewPaths = ['/opt/homebrew/bin/brew', '/usr/local/bin/brew'];
        $brew = '';
        foreach ($brewPaths as $p) {
            if (file_exists($p)) {
                $brew = $p;
                break;
            }
        }

        if (empty($brew)) {
            return ['success' => false, 'error' => 'Homebrew not found, please install it first'];
        }

        // Homebrew must NOT run as root. If we're root (e.g. LaunchDaemon), run as the real user.
        $brewCmd = "{$brew} install suricata";
        if (posix_getuid() === 0) {
            // Find the actual user who owns the Homebrew prefix
            $brewOwner = trim(Process::run("stat -f '%Su' {$brew} 2>/dev/null || stat -c '%U' {$brew} 2>/dev/null")->output());
            if (!empty($brewOwner) && $brewOwner !== 'root') {
                $brewCmd = "sudo -u {$brewOwner} {$brew} install suricata";
            } else {
                return ['success' => false, 'error' => 'Cannot run Homebrew as root. Please install Suricata manually: brew install suricata'];
            }
        }

        $result = Process::timeout(600)->run("{$brewCmd} 2>&1");
        if ($result->successful()) {
            return ['success' => true];
        }

        return ['success' => false, 'error' => 'brew install suricata failed: ' . substr($result->output(), -500)];
    }

    /**
     * Install Suricata on Windows (MSI + WinDivert)
     *
     * Detects system architecture (x64/x86) and installs the correct version.
     * WinDivert driver is EV code-signed — no KMCI/Secure Boot issues.
     */
    private function installSuricataWindows(): array
    {
        Log::info('[Suricata] Installing on Windows with WinDivert...');

        // Detect system architecture
        $arch = $this->detectWindowsArchitecture();
        Log::info("[Suricata] Detected Windows architecture: {$arch}");

        // Set CYGWIN env var system-wide BEFORE installation to prevent TP_NUM_C_BUFS crash
        try {
            Process::timeout(10)->run('setx CYGWIN "tls_num_c_bufs:8192" /M 2>&1');
            Log::info('[Suricata] Set CYGWIN=tls_num_c_bufs:8192 system-wide');
        } catch (\Exception $e) {
            Log::warning('[Suricata] Failed to set CYGWIN env var: ' . $e->getMessage());
        }

        // Clean up broken 32-bit install on 64-bit system (0xc000007b fix)
        if ($arch === 'x64') {
            $this->cleanupBrokenSuricataInstall();
        }

        try {
            // Strategy 1: Try WinGet with correct architecture
            $archFlag = $arch === 'x64' ? ' --architecture x64' : '';
            $result = Process::timeout(600)->run("winget install OISF.Suricata --silent --accept-source-agreements{$archFlag} 2>&1");
            if ($result->successful() && !str_contains($result->output(), 'No applicable upgrade found')) {
                Log::info("[Suricata] Installed via WinGet ({$arch})");
                return ['success' => true, 'method' => 'winget'];
            }
            Log::debug('[Suricata] WinGet install result: ' . substr($result->output(), -300));

            // Strategy 2: Try Chocolatey
            $chocoPath = '';
            foreach (['C:\\ProgramData\\chocolatey\\choco.exe', 'C:\\ProgramData\\chocolatey\\bin\\choco.exe'] as $p) {
                if (file_exists($p)) {
                    $chocoPath = $p;
                    break;
                }
            }
            if (!empty($chocoPath)) {
                $result = Process::timeout(600)->run("\"{$chocoPath}\" install suricata -y 2>&1");
                if ($result->successful()) {
                    Log::info('[Suricata] Installed via Chocolatey');
                    return ['success' => true, 'method' => 'chocolatey'];
                }
            }

            // Strategy 3: Download official MSI (dynamically detect latest version)
            Log::info('[Suricata] Trying direct MSI download...');
            return $this->installSuricataViaMsi($arch);

        } catch (\Exception $e) {
            Log::error('[Suricata] Windows install failed: ' . $e->getMessage());
            return ['success' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Detect Windows system architecture (x64 or x86)
     */
    private function detectWindowsArchitecture(): string
    {
        // Method 1: Check PROCESSOR_ARCHITECTURE env var
        $procArch = getenv('PROCESSOR_ARCHITECTURE');
        if ($procArch === 'AMD64' || $procArch === 'ARM64') {
            return 'x64';
        }

        // Method 2: Check if Program Files (x86) exists (only on 64-bit Windows)
        if (is_dir('C:\\Program Files (x86)')) {
            return 'x64';
        }

        // Method 3: Use PowerShell
        try {
            $result = Process::timeout(10)->run('powershell -Command "[Environment]::Is64BitOperatingSystem" 2>&1');
            if (str_contains(strtolower(trim($result->output())), 'true')) {
                return 'x64';
            }
        } catch (\Exception $e) {
            // Ignore
        }

        return 'x86';
    }

    /**
     * Clean up broken Suricata installs (e.g. 32-bit on 64-bit Windows causing 0xc000007b)
     */
    private function cleanupBrokenSuricataInstall(): void
    {
        $x86Path = 'C:\\Program Files (x86)\\Suricata\\suricata.exe';
        $x64Path = 'C:\\Program Files\\Suricata\\suricata.exe';

        if (file_exists($x86Path) && !file_exists($x64Path)) {
            Log::warning('[Suricata] Found 32-bit Suricata on 64-bit Windows — uninstalling to fix 0xc000007b...');
            try {
                // Try to uninstall via winget first
                Process::timeout(120)->run('winget uninstall OISF.Suricata --silent 2>&1');
                Log::info('[Suricata] Uninstalled 32-bit Suricata via winget');
            } catch (\Exception $e) {
                // Try MSI uninstall
                try {
                    Process::timeout(120)->run('powershell -Command "Get-WmiObject Win32_Product | Where-Object { $_.Name -like \'*Suricata*\' } | ForEach-Object { $_.Uninstall() }" 2>&1');
                } catch (\Exception $e2) {
                    Log::warning('[Suricata] Could not auto-uninstall 32-bit Suricata: ' . $e2->getMessage());
                }
            }
        }
    }

    /**
     * Install Suricata via direct MSI download with architecture detection
     */
    private function installSuricataViaMsi(string $arch): array
    {
        $bitSuffix = $arch === 'x64' ? '64bit' : '32bit';
        $installDir = $arch === 'x64' ? 'C:\\Program Files\\Suricata' : 'C:\\Program Files (x86)\\Suricata';

        // Build PowerShell script that discovers the latest MSI URL dynamically
        $script = "\$ErrorActionPreference='SilentlyContinue'\r\n" .
            "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12\r\n" .
            "\$arch='{$bitSuffix}'\r\n" .
            "\$msiPath=\"\$env:TEMP\\suricata.msi\"\r\n" .
            "\r\n" .
            "# Try to find latest MSI from Suricata downloads page\r\n" .
            "\$downloadUrls = @(\r\n" .
            "    'https://www.openinfosecfoundation.org/download/windows/',\r\n" .
            "    'https://suricata.io/download/'\r\n" .
            ")\r\n" .
            "\$msiUrl = ''\r\n" .
            "foreach (\$baseUrl in \$downloadUrls) {\r\n" .
            "    try {\r\n" .
            "        \$page = (New-Object Net.WebClient).DownloadString(\$baseUrl)\r\n" .
            "        # Match MSI links for our architecture: Suricata-X.Y.Z-N-{64bit|32bit}.msi\r\n" .
            "        \$pattern = 'href=\"([^\"]*Suricata-[\\d.]+-\\d+-' + \$arch + '\\.msi)'\r\n" .
            "        if (\$page -match \$pattern) {\r\n" .
            "            \$msiUrl = \$matches[1]\r\n" .
            "            if (\$msiUrl -notmatch '^http') { \$msiUrl = \$baseUrl.TrimEnd('/') + '/' + \$msiUrl }\r\n" .
            "            Write-Output \"Found MSI: \$msiUrl\"\r\n" .
            "            break\r\n" .
            "        }\r\n" .
            "    } catch {\r\n" .
            "        Write-Output \"Could not fetch \$baseUrl\"\r\n" .
            "    }\r\n" .
            "}\r\n" .
            "\r\n" .
            "# Fallback: try known recent versions\r\n" .
            "if ([string]::IsNullOrEmpty(\$msiUrl)) {\r\n" .
            "    \$versions = @('8.0.3', '8.0.2', '8.0.1', '8.0.0', '7.0.10', '7.0.8', '7.0.7', '7.0.6')\r\n" .
            "    foreach (\$v in \$versions) {\r\n" .
            "        \$tryUrl = \"https://www.openinfosecfoundation.org/download/windows/Suricata-\$v-1-\$arch.msi\"\r\n" .
            "        try {\r\n" .
            "            \$req = [System.Net.WebRequest]::Create(\$tryUrl)\r\n" .
            "            \$req.Method = 'HEAD'\r\n" .
            "            \$req.Timeout = 10000\r\n" .
            "            \$resp = \$req.GetResponse()\r\n" .
            "            \$resp.Close()\r\n" .
            "            \$msiUrl = \$tryUrl\r\n" .
            "            Write-Output \"Found working MSI URL: \$msiUrl\"\r\n" .
            "            break\r\n" .
            "        } catch {\r\n" .
            "            continue\r\n" .
            "        }\r\n" .
            "    }\r\n" .
            "}\r\n" .
            "\r\n" .
            "if ([string]::IsNullOrEmpty(\$msiUrl)) {\r\n" .
            "    Write-Output 'SURICATA_NO_MSI_FOUND'\r\n" .
            "    exit 1\r\n" .
            "}\r\n" .
            "\r\n" .
            "# Download MSI\r\n" .
            "Write-Output 'Downloading Suricata MSI...'\r\n" .
            "try {\r\n" .
            "    (New-Object Net.WebClient).DownloadFile(\$msiUrl, \$msiPath)\r\n" .
            "} catch {\r\n" .
            "    Write-Output \"Download failed: \$_\"\r\n" .
            "    exit 1\r\n" .
            "}\r\n" .
            "\r\n" .
            "if (!(Test-Path \$msiPath)) {\r\n" .
            "    Write-Output 'MSI download failed'\r\n" .
            "    exit 1\r\n" .
            "}\r\n" .
            "\r\n" .
            "# Install MSI silently\r\n" .
            "Write-Output 'Installing Suricata MSI...'\r\n" .
            "\$p = Start-Process msiexec -ArgumentList '/i',\$msiPath,'/quiet','/norestart' -Wait -PassThru\r\n" .
            "Write-Output \"MSI exit code: \$(\$p.ExitCode)\"\r\n" .
            "\r\n" .
            "if (\$p.ExitCode -eq 0) {\r\n" .
            "    Write-Output 'SURICATA_INSTALL_OK'\r\n" .
            "\r\n" .
            "    # Check for WinDivert in both possible install locations\r\n" .
            "    \$searchPaths = @('C:\\Program Files\\Suricata', 'C:\\Program Files (x86)\\Suricata')\r\n" .
            "    \$windivert = \$null\r\n" .
            "    foreach (\$sp in \$searchPaths) {\r\n" .
            "        if (Test-Path \$sp) {\r\n" .
            "            \$windivert = Get-ChildItem -Path \$sp -Recurse -Filter 'WinDivert.dll' -ErrorAction SilentlyContinue\r\n" .
            "            if (\$windivert) { break }\r\n" .
            "        }\r\n" .
            "    }\r\n" .
            "    if (\$windivert) {\r\n" .
            "        Write-Output \"WinDivert found: \$(\$windivert.FullName)\"\r\n" .
            "    } else {\r\n" .
            "        Write-Output 'WinDivert not bundled, downloading...'\r\n" .
            "        \$wdUrl='https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip'\r\n" .
            "        \$wdZip=\"\$env:TEMP\\WinDivert.zip\"\r\n" .
            "        \$wdDir='{$installDir}'\r\n" .
            "        try {\r\n" .
            "            (New-Object Net.WebClient).DownloadFile(\$wdUrl, \$wdZip)\r\n" .
            "            Expand-Archive -Path \$wdZip -DestinationPath \$wdDir -Force\r\n" .
            "            Write-Output 'WinDivert deployed successfully'\r\n" .
            "        } catch {\r\n" .
            "            Write-Output \"WinDivert download failed: \$_\"\r\n" .
            "        }\r\n" .
            "    }\r\n" .
            "} else {\r\n" .
            "    Write-Output 'SURICATA_INSTALL_FAIL'\r\n" .
            "}\r\n";

        $r = Process::timeout(600)->run("powershell -NonInteractive -ExecutionPolicy Bypass -Command \"{$script}\"");
        $out = $r->output();
        Log::info('[Suricata] MSI install output: ' . substr($out, 0, 2000));

        if (str_contains($out, 'SURICATA_INSTALL_OK')) {
            return ['success' => true, 'method' => 'msi'];
        }

        return ['success' => false, 'error' => 'All Windows install methods failed. Output: ' . substr($out, -500)];
    }

    /**
     * Report an event to the Hub
     */
    public function reportAgentEvent(string $eventType, string $message, array $details = []): void
    {
        try {
            if (empty($this->wafUrl) || empty($this->agentToken)) {
                Log::warning('Cannot report event: Hub URL or token not configured');
                return;
            }

            $this->getHttpClient(10)
                ->post("{$this->wafUrl}/api/ids/agents/events", [
                    'token' => $this->agentToken,
                    'events' => [
                        [
                            'event_type' => $eventType,
                            'message' => $message,
                            'details' => $details ?: null,
                            'created_at' => now()->toIso8601String(),
                        ],
                    ],
                ]);
        } catch (\Exception $e) {
            Log::warning('Failed to report event to Hub: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle virus definitions update signal from Hub
     */
    private function handleDefinitionsUpdate(): void
    {
        try {
            Log::info('Virus definitions update signal received, running freshclam...');
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot update definitions');
                return;
            }
            
            // Run freshclam to update virus definitions
            $result = $clamav->updateDefinitions();
            
            if ($result['success']) {
                Log::info('Virus definitions updated successfully', [
                    'definitions_date' => $result['definitions_date'] ?? 'unknown',
                ]);
                
                // Report new definitions date to Hub
                $clamav->reportToHub([
                    'definitions_date' => $result['definitions_date'] ?? null,
                    'status' => 'healthy',
                ]);
            } else {
                Log::error('Virus definitions update failed: ' . ($result['message'] ?? 'Unknown error'));
            }
            
        } catch (\Exception $e) {
            Log::error('Definitions update failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle system reboot signal from WAF Hub
     */
    private function handleSystemReboot(): void
    {
        try {
            echo "⚠️ REBOOT SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('System reboot initiated by WAF Hub remote command');
            
            // Write to a file log that works even in scheduled task context
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\reboot.log'
                : base_path('storage/logs/reboot.log');
            $timestamp = date('Y-m-d H:i:s');
            file_put_contents($logFile, "[{$timestamp}] Reboot signal received from WAF Hub\n", FILE_APPEND);
            
            // Small delay to allow log to be written
            sleep(2);
            
            if (PHP_OS_FAMILY === 'Windows') {
                // Windows: Create a one-time scheduled task to reboot
                // This is more reliable than direct exec() in scheduled task context
                echo "🔄 Executing Windows restart command...\n";
                Log::info('Executing Windows restart command...');
                file_put_contents($logFile, "[{$timestamp}] Executing Windows restart via schtasks...\n", FILE_APPEND);
                
                $output = [];
                $returnCode = 0;
                
                // Method 1: Create a one-time scheduled task to run shutdown
                // This bypasses any exec() restrictions in the current scheduled task context
                $taskName = 'SecurityOneIDS-Reboot-' . time();
                $rebootTime = date('H:i', strtotime('+1 minute'));
                $rebootDate = date('Y/m/d');
                
                // Create task
                $createCommand = "schtasks /create /tn \"{$taskName}\" /tr \"shutdown /r /t 5 /f /c \\\"Security One IDS: Remote Reboot\\\"\" /sc once /st {$rebootTime} /sd {$rebootDate} /f /ru SYSTEM";
                exec($createCommand . ' 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] schtasks create result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                
                if ($returnCode === 0) {
                    // Run the task immediately
                    $output = [];
                    exec("schtasks /run /tn \"{$taskName}\" 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] schtasks run result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                }
                
                // Fallback: try direct shutdown if schtasks failed
                if ($returnCode !== 0) {
                    file_put_contents($logFile, "[{$timestamp}] schtasks failed, trying direct shutdown...\n", FILE_APPEND);
                    $output = [];
                    exec('C:\\Windows\\System32\\shutdown.exe /r /t 10 /f 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] Direct shutdown result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                }
                
                // Last resort: PowerShell
                if ($returnCode !== 0) {
                    file_put_contents($logFile, "[{$timestamp}] Trying PowerShell...\n", FILE_APPEND);
                    exec('powershell -Command "Restart-Computer -Force" 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] PowerShell result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                // macOS: Use shutdown command directly (osascript requires GUI session)
                echo "🔄 Executing macOS restart command...\n";
                Log::info('Executing macOS restart command...');
                file_put_contents($logFile, "[{$timestamp}] Executing macOS restart...\n", FILE_APPEND);
                
                // For launchd service, use shutdown command directly
                // sudo must be configured with NOPASSWD for this user/command
                $output = [];
                $returnCode = 0;
                
                // Method 1: Try shutdown with sudo (launchd runs as root)
                exec('sudo /sbin/shutdown -r now 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] shutdown result: code={$returnCode}, output=" . implode(' ', $output) . "\n", FILE_APPEND);
                
                if ($returnCode !== 0) {
                    // Method 2: Try without sudo (if running as root)
                    exec('/sbin/shutdown -r now 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] shutdown (no sudo) result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 3: Try reboot command
                    exec('sudo /sbin/reboot 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] reboot result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } else {
                // Linux: Use shutdown command
                echo "🔄 Executing Linux restart command...\n";
                Log::info('Executing Linux restart command...');
                exec('sudo shutdown -r +1 "Security One IDS Agent: Reboot requested by WAF Hub" 2>&1 &');
            }
            
            echo "✅ Reboot command dispatched\n";
            Log::info('Reboot command dispatched');
            file_put_contents($logFile, "[{$timestamp}] Reboot command dispatched successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to execute reboot: " . $e->getMessage() . "\n";
            Log::error('Failed to execute reboot: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle system lock signal from WAF Hub
     * Locks the screen to prevent login
     */
    private function handleSystemLock(): void
    {
        try {
            echo "⚠️ LOCK SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('System lock initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\lock.log'
                : base_path('storage/logs/lock.log');
            $timestamp = date('Y-m-d H:i:s');
            
            // Ensure log directory exists
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Lock signal received from WAF Hub\n", FILE_APPEND);
            
            if (PHP_OS_FAMILY === 'Windows') {
                // Windows: Lock workstation
                // Note: LockWorkStation() API doesn't work from Session 0 (service)
                // We need to run the lock command in the user's interactive session
                echo "🔒 Executing Windows lock command...\n";
                Log::info('Executing Windows lock command...');
                file_put_contents($logFile, "[{$timestamp}] Executing Windows lock...\n", FILE_APPEND);
                
                $output = [];
                $returnCode = 1;
                
                // Step 1: Find the currently logged-in user using multiple methods
                $userOutput = [];
                $username = null;
                
                // Method 1: Try query user (Windows Pro/Enterprise with RDS)
                exec('query user 2>&1', $userOutput, $rc);
                file_put_contents($logFile, "[{$timestamp}] query user output: " . implode(" ", $userOutput) . "\n", FILE_APPEND);
                
                foreach ($userOutput as $line) {
                    if (preg_match('/^>?(\S+)\s+\S+\s+\d+\s+Active/i', trim($line), $matches)) {
                        $username = $matches[1];
                        break;
                    }
                }
                
                // Method 2: Use wmic to get logged-in users
                if (!$username) {
                    $userOutput = [];
                    exec('wmic computersystem get username 2>&1', $userOutput, $rc);
                    file_put_contents($logFile, "[{$timestamp}] wmic username output: " . implode(" ", $userOutput) . "\n", FILE_APPEND);
                    foreach ($userOutput as $line) {
                        $line = trim($line);
                        // Format: DOMAIN\username or just username
                        if ($line && $line !== 'UserName' && stripos($line, 'username') === false) {
                            // Extract just the username part (after backslash if present)
                            if (strpos($line, '\\') !== false) {
                                $username = substr($line, strrpos($line, '\\') + 1);
                            } else {
                                $username = $line;
                            }
                            break;
                        }
                    }
                }
                
                // Method 3: Find explorer.exe owner
                if (!$username) {
                    $userOutput = [];
                    exec('tasklist /FI "IMAGENAME eq explorer.exe" /FO CSV /NH 2>&1', $userOutput, $rc);
                    file_put_contents($logFile, "[{$timestamp}] tasklist output: " . implode(" ", $userOutput) . "\n", FILE_APPEND);
                    // If explorer.exe is running, someone is logged in
                    if (!empty($userOutput) && strpos($userOutput[0], 'explorer.exe') !== false) {
                        // Get username from environment
                        $username = getenv('USERNAME') ?: null;
                    }
                }
                
                file_put_contents($logFile, "[{$timestamp}] Found active user: " . ($username ?? 'none') . "\n", FILE_APPEND);
                
                if ($username) {
                    // Method 1: Create scheduled task that runs as the interactive user
                    $lockScript = 'C:\\ProgramData\\SecurityOneIDS\\lock.vbs';
                    // Use VBScript which can interact with the desktop
                    $vbsContent = 'CreateObject("Wscript.Shell").Run "rundll32.exe user32.dll,LockWorkStation", 0, False';
                    file_put_contents($lockScript, $vbsContent);
                    
                    // Create task that runs as INTERACTIVE user (the one currently logged in)
                    $createCmd = 'schtasks /Create /TN "SecurityOneLock" /TR "wscript.exe \"' . $lockScript . '\"" /SC ONCE /ST 00:00 /F /RU "' . $username . '" /IT';
                    exec($createCmd . ' 2>&1', $output, $rc1);
                    file_put_contents($logFile, "[{$timestamp}] schtasks create for user '{$username}': code={$rc1}, output=" . implode(" ", array_slice($output, -3)) . "\n", FILE_APPEND);
                    
                    if ($rc1 === 0) {
                        // Run the task
                        exec('schtasks /Run /TN "SecurityOneLock" 2>&1', $output, $returnCode);
                        file_put_contents($logFile, "[{$timestamp}] schtasks run: code={$returnCode}\n", FILE_APPEND);
                        
                        // Wait and cleanup
                        sleep(3);
                        exec('schtasks /Delete /TN "SecurityOneLock" /F 2>&1');
                    }
                    @unlink($lockScript);
                }
                
                // Method 2: Try using logoff (more drastic but reliable)
                if ($returnCode !== 0) {
                    // Use msg command to notify then lock - this reaches interactive session
                    exec('msg * /TIME:1 "System will lock in 1 second..." 2>&1', $output, $rc);
                    sleep(1);
                    // Create a batch file and run via scheduled task with SYSTEM and /IT
                    $batchFile = 'C:\\ProgramData\\SecurityOneIDS\\lock.bat';
                    file_put_contents($batchFile, '@echo off' . "\r\n" . 'rundll32.exe user32.dll,LockWorkStation');
                    exec('schtasks /Create /TN "SysLock" /TR "' . $batchFile . '" /SC ONCE /ST 00:00 /F /RU SYSTEM /IT 2>&1', $output, $rc1);
                    exec('schtasks /Run /TN "SysLock" 2>&1', $output, $returnCode);
                    sleep(2);
                    exec('schtasks /Delete /TN "SysLock" /F 2>&1');
                    @unlink($batchFile);
                    file_put_contents($logFile, "[{$timestamp}] SYSTEM scheduled task result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                // macOS: Lock screen properly (not just sleep display)
                echo "🔒 Executing macOS lock command...\n";
                Log::info('Executing macOS lock command...');
                file_put_contents($logFile, "[{$timestamp}] Executing macOS lock...\n", FILE_APPEND);
                
                $output = [];
                $returnCode = 1;
                
                // Method 1: CGSession -suspend - this is the proper lock command
                // This immediately locks the screen and requires password to unlock
                exec('/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] CGSession -suspend result: code={$returnCode}\n", FILE_APPEND);
                
                if ($returnCode !== 0) {
                    // Method 2: Use osascript to simulate Ctrl+Command+Q (lock screen shortcut)
                    exec('osascript -e \'tell application "System Events" to keystroke "q" using {command down, control down}\' 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] osascript keystroke result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 3: Start screen saver (locks if password is required)
                    exec('osascript -e \'tell application "System Events" to start current screen saver\' 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] screen saver result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 4: pmset displaysleepnow as fallback
                    exec('pmset displaysleepnow 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] pmset result: code={$returnCode}\n", FILE_APPEND);
                }
                
            } else {
                // Linux: Try multiple methods
                echo "🔒 Executing Linux lock command...\n";
                Log::info('Executing Linux lock command...');
                file_put_contents($logFile, "[{$timestamp}] Executing Linux lock...\n", FILE_APPEND);
                
                // Method 1: loginctl (systemd-based systems)
                $output = [];
                $returnCode = 0;
                exec('loginctl lock-sessions 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] loginctl result: code={$returnCode}\n", FILE_APPEND);
                
                if ($returnCode !== 0) {
                    // Method 2: dm-tool (LightDM)
                    exec('dm-tool lock 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] dm-tool result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 3: gnome-screensaver
                    exec('gnome-screensaver-command -l 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] gnome-screensaver result: code={$returnCode}\n", FILE_APPEND);
                }
                
                if ($returnCode !== 0) {
                    // Method 4: xdg-screensaver
                    exec('xdg-screensaver lock 2>&1', $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] xdg-screensaver result: code={$returnCode}\n", FILE_APPEND);
                }
            }
            
            echo "✅ Lock command dispatched\n";
            Log::info('Lock command dispatched');
            file_put_contents($logFile, "[{$timestamp}] Lock command dispatched successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to execute lock: " . $e->getMessage() . "\n";
            Log::error('Failed to execute lock: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle system unlock signal from WAF Hub
     * Attempts to unlock the screen (limited by OS security)
     */
    private function handleSystemUnlock(): void
    {
        try {
            echo "⚠️ UNLOCK SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('System unlock initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\unlock.log'
                : base_path('storage/logs/unlock.log');
            $timestamp = date('Y-m-d H:i:s');
            
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Unlock signal received from WAF Hub\n", FILE_APPEND);
            
            // Note: Most OS don't allow remote unlock without password for security
            // This will attempt to activate/wake the display
            if (PHP_OS_FAMILY === 'Windows') {
                echo "🔓 Attempting Windows unlock (waking display)...\n";
                // Send key press to wake display
                exec('powershell -Command "[System.Windows.Forms.SendKeys]::SendWait(\' \')"  2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Windows wake result: code={$returnCode}\n", FILE_APPEND);
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                echo "🔓 Attempting macOS unlock (waking display)...\n";
                exec('caffeinate -u -t 1 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] macOS caffeinate result: code={$returnCode}\n", FILE_APPEND);
                
            } else {
                echo "🔓 Attempting Linux unlock...\n";
                exec('loginctl unlock-sessions 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Linux unlock result: code={$returnCode}\n", FILE_APPEND);
            }
            
            echo "✅ Unlock command dispatched\n";
            Log::info('Unlock command dispatched');
            file_put_contents($logFile, "[{$timestamp}] Unlock command dispatched\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to execute unlock: " . $e->getMessage() . "\n";
            Log::error('Failed to execute unlock: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle disable login signal from WAF Hub
     * Disables password authentication for all users
     */
    private function handleDisableLogin(): void
    {
        try {
            echo "⚠️ DISABLE LOGIN SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('Disable login initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\login_control.log'
                : base_path('storage/logs/login_control.log');
            $timestamp = date('Y-m-d H:i:s');
            
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Disable login signal received from WAF Hub\n", FILE_APPEND);
            
            if (PHP_OS_FAMILY === 'Windows') {
                echo "🚫 Disabling Windows user accounts...\n";
                // Disable all non-system user accounts
                exec('powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.Name -ne \'Administrator\'} | Disable-LocalUser" 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Windows disable users result: code={$returnCode}\n", FILE_APPEND);
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                echo "🚫 Disabling macOS user login...\n";
                // Get current console user (may be different from running user)
                $user = trim(exec("stat -f '%Su' /dev/console 2>/dev/null") ?: '');
                $cleanUser = preg_replace('/[\r\n]+/', ' ', $user);
                file_put_contents($logFile, "[{$timestamp}] Console user: {$cleanUser}\n", FILE_APPEND);
                
                if ($cleanUser && preg_match('/^[a-zA-Z0-9._-]+$/', $cleanUser) && $cleanUser !== 'root' && $cleanUser !== 'daemon' && $cleanUser !== 'nobody' && $cleanUser !== '_mbsetupuser') {
                    $dsclDisableExecuted = false;
                    $dsclDisableResult = null;
                    $pwpolicyDisableExecuted = false;
                    $pwpolicyDisableResult = null;
                    $dsclPasswdResult = null;

                    // Method 1: Use dscl to disable user account
                    // The correct way is to set AuthenticationAuthority to DisabledUser
                    try {
                        $process1 = new SymfonyProcess(['sudo', 'dscl', '.', '-create', '/Users/' . $cleanUser, 'AuthenticationAuthority', ';DisabledUser;']);
                        $process1->setTimeout(60);
                        $process1->run();
                        $dsclDisableExecuted = true;
                        $dsclDisableResult = $process1->getExitCode() ?? 1;
                        $outputStr = trim($process1->getOutput() . ' ' . $process1->getErrorOutput());
                        file_put_contents($logFile, "[{$timestamp}] dscl disable user {$cleanUser}: code={$dsclDisableResult}, output={$outputStr}\n", FILE_APPEND);
                    } catch (\Exception $e) {
                        file_put_contents($logFile, "[{$timestamp}] dscl disable user {$cleanUser} error: " . $e->getMessage() . "\n", FILE_APPEND);
                    }
                    
                    $method1Failed = !$dsclDisableExecuted || $dsclDisableResult !== 0;

                    if ($method1Failed) {
                        // Method 2: Lock the user's password (they won't be able to login)
                        try {
                            $process2 = new SymfonyProcess(['sudo', 'pwpolicy', '-u', $cleanUser, 'disableuser']);
                            $process2->setTimeout(60);
                            $process2->run();
                            $pwpolicyDisableExecuted = true;
                            $pwpolicyDisableResult = $process2->getExitCode() ?? 1;
                            file_put_contents($logFile, "[{$timestamp}] pwpolicy disable user {$cleanUser}: code={$pwpolicyDisableResult}\n", FILE_APPEND);
                        } catch (\Exception $e) {
                            file_put_contents($logFile, "[{$timestamp}] pwpolicy disable user {$cleanUser} error: " . $e->getMessage() . "\n", FILE_APPEND);
                        }
                    }
                    
                    $method2Failed = !$pwpolicyDisableExecuted || $pwpolicyDisableResult !== 0;

                    if ($method1Failed && $method2Failed) {
                        // Method 3: Set an impossible password hash
                        try {
                            $process3 = new SymfonyProcess(['sudo', 'dscl', '.', '-passwd', '/Users/' . $cleanUser, '*']);
                            $process3->setTimeout(60);
                            $process3->run();
                            $dsclPasswdResult = $process3->getExitCode() ?? 1;
                            file_put_contents($logFile, "[{$timestamp}] dscl set impossible password: code={$dsclPasswdResult}\n", FILE_APPEND);
                        } catch (\Exception $e) {
                            file_put_contents($logFile, "[{$timestamp}] dscl set impossible password error: " . $e->getMessage() . "\n", FILE_APPEND);
                        }
                    }
                } else {
                    file_put_contents($logFile, "[{$timestamp}] No valid console user found to disable\n", FILE_APPEND);
                }
                
            } else {
                echo "🚫 Disabling Linux user login...\n";
                // Lock all non-root users
                exec('for user in $(awk -F: \'$3 >= 1000 && $3 < 65534 {print $1}\' /etc/passwd); do passwd -l "$user" 2>/dev/null; done', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Linux disable users result: code={$returnCode}\n", FILE_APPEND);
            }
            
            echo "✅ Login disabled\n";
            Log::info('Login disabled');
            file_put_contents($logFile, "[{$timestamp}] Login disabled successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to disable login: " . $e->getMessage() . "\n";
            Log::error('Failed to disable login: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle enable login signal from WAF Hub
     * Restores password authentication for all users
     */
    private function handleEnableLogin(): void
    {
        try {
            echo "⚠️ ENABLE LOGIN SIGNAL RECEIVED FROM WAF HUB!\n";
            Log::warning('Enable login initiated by WAF Hub remote command');
            
            $logFile = PHP_OS_FAMILY === 'Windows' 
                ? 'C:\\ProgramData\\SecurityOneIDS\\logs\\login_control.log'
                : base_path('storage/logs/login_control.log');
            $timestamp = date('Y-m-d H:i:s');
            
            $logDir = dirname($logFile);
            if (!is_dir($logDir)) {
                @mkdir($logDir, 0755, true);
            }
            
            file_put_contents($logFile, "[{$timestamp}] Enable login signal received from WAF Hub\n", FILE_APPEND);
            
            if (PHP_OS_FAMILY === 'Windows') {
                echo "✅ Enabling Windows user accounts...\n";
                // Enable previously disabled users, but exclude system accounts (Guest, Administrator)
                exec('powershell -Command "Get-LocalUser | Where-Object {$_.Enabled -eq $false -and $_.Name -ne \'Guest\' -and $_.Name -ne \'Administrator\'} | Enable-LocalUser" 2>&1', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Windows enable users result: code={$returnCode}\n", FILE_APPEND);
                
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                echo "✅ Enabling macOS user login...\n";
                // Get all regular users and enable them
                $usersOutput = [];
                exec("dscl . -list /Users | grep -v '^_' | grep -v 'daemon' | grep -v 'nobody' | grep -v 'root' 2>/dev/null", $usersOutput, $rc);
                
                $failedUsers = [];
                foreach ($usersOutput as $user) {
                    $user = trim($user);
                    if (!$user) continue;
                    
                    $cleanUser = (string) preg_replace('/[\r\n]+/', ' ', $user);

                    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $cleanUser)) continue;

                    $dsclClearExecuted = false;
                    $dsclClearResult = null;
                    $pwpolicyEnableExecuted = false;
                    $pwpolicyEnableResult = null;

                    // Remove DisabledUser from AuthenticationAuthority
                    try {
                        $process1 = new SymfonyProcess(['sudo', 'dscl', '.', '-delete', '/Users/' . $cleanUser, 'AuthenticationAuthority']);
                        $process1->setTimeout(60);
                        $process1->run();
                        $dsclClearExecuted = true;
                        $dsclClearResult = $process1->getExitCode() ?? 1;
                        file_put_contents($logFile, "[{$timestamp}] dscl clear auth for {$cleanUser}: code={$dsclClearResult}\n", FILE_APPEND);
                    } catch (\Exception $e) {
                        file_put_contents($logFile, "[{$timestamp}] dscl clear auth for {$cleanUser} error: " . $e->getMessage() . "\n", FILE_APPEND);
                    }
                    
                    // Re-enable with pwpolicy  
                    try {
                        $process2 = new SymfonyProcess(['sudo', 'pwpolicy', '-u', $cleanUser, 'enableuser']);
                        $process2->setTimeout(60);
                        $process2->run();
                        $pwpolicyEnableExecuted = true;
                        $pwpolicyEnableResult = $process2->getExitCode() ?? 1;
                        file_put_contents($logFile, "[{$timestamp}] pwpolicy enable user {$cleanUser}: code={$pwpolicyEnableResult}\n", FILE_APPEND);
                    } catch (\Exception $e) {
                        file_put_contents($logFile, "[{$timestamp}] pwpolicy enable user {$cleanUser} error: " . $e->getMessage() . "\n", FILE_APPEND);
                    }

                    $dsclSuccess = $dsclClearExecuted && $dsclClearResult === 0;
                    $pwpolicySuccess = $pwpolicyEnableExecuted && $pwpolicyEnableResult === 0;

                    if ($dsclSuccess !== $pwpolicySuccess) {
                        Log::warning("Partial success: dscl=" . ($dsclSuccess ? 'success' : 'failed') . " pwpolicy=" . ($pwpolicySuccess ? 'success' : 'failed') . " for user {$cleanUser}");
                    }

                    $success = $dsclSuccess && $pwpolicySuccess;
                    if (!$success) {
                        Log::error("Critical failure: Could not fully enable user {$cleanUser} via dscl and pwpolicy.");
                        $failedUsers[] = $cleanUser;
                        continue;
                    }
                }

                if (!empty($failedUsers)) {
                    Log::error("Critical failure: Could not enable the following users: " . implode(', ', $failedUsers));
                }
                
            } else {
                echo "✅ Enabling Linux user login...\n";
                exec('for user in $(awk -F: \'$3 >= 1000 && $3 < 65534 {print $1}\' /etc/passwd); do passwd -u "$user" 2>/dev/null; done', $output, $returnCode);
                file_put_contents($logFile, "[{$timestamp}] Linux enable users result: code={$returnCode}\n", FILE_APPEND);
            }
            
            echo "✅ Login enabled\n";
            Log::info('Login enabled');
            file_put_contents($logFile, "[{$timestamp}] Login enabled successfully\n", FILE_APPEND);
            
        } catch (\Exception $e) {
            echo "❌ Failed to enable login: " . $e->getMessage() . "\n";
            Log::error('Failed to enable login: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle blocked IPs from WAF Hub
     * Syncs the list of IPs that should be blocked locally
     */
    private function handleBlockedIps(array $blockedIps): void
    {
        try {
            $blockingService = app(\App\Services\BlockingService::class);
            $localBlocked = $blockingService->getBlockedIPs();
            
            $hubIps = array_column($blockedIps, 'ip');
            $localIps = array_keys($localBlocked);
            
            // Block new IPs from Hub
            $newBlocks = array_diff($hubIps, $localIps);
            foreach ($newBlocks as $ip) {
                $blockData = collect($blockedIps)->firstWhere('ip', $ip);
                if ($blockData) {
                    Log::info("Blocking IP from WAF Hub: {$ip}", ['reason' => $blockData['reason']]);
                    echo "🚫 Blocking IP from Hub: {$ip}\n";
                    $blockingService->blockIP(
                        $ip,
                        $blockData['reason'] ?? 'Blocked by WAF Hub',
                        'high',
                        $blockData['duration'] ?? null
                    );
                }
            }
            
            // Unblock IPs that are no longer in Hub list
            $staleBlocks = array_diff($localIps, $hubIps);
            foreach ($staleBlocks as $ip) {
                // Only unblock if it was originally from Hub (check reason)
                if (isset($localBlocked[$ip]) && str_contains($localBlocked[$ip]['reason'] ?? '', 'Hub')) {
                    Log::info("Unblocking IP removed from WAF Hub: {$ip}");
                    echo "✅ Unblocking IP (removed from Hub): {$ip}\n";
                    $blockingService->unblockIP($ip);
                }
            }
            
            if (count($newBlocks) > 0 || count($staleBlocks) > 0) {
                Log::info('Blocked IPs synced from WAF Hub', [
                    'new_blocks' => count($newBlocks),
                    'removed_blocks' => count($staleBlocks),
                    'total_active' => count($hubIps),
                ]);
            }
            
        } catch (\Exception $e) {
            Log::error('Failed to handle blocked IPs: ' . $e->getMessage());
        }
    }
    
    /**
     * Check if remote has newer code and auto-update if needed
     *
     * Compares local HEAD commit hash against origin/main.
     * No version number comparison — purely git commit based.
     */
    private function checkAndAutoUpdate(): void
    {
        try {
            $installDir = base_path();

            // Throttle: only check once every 5 minutes
            $lastCheckFile = storage_path('app/last_auto_update_check.txt');
            if (file_exists($lastCheckFile)) {
                $lastCheck = (int) file_get_contents($lastCheckFile);
                if (time() - $lastCheck < 300) {
                    return;
                }
            }
            file_put_contents($lastCheckFile, time());

            // Fetch latest from remote (lightweight operation)
            $fetchResult = Process::path($installDir)
                ->timeout(30)
                ->run('git fetch origin main 2>&1');

            if (!$fetchResult->successful()) {
                Log::debug('Auto-update: git fetch failed', ['output' => $fetchResult->output()]);
                return;
            }

            // Compare local HEAD vs remote HEAD
            $localHash = trim(Process::path($installDir)
                ->run('git rev-parse HEAD 2>/dev/null')
                ->output());

            $remoteHash = trim(Process::path($installDir)
                ->run('git rev-parse origin/main 2>/dev/null')
                ->output());

            if (empty($localHash) || empty($remoteHash)) {
                return;
            }

            if ($localHash === $remoteHash) {
                Log::debug('Auto-update: already up to date', ['hash' => substr($localHash, 0, 8)]);
                return;
            }

            Log::info('Auto-update: new code detected, updating...', [
                'local' => substr($localHash, 0, 8),
                'remote' => substr($remoteHash, 0, 8),
            ]);

            $this->reportAgentEvent('code_update', 'Auto-update: detecting new code version, updating...');
            $this->handleIdsUpdate();

        } catch (\Exception $e) {
            Log::debug('Auto-update check failed: ' . $e->getMessage());
        }
    }

    /**
     * Handle IDS update signal
     */
    private function handleIdsUpdate(): void
    {
        try {
            Log::info('IDS update signal received, starting update...');
            
            // Report "updating" status to WAF Hub
            $this->reportUpdateStatus('updating');
            
            // Get install directory and detect platform
            $installDir = base_path();
            $isWindows = PHP_OS_FAMILY === 'Windows';
            $isDocker = file_exists('/.dockerenv') || getenv('DOCKER_CONTAINER');
            
            // Force update: fetch + reset --hard to avoid conflicts with local changes
            Log::info('Fetching latest code from git...', ['platform' => $isWindows ? 'windows' : 'unix']);
            
            if ($isWindows) {
                // Windows: Use cmd.exe for better output capturing
                $gitResult = Process::path($installDir)
                    ->timeout(300)
                    ->run('cmd /c "git fetch origin main 2>&1 && git reset --hard origin/main 2>&1"');
                
                // Log both output and error for debugging
                Log::info('Git command completed', [
                    'output' => $gitResult->output(),
                    'error' => $gitResult->errorOutput(),
                    'exitCode' => $gitResult->exitCode(),
                ]);
            } else {
                // Clean untracked files that might conflict, then force update
                Process::path($installDir)
                    ->timeout(30)
                    ->run('git clean -fd 2>&1');
                    
                $gitResult = Process::path($installDir)
                    ->timeout(300)
                    ->run('git fetch origin main 2>&1 && git reset --hard origin/main 2>&1');
            }
            
            if (!$gitResult->successful()) {
                $errorMsg = $gitResult->output() ?: $gitResult->errorOutput() ?: 'Unknown error (exit code: ' . $gitResult->exitCode() . ')';
                Log::error('Git pull failed: ' . $errorMsg);
                $this->reportUpdateStatus('error');
                return;
            }
            
            Log::info('Git pull successful', ['output' => $gitResult->output()]);
            
            // Clear Suricata install failure cache — new code might fix the issue
            @unlink(storage_path('app/suricata_install_failed.txt'));

            // Clear Suricata rules hash — force re-sync so updated converter re-processes rules
            @unlink(storage_path('app/suricata_rules_hash.txt'));
            Log::info('Cleared Suricata rules hash to force re-sync with updated code');
            
            // Run composer install
            Log::info('Running composer install...');
            
            if ($isWindows) {
                // Windows: Find composer and run with PowerShell
                $composerCmd = 'composer';
                
                // Check if composer.phar exists in directory
                if (file_exists($installDir . '/composer.phar')) {
                    $composerCmd = 'php composer.phar';
                } elseif (file_exists($installDir . '/composer.bat')) {
                    $composerCmd = 'composer.bat';
                }
                
                $composerResult = Process::path($installDir)
                    ->timeout(600)
                    ->env(['COMPOSER_ALLOW_SUPERUSER' => '1'])
                    ->run("powershell -Command \"{$composerCmd} install --no-interaction --no-dev --optimize-autoloader 2>&1\"");
            } else {
                $homeDir = getenv('HOME') ?: (PHP_OS_FAMILY === 'Darwin' ? '/Users/' . get_current_user() : '/home/' . get_current_user());
                $composerResult = Process::path($installDir)
                    ->timeout(600)
                    ->env([
                        'HOME' => $homeDir,
                        'COMPOSER_HOME' => $homeDir . '/.composer',
                        'COMPOSER_ALLOW_SUPERUSER' => '1',
                    ])
                    ->run('composer install --no-interaction --no-dev --optimize-autoloader 2>&1');
            }
            
            if (!$composerResult->successful()) {
                Log::warning('Composer install warning: ' . $composerResult->output());
                // Continue anyway, might just be warnings
            }
            
            // Run database migrations if any
            Log::info('Running database migrations...');
            Artisan::call('migrate', ['--force' => true]);
            
            // Clear caches
            Log::info('Clearing caches...');
            Artisan::call('config:clear');
            Artisan::call('cache:clear');
            
            // Force PHP to reload updated source files (critical for code updates)
            if (function_exists('opcache_reset')) {
                opcache_reset();
                Log::info('PHP opcache cleared');
            }
            
            // Handle environment-specific restart
            if ($isDocker) {
                Log::info('Docker environment detected, triggering container rebuild...');
                
                $rebuildScript = $installDir . '/docker/rebuild.sh';
                if (file_exists($rebuildScript)) {
                    Log::info('Running Docker rebuild script...');
                    exec("nohup bash {$rebuildScript} >> /var/www/html/storage/logs/docker-rebuild.log 2>&1 &");
                } else {
                    file_put_contents($installDir . '/storage/rebuild_requested', date('Y-m-d H:i:s'));
                    Log::info('Docker rebuild marker created, waiting for external rebuild...');
                }
            } elseif ($isWindows) {
                // Windows: Restart PHP process or Windows service if applicable
                Log::info('Windows update completed, regenerating sync script...');
                
                // Regenerate the sync service script with latest template
                $this->regenerateWindowsSyncScript($installDir);
                
                Log::info('Windows sync script regenerated, no automatic restart required');
                // Note: Windows Agent typically runs as a scheduled task or service
                // The next heartbeat will pick up the new code
            }
            
            // Get new version from config
            $newVersion = config('ids.version') ?? '1.0.0';
            
            Log::info('IDS update completed successfully', ['new_version' => $newVersion]);
            
            // Mark that code was updated — skip rule sync in this cycle
            // because PHP still has old classes in memory
            $this->codeUpdated = true;
            
            // Report "completed" status to WAF Hub with new version
            $this->reportUpdateStatus('completed', $newVersion);
            
            // Mark update as processed locally
            $configPath = storage_path('app/waf_config.json');
            if (file_exists($configPath)) {
                $config = json_decode(file_get_contents($configPath), true) ?: [];
                unset($config['addons']['update_ids']);
                file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT));
            }
        } catch (\Exception $e) {
            Log::error('IDS update failed: ' . $e->getMessage());
            $this->reportUpdateStatus('error');
        }
    }
    
    /**
     * Report update status to WAF Hub
     */
    private function reportUpdateStatus(string $status, ?string $version = null): void
    {
        try {
            $wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');
            
            // Read token from .env
            $envPath = base_path('.env');
            $token = env('AGENT_TOKEN', '');
            
            if (empty($token) && file_exists($envPath)) {
                $envContent = file_get_contents($envPath);
                if (preg_match('/^AGENT_TOKEN=(.*)$/m', $envContent, $matches)) {
                    $token = trim($matches[1], '"\'');
                }
            }
            
            if (empty($wafUrl) || empty($token)) {
                Log::warning('Cannot report update status: WAF not configured');
                return;
            }
            
            $payload = [
                'update_status' => $status,
            ];
            
            if ($version) {
                $payload['version'] = $version;
            }
            
            $response = $this->getHttpClient(30)
                ->withToken($token)
                ->post("{$wafUrl}/api/ids/agents/update-status", $payload);
            
            if ($response->successful()) {
                Log::info("Update status '{$status}' reported successfully");
            } else {
                Log::error('Failed to report update status', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
            }
        } catch (\Exception $e) {
            Log::error('Failed to report update status: ' . $e->getMessage());
        }
    }
    
    /**
     * Handle scan now signal from WAF Hub
     */
    private function handleScanNow(): void
    {
        try {
            Log::info('Scan now signal received, starting ClamAV scan...');
            
            $clamav = app(\App\Services\ClamavService::class);
            
            if (!$clamav->isInstalled()) {
                Log::warning('ClamAV not installed, cannot perform scan');
                return;
            }
            
            // Use platform-specific scan paths
            $platform = match (PHP_OS_FAMILY) {
                'Windows' => 'windows',
                'Darwin' => 'macos',
                default => 'linux',
            };
            
            // Determine scan type from config
            $config = $this->getSyncedConfig();
            $scanType = $config['scan_type'] ?? 'quick';
            
            if ($platform === 'windows') {
                if ($scanType === 'full') {
                    $scanPaths = [
                        'C:\\Users',
                        'C:\\Program Files',
                        'C:\\Program Files (x86)',
                        'C:\\Windows\\Temp',
                    ];
                } else {
                    // Quick scan — user profiles and temp only
                    $scanPaths = [
                        'C:\\Users',
                        'C:\\Windows\\Temp',
                    ];
                }
            } elseif ($platform === 'macos') {
                $scanPaths = [
                    '/Users',
                    '/Applications',
                    '/tmp',
                ];
            } else {
                $scanPaths = [
                    '/home',
                    '/var/www',
                    '/tmp',
                ];
            }
            
            Log::info("Starting ClamAV scan on {$platform}", ['paths' => $scanPaths]);
            
            // Send "scanning" status to WAF Hub immediately
            $clamav->reportToHub(['scan_status' => 'scanning']);
            
            $allResults = [
                'last_scan' => now()->toDateTimeString(),
                'infected_files' => 0,
                'scanned_files' => 0,
                'threats' => [],
                'scan_status' => 'scanning',
            ];
            
            foreach ($scanPaths as $path) {
                if (is_dir($path)) {
                    Log::info("Scanning directory: {$path}");
                    $result = $clamav->scan($path);
                    
                    if ($result['success']) {
                        $allResults['scanned_files'] += $result['scanned_files'] ?? 0;
                        $allResults['infected_files'] += $result['infected_files'] ?? 0;
                        $allResults['threats'] = array_merge($allResults['threats'], $result['threats'] ?? []);
                    }
                }
            }
            
            Log::info('ClamAV scan completed', [
                'scanned_files' => $allResults['scanned_files'],
                'infected_files' => $allResults['infected_files'],
            ]);
            
            // Report completed results to WAF Hub with idle status
            $allResults['scan_status'] = 'idle';
            $clamav->reportToHub($allResults);
            
        } catch (\Exception $e) {
            Log::error('Scan now failed: ' . $e->getMessage());
            
            // Report error status
            try {
                $clamav = app(\App\Services\ClamavService::class);
                $clamav->reportToHub(['scan_status' => 'idle']);
            } catch (\Exception $ex) {
                // Ignore
            }
        }
    }

    /**
     * Get synced config from local storage
     */
    public function getSyncedConfig(): array
    {
        $configPath = storage_path('app/waf_config.json');
        
        if (file_exists($configPath)) {
            return json_decode(file_get_contents($configPath), true) ?: [];
        }
        
        return [];
    }

    /**
     * Report alerts to WAF
     */
    public function reportAlerts(array $alerts): bool
    {
        if (empty($this->wafUrl) || empty($this->agentToken) || empty($alerts)) {
            return false;
        }

        try {
            $response = $this->getHttpClient(30)->post("{$this->wafUrl}/api/ids/agents/alerts", [
                'token' => $this->agentToken,
                'alerts' => $alerts,
            ]);

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Failed to report alerts: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Fetch rules from WAF
     */
    public function fetchRules(): ?array
    {
        if (empty($this->wafUrl) || empty($this->agentToken)) {
            return null;
        }

        try {
            $response = $this->getHttpClient(30)->get("{$this->wafUrl}/api/ids/agents/rules", [
                'token' => $this->agentToken,
            ]);

            if ($response->successful()) {
                return $response->json();
            }

            return null;
        } catch (\Exception $e) {
            Log::error('Failed to fetch rules: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Sync rules from WAF to local IdsSignature database
     */
    public function syncRulesToDatabase(array $rules): int
    {
        $synced = 0;
        
        foreach ($rules as $rule) {
            try {
                \App\Models\IdsSignature::updateOrCreate(
                    ['name' => $rule['name']],
                    [
                        'description' => $rule['description'] ?? null,
                        'pattern' => $rule['pattern'] ?? '',
                        'category' => $rule['category'] ?? 'general',
                        'severity' => $rule['severity'] ?? 'medium',
                        'match_uri' => true,
                        'match_user_agent' => false,
                        'match_referer' => false,
                        'enabled' => $rule['enabled'] ?? true,
                    ]
                );
                $synced++;
            } catch (\Exception $e) {
                Log::error('Failed to sync rule: ' . ($rule['name'] ?? 'unknown'), [
                    'error' => $e->getMessage(),
                ]);
            }
        }
        
        Log::info("Synced {$synced} rules from WAF to local database");
        return $synced;
    }

    /**
     * Upload local signatures to WAF Hub
     */
    public function uploadSignatures(): int
    {
        if (empty($this->wafUrl)) {
            Log::warning('WAF_URL not configured for upload');
            return 0;
        }

        // Use the WAF-assigned token (from registration) if available
        $token = cache()->get('waf_agent_token', $this->agentToken);
        if (empty($token)) {
            Log::warning('No agent token available for upload');
            return 0;
        }

        // Get all local signatures
        $signatures = \App\Models\IdsSignature::where('enabled', true)->get();
        
        if ($signatures->isEmpty()) {
            Log::info('No signatures to upload');
            return 0;
        }

        try {
            $response = $this->getHttpClient(60)->post("{$this->wafUrl}/api/ids/agents/sync-rules", [
                'token' => $token,
                'signatures' => $signatures->map(fn($sig) => [
                    'name' => $sig->name,
                    'pattern' => $sig->pattern,
                    'category' => $sig->category,
                    'severity' => $sig->severity,
                    'description' => $sig->description,
                ])->toArray(),
            ]);

            if ($response->successful()) {
                $data = $response->json();
                Log::info('Successfully uploaded signatures to WAF', $data);
                return $data['synced'] ?? 0;
            }

            Log::error('Failed to upload signatures', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return 0;
        } catch (\Exception $e) {
            Log::error('Exception during signature upload: ' . $e->getMessage());
            return 0;
        }
    }

    /**
     * Get the last git pull/fetch time from FETCH_HEAD or .git/refs/heads/main
     */
    protected function getLastGitPullTime(): ?string
    {
        $basePath = base_path();
        
        // Check FETCH_HEAD (updated on git fetch/pull)
        $fetchHead = "{$basePath}/.git/FETCH_HEAD";
        if (file_exists($fetchHead)) {
            $mtime = filemtime($fetchHead);
            if ($mtime) {
                return date('Y-m-d H:i:s', $mtime);
            }
        }
        
        // Fallback: check refs/heads/main or master
        $refs = [
            "{$basePath}/.git/refs/heads/main",
            "{$basePath}/.git/refs/heads/master",
        ];
        
        foreach ($refs as $ref) {
            if (file_exists($ref)) {
                $mtime = filemtime($ref);
                if ($mtime) {
                    return date('Y-m-d H:i:s', $mtime);
                }
            }
        }
        
        // Last fallback: use git log to get last commit time
        $output = @shell_exec("cd {$basePath} && git log -1 --format=%ci 2>/dev/null");
        if ($output) {
            return trim($output);
        }
        
        return null;
    }

    /**
     * Get discovered log file paths for heartbeat
     *
     * Cached for 5 minutes to avoid rescanning every heartbeat
     */
    /**
     * Collect recent agent log entries for upload to Hub
     */
    protected function collectRecentLogs(): array
    {
        $logs = [];
        $lastSentFile = storage_path('app/last_log_position.json');
        $maxLines = 100;
        
        // Get the current log file
        $logFile = storage_path('logs/laravel-' . date('Y-m-d') . '.log');
        if (!file_exists($logFile)) {
            $logFile = storage_path('logs/laravel.log');
        }
        if (!file_exists($logFile)) {
            return [];
        }
        
        // Read last sent position
        $lastPosition = 0;
        if (file_exists($lastSentFile)) {
            $posData = json_decode(file_get_contents($lastSentFile), true);
            if (($posData['file'] ?? '') === $logFile) {
                $lastPosition = $posData['position'] ?? 0;
            }
        }
        
        $fileSize = filesize($logFile);
        if ($fileSize <= $lastPosition) {
            // File was rotated or no new content
            $lastPosition = max(0, $fileSize - 50000); // Read last ~50KB on rotation
        }
        
        $handle = fopen($logFile, 'r');
        if (!$handle) {
            return [];
        }
        
        fseek($handle, $lastPosition);
        $newContent = fread($handle, min($fileSize - $lastPosition, 100000)); // Max 100KB
        $newPosition = ftell($handle);
        fclose($handle);
        
        // Save position for next sync
        file_put_contents($lastSentFile, json_encode([
            'file' => $logFile,
            'position' => $newPosition,
        ]));
        
        if (empty($newContent)) {
            return [];
        }
        
        // Parse log entries
        $lines = explode("\n", $newContent);
        $currentEntry = null;
        
        foreach ($lines as $line) {
            $line = trim($line);
            if (empty($line)) {
                continue;
            }
            
            // Match Laravel log format: [2026-01-01 00:00:00] environment.LEVEL: message
            if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+\w+\.(\w+):\s+(.+)$/', $line, $m)) {
                if ($currentEntry) {
                    $logs[] = $currentEntry;
                }
                $currentEntry = [
                    'timestamp' => $m[1],
                    'level' => strtolower($m[2]),
                    'message' => $m[3],
                ];
            } elseif ($currentEntry) {
                // Append continuation line (stack traces, etc.)
                $currentEntry['message'] .= "\n" . $line;
            }
        }
        
        if ($currentEntry) {
            $logs[] = $currentEntry;
        }
        
        // Keep only the last N entries, prioritize WARNING/ERROR
        if (count($logs) > $maxLines) {
            // Split into important and info logs
            $important = array_filter($logs, fn($l) => in_array($l['level'], ['warning', 'error', 'critical', 'emergency']));
            $info = array_filter($logs, fn($l) => !in_array($l['level'], ['warning', 'error', 'critical', 'emergency']));
            
            // Take all important + recent info up to limit
            $important = array_slice($important, -$maxLines);
            $remaining = $maxLines - count($important);
            if ($remaining > 0) {
                $info = array_slice($info, -$remaining);
            } else {
                $info = [];
            }
            
            $logs = array_merge($important, $info);
            // Sort by timestamp
            usort($logs, fn($a, $b) => $a['timestamp'] <=> $b['timestamp']);
        }
        
        // Truncate long messages
        foreach ($logs as &$log) {
            if (strlen($log['message']) > 2000) {
                $log['message'] = substr($log['message'], 0, 2000) . '... (truncated)';
            }
        }
        
        return array_values($logs);
    }

    protected function getDiscoveredLogPaths(): array
    {
        $cacheFile = storage_path('app/discovered_logs_cache.json');
        
        // Use cached result if less than 5 minutes old
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < 300) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if (is_array($cached)) {
                return $cached;
            }
        }

        try {
            $discovery = app(\App\Services\LogDiscoveryService::class);
            $logs = $discovery->discoverLogFiles()->map(fn($log) => [
                'path' => $log['path'],
                'type' => $log['type'],
                'format' => $log['format'] ?? 'unknown',
                'size' => $log['size'] ?? 0,
            ])->values()->toArray();

            // Cache the result
            file_put_contents($cacheFile, json_encode($logs));

            return $logs;
        } catch (\Exception $e) {
            Log::debug('Log discovery failed: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get system information
     */
    protected function getSystemInfo(): array
    {
        // Include Snort status in system info for Hub
        $snortInfo = $this->getSnortInfo();
        // Include Suricata status in system info for Hub
        $suricataInfo = $this->getSuricataInfo();

        return [
            'os' => PHP_OS,
            'php_version' => PHP_VERSION,
            'memory_usage' => memory_get_usage(true),
            'load_average' => function_exists('sys_getloadavg') ? sys_getloadavg() : [],
            'uptime' => $this->getUptime(),
            // Enhanced system metrics for WAF Hub display
            'cpu' => $this->getCpuUsage(),
            'memory' => $this->getMemoryUsage(),
            'disk' => $this->getDiskUsage(),
            'network' => $this->getNetworkUsage(),
            // Snort IPS status
            'snort' => $snortInfo,
            // Suricata IDS/IPS status
            'suricata' => $suricataInfo,
        ];
    }

    /**
     * Get Snort IPS status information for heartbeat (deprecated — always returns disabled)
     */
    private function getSnortInfo(): array
    {
        return [
            'installed' => false,
            'version' => null,
            'running' => false,
            'engine' => 'deprecated',
        ];
    }

    /**
     * Get Suricata IDS/IPS status information for heartbeat
     */
    private function getSuricataInfo(): array
    {
        try {
            $suricata = app(\App\Services\Detection\SuricataEngine::class);
            return $suricata->getStatus();
        } catch (\Exception $e) {
            return [
                'installed' => false,
                'version' => null,
                'running' => false,
            ];
        }
    }

    /**
     * Get CPU usage percentage
     */
    protected function getCpuUsage(): array
    {
        $percent = 0;
        
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: Use wmic
            $output = [];
            @exec('wmic cpu get loadpercentage 2>&1', $output);
            foreach ($output as $line) {
                $line = trim($line);
                if (is_numeric($line)) {
                    $percent = (float) $line;
                    break;
                }
            }
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            // macOS: Use top or ps
            $output = @shell_exec("ps -A -o %cpu | awk '{s+=$1} END {print s}'");
            if ($output) {
                $percent = min(100, (float) trim($output));
            }
        } else {
            // Linux: Read from /proc/stat
            if (file_exists('/proc/stat')) {
                $stat1 = file_get_contents('/proc/stat');
                usleep(100000); // 100ms
                $stat2 = file_get_contents('/proc/stat');
                
                preg_match('/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m', $stat1, $m1);
                preg_match('/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m', $stat2, $m2);
                
                if ($m1 && $m2) {
                    $total1 = $m1[1] + $m1[2] + $m1[3] + $m1[4];
                    $total2 = $m2[1] + $m2[2] + $m2[3] + $m2[4];
                    $idle1 = $m1[4];
                    $idle2 = $m2[4];
                    
                    $totalDiff = $total2 - $total1;
                    $idleDiff = $idle2 - $idle1;
                    
                    if ($totalDiff > 0) {
                        $percent = round((1 - $idleDiff / $totalDiff) * 100, 1);
                    }
                }
            }
        }
        
        return ['percent' => $percent];
    }

    /**
     * Get memory usage
     */
    protected function getMemoryUsage(): array
    {
        $total = 0;
        $used = 0;
        $percent = 0;
        
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: Use wmic
            $output = [];
            @exec('wmic OS get FreePhysicalMemory,TotalVisibleMemorySize /value 2>&1', $output);
            $values = [];
            foreach ($output as $line) {
                if (preg_match('/^(\w+)=(\d+)/', trim($line), $m)) {
                    $values[$m[1]] = (int) $m[2] * 1024; // KB to bytes
                }
            }
            $total = $values['TotalVisibleMemorySize'] ?? 0;
            $free = $values['FreePhysicalMemory'] ?? 0;
            $used = $total - $free;
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            // macOS: Use vm_stat and sysctl
            $vmstat = @shell_exec('vm_stat 2>/dev/null');
            
            // Get page size (typically 4096 or 16384 on ARM Macs)
            $pageSize = 4096;
            if ($vmstat && preg_match('/page size of (\d+) bytes/', $vmstat, $m)) {
                $pageSize = (int) $m[1];
            }
            
            // Get total memory from sysctl
            $totalOutput = @shell_exec('sysctl -n hw.memsize 2>/dev/null');
            $total = $totalOutput ? (int) trim($totalOutput) : 0;
            
            if ($vmstat && $total > 0) {
                // Parse vm_stat - note: output uses "." at end of numbers
                $stats = [];
                preg_match_all('/^(.+?):\s+([\d.]+)/m', $vmstat, $matches, PREG_SET_ORDER);
                foreach ($matches as $match) {
                    $key = trim($match[1]);
                    $value = (int) str_replace('.', '', $match[2]);
                    $stats[$key] = $value;
                }
                
                // Calculate used memory: active + wired + compressed
                $activePages = $stats['Pages active'] ?? 0;
                $wiredPages = $stats['Pages wired down'] ?? 0;
                $compressedPages = $stats['Pages occupied by compressor'] ?? 0;
                
                $usedPages = $activePages + $wiredPages + $compressedPages;
                $used = $usedPages * $pageSize;
            } else {
                // Fallback: use top command
                $topOutput = @shell_exec("top -l 1 -s 0 | grep 'PhysMem' 2>/dev/null");
                if ($topOutput) {
                    // Parse: "PhysMem: 15G used (1234M wired), 1234M unused."
                    if (preg_match('/(\d+)([MG])\s+used/i', $topOutput, $usedMatch)) {
                        $multiplier = strtoupper($usedMatch[2]) === 'G' ? 1073741824 : 1048576;
                        $used = (int) $usedMatch[1] * $multiplier;
                    }
                    if (preg_match('/(\d+)([MG])\s+unused/i', $topOutput, $unusedMatch)) {
                        $multiplier = strtoupper($unusedMatch[2]) === 'G' ? 1073741824 : 1048576;
                        $unused = (int) $unusedMatch[1] * $multiplier;
                        $total = $used + $unused;
                    }
                }
                // If still no total, try system_profiler as last resort
                if ($total === 0) {
                    $profilerOutput = @shell_exec("system_profiler SPHardwareDataType 2>/dev/null | grep 'Memory'");
                    if ($profilerOutput && preg_match('/(\d+)\s*GB/', $profilerOutput, $m)) {
                        $total = (int) $m[1] * 1073741824;
                    }
                }
            }
        } else {
            // Linux: Read from /proc/meminfo
            if (file_exists('/proc/meminfo')) {
                $meminfo = file_get_contents('/proc/meminfo');
                preg_match('/MemTotal:\s+(\d+)/', $meminfo, $totalMatch);
                preg_match('/MemAvailable:\s+(\d+)/', $meminfo, $availMatch);
                
                $total = isset($totalMatch[1]) ? (int) $totalMatch[1] * 1024 : 0;
                $available = isset($availMatch[1]) ? (int) $availMatch[1] * 1024 : 0;
                $used = $total - $available;
            }
        }
        
        if ($total > 0) {
            $percent = round(($used / $total) * 100, 1);
        }
        
        return [
            'total' => $total,
            'used' => $used,
            'percent' => $percent,
        ];
    }

    /**
     * Get disk usage
     */
    protected function getDiskUsage(): array
    {
        $path = PHP_OS_FAMILY === 'Windows' ? 'C:' : '/';
        
        $total = @disk_total_space($path) ?: 0;
        $free = @disk_free_space($path) ?: 0;
        $used = $total - $free;
        $percent = $total > 0 ? round(($used / $total) * 100, 1) : 0;
        
        return [
            'total' => $total,
            'used' => $used,
            'percent' => $percent,
        ];
    }

    /**
     * Get network usage (bytes sent/recv per second)
     */
    protected function getNetworkUsage(): array
    {
        $bytesSent = 0;
        $bytesRecv = 0;
        
        // Use file cache to persist between heartbeats
        $cacheFile = storage_path('app/network_stats_cache.json');
        $lastStats = null;
        $lastTime = null;
        
        Log::debug('getNetworkUsage: starting', ['cacheFile' => $cacheFile, 'exists' => file_exists($cacheFile)]);
        
        if (file_exists($cacheFile)) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if ($cached && isset($cached['stats']) && isset($cached['time'])) {
                $lastStats = $cached['stats'];
                $lastTime = $cached['time'];
                Log::debug('getNetworkUsage: cached data loaded', [
                    'lastStats' => $lastStats,
                    'lastTime' => $lastTime,
                ]);
            }
        }
        
        $currentStats = $this->getNetworkStats();
        $currentTime = microtime(true);
        
        Log::debug('getNetworkUsage: current stats', [
            'currentStats' => $currentStats,
            'currentTime' => $currentTime,
        ]);
        
        if ($lastStats !== null && $lastTime !== null) {
            $timeDiff = $currentTime - $lastTime;
            Log::debug('getNetworkUsage: time diff', ['timeDiff' => $timeDiff]);
            
            // Only calculate if time diff is reasonable (1-600 seconds)
            if ($timeDiff > 1 && $timeDiff < 600) {
                $sentDiff = $currentStats['sent'] - $lastStats['sent'];
                $recvDiff = $currentStats['recv'] - $lastStats['recv'];
                
                Log::debug('getNetworkUsage: diffs', ['sentDiff' => $sentDiff, 'recvDiff' => $recvDiff]);
                
                // Handle counter reset (system reboot)
                if ($sentDiff >= 0 && $recvDiff >= 0) {
                    $bytesSent = (int) ($sentDiff / $timeDiff);
                    $bytesRecv = (int) ($recvDiff / $timeDiff);
                    Log::debug('getNetworkUsage: calculated rates', ['bytesSent' => $bytesSent, 'bytesRecv' => $bytesRecv]);
                }
            } else {
                Log::debug('getNetworkUsage: timeDiff out of range, skipping calculation');
            }
        } else {
            Log::debug('getNetworkUsage: no previous data, first run');
        }
        
        // Save current stats for next call
        $writeResult = file_put_contents($cacheFile, json_encode([
            'stats' => $currentStats,
            'time' => $currentTime,
        ]));
        Log::debug('getNetworkUsage: saved cache', ['writeResult' => $writeResult]);
        
        $result = [
            'bytes_sent' => max(0, $bytesSent),
            'bytes_recv' => max(0, $bytesRecv),
        ];
        Log::debug('getNetworkUsage: returning', $result);
        
        return $result;
    }

    /**
     * Get raw network statistics
     */
    protected function getNetworkStats(): array
    {
        $sent = 0;
        $recv = 0;
        
        // Debug: Log OS detection
        Log::debug('getNetworkStats: OS detection', [
            'PHP_OS_FAMILY' => PHP_OS_FAMILY,
            'PHP_OS' => PHP_OS,
            'php_uname' => php_uname('s'),
        ]);
        
        if (PHP_OS_FAMILY === 'Windows') {
            // Windows: Use netstat
            $output = [];
            @exec('netstat -e 2>&1', $output);
            foreach ($output as $line) {
                if (preg_match('/Bytes\s+(\d+)\s+(\d+)/', $line, $m)) {
                    $recv = (int) $m[1];
                    $sent = (int) $m[2];
                    break;
                }
            }
        } elseif (PHP_OS_FAMILY === 'Darwin') {
            // macOS: Try multiple methods to get network bytes
            Log::debug('macOS network stats: starting collection');
            
            // Method 1: netstat -I for specific interface (most reliable)
            $interfaces = ['en0', 'en1', 'en2', 'en3', 'en4', 'en5'];
            foreach ($interfaces as $iface) {
                $output = @shell_exec("netstat -I $iface -b 2>/dev/null");
                if ($output) {
                    Log::debug("macOS netstat -I $iface output", ['output' => $output]);
                    $lines = explode("\n", trim($output));
                    // Second line contains the data
                    if (isset($lines[1])) {
                        $parts = preg_split('/\s+/', trim($lines[1]));
                        Log::debug("macOS $iface parsed parts", ['parts' => $parts, 'count' => count($parts)]);
                        // Format: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
                        if (count($parts) >= 10 && is_numeric($parts[6]) && is_numeric($parts[9])) {
                            $recv += (int) $parts[6];
                            $sent += (int) $parts[9];
                            Log::debug("macOS $iface bytes found", ['recv' => $parts[6], 'sent' => $parts[9]]);
                        }
                    }
                }
            }
            
            // Fallback: parse netstat -ib if we got no data
            if ($sent === 0 && $recv === 0) {
                Log::debug('macOS: Method 1 failed, trying netstat -ib fallback');
                $output = @shell_exec('netstat -ib 2>&1');
                if ($output) {
                    Log::debug('macOS netstat -ib raw output', ['output' => substr($output, 0, 1000)]);
                    foreach (explode("\n", $output) as $line) {
                        // Match en* interfaces with Link# network
                        if (preg_match('/^(en\d+)\s+\d+\s+<Link#/', $line)) {
                            Log::debug('macOS matched Link# line', ['line' => $line]);
                            $parts = preg_split('/\s+/', trim($line));
                            // Find numeric columns for bytes (usually columns 6 and 9)
                            $numericCols = [];
                            foreach ($parts as $idx => $val) {
                                if (is_numeric($val) && $val > 0) {
                                    $numericCols[] = ['idx' => $idx, 'val' => (int)$val];
                                }
                            }
                            Log::debug('macOS numeric columns found', ['numericCols' => $numericCols]);
                            // Typically: [mtu, ipkts, ierrs, ibytes, opkts, oerrs, obytes, coll]
                            // ibytes is usually the 4th numeric, obytes is 7th
                            if (count($numericCols) >= 7) {
                                $recv += $numericCols[3]['val'] ?? 0;
                                $sent += $numericCols[6]['val'] ?? 0;
                            }
                        }
                    }
                }
            }
            
            // Log final result
            Log::debug('macOS network stats final result', ['sent' => $sent, 'recv' => $recv]);
        } else {
            // Linux: Read from /proc/net/dev
            if (file_exists('/proc/net/dev')) {
                $content = file_get_contents('/proc/net/dev');
                $lines = explode("\n", $content);
                foreach ($lines as $line) {
                    // Skip loopback
                    if (strpos($line, 'lo:') !== false) continue;
                    if (preg_match('/^\s*\w+:\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)/', $line, $m)) {
                        $recv += (int) $m[1];
                        $sent += (int) $m[2];
                    }
                }
            }
        }
        
        return ['sent' => $sent, 'recv' => $recv];
    }

    /**
     * Get server uptime
     */
    protected function getUptime(): ?int
    {
        if (file_exists('/proc/uptime')) {
            $uptime = file_get_contents('/proc/uptime');
            return (int) explode(' ', $uptime)[0];
        }
        return null;
    }

    /**
     * Get public IP address (real external IP, not Docker internal)
     */
    protected function getPublicIp(): ?string
    {
        // Check cache first
        $cachedIp = cache()->get('agent_public_ip');
        if ($cachedIp) {
            return $cachedIp;
        }

        // Try multiple external IP services
        $services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://icanhazip.com',
            'https://ipinfo.io/ip',
        ];

        foreach ($services as $service) {
            try {
                $response = Http::timeout(5)->get($service);
                if ($response->successful()) {
                    $ip = trim($response->body());
                    // Validate IP format
                    if (filter_var($ip, FILTER_VALIDATE_IP)) {
                        // Cache for 1 hour
                        cache()->put('agent_public_ip', $ip, now()->addHour());
                        return $ip;
                    }
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        // Fallback to local IP if all external services fail
        $ip = gethostbyname(gethostname());
        if ($ip && $ip !== gethostname()) {
            return $ip;
        }

        return '0.0.0.0';
    }

    /**
     * Get CA certificate path for Windows SSL verification
     */
    protected function getCaCertPath(): ?string
    {
        // Check common locations for cacert.pem on Windows
        $possiblePaths = [];
        
        // Get PHP directory
        $phpBinary = PHP_BINARY;
        if ($phpBinary) {
            $phpDir = dirname($phpBinary);
            $possiblePaths[] = $phpDir . '\\cacert.pem';
            $possiblePaths[] = $phpDir . '\\extras\\ssl\\cacert.pem';
        }
        
        // Check common PHP installation locations
        $possiblePaths = array_merge($possiblePaths, [
            'C:\\tools\\php85\\cacert.pem',
            'C:\\tools\\php\\cacert.pem',
            'C:\\php\\cacert.pem',
            'C:\\xampp\\php\\extras\\ssl\\cacert.pem',
            'C:\\xampp-new\\php\\extras\\ssl\\cacert.pem',
            'C:\\Program Files\\PHP\\cacert.pem',
            'C:\\ProgramData\\ComposerSetup\\bin\\cacert.pem',
        ]);
        
        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                Log::debug('Found CA certificate at: ' . $path);
                return $path;
            }
        }
        
        // If not found, try to download it
        $downloadPath = sys_get_temp_dir() . '\\cacert.pem';
        if (!file_exists($downloadPath)) {
            try {
                // Download from curl.se (using file_get_contents with SSL disabled for bootstrap)
                $context = stream_context_create([
                    'ssl' => [
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                    ],
                ]);
                $cacert = @file_get_contents('https://curl.se/ca/cacert.pem', false, $context);
                if ($cacert) {
                    file_put_contents($downloadPath, $cacert);
                    Log::info('Downloaded CA certificate to: ' . $downloadPath);
                    return $downloadPath;
                }
            } catch (\Exception $e) {
                Log::warning('Failed to download CA certificate: ' . $e->getMessage());
            }
        } elseif (file_exists($downloadPath)) {
            return $downloadPath;
        }
        
        return null;
    }

    /**
     * Sync alert to WAF Hub
     *
     * @param array $alertData
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncAlert(array $alertData): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for alerts');
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/alerts", [
                    'agent_id' => $this->getAgentId(),
                    'alert' => $alertData,
                ]);

            if ($response->successful()) {
                Log::info('Alert synced to WAF Hub', [
                    'ip' => $alertData['source_ip'] ?? 'unknown',
                    'severity' => $alertData['severity'] ?? 'unknown',
                ]);
            } else {
                Log::error('WAF Hub rejected alert', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                ]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync alert to WAF Hub', [
                'error' => $e->getMessage(),
                'ip' => $alertData['source_ip'] ?? 'unknown',
            ]);
            return null;
        }
    }

    /**
     * Get agent ID from config or cache
     */
    private function getAgentId(): ?int
    {
        // Try to get from environment first
        if ($agentId = env('IDS_AGENT_ID')) {
            return (int) $agentId;
        }

        // Or from cache (set during registration)
        return cache('ids_agent_id');
    }

    /**
     * Check if WAF sync is properly configured
     */
    private function isConfigured(): bool
    {
        return !empty($this->agentToken) && !empty($this->wafUrl);
    }

    /**
     * Sync blocked IP to WAF Hub
     *
     * @param array $blockData
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncBlockedIP(array $blockData): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for blocking');
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/block-ip", [
                    'agent_id' => $this->getAgentId(),
                    'block' => $blockData,
                ]);

            if ($response->successful()) {
                Log::info('Blocked IP synced to WAF Hub', [
                    'ip' => $blockData['ip'] ?? 'unknown',
                ]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync blocked IP', [
                'error' => $e->getMessage(),
                'ip' => $blockData['ip'] ?? 'unknown',
            ]);
            return null;
        }
    }

    /**
     * Sync IP unblock to WAF Hub
     *
     * @param string $ip
     * @return \Illuminate\Http\Client\Response|null
     */
    public function syncUnblockIP(string $ip): ?\Illuminate\Http\Client\Response
    {
        if (!$this->isConfigured()) {
            Log::warning('WAF sync not configured for unblocking');
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->post("{$this->wafUrl}/api/ids/unblock-ip", [
                    'agent_id' => $this->getAgentId(),
                    'ip' => $ip,
                ]);

            if ($response->successful()) {
                Log::info('Unblocked IP synced to WAF Hub', ['ip' => $ip]);
            }

            return $response;
        } catch (\Exception $e) {
            Log::error('Failed to sync IP unblock', [
                'error' => $e->getMessage(),
                'ip' => $ip,
            ]);
            return null;
        }
    }

    /**
     * Fetch agent configuration from WAF Hub
     */
    public function fetchAgentConfig(): ?array
    {
        if (!$this->isConfigured()) {
            return null;
        }

        try {
            $response = $this->getHttpClient(10)
                ->withToken($this->agentToken)
                ->get("{$this->wafUrl}/api/ids/agents/config");

            if ($response->successful()) {
                $config = $response->json()['config'] ?? [];
                // Cache for 1 hour
                cache()->put('waf_agent_config', $config, now()->addHour());
                Log::info('Agent configuration fetched and cached from WAF Hub');
                return $config;
            }

            Log::warning('Failed to fetch agent config', [
                'status' => $response->status(),
                'body' => $response->body(),
            ]);
            return null;
        } catch (\Exception $e) {
            Log::error('Exception during agent config fetch: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Get cached agent configuration
     */
    public function getCachedConfig(): array
    {
        return cache()->get('waf_agent_config') ?? $this->fetchAgentConfig() ?? [];
    }

    /**
     * Detect the current platform
     */
    private function detectPlatform(): string
    {
        // Check if running in Docker (likely server deployment)
        if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) {
            return 'server';
        }
        
        if (stripos(PHP_OS, 'WIN') === 0) {
            return 'windows';
        } elseif (stripos(PHP_OS, 'Darwin') !== false) {
            return 'macos';
        }
        
        // Linux (desktop and server unified as 'linux')
        return 'linux';
    }
    
    /**
     * Regenerate the Windows sync service script with latest template
     */
    private function regenerateWindowsSyncScript(string $installDir): void
    {
        try {
            $dataDir = 'C:\ProgramData\SecurityOneIDS';
            $logDir = $dataDir . '\logs';
            
            // Ensure log directory exists
            if (!is_dir($logDir)) {
                mkdir($logDir, 0755, true);
            }
            
            // Create the simplified sync service script
            $script = <<<'POWERSHELL'
$ErrorActionPreference = 'Continue'

# Configuration
$InstallDir = 'INSTALL_DIR_PLACEHOLDER'
$LogDir = 'DATA_DIR_PLACEHOLDER\logs'
$LogFile = "$LogDir\watchdog.log"
$MaxFailures = 10
$FailCount = 0

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Find PHP path
$PhpPath = 'php'
$PossiblePaths = @(
    'C:\php\php.exe',
    'C:\tools\php\php.exe',
    'C:\Program Files\PHP\php.exe',
    'C:\xampp\php\php.exe',
    'C:\xampp-new\php\php.exe'
)
foreach ($p in $PossiblePaths) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        $PhpPath = $p
        break
    }
}

function Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Msg"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    
    # Rotate if > 5MB
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile -EA SilentlyContinue).Length -gt 5MB)) {
        Move-Item $LogFile "$LogFile.old" -Force -EA SilentlyContinue
    }
}

Log "=== Sync Watchdog v3.0 Starting ===" 'INFO'
Log "Install Dir: $InstallDir" 'INFO'
Log "PHP Path: $PhpPath" 'INFO'

# Main loop - run waf:sync every 60 seconds
while ($true) {
    try {
        Set-Location $InstallDir
        
        # Run sync command with timeout (6 min max for concurrent tasks)
        $proc = Start-Process -FilePath $PhpPath -ArgumentList 'artisan','waf:sync' -WorkingDirectory $InstallDir -NoNewWindow -PassThru -Wait:$false
        $exited = $proc.WaitForExit(360000)  # 6 min timeout
        
        if (-not $exited) {
            Log "waf:sync timeout - killing process" 'WARN'
            $proc.Kill()
            $FailCount++
        } elseif ($proc.ExitCode -ne 0) {
            Log "waf:sync failed with code $($proc.ExitCode)" 'ERROR'
            $FailCount++
        } else {
            Log "waf:sync completed successfully" 'INFO'
            $FailCount = 0
        }
        
        # Full reset after too many failures
        if ($FailCount -ge $MaxFailures) {
            Log "Too many failures ($FailCount), performing full reset..." 'WARN'
            
            # Clear Laravel cache
            & $PhpPath artisan cache:clear 2>&1 | Out-Null
            & $PhpPath artisan config:clear 2>&1 | Out-Null
            
            $FailCount = 0
            Log "Reset complete, waiting 60s..." 'INFO'
            Start-Sleep -Seconds 60
        }
        
    } catch {
        Log "Exception: $($_.Exception.Message)" 'ERROR'
        $FailCount++
    }
    
    # Wait before next sync
    Start-Sleep -Seconds 60
}
POWERSHELL;

            // Replace placeholders
            $script = str_replace('INSTALL_DIR_PLACEHOLDER', $installDir, $script);
            $script = str_replace('DATA_DIR_PLACEHOLDER', $dataDir, $script);
            
            // Write the script
            $scriptPath = $installDir . '\run-sync-service.ps1';
            file_put_contents($scriptPath, $script);
            
            Log::info('Windows sync script regenerated', ['path' => $scriptPath]);
            
        } catch (\Exception $e) {
            Log::error('Failed to regenerate Windows sync script: ' . $e->getMessage());
        }
    }
}

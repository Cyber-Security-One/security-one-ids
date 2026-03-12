<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * Blocking Service
 * 
 * Manages IP blocking via WAF rules and iptables
 */
class BlockingService
{
    private WafSyncService $wafSync;
    private const CACHE_PREFIX = 'blocked_ip:';
    private const BLOCK_DURATION = 3600; // 1 hour default

    public function __construct(WafSyncService $wafSync)
    {
        $this->wafSync = $wafSync;
    }

    /**
     * Block an IP address
     *
     * @param string $ip IP to block
     * @param string $reason Block reason
     * @param string $severity Threat severity
     * @param int|null $duration Block duration in seconds (null = permanent)
     * @return bool Success
     */
    public function blockIP(string $ip, string $reason, string $severity = 'high', ?int $duration = null): bool
    {
        // Check if IPS (blocking) is enabled from WAF Hub config
        $wafConfigPath = storage_path('app/waf_config.json');
        $ipsEnabled = false;
        
        if (file_exists($wafConfigPath)) {
            $wafConfig = json_decode(file_get_contents($wafConfigPath), true);
            $ipsEnabled = $wafConfig['ips_enabled'] ?? false;
        }
        
        // Fall back to env if not in waf_config
        if (!$ipsEnabled) {
            $ipsEnabled = config('ids.blocking.enabled', false);
        }
        
        if (!$ipsEnabled) {
            Log::info('IPS (blocking) disabled, skipping block', ['ip' => $ip]);
            return false;
        }

        // Whitelist check
        if ($this->isWhitelisted($ip)) {
            Log::warning('IP is whitelisted, skipping block', ['ip' => $ip]);
            return false;
        }

        // Already blocked check
        if ($this->isBlocked($ip)) {
            Log::info('IP already blocked', ['ip' => $ip]);
            return true;
        }

        $duration = $duration ?? $this->getBlockDuration($severity);
        $mode = config('ids.blocking.mode', 'hybrid');

        Log::warning('Blocking IP', [
            'ip' => $ip,
            'reason' => $reason,
            'severity' => $severity,
            'duration' => $duration,
            'mode' => $mode,
        ]);

        $success = false;

        // WAF Rules blocking
        if (in_array($mode, ['waf', 'hybrid'])) {
            $success = $this->blockViaWAF($ip, $reason, $duration) || $success;
        }

        // iptables blocking for critical threats
        if (in_array($mode, ['iptables', 'hybrid']) && in_array($severity, ['critical', 'high'])) {
            $success = $this->blockViaIptables($ip, $reason) || $success;
        }

        // Cache the block
        if ($success) {
            $this->cacheBlock($ip, $reason, $duration);
            
            // Schedule auto-unblock if temporary
            if ($duration !== null) {
                $this->scheduleUnblock($ip, $duration);
            }
        }

        return $success;
    }

    /**
     * Block via WAF rules
     */
    private function blockViaWAF(string $ip, string $reason, ?int $duration): bool
    {
        try {
            $response = $this->wafSync->syncBlockedIP([
                'ip' => $ip,
                'reason' => $reason,
                'duration' => $duration,
                'blocked_at' => now()->toDateTimeString(),
                'expires_at' => $duration ? now()->addSeconds($duration)->toDateTimeString() : null,
            ]);

            if ($response && $response->successful()) {
                Log::info('IP blocked via WAF', ['ip' => $ip]);
                return true;
            }

            Log::error('Failed to block via WAF', [
                'ip' => $ip,
                'status' => $response ? $response->status() : 'no response',
            ]);
            return false;

        } catch (\Exception $e) {
            Log::error('Exception blocking via WAF', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Block via iptables (system-level)
     */
    private function blockViaIptables(string $ip, string $reason): bool
    {
        try {
            // Validate IP format
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                Log::error('Invalid IP format for iptables', ['ip' => $ip]);
                return false;
            }

            // Add iptables rule
            $command = sprintf('sudo iptables -I INPUT -s %s -j DROP', escapeshellarg($ip));
            exec($command, $output, $returnCode);

            if ($returnCode === 0) {
                Log::info('IP blocked via iptables', ['ip' => $ip, 'reason' => $reason]);
                
                // Save to iptables persistent
                $this->saveIptablesRule($ip);
                
                return true;
            }

            Log::error('iptables command failed', [
                'ip' => $ip,
                'return_code' => $returnCode,
                'output' => implode("\n", $output),
            ]);
            return false;

        } catch (\Exception $e) {
            Log::error('Exception blocking via iptables', [
                'ip' => $ip,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Unblock an IP address
     */
    public function unblockIP(string $ip): bool
    {
        Log::info('Unblocking IP', ['ip' => $ip]);

        $mode = config('ids.blocking.mode', 'hybrid');
        $success = false;

        // Remove from WAF
        if (in_array($mode, ['waf', 'hybrid'])) {
            $success = $this->unblockViaWAF($ip) || $success;
        }

        // Remove from iptables
        if (in_array($mode, ['iptables', 'hybrid'])) {
            $success = $this->unblockViaIptables($ip) || $success;
        }

        // Remove from cache
        Cache::forget(self::CACHE_PREFIX . $ip);

        return $success;
    }

    /**
     * Unblock via WAF
     */
    private function unblockViaWAF(string $ip): bool
    {
        try {
            $response = $this->wafSync->syncUnblockIP($ip);
            
            if ($response && $response->successful()) {
                Log::info('IP unblocked via WAF', ['ip' => $ip]);
                return true;
            }

            return false;
        } catch (\Exception $e) {
            Log::error('Exception unblocking via WAF', ['ip' => $ip, 'error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Unblock via iptables
     */
    private function unblockViaIptables(string $ip): bool
    {
        try {
            $command = sprintf('sudo iptables -D INPUT -s %s -j DROP', escapeshellarg($ip));
            exec($command, $output, $returnCode);

            if ($returnCode === 0) {
                Log::info('IP unblocked via iptables', ['ip' => $ip]);
                $this->removeIptablesRule($ip);
                return true;
            }

            return false;
        } catch (\Exception $e) {
            Log::error('Exception unblocking via iptables', ['ip' => $ip, 'error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Check if IP is blocked
     */
    public function isBlocked(string $ip): bool
    {
        // Check cache first
        if (Cache::has(self::CACHE_PREFIX . $ip)) {
            return true;
        }
        
        // Also check blocked IPs from WAF Hub config
        $blockedIps = $this->getBlockedIPs();
        return isset($blockedIps[$ip]);
    }

    /**
     * Check if IP is whitelisted
     */
    public function isWhitelisted(string $ip): bool
    {
        $whitelist = config('ids.blocking.whitelist', []);
        return in_array($ip, $whitelist);
    }

    /**
     * Get block duration based on severity
     */
    private function getBlockDuration(string $severity): int
    {
        return match ($severity) {
            'critical' => 86400, // 24 hours
            'high' => 3600,      // 1 hour
            'medium' => 1800,    // 30 minutes
            'low' => 600,        // 10 minutes
            default => self::BLOCK_DURATION,
        };
    }

    /**
     * Cache the block
     */
    private function cacheBlock(string $ip, string $reason, ?int $duration): void
    {
        $data = [
            'ip' => $ip,
            'reason' => $reason,
            'blocked_at' => now()->toDateTimeString(),
        ];

        if ($duration !== null) {
            Cache::put(self::CACHE_PREFIX . $ip, $data, $duration);
        } else {
            Cache::forever(self::CACHE_PREFIX . $ip, $data);
        }
    }

    /**
     * Schedule automatic unblock
     */
    private function scheduleUnblock(string $ip, int $duration): void
    {
        // Using cache expiration as scheduler
        // When cache expires, the block is automatically removed
        // For iptables, we need explicit cleanup job
        if (config('ids.blocking.mode') === 'iptables' || config('ids.blocking.mode') === 'hybrid') {
            // TODO: Dispatch UnblockIPJob with delay
            // dispatch(new UnblockIPJob($ip))->delay($duration);
        }
    }

    /**
     * Save iptables rule to persistent storage
     */
    private function saveIptablesRule(string $ip): void
    {
        $rulesFile = storage_path('app/iptables_blocks.txt');
        file_put_contents($rulesFile, $ip . "\n", FILE_APPEND);
    }

    /**
     * Remove iptables rule from persistent storage
     */
    private function removeIptablesRule(string $ip): void
    {
        $rulesFile = storage_path('app/iptables_blocks.txt');
        
        if (file_exists($rulesFile)) {
            $rules = file($rulesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $rules = array_filter($rules, fn($rule) => $rule !== $ip);
            file_put_contents($rulesFile, implode("\n", $rules) . "\n");
        }
    }

    /**
     * Restore iptables rules on system boot
     */
    public function restoreIptablesRules(): void
    {
        $rulesFile = storage_path('app/iptables_blocks.txt');
        
        if (!file_exists($rulesFile)) {
            return;
        }

        $ips = file($rulesFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        
        foreach ($ips as $ip) {
            $this->blockViaIptables($ip, 'Restored from persistent storage');
        }

        Log::info('Restored iptables rules', ['count' => count($ips)]);
    }

    /**
     * Get currently blocked IPs from WAF Hub config and local cache
     */
    public function getBlockedIPs(): array
    {
        $blockedIps = [];
        
        // Load blocked IPs from WAF Hub config file
        $configPath = storage_path('app/waf_config.json');
        if (file_exists($configPath)) {
            try {
                $config = json_decode(file_get_contents($configPath), true);
                if (!empty($config['blocked_ips']) && is_array($config['blocked_ips'])) {
                    foreach ($config['blocked_ips'] as $blocked) {
                        $ip = $blocked['ip'] ?? null;
                        if ($ip) {
                            $blockedIps[$ip] = [
                                'reason' => $blocked['reason'] ?? 'Blocked by WAF Hub',
                                'blocked_at' => $blocked['blocked_at'] ?? null,
                                'expires_at' => $blocked['expires_at'] ?? null,
                            ];
                        }
                    }
                }
            } catch (\Exception $e) {
                Log::warning('Failed to read blocked IPs from config: ' . $e->getMessage());
            }
        }
        
        return $blockedIps;
    }
}

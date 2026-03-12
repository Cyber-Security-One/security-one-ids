<?php

namespace App\Console\Commands;

use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

class SyncToWaf extends Command
{
    protected $signature = 'waf:sync 
        {--register : Force registration}
        {--once : Run once and exit (for debugging)}
        {--debug : Show debug information}';
    protected $description = 'Sync this IDS Agent with the central WAF (concurrent)';

    public function handle(WafSyncService $wafSync): int
    {
        $this->info('Starting WAF synchronization...');

        // Register if first time or forced
        if ($this->option('register') || !cache()->has('waf_registered')) {
            $this->info('Registering with WAF...');
            if ($wafSync->register()) {
                cache()->put('waf_registered', true, now()->addDays(30));
                $this->info('✓ Successfully registered with WAF');
                
                // Upload signatures immediately after registration
                $this->info('Uploading signatures after registration...');
                $uploaded = $wafSync->uploadSignatures();
                $this->info("✓ Uploaded {$uploaded} signatures to WAF");
            } else {
                $this->error('✗ Failed to register with WAF');
                return 1;
            }
        }

        // Debug output if requested
        if ($this->option('debug')) {
            $this->showDebugInfo();
        }

        // === Run ALL tasks concurrently (5 parallel processes) ===
        $this->info('Dispatching 4 concurrent task groups...');
        $phpBinary = PHP_BINARY ?: 'php';
        $basePath = base_path();
        $startTime = microtime(true);

        try {
            $pool = Process::pool(function ($pool) use ($phpBinary, $basePath) {
                // Group 1: Heartbeat (independent, fast)
                $pool->path($basePath)
                    ->timeout(60)
                    ->command([$phpBinary, 'artisan', 'waf:heartbeat']);
                
                // Group 2: Quick sync (rules, alerts, blocked IPs)
                $pool->path($basePath)
                    ->timeout(300)
                    ->command([$phpBinary, 'artisan', 'ids:sync-quick']);
                
                // Group 3: Suricata management (install, start, update)
                $pool->path($basePath)
                    ->timeout(600)
                    ->command([$phpBinary, 'artisan', 'ids:sync-suricata']);
                
                // Group 4: Maintenance (ClamAV, updates, system signals)
                $pool->path($basePath)
                    ->timeout(600)
                    ->command([$phpBinary, 'artisan', 'ids:sync-maintenance']);
            })->start()->wait();

            $elapsed = round(microtime(true) - $startTime, 1);
            
            $labels = ['Heartbeat', 'Quick', 'Suricata', 'Maintenance'];
            foreach ($pool as $i => $result) {
                $label = $labels[$i] ?? "Group {$i}";
                if ($result->successful()) {
                    $this->info("  ✓ {$label} completed");
                } else {
                    $this->warn("  ✗ {$label} failed (exit: {$result->exitCode()})");
                    $output = $result->errorOutput() ?: $result->output();
                    if ($output) {
                        Log::warning("[{$label}] Output: " . substr($output, 0, 500));
                    }
                }
            }

            $this->info("Concurrent sync completed in {$elapsed}s");
        } catch (\Exception $e) {
            $this->error('Concurrent dispatch failed: ' . $e->getMessage());
            Log::error('Process::pool() failed, falling back to sequential: ' . $e->getMessage());
            
            // Fallback: run sequentially if pool fails
            $this->info('Running tasks sequentially...');
            $wafSync->heartbeat();
            $wafSync->runQuickSync();
            $wafSync->runSuricataSync();
            $wafSync->runMaintenanceSync();
        }

        $this->info('Sync completed!');
        return 0;
    }

    /**
     * Show debug information
     */
    private function showDebugInfo(): void
    {
        $this->info('=== DEBUG INFO ===');
        $this->info('PHP_OS_FAMILY: ' . $this->getPlatformName());
        $this->info('PHP_OS: ' . PHP_OS);
        $this->info('php_uname: ' . php_uname('s'));
        
        if ($this->isMac()) {
            $this->info('Detected macOS, testing netstat...');
            $output = shell_exec('netstat -I en0 -b 2>&1');
            $this->info("netstat -I en0 -b output:\n" . $output);
            
            $lines = explode("\n", trim($output ?? ''));
            if (isset($lines[1])) {
                $parts = preg_split('/\s+/', trim($lines[1]));
                $this->info('Parsed columns: ' . count($parts));
                if (count($parts) >= 10) {
                    $this->info("Ibytes (col 6): " . ($parts[6] ?? 'N/A'));
                    $this->info("Obytes (col 9): " . ($parts[9] ?? 'N/A'));
                }
            }
        } elseif ($this->isWindows()) {
            $this->info('Detected Windows');
        } else {
            $this->info('Detected Linux');
        }
        $this->info('=== END DEBUG ===');
    }
}

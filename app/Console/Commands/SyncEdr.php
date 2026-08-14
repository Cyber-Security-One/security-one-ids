<?php

namespace App\Console\Commands;

use App\Services\Detection\OsqueryEngine;
use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class SyncEdr extends Command
{
    protected $signature = 'ids:sync-edr
        {--status : Show endpoint sensor status and exit}
        {--install : Install the endpoint sensor and exit}
        {--start : Start the endpoint sensor and exit}
        {--stop : Stop the endpoint sensor and exit}
        {--dry-run : Collect and print alerts without sending them to the Hub}';

    protected $description = 'Run endpoint sensor (EDR) tasks: install, start, collect process behaviour alerts';

    public function handle(WafSyncService $wafSync, OsqueryEngine $engine): int
    {
        if ($this->option('status')) {
            return $this->showStatus($engine);
        }

        if ($this->option('install')) {
            $result = $engine->install();
            $this->line(json_encode($result, JSON_PRETTY_PRINT));

            return empty($result['success']) ? 1 : 0;
        }

        if ($this->option('start')) {
            $result = $engine->start();
            $this->line(json_encode($result, JSON_PRETTY_PRINT));

            return empty($result['success']) ? 1 : 0;
        }

        if ($this->option('stop')) {
            $stopped = $engine->stop();
            $this->line($stopped ? 'Sensor stopped' : 'Failed to stop sensor');

            return $stopped ? 0 : 1;
        }

        if ($this->option('dry-run')) {
            return $this->dryRun();
        }

        Log::debug('[SyncEdr] Starting endpoint sensor tasks...');

        try {
            $wafSync->runEdrSync();
            Log::debug('[SyncEdr] Completed');
        } catch (\Exception $e) {
            Log::error('[SyncEdr] Error: ' . $e->getMessage());

            return 1;
        }

        return 0;
    }

    private function showStatus(OsqueryEngine $engine): int
    {
        $status = $engine->getStatus();

        $this->info('Endpoint Sensor (EDR) Status');
        $this->line(str_repeat('=', 46));

        foreach ($status as $key => $value) {
            $rendered = match (true) {
                is_bool($value) => $value ? 'yes' : 'no',
                $value === null => '-',
                default => (string) $value,
            };
            $this->line(sprintf('  %-20s %s', $key, $rendered));
        }

        if (!$status['supported']) {
            $this->warn('  → This platform is not supported yet (Linux only).');
        } elseif (!$status['installed']) {
            $this->warn('  → Not installed. Run: php artisan ids:sync-edr --install');
        } elseif ($status['backend'] === '') {
            $this->error('  → No usable backend: needs kernel 5.8+ with BTF, or auditd stopped.');
        } elseif (!$status['running']) {
            $this->warn('  → Installed but not running. Run: php artisan ids:sync-edr --start');
        }

        return 0;
    }

    /**
     * Collect a cycle and print what would have been sent. This is the loop
     * to use when tuning exclusions against a customer's real workload.
     */
    private function dryRun(): int
    {
        $collector = app(\App\Services\EdrEventCollector::class);

        $config = json_decode((string) @file_get_contents(storage_path('app/waf_config.json')), true) ?: [];
        $addons = $config['addons'] ?? [];

        $result = $collector->collect([
            'exclusions' => is_array($addons['edr_exclusions'] ?? null) ? $addons['edr_exclusions'] : [],
            'web_account_allowlist' => is_array($addons['edr_web_account_allowlist'] ?? null)
                ? $addons['edr_web_account_allowlist']
                : [],
        ]);

        $stats = $result['stats'];
        $this->info("Events processed: {$stats['events']}   Alerts: {$stats['alerts']}   Backend: " . ($stats['backend'] ?: '-'));

        if (!empty($stats['by_rule'])) {
            $this->newLine();
            $this->info('Rule hits:');
            foreach ($stats['by_rule'] as $rule => $count) {
                $this->line(sprintf('  %-10s %d', $rule, $count));
            }
        }

        foreach ($result['alerts'] as $alert) {
            $this->newLine();
            $this->warn("[{$alert['severity']}] " . $alert['detections']);
            $this->line('  user=' . $alert['process']['user']
                . ' pid=' . $alert['process']['pid']
                . ' ppid=' . $alert['process']['ppid']
                . ' cwd=' . $alert['process']['cwd']);
            $this->line('  mitre=' . implode(',', $alert['mitre']));
        }

        if ($result['alerts'] === []) {
            $this->line('No alerts in this cycle.');
        }

        return 0;
    }
}

<?php

namespace App\Console\Commands;

use App\Services\ClamavService;
use App\Services\Correlation\EdrCorrelator;
use App\Services\Detection\OsqueryEngine;
use App\Services\Detection\SuricataEngine;
use App\Services\EdrEventSpool;
use App\Services\Platform\EdrPlatformProfile;
use App\Services\Quality\EdrRuleGovernor;
use App\Services\WafSyncService;
use Illuminate\Console\Command;

/**
 * One snapshot of everything this agent knows about itself.
 *
 * Exists because the status was only ever available as prose spread across
 * five commands, which is fine for a person at a terminal and useless to
 * anything else. A console — a menu bar app, a dashboard, a health check —
 * needs a single structured answer, and needs it to be the *same* answer the
 * CLI gives rather than a second implementation that drifts.
 *
 * Three rules shape the output:
 *
 *  - **A section that fails reports its failure and does not take the others
 *    with it.** A broken ClamAV must not make the EDR status unavailable;
 *    that is how a console ends up showing nothing at all because one
 *    subsystem is down.
 *  - **"Unknown" is never rendered as "fine".** Every section carries a state
 *    of ok / degraded / down / unknown, and unknown means the agent could not
 *    determine it — usually because the command was not run as root. A console
 *    that paints unknown green is worse than one that shows nothing.
 *  - **No secrets.** The Hub token never appears here. The output is meant to
 *    be read by an unprivileged UI, so it must be safe to leave world-readable.
 */
class AgentStatus extends Command
{
    protected $signature = 'ids:status
        {--json : Emit the full snapshot as JSON}';

    protected $description = 'Report the health of every agent subsystem in one place';

    public function handle(): int
    {
        $snapshot = $this->snapshot();

        if ($this->option('json')) {
            $this->line((string) json_encode($snapshot, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

            return $snapshot['overall']['state'] === 'down' ? 1 : 0;
        }

        $this->render($snapshot);

        return $snapshot['overall']['state'] === 'down' ? 1 : 0;
    }

    /**
     * @return array<string, mixed>
     */
    public function snapshot(): array
    {
        $platform = EdrPlatformProfile::current();

        $snapshot = [
            'generated_at' => date('c'),
            'host' => [
                'name' => gethostname() ?: 'unknown',
                'platform' => $platform->family(),
                'os' => php_uname('s') . ' ' . php_uname('r'),
                'arch' => php_uname('m'),
                'agent_path' => base_path(),
                'privileged' => function_exists('posix_getuid') ? posix_getuid() === 0 : null,
            ],
            'edr' => $this->section(fn (): array => $this->edr($platform)),
            'correlator' => $this->section(fn (): array => $this->correlator()),
            'suricata' => $this->section(fn (): array => $this->suricata()),
            'clamav' => $this->section(fn (): array => $this->clamav()),
            'hub' => $this->section(fn (): array => $this->hub()),
        ];

        $snapshot['overall'] = $this->overall($snapshot);

        return $snapshot;
    }

    /**
     * Run one section, and turn a failure into a reported state rather than a
     * dead snapshot.
     */
    private function section(callable $probe): array
    {
        try {
            return $probe();
        } catch (\Throwable $e) {
            return [
                'state' => 'unknown',
                'detail' => 'could not be determined: ' . $e->getMessage(),
            ];
        }
    }

    private function edr(EdrPlatformProfile $platform): array
    {
        $engine = app(OsqueryEngine::class);
        $status = $engine->getStatus();
        $spool = app(EdrEventSpool::class)->stats();

        $backend = (string) $status['backend'];
        $running = (bool) $status['running'];

        $state = match (true) {
            !$status['supported'] => 'unsupported',
            !$status['installed'] => 'down',
            $backend === '' => 'down',
            !$running => 'down',
            default => 'ok',
        };

        // What the operator has to do next, in the platform's own terms. On
        // macOS the answer to an empty backend is always the Full Disk Access
        // grant, and saying "check the kernel version" there sends them after
        // a fault that is not present.
        $action = match (true) {
            !$status['supported'] => 'No sensor exists for this platform yet.',
            !$status['installed'] && $platform->isDarwin() =>
                'Install with: brew install --cask osquery',
            !$status['installed'] => 'Install with: php artisan ids:sync-edr --install',
            $backend === '' && $platform->isDarwin() =>
                'Grant Full Disk Access to osqueryd in System Settings → Privacy & Security.',
            $backend === '' => 'No usable backend: needs kernel 5.8+ with BTF, or auditd stopped.',
            !$running => 'Start with: php artisan ids:sync-edr --start',
            default => null,
        };

        // Per class, never averaged. The classes have separate ceilings by
        // design, so one figure over the whole file reports the long tail as
        // if it were the window an investigation has — 67 hours on this host
        // while the process telemetry anything would actually query reached
        // back barely one.
        $windows = app(EdrEventSpool::class)->retentionWindows();

        return [
            'state' => $state,
            'action' => $action,
            'backend' => $backend !== '' ? $backend : null,
            'installed' => (bool) $status['installed'],
            'running' => $running,
            'version' => $status['version'] ?: null,
            'pid' => $status['pid'] ?: null,
            'container_visibility' => $platform->containerVisibility(),
            'event_clock_anchorable' => $platform->canAnchorEventClock(),
            'spool' => [
                'available' => (bool) $spool['available'],
                'total_events' => (int) $spool['total'],
                'pending_upload' => (int) $spool['pending'],
                'sent' => (int) $spool['sent'],
                'with_alerts' => (int) $spool['alerts'],
                'size_bytes' => (int) $spool['size_bytes'],
                // Not "rows / ceiling": that reads as a disk problem and is
                // the same number on every host. Hours of history per class is
                // the question an investigation actually asks, and the answer
                // differs by an order of magnitude between them.
                'retention' => $windows,
                'oldest_event' => $spool['oldest_ts'] ? date('c', (int) $spool['oldest_ts']) : null,
            ],
        ];
    }

    private function correlator(): array
    {
        $options = $this->hubOptions();
        $enabled = (bool) ($options['correlator_enabled'] ?? false);

        $correlator = EdrCorrelator::make($options);
        $store = $correlator->store();

        if (!$store->isAvailable()) {
            $correlator->close();

            return ['state' => 'unknown', 'detail' => 'correlator state is not readable'];
        }

        $scored = (int) ($store->getMeta('scored_events') ?? '0');
        $first = (int) ($store->getMeta('first_event_ts') ?? '0');
        $last = (int) ($store->getMeta('last_event_ts') ?? '0');
        $warmEvents = max(1000, (int) ($options['correlator_warm_events'] ?? 50000));
        $warmDays = max(3, (int) ($options['correlator_warm_days'] ?? 14));
        $spanDays = $first > 0 && $last > $first ? round(($last - $first) / 86400, 1) : 0.0;
        $mature = $correlator->isMature();

        $stats = $store->stats();
        $anomalies = (int) ($store->getMeta('clock_anomaly_count') ?? '0');
        $resetAt = $store->getMeta('state_reset_at');

        $correlator->close();

        return [
            // Warming is not a fault, and a console that paints it red trains
            // people to ignore red. It is the designed state for a fortnight.
            'state' => match (true) {
                !$enabled => 'disabled',
                $mature => 'ok',
                default => 'warming',
            },
            'enabled' => $enabled,
            'mature' => $mature,
            'warmup' => [
                'events' => $scored,
                'events_required' => $warmEvents,
                'days_observed' => $spanDays,
                'days_required' => $warmDays,
                'progress' => $warmEvents > 0 && $warmDays > 0
                    ? round(min(1.0, min($scored / $warmEvents, $spanDays / $warmDays)) * 100)
                    : 0,
            ],
            'learned' => [
                'facets' => (int) $stats['facets'],
                'actors' => (int) $stats['actors'],
                'lineage_rows' => (int) $stats['procs'],
                'incidents_seen' => (int) $stats['incidents_seen'],
            ],
            'clock_anomalies' => $anomalies,
            'state_reset_at' => $resetAt !== null ? date('c', (int) $resetAt) : null,
        ];
    }

    private function suricata(): array
    {
        $engine = app(SuricataEngine::class);
        $status = $engine->getStatus();

        return [
            'state' => match (true) {
                empty($status['installed']) => 'down',
                empty($status['running']) => 'down',
                default => 'ok',
            },
            'installed' => (bool) ($status['installed'] ?? false),
            'running' => (bool) ($status['running'] ?? false),
            'version' => $status['version'] ?? null,
            'mode' => $status['mode'] ?? ($status['running_mode'] ?? null),
            'rules' => $status['rule_count'] ?? ($status['rules'] ?? null),
            'action' => empty($status['installed'])
                ? 'Install with: php artisan ids:sync-suricata --install'
                : (empty($status['running']) ? 'Start with: php artisan ids:sync-suricata --start' : null),
        ];
    }

    private function clamav(): array
    {
        $service = app(ClamavService::class);
        $status = $service->getStatus();

        return [
            'state' => empty($status['installed']) ? 'down' : 'ok',
            'installed' => (bool) ($status['installed'] ?? false),
            'version' => $status['version'] ?? null,
            'definitions_date' => $status['definitions_date'] ?? ($status['last_update'] ?? null),
            'last_scan' => $status['last_scan'] ?? null,
            'action' => empty($status['installed']) ? 'ClamAV is not installed.' : null,
        ];
    }

    private function hub(): array
    {
        $config = app(WafSyncService::class)->getConnectionConfig();
        $configured = $config['url'] !== '' && $config['token'] !== '';

        $backoffUntil = (int) cache()->get('edr_upload_backoff_until', 0);
        $failures = (int) cache()->get('edr_upload_failures', 0);
        $pending = 0;

        try {
            $pending = (int) app(EdrEventSpool::class)->stats()['pending'];
        } catch (\Throwable $e) {
            // Reported by the EDR section; not worth failing this one for.
        }

        $privileged = function_exists('posix_getuid') ? posix_getuid() === 0 : true;

        return [
            // Credentials live in a root-only file, so an unprivileged caller
            // genuinely cannot tell. Saying so beats reporting "not
            // configured", which is a different and alarming claim.
            'state' => match (true) {
                !$configured && !$privileged => 'unknown',
                !$configured => 'down',
                $backoffUntil > time() => 'degraded',
                default => 'ok',
            },
            'configured' => $configured,
            // The host only, never the token, and never the full URL with any
            // query string it might carry.
            'url' => $configured ? (parse_url($config['url'], PHP_URL_HOST) ?: null) : null,
            'backoff_until' => $backoffUntil > time() ? date('c', $backoffUntil) : null,
            'consecutive_failures' => $failures,
            'queued_alerts' => $pending,
            'detail' => !$configured && !$privileged
                ? 'Hub credentials are root-only; run with sudo to read them.'
                : null,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function overall(array $snapshot): array
    {
        $reasons = [];
        $worst = 'ok';

        $rank = ['ok' => 0, 'disabled' => 0, 'warming' => 1, 'unsupported' => 1, 'unknown' => 2, 'degraded' => 2, 'down' => 3];

        foreach (['edr', 'correlator', 'suricata', 'clamav', 'hub'] as $key) {
            $state = (string) ($snapshot[$key]['state'] ?? 'unknown');

            if (($rank[$state] ?? 2) > ($rank[$worst] ?? 0)) {
                $worst = $state;
            }

            if (in_array($state, ['down', 'degraded', 'unknown'], true)) {
                $reasons[] = $key . ': ' . ($snapshot[$key]['action'] ?? $snapshot[$key]['detail'] ?? $state);
            }
        }

        return [
            'state' => match ($worst) {
                'down' => 'down',
                'degraded', 'unknown' => 'degraded',
                default => 'ok',
            },
            'reasons' => $reasons,
        ];
    }

    private function hubOptions(): array
    {
        $config = json_decode((string) @file_get_contents(storage_path('app/waf_config.json')), true) ?: [];
        $addons = $config['addons'] ?? [];

        $options = ['host_id' => gethostname() ?: 'unknown'];

        foreach ($addons as $key => $value) {
            if (str_starts_with((string) $key, 'edr_correlator_')) {
                $options[substr((string) $key, 4)] = $value;
            }
        }

        return $options;
    }

    /* ------------------------------------------------------------------ */
    /* Human view                                                          */
    /* ------------------------------------------------------------------ */

    private function render(array $s): void
    {
        $dot = static fn (string $state): string => match ($state) {
            'ok' => '<fg=green>●</>',
            'warming' => '<fg=cyan>●</>',
            'degraded' => '<fg=yellow>●</>',
            'disabled', 'unsupported' => '<fg=gray>○</>',
            'down' => '<fg=red>●</>',
            default => '<fg=yellow>?</>',
        };

        $this->newLine();
        $this->line("  {$dot($s['overall']['state'])} <options=bold>Security One Agent</> — {$s['host']['name']}  <fg=gray>({$s['host']['os']} {$s['host']['arch']})</>");
        $this->newLine();

        $edr = $s['edr'];
        $this->line("  {$dot($edr['state'])} <options=bold>Endpoint sensor</>   " . ($edr['backend'] ?? '<fg=gray>no backend</>'));

        if (isset($edr['spool'])) {
            $this->line('      ' . number_format($edr['spool']['total_events']) . ' events · '
                . number_format($edr['spool']['pending_upload']) . ' queued');

            foreach ($edr['spool']['retention'] as $class => $w) {
                if ($w['events'] === 0) {
                    continue;
                }

                $this->line(sprintf(
                    '        %-9s %8s events · %s of history',
                    $class,
                    number_format($w['events']),
                    $w['hours'] !== null ? $w['hours'] . 'h' : 'unknown'
                ));
            }
        }

        $c = $s['correlator'];
        $this->line("  {$dot($c['state'])} <options=bold>Correlator</>        " . ($c['state'] === 'warming'
            ? "warming {$c['warmup']['progress']}% ({$c['warmup']['days_observed']}/{$c['warmup']['days_required']} days)"
            : $c['state']));

        $su = $s['suricata'];
        $this->line("  {$dot($su['state'])} <options=bold>Suricata</>          " . ($su['version'] ?? '-')
            . ($su['rules'] ? ' · ' . number_format((int) $su['rules']) . ' rules' : ''));

        $cl = $s['clamav'];
        $this->line("  {$dot($cl['state'])} <options=bold>ClamAV</>            " . ($cl['version'] ?? '-'));

        $hub = $s['hub'];
        $this->line("  {$dot($hub['state'])} <options=bold>Hub</>               " . ($hub['url'] ?? ($hub['detail'] ?? 'not configured')));

        if ($s['overall']['reasons'] !== []) {
            $this->newLine();
            $this->line('  <options=bold>Needs attention</>');

            foreach ($s['overall']['reasons'] as $reason) {
                $this->line("    <fg=yellow>→</> {$reason}");
            }
        }

        $this->newLine();
    }
}

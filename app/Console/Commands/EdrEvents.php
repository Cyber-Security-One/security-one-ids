<?php

namespace App\Console\Commands;

use App\Services\ClamavService;
use App\Services\Detection\SuricataEngine;
use App\Services\EdrEventSpool;
use App\Services\Response\FileQuarantine;
use Illuminate\Console\Command;

/**
 * Recent endpoint events, for a console to render.
 *
 * The status snapshot answers "how many events are held". That is the right
 * answer for a dot in the menu bar and the wrong one for anything that wants
 * to show the events themselves, so this exists alongside it rather than
 * inside it.
 *
 * It reads through EdrEventSpool for the same reason the macOS console reads
 * through `ids:status`: the spool owns decryption, redaction and the schema,
 * and a second reader that opened the SQLite file directly would be a second
 * implementation of all three — one that keeps working, quietly wrongly, on
 * the day any of them changes.
 *
 * cmdline is deliberately not emitted. It is the field most likely to carry a
 * secret that slipped past redaction, and nothing that draws a picture of
 * events needs it.
 */
class EdrEvents extends Command
{
    protected $signature = 'ids:events
        {--json : Emit JSON}
        {--limit=200 : How many of the most recent events to return}
        {--alerts : Only events that carry a severity}
        {--source=all : all, edr, ids, ips or av}';

    protected $description = 'List recent endpoint sensor events';

    public function handle(
        EdrEventSpool $spool,
        SuricataEngine $suricata,
        ClamavService $clamav,
        FileQuarantine $quarantine
    ): int {
        if (!$spool->isAvailable()) {
            $payload = [
                'available' => false,
                'reason' => 'The event spool is not available on this host.',
                'events' => [],
            ];

            $this->line($this->option('json') ? (string) json_encode($payload) : $payload['reason']);

            return self::FAILURE;
        }

        $limit = max(1, min(2000, (int) $this->option('limit')));

        $rows = $spool->query([
            'limit' => $limit,
            'alerts_only' => (bool) $this->option('alerts'),
        ]);

        $events = [];
        $byAction = [];
        $bySeverity = [];

        foreach ($rows as $row) {
            // Severity is null for the overwhelming majority of rows by
            // design — most of the spool is retro-hunt material, not alerts —
            // so it is bucketed under a name rather than dropped, which would
            // make the counts disagree with the total.
            $severity = $row['severity'] ?? null;
            $severityKey = $severity === null || $severity === '' ? 'none' : (string) $severity;
            $action = (string) ($row['action'] ?? 'unknown');

            $byAction[$action] = ($byAction[$action] ?? 0) + 1;
            $bySeverity[$severityKey] = ($bySeverity[$severityKey] ?? 0) + 1;

            $events[] = [
                'ts' => (int) ($row['ts'] ?? 0),
                'action' => $action,
                'sensor' => $row['sensor'] ?? null,
                'pid' => isset($row['pid']) ? (int) $row['pid'] : null,
                'ppid' => isset($row['ppid']) ? (int) $row['ppid'] : null,
                'user' => $row['username'] ?? null,
                'path' => $row['path'] ?? null,
                'severity' => $severity,
                // Whether this one is bound for the Hub. Most are not: shipping
                // every exec would be hundreds of megabytes a day per host.
                'deliver' => (bool) ($row['deliver'] ?? false),
                'sent' => ($row['sent_at'] ?? null) !== null,
            ];
        }

        // What the spool holds, against what this call returned. A console
        // that draws 240 points out of 400,000 and says nothing about the
        // difference is lying by omission about the size of the haystack.
        $held = null;

        try {
            $held = (int) ($spool->stats()['total'] ?? 0);
        } catch (\Throwable $e) {
            // Reported by the status snapshot; not worth failing this for.
        }

        foreach ($events as &$row) {
            $row['source'] = 'edr';
        }

        unset($row);

        $sources = [
            'edr' => ['available' => true, 'returned' => count($events), 'held' => $held],
        ];

        $wanted = (string) $this->option('source');
        $want = static fn (string $name): bool => $wanted === 'all' || $wanted === $name;

        if (!$want('edr')) {
            $events = [];
            $sources['edr']['returned'] = 0;
        }

        // Suricata carries both roles in one log: an `alert` was seen and
        // reported, a `drop` was seen and stopped. They are the difference
        // between an IDS and an IPS, so they are reported as separate sources
        // rather than merged into "network".
        foreach ($this->suricataEvents($suricata, $limit) as $alert) {
            if (!$want($alert['source'])) {
                continue;
            }

            $events[] = $alert;
            $sources[$alert['source']]['available'] = true;
            $sources[$alert['source']]['returned'] = ($sources[$alert['source']]['returned'] ?? 0) + 1;
        }

        foreach (['ids', 'ips'] as $role) {
            $sources[$role] = $sources[$role] ?? ['available' => true, 'returned' => 0];
        }

        // Antivirus is the honest gap here. ClamAV keeps no detection history
        // — a detection exists only inside the return value of the scan that
        // found it — so the only durable record on this host is what was
        // quarantined as a result. That is reported as what it is rather than
        // dressed up as a detection feed, because an empty AV row that means
        // "nothing kept" must not read as "nothing found".
        $av = $this->quarantineEvents($quarantine, $limit);

        if ($want('av')) {
            $events = array_merge($events, $av);
        }

        $sources['av'] = [
            'available' => true,
            'returned' => $want('av') ? count($av) : 0,
            'note' => 'Quarantined files only. ClamAV keeps no detection history to read.',
        ];

        usort($events, static fn (array $a, array $b): int => ($b['ts'] ?? 0) <=> ($a['ts'] ?? 0));

        // Counted after the cut, not before.
        //
        // Every source is read up to the limit and then the merged list is
        // trimmed to it, so a noisy source crowds a quiet one out of the tail:
        // 400 Suricata alerts and 400 spool rows go in, 371 and 29 come out.
        // Reporting what went in would tell the console it is drawing events
        // that are not in the payload it was handed.
        $read = array_map(static fn (array $source): int => (int) ($source['returned'] ?? 0), $sources);
        $events = array_slice($events, 0, $limit);

        foreach ($sources as $name => $source) {
            $sources[$name]['read'] = $read[$name] ?? 0;
            $sources[$name]['returned'] = 0;
        }

        foreach ($events as $event) {
            $name = (string) ($event['source'] ?? 'edr');
            $sources[$name]['returned'] = ($sources[$name]['returned'] ?? 0) + 1;
        }

        $timestamps = array_column($events, 'ts');

        $payload = [
            'available' => true,
            'generated_at' => date('c'),
            'returned' => count($events),
            'held' => $held,
            'sources' => $sources,
            'limit' => $limit,
            'window' => [
                'from' => $timestamps === [] ? null : date('c', min($timestamps)),
                'to' => $timestamps === [] ? null : date('c', max($timestamps)),
            ],
            'by_action' => $byAction,
            'by_severity' => $bySeverity,
            'events' => $events,
        ];

        if ($this->option('json')) {
            $this->line((string) json_encode($payload, JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->line(sprintf('%d events', count($events)));

        foreach ($events as $event) {
            $this->line(sprintf(
                '  %s  %-14s %-8s pid=%-7s %s',
                date('H:i:s', $event['ts']),
                $event['action'],
                $event['severity'] ?? '-',
                $event['pid'] ?? '-',
                $event['path'] ?? ''
            ));
        }

        return self::SUCCESS;
    }

    /**
     * Suricata alerts and drops, normalised to the shape above.
     */
    private function suricataEvents(SuricataEngine $suricata, int $limit): array
    {
        $events = [];

        try {
            foreach ($suricata->parseAlerts($limit) as $alert) {
                $stamp = strtotime((string) ($alert['timestamp'] ?? '')) ?: 0;

                if ($stamp === 0) {
                    continue;
                }

                $blocked = ($alert['action'] ?? 'alert') === 'drop';

                $events[] = [
                    'ts' => $stamp,
                    'source' => $blocked ? 'ips' : 'ids',
                    'action' => $blocked ? 'blocked' : 'detected',
                    'sensor' => 'suricata',
                    'pid' => null,
                    'ppid' => null,
                    'user' => null,
                    // The signature is what an operator reads; the addresses
                    // are what they pivot on, so both are kept in one line.
                    'path' => trim(sprintf(
                        '%s  %s → %s',
                        (string) ($alert['signature'] ?? 'Unknown'),
                        (string) ($alert['source_ip'] ?? '?'),
                        (string) ($alert['destination_ip'] ?? '?')
                    )),
                    'severity' => $alert['severity'] ?? null,
                    'deliver' => true,
                    'sent' => false,
                ];
            }
        } catch (\Throwable $e) {
            // A console is not worth failing the whole command for.
        }

        return $events;
    }

    /**
     * Files taken out of circulation — the durable half of the AV story.
     */
    private function quarantineEvents(FileQuarantine $quarantine, int $limit): array
    {
        $events = [];

        try {
            foreach (array_slice($quarantine->listQuarantined(), 0, $limit) as $entry) {
                $stamp = (int) ($entry['quarantined_at'] ?? 0);

                if ($stamp === 0 && isset($entry['quarantined_at'])) {
                    $stamp = strtotime((string) $entry['quarantined_at']) ?: 0;
                }

                $events[] = [
                    'ts' => $stamp,
                    'source' => 'av',
                    'action' => 'quarantined',
                    'sensor' => 'clamav',
                    'pid' => null,
                    'ppid' => null,
                    'user' => null,
                    'path' => (string) ($entry['original_path'] ?? $entry['path'] ?? ''),
                    'severity' => 'high',
                    'deliver' => true,
                    'sent' => false,
                ];
            }
        } catch (\Throwable $e) {
            // Same.
        }

        return $events;
    }
}

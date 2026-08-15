<?php

namespace App\Console\Commands;

use App\Services\EdrEventSpool;
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
        {--alerts : Only events that carry a severity}';

    protected $description = 'List recent endpoint sensor events';

    public function handle(EdrEventSpool $spool): int
    {
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

        $timestamps = array_column($events, 'ts');

        $payload = [
            'available' => true,
            'generated_at' => date('c'),
            'returned' => count($events),
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
}

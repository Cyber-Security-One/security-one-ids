<?php

namespace App\Services;

/**
 * Shapes normalised endpoint events into Hub alert payloads.
 *
 * Extracted from the collector because delivery now happens from the spool,
 * not from the collection cycle: a Hub outage must leave alerts queued on
 * disk and retried later, which means the uploader has to be able to rebuild
 * the exact same payload from a stored row hours after the event.
 */
class EdrAlertFactory
{
    private ?string $hostIp = null;
    private EdrSecretRedactor $redactor;

    public function __construct(?EdrSecretRedactor $redactor = null)
    {
        $this->redactor = $redactor ?? new EdrSecretRedactor();
    }

    /**
     * The flat fields match what the Hub already accepts from Suricata, so
     * EDR findings land in the existing alert pipeline; the `process`,
     * `rules` and `mitre` blocks carry the detail the EDR views need.
     *
     * @param array $event    normalised event
     * @param array $findings rule hits for that event
     */
    public function fromEvent(array $event, array $findings): array
    {
        $severity = EdrRuleEngine::worstSeverity($findings);

        $labels = array_map(
            static fn (array $f): string => trim(
                ($f['rule'] ?? '?') . ' ' . ($f['name'] ?? '') . ' (' . ($f['mitre'] ?? '-') . ')'
            ),
            $findings
        );

        $path = (string) ($event['path'] ?? '');

        // Redacted here as well as in the spool.
        //
        // The delivery path rebuilds alerts from spooled rows, which are
        // already clean — but this method is also called on the *live* event
        // for the dry-run view, and the incident evidence beside it is
        // redacted. One field of an alert carrying a password while its
        // neighbour does not is the kind of inconsistency that becomes a leak
        // the moment someone ships the other path. Redaction is idempotent, so
        // doing it in both places costs nothing and removes the question.
        $cmdline = (string) $this->redactor->redact(
            ($event['cmdline'] ?? '') !== '' ? (string) $event['cmdline'] : $path
        );
        $event['cmdline'] = $cmdline;
        $ts = (int) ($event['ts'] ?? time());

        return [
            // Existing Hub alert contract.
            'source_ip' => $this->hostIp(),
            'severity' => $severity,
            'category' => 'endpoint-behaviour',
            'source' => 'edr',
            'detections' => '[EDR] ' . implode(' | ', $labels) . ' — ' . $this->truncate($cmdline, 400),
            // Bounded, unlike every other copy of the event in this payload.
            //
            // A single Linux argument can be 128 KB and an argv can approach
            // 2 MB, so one pathological command line produced a multi-megabyte
            // alert — and a batch of two hundred of them exceeded the Hub's
            // request ceiling, which the uploader could only answer by
            // retrying the same oversized batch forever. The detail worth
            // keeping is in the first few kilobytes; the rest is an argument
            // list nobody reads and a stalled queue.
            'raw_log' => $this->truncate(
                (string) json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                16384
            ),
            'uri' => $this->truncate($path, 255),
            'method' => strtoupper((string) ($event['action'] ?? 'exec')),

            // EDR detail.
            'process' => [
                'pid' => (int) ($event['pid'] ?? 0),
                'ppid' => (int) ($event['ppid'] ?? 0),
                'path' => $path,
                'cmdline' => $this->truncate($cmdline, 2000),
                'cwd' => (string) ($event['cwd'] ?? ''),
                'user' => (string) ($event['username'] ?? ''),
                'uid' => (int) ($event['uid'] ?? -1),
                'container_id' => (string) ($event['container_id'] ?? ''),
                'observed_at' => date('c', $ts),
            ],
            'rules' => $findings,
            'mitre' => array_values(array_unique(array_filter(array_column($findings, 'mitre')))),
        ];
    }

    /**
     * Shape a correlated incident.
     *
     * The flat fields stay identical to every other EDR alert, so an incident
     * lands in the same Hub pipeline as a rule hit and needs no new plumbing.
     * What is different is the `incident` block: the score, the stages, and
     * the individual events that contributed with their weights. An analyst
     * looking at a correlated finding needs the arithmetic, not a verdict —
     * a score they cannot check is a score they cannot argue with, and an
     * unarguable alert at 3 a.m. gets the feature switched off.
     *
     * @param array $event    the highest-charge contributing event
     * @param array $findings the incident findings (EDR-100 / EDR-101)
     */
    public function fromIncident(array $event, array $findings): array
    {
        $alert = $this->fromEvent($event, $findings);

        $incident = null;
        $incidentRule = 'EDR-100';

        foreach ($findings as $finding) {
            if (isset($finding['incident']) && is_array($finding['incident'])) {
                $incident = $finding['incident'];
                // The rule id has to come from the finding that carries the
                // incident, not from whichever finding happens to be first.
                // After a round trip through the spool the row's `rule_hits`
                // holds the event's own rule hits alongside the incident, so
                // taking [0] headlined a correlated alert with, say, EDR-004.
                $incidentRule = (string) ($finding['rule'] ?? $incidentRule);
                break;
            }
        }

        if ($incident === null) {
            return $alert;
        }

        $alert['category'] = 'endpoint-incident';
        $alert['incident'] = $incident;
        $alert['mitre'] = array_values(array_unique(array_merge(
            $alert['mitre'],
            array_filter((array) ($incident['mitre'] ?? []))
        )));

        // The one-line summary an operator sees in a list view should name the
        // chain, not the single command that happened to score highest.
        $alert['detections'] = sprintf(
            '[EDR] %s — %s (score %.1f / %.1f, %d event%s)',
            $incidentRule,
            implode(' → ', (array) ($incident['classes'] ?? [])),
            (float) ($incident['score'] ?? 0),
            (float) ($incident['threshold'] ?? 0),
            (int) ($incident['events_contributing'] ?? 0),
            ((int) ($incident['events_contributing'] ?? 0)) === 1 ? '' : 's'
        );

        return $alert;
    }

    /**
     * Rebuild an alert from a spooled row. The row is the durable record, so
     * this is the path every retry after a Hub outage goes through.
     */
    public function fromSpoolRow(array $row): ?array
    {
        $findings = json_decode((string) ($row['rule_hits'] ?? ''), true);
        if (!is_array($findings) || $findings === []) {
            // A queued row with no rule hits should not exist; skip rather
            // than ship a finding-less "alert" the Hub cannot render.
            return null;
        }

        $event = [
            'ts' => (int) ($row['ts'] ?? time()),
            'host' => $row['host'] ?? null,
            'action' => $row['action'] ?? 'exec',
            'sensor' => $row['sensor'] ?? null,
            'pid' => (int) ($row['pid'] ?? 0),
            'ppid' => (int) ($row['ppid'] ?? 0),
            'uid' => (int) ($row['uid'] ?? -1),
            'username' => $row['username'] ?? '',
            'path' => $row['path'] ?? '',
            'cmdline' => $row['cmdline'] ?? '',
            'cwd' => $row['cwd'] ?? '',
            'container_id' => $row['container_id'] ?? '',
            'syscall' => $row['syscall'] ?? '',
        ];

        $extra = json_decode((string) ($row['extra'] ?? ''), true);
        if (is_array($extra)) {
            $event += $extra;
        }

        // An incident rides inside `rule_hits`, so a queued incident that only
        // reaches the Hub after an outage is rebuilt with its block intact
        // rather than flattened back into an ordinary rule hit.
        foreach ($findings as $finding) {
            if (isset($finding['incident'])) {
                return $this->fromIncident($event, $findings);
            }
        }

        return $this->fromEvent($event, $findings);
    }

    private function truncate(string $value, int $limit): string
    {
        return strlen($value) > $limit ? substr($value, 0, $limit - 3) . '...' : $value;
    }

    /**
     * The alert is about activity on this host, so the host's own address is
     * the meaningful "source" for the existing Hub schema.
     */
    private function hostIp(): string
    {
        if ($this->hostIp !== null) {
            return $this->hostIp;
        }

        $ip = trim((string) @shell_exec("ip route get 1.1.1.1 2>/dev/null | awk '{print \$7; exit}'"));

        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $ip = gethostbyname(gethostname() ?: 'localhost');
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $ip = '127.0.0.1';
        }

        return $this->hostIp = $ip;
    }
}

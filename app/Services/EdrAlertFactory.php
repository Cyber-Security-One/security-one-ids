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
        $cmdline = ($event['cmdline'] ?? '') !== '' ? (string) $event['cmdline'] : $path;
        $ts = (int) ($event['ts'] ?? time());

        return [
            // Existing Hub alert contract.
            'source_ip' => $this->hostIp(),
            'severity' => $severity,
            'category' => 'endpoint-behaviour',
            'source' => 'edr',
            'detections' => '[EDR] ' . implode(' | ', $labels) . ' — ' . $this->truncate($cmdline, 400),
            'raw_log' => json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
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

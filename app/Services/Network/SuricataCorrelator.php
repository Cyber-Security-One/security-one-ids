<?php

namespace App\Services\Network;

use App\Services\EdrEventSpool;
use Illuminate\Support\Facades\Log;

/**
 * Names the process behind a Suricata alert.
 *
 * This is the join the whole IDS-to-EDR move exists for. Suricata sees a flow
 * and a signature but has no idea which process on the host is at either end;
 * the socket sensor knows the process but has no idea the traffic was
 * malicious. Neither half can answer "what do I do about this" alone.
 *
 * The obvious join key — the 4-tuple — is unavailable. Measured on a real host,
 * `local_port` is 0 on 100% of bpf_socket_events rows across all four
 * syscalls, so the host's own port is simply not in the telemetry. What is
 * available is the peer's address and port, which means the alert first has to
 * be oriented: which end of this flow is us.
 *
 * How well that works was measured against 38,969 real alerts and 283,664 real
 * socket events, and the answer depends almost entirely on two choices.
 *
 * Matching the right syscall matters because an inbound alert must be matched
 * against accepts and an outbound one against connects. Conflating them is what
 * the existing socket handling does — every syscall is stored as action
 * 'connect' — and it inflates the candidate set with connections that went the
 * other way.
 *
 * The window matters more, and not smoothly:
 *
 *   window   outbound matched   unique      inbound matched   unique
 *      2s               1,586    82.5%                  115   100.0%
 *      5s               3,571    83.6%                  768   100.0%
 *     15s               7,431    79.1%                3,777    99.9%
 *     60s               7,759    32.1%                8,181    99.5%
 *    300s               9,664    26.9%                8,291    97.0%
 *
 * Fifteen seconds buys 96% of the coverage a minute would, at more than twice
 * the unique-attribution rate. The collapse between 15s and 60s is php-fpm's
 * worker pool: given a minute, several workers reach the same destination and
 * there is no longer a single answer. Widening the window past the measured
 * cliff does not find more culprits, it finds more suspects.
 *
 * Inbound attribution is near-perfect at every window because the peer's
 * ephemeral port is unique per connection, which makes it a genuinely strong
 * key rather than a heuristic.
 *
 * One caveat on that table, because the number is load-bearing and the
 * measurement behind it is not as clean as it looks. Those socket events were
 * timestamped with the osquery result row's flush time, and the flush lands
 * measurably later than the event it describes: across 14,787 real rows,
 * `(btime + ntime) - unixTime` ran from -3s to -297s with a median of -13.9s
 * (-19.3s for socket events specifically). So a good part of what the
 * fifteen-second window buys is absorbing that lag rather than bounding
 * causality, and the real optimum against the kernel event clock is almost
 * certainly tighter — which would attribute *better*, since 2s and 5s already
 * measured 82.5% and 83.6% unique against the looser clock.
 *
 * It is not recalibrated yet, and deliberately so rather than quietly. The
 * spool does not carry `ntime` today, and re-running the sweep needs a window
 * where kernel-clocked socket telemetry and Suricata alerts overlap: the raw
 * osquery log rotates at 16MB x 2 and held only the last ten minutes when this
 * was checked, against a last alert five hours earlier. Fitting a curve to
 * non-overlapping data would have produced a number rather than an answer.
 * Fifteen seconds is therefore the conservative setting, and the recalibration
 * is owed once `ntime` reaches the spool.
 *
 * Everything here is reported with the confidence it actually has. An alert
 * matching two processes says so and names both; it does not pick one. And
 * "nothing matched" is split into two outcomes that mean opposite things — no
 * telemetry covering that moment is a gap in what we recorded, while telemetry
 * that covers it and contains no such connection is evidence that no local
 * process opened it.
 */
class SuricataCorrelator
{
    /**
     * Attribution window, in seconds. See the class docblock for the
     * measurement: 15s sits at the top of the coverage-versus-uniqueness curve
     * and 60s is past the cliff.
     */
    public const DEFAULT_WINDOW = 15;

    /**
     * Rows per spool query. The spool caps its own queries at 10,000; staying
     * under that means a full page is a reliable signal that more exists,
     * rather than an ambiguous one.
     */
    private const PAGE_ROWS = 9000;

    /**
     * Total rows an attribution batch may pull, across pages.
     *
     * A ceiling has to exist — a week of alerts against a spool holding
     * hundreds of thousands of socket events per hour would otherwise try to
     * load all of it — but where the ceiling bites, coverage shrinks to what
     * was actually read rather than the answer quietly degrading.
     */
    private const MAX_TOTAL_ROWS = 90000;

    private EdrEventSpool $spool;

    /** @var array<string, true>|null */
    private ?array $hostAddresses = null;

    public function __construct(EdrEventSpool $spool)
    {
        $this->spool = $spool;
    }

    /**
     * Add process attribution to a batch of Suricata alerts.
     *
     * Accepts any of the three alert shapes this codebase produces — raw
     * eve.json events, `SuricataEngine::parseAlerts()` output, and the alerts
     * the sync service ships to the Hub — and returns them with an
     * `edr_attribution` block added.
     *
     * Alerts are never dropped or reordered. An alert nothing can be said about
     * still reaches the Hub, carrying the reason nothing could be said: the EDR
     * layer does not get to decide which IDS detections an operator sees.
     *
     * @param array<int, array> $alerts
     * @return array{alerts: array<int, array>, stats: array}
     */
    public function attribute(array $alerts, array $options = []): array
    {
        $window = max(1, (int) ($options['suricata_attribution_window'] ?? self::DEFAULT_WINDOW));

        $stats = [
            'alerts' => count($alerts),
            'unique' => 0,
            'ambiguous' => 0,
            'no_telemetry' => 0,
            'no_match' => 0,
            'not_orientable' => 0,
            'window_seconds' => $window,
        ];

        if ($alerts === []) {
            return ['alerts' => [], 'stats' => $stats];
        }

        $times = [];

        foreach ($alerts as $alert) {
            $ts = $this->alertTime($alert);

            if ($ts !== null) {
                $times[] = $ts;
            }
        }

        if ($times === []) {
            foreach ($alerts as $i => $alert) {
                $alerts[$i]['edr_attribution'] = $this->attribution('none', 'alert_has_no_timestamp', null, [], $window);
            }

            $stats['no_telemetry'] = count($alerts);

            return ['alerts' => $alerts, 'stats' => $stats];
        }

        $index = $this->loadSocketEvents(min($times) - $window, max($times) + $window);

        foreach ($alerts as $i => $alert) {
            $result = $this->attributeOne($alert, $index, $window);
            $alerts[$i]['edr_attribution'] = $result;

            $bucket = match ($result['confidence']) {
                'unique' => 'unique',
                'ambiguous' => 'ambiguous',
                default => match ($result['reason']) {
                    'no_telemetry_for_window', 'alert_has_no_timestamp' => 'no_telemetry',
                    'both_endpoints_local', 'no_peer_endpoint' => 'not_orientable',
                    default => 'no_match',
                },
            };

            $stats[$bucket]++;
        }

        return ['alerts' => $alerts, 'stats' => $stats];
    }

    /**
     * @param array{events: array<string, array<int, array{ts:int,path:string,pid:int}>>, from:int, to:int, covered:bool, truncated:bool} $index
     */
    private function attributeOne(array $alert, array $index, int $window): array
    {
        $ts = $this->alertTime($alert);

        if ($ts === null) {
            return $this->attribution('none', 'alert_has_no_timestamp', null, [], $window);
        }

        $orientation = $this->orient($alert);

        if ($orientation === null) {
            // Both ends local, or neither. Container-to-container traffic on a
            // bridge lands here, and so does anything the host merely forwards.
            return $this->attribution('none', 'both_endpoints_local', null, [], $window);
        }

        [$direction, $peerAddress, $peerPort] = $orientation;

        if ($peerAddress === null) {
            return $this->attribution('none', 'no_peer_endpoint', $direction, [], $window);
        }

        // A gap in what we recorded and an absence of matching traffic mean
        // opposite things, and an investigation acts on them differently. The
        // spool covering the moment is the difference between "we did not see"
        // and "it did not happen".
        if (!$this->covers($index, $ts)) {
            return $this->attribution('none', 'no_telemetry_for_window', $direction, [], $window);
        }

        // Outbound alerts are matched against connects, inbound against
        // accepts. The peer port is the service port for an outbound flow and
        // the client's ephemeral port for an inbound one — which is why inbound
        // attribution is near-unique and outbound is not.
        $syscall = $direction === 'outbound' ? 'connect' : 'accept';
        $candidates = $index['events'][$this->key($peerAddress, $peerPort, $syscall)] ?? [];

        $matched = [];

        foreach ($candidates as $event) {
            if (abs($event['ts'] - $ts) > $window) {
                continue;
            }

            $path = $event['path'];

            if (!isset($matched[$path])) {
                $matched[$path] = ['path' => $path, 'pids' => [], 'events' => 0, 'nearest' => PHP_INT_MAX];
            }

            $matched[$path]['events']++;
            $matched[$path]['nearest'] = min($matched[$path]['nearest'], abs($event['ts'] - $ts));

            if ($event['pid'] > 0 && count($matched[$path]['pids']) < 16) {
                $matched[$path]['pids'][$event['pid']] = true;
            }
        }

        if ($matched === []) {
            return $this->attribution('none', 'no_matching_connection', $direction, [], $window);
        }

        $processes = [];

        foreach ($matched as $entry) {
            $pids = array_keys($entry['pids']);
            sort($pids);

            $processes[] = [
                'path' => $entry['path'],
                'pids' => $pids,
                'events' => $entry['events'],
                'seconds_from_alert' => $entry['nearest'],
            ];
        }

        // Closest in time first, then busiest. Ordering is presentation only —
        // an ambiguous result stays ambiguous, and the first entry is not a
        // verdict.
        usort($processes, static function (array $a, array $b): int {
            return [$a['seconds_from_alert'], -$a['events']] <=> [$b['seconds_from_alert'], -$b['events']];
        });

        $confidence = count($processes) === 1 ? 'unique' : 'ambiguous';
        $reason = $confidence === 'unique' ? 'matched_one_process' : 'multiple_candidates';

        return $this->attribution($confidence, $reason, $direction, $processes, $window);
    }

    /**
     * @param array<int, array> $processes
     */
    private function attribution(
        string $confidence,
        string $reason,
        ?string $direction,
        array $processes,
        int $window
    ): array {
        return [
            'confidence' => $confidence,
            'reason' => $reason,
            'direction' => $direction,
            'processes' => $processes,
            'window_seconds' => $window,
        ];
    }

    /**
     * Read the flow endpoints out of whatever alert shape was handed over.
     *
     * Three shapes exist in this codebase and they disagree on field names.
     * Raw eve.json events use `src_ip`/`dest_ip`; `SuricataEngine::parseAlerts()`
     * renames them to `source_ip`/`destination_ip`; and the alerts the sync
     * service actually ships to the Hub keep only `source_ip`, fold the
     * destination into a `uri` string, and carry the original JSON in
     * `raw_log`.
     *
     * Supporting all three is not defensiveness for its own sake. Written
     * against one shape, this class would have returned "no peer endpoint" for
     * every alert from the other two, and reported it as a clean result: a
     * hundred percent attribution failure that looks exactly like a quiet
     * network. The `raw_log` fallback exists because that is the only field in
     * the shipped shape that still holds the ports.
     *
     * @return array<string, mixed> the flow fields, normalised
     */
    private function flow(array $alert): array
    {
        $candidates = [$alert];

        if (isset($alert['raw_log']) && is_string($alert['raw_log'])) {
            $decoded = json_decode($alert['raw_log'], true);

            if (is_array($decoded)) {
                $candidates[] = $decoded;
            }
        }

        $flow = ['src' => null, 'dst' => null, 'src_port' => null, 'dst_port' => null, 'ts' => null];

        foreach ($candidates as $source) {
            $flow['src'] ??= $source['src_ip'] ?? $source['source_ip'] ?? null;
            $flow['dst'] ??= $source['dest_ip'] ?? $source['destination_ip'] ?? null;
            $flow['src_port'] ??= $source['src_port'] ?? $source['source_port'] ?? null;
            $flow['dst_port'] ??= $source['dest_port'] ?? $source['destination_port'] ?? null;
            $flow['ts'] ??= $source['timestamp'] ?? null;
        }

        // The shipped shape puts the destination in `uri` as "ip:port" and
        // keeps nothing else. Parsed last, so a real field always wins.
        if ($flow['dst'] === null && isset($alert['uri']) && is_string($alert['uri'])) {
            $position = strrpos($alert['uri'], ':');

            if ($position !== false) {
                $flow['dst'] = substr($alert['uri'], 0, $position);
                $flow['dst_port'] ??= substr($alert['uri'], $position + 1);
            }
        }

        return $flow;
    }

    /**
     * Work out which end of the flow is this host.
     *
     * Returns [direction, peer address, peer port], or null when the flow does
     * not have exactly one local end.
     *
     * @return array{0:string, 1:?string, 2:?int}|null
     */
    public function orient(array $alert): ?array
    {
        $flow = $this->flow($alert);

        $src = $this->address($flow['src']);
        $dst = $this->address($flow['dst']);

        $srcLocal = $src !== null && $this->isHostAddress($src);
        $dstLocal = $dst !== null && $this->isHostAddress($dst);

        if ($srcLocal === $dstLocal) {
            return null;
        }

        return $srcLocal
            ? ['outbound', $dst, $this->port($flow['dst_port'])]
            : ['inbound', $src, $this->port($flow['src_port'])];
    }

    /**
     * Pull socket events for the batch's span and index them by endpoint.
     *
     * Paged backwards from the newest, because the spool orders by descending
     * time and a single page is nowhere near a busy host's volume — 14,878
     * outbound socket events in 90 minutes, measured.
     *
     * The coverage this reports is the range actually read, never the range
     * requested. Getting that wrong is what the first version did, and the
     * consequence was not a missing feature: 448 of 500 replayed real flows
     * came back as "no local process opened this connection", which in an
     * investigation means the traffic did not originate here. The truth was
     * that only the most recent few minutes had been loaded. An honest
     * "telemetry does not reach that far back" and a confident wrong answer
     * are not close to equivalent.
     *
     * @return array{events: array<string, array<int, array{ts:int,path:string,pid:int}>>, from:int, to:int, covered:bool, truncated:bool}
     */
    private function loadSocketEvents(int $from, int $to): array
    {
        // Coverage is the range that was *read*, which is not the range the
        // rows happen to span. Those differ in a way that matters: a query
        // returning everything available between two bounds has covered both
        // bounds even if the newest row sits in the middle, because "no events
        // after this point" is a fact about the host, not a gap in what we
        // looked at. Reporting the newest row's timestamp as the ceiling makes
        // every alert arriving in a quiet second unanswerable.
        //
        // Only truncation genuinely narrows coverage, and then it narrows the
        // floor: everything above the oldest row read was seen, nothing below it
        // was.
        $index = [
            'events' => [],
            'from' => $from,
            'to' => $to,
            'covered' => false,
            'truncated' => false,
        ];

        $oldestRead = PHP_INT_MAX;

        $until = $to;
        $total = 0;
        // Row ids already folded in. Paging by timestamp alone cannot avoid
        // re-reading the boundary second, and stepping past it instead would
        // silently drop every other row sharing it — measured at roughly a
        // hundred socket events per second on this host, so a boundary loses
        // dozens of rows and turns a correct attribution into a confidently
        // wrong one. Re-reading and deduplicating is the cheaper mistake.
        $seen = [];

        while ($total < self::MAX_TOTAL_ROWS) {
            try {
                $rows = $this->spool->query([
                    'since' => $from,
                    'until' => $until,
                    'limit' => self::PAGE_ROWS,
                ]);
            } catch (\Throwable $e) {
                Log::warning('[EDR suricata] Could not read socket telemetry: ' . $e->getMessage());
                break;
            }

            if ($rows === []) {
                // Nothing remains in the requested span, so it was read in full.
                break;
            }

            $oldest = PHP_INT_MAX;
            $fresh = 0;

            foreach ($rows as $row) {
                $ts = (int) ($row['ts'] ?? 0);
                $oldest = min($oldest, $ts);

                $id = $row['id'] ?? null;

                if ($id !== null) {
                    if (isset($seen[$id])) {
                        continue;
                    }

                    $seen[$id] = true;
                }

                $total++;
                $fresh++;

                $socket = $this->socketEndpoint($row);

                if ($socket === null) {
                    continue;
                }

                $index['covered'] = true;
                $index['events'][$socket['key']][] = [
                    'ts' => $ts,
                    'path' => (string) ($row['path'] ?? ''),
                    'pid' => (int) ($row['pid'] ?? 0),
                ];
            }

            $oldestRead = min($oldestRead, $oldest);

            if (count($rows) < self::PAGE_ROWS) {
                // A short page means the span is exhausted: it was all read.
                break;
            }

            if ($oldest <= $from) {
                break;
            }

            if ($fresh === 0) {
                // A whole page of already-seen rows means one second holds more
                // rows than a page, so walking further back is impossible
                // without dropping data. Stop and let coverage say so.
                Log::warning('[EDR suricata] A single second exceeds the page size; attribution stops here', [
                    'second' => $oldest,
                    'page' => self::PAGE_ROWS,
                ]);
                break;
            }

            // Inclusive of the boundary second: the duplicate ids it returns
            // are filtered above, which is what makes the walk lossless.
            $until = $oldest;
        }

        if ($total >= self::MAX_TOTAL_ROWS && $oldestRead !== PHP_INT_MAX) {
            // The floor rises to what was actually reached. Alerts older than
            // this now say "no telemetry" instead of "no such connection",
            // which is the difference between an admitted gap and a false
            // exoneration.
            $index['truncated'] = true;
            $index['from'] = max($from, $oldestRead);

            Log::warning('[EDR suricata] Attribution stopped at the row budget; older alerts report no telemetry', [
                'budget' => self::MAX_TOTAL_ROWS,
                'covered_from' => $index['from'],
                'requested_from' => $from,
            ]);
        }

        return $index;
    }

    /**
     * Read a spooled row's peer endpoint and syscall, across both event shapes.
     *
     * The spool carries history in two forms and an investigation reaching back
     * a week spans both. Events written before the network module stored every
     * socket syscall as action 'connect' with the real one in the `syscall`
     * column; events written by the network collector use `net_connect` and
     * `net_accept` and nest the address under `network`. Reading only the
     * current shape would make the older half of the retention window look
     * like a host that never touched the network.
     *
     * @return array{key: string}|null
     */
    private function socketEndpoint(array $row): ?array
    {
        $action = (string) ($row['action'] ?? '');
        $syscall = strtolower((string) ($row['syscall'] ?? ''));

        $syscall = match ($action) {
            'net_connect' => 'connect',
            'net_accept' => 'accept',
            'net_bind', 'net_listen', 'net_listener' => 'listen',
            // The legacy shape: one action for every socket syscall, with the
            // distinction only in the syscall column.
            'connect' => in_array($syscall, ['connect', 'accept', 'bind', 'listen'], true) ? $syscall : '',
            default => '',
        };

        if ($syscall !== 'connect' && $syscall !== 'accept') {
            return null;
        }

        $extra = $row['extra'] ?? null;

        if (is_string($extra)) {
            $extra = json_decode($extra, true);
        }

        if (!is_array($extra)) {
            return null;
        }

        // The network collector nests under `network`; the legacy shape is flat.
        $net = is_array($extra['network'] ?? null) ? $extra['network'] : $extra;

        $address = $this->address($net['remote_address'] ?? null);

        if ($address === null) {
            return null;
        }

        return ['key' => $this->key($address, $this->port($net['remote_port'] ?? null), $syscall)];
    }

    /**
     * Whether telemetry was actually read for this moment.
     *
     * Uses the range the rows really spanned, not the range asked for.
     */
    private function covers(array $index, int $ts): bool
    {
        return $index['covered'] && $ts >= $index['from'] && $ts <= $index['to'];
    }

    private function key(string $address, ?int $port, string $syscall): string
    {
        return $address . '|' . ($port ?? '') . '|' . $syscall;
    }

    /**
     * Normalise an address for comparison, unwrapping IPv4-mapped IPv6.
     *
     * Suricata reports dotted quads and osquery reports the compressed hex
     * form of the same address, so without this the two halves of the join
     * describe the same endpoint with different strings and never meet.
     */
    private function address(mixed $value): ?string
    {
        if (!is_string($value) || trim($value) === '' || $value === 'unknown') {
            return null;
        }

        $value = trim($value);
        $binary = @inet_pton($value);

        if ($binary === false) {
            return null;
        }

        if (strlen($binary) === 16
            && substr($binary, 0, 10) === str_repeat("\0", 10)
            && substr($binary, 10, 2) === "\xff\xff"
        ) {
            $v4 = @inet_ntop(substr($binary, 12, 4));

            if ($v4 !== false) {
                return $v4;
            }
        }

        $canonical = @inet_ntop($binary);

        return $canonical === false ? $value : $canonical;
    }

    private function port(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        $port = (int) $value;

        return $port > 0 && $port <= 65535 ? $port : null;
    }

    private function isHostAddress(string $address): bool
    {
        return isset($this->hostAddresses()[$address]);
    }

    /**
     * Every address that is this host, including container bridge gateways.
     *
     * The bridges are not optional. On this host they are 172.17.0.1 through
     * 172.20.0.1, and leaving them out inverts the direction of every alert
     * involving container traffic: the host end looks foreign, so an outbound
     * flow is matched against accepts and finds nothing.
     *
     * @return array<string, true>
     */
    private function hostAddresses(): array
    {
        if ($this->hostAddresses !== null) {
            return $this->hostAddresses;
        }

        $addresses = ['127.0.0.1' => true, '::1' => true];

        foreach (['/proc/net/fib_trie' => false, '/proc/net/if_inet6' => true] as $file => $isV6) {
            $contents = @file_get_contents($file);

            if ($contents === false) {
                continue;
            }

            if ($isV6) {
                foreach (preg_split('/\R/', $contents) ?: [] as $line) {
                    $hex = strtok(trim($line), ' ');

                    if (is_string($hex) && strlen($hex) === 32) {
                        $packed = @hex2bin($hex);
                        $ip = $packed === false ? false : @inet_ntop($packed);

                        if ($ip !== false) {
                            $addresses[$ip] = true;
                        }
                    }
                }

                continue;
            }

            // fib_trie lists every locally-configured address under /32 host
            // entries marked LOCAL, which covers bridges without shelling out.
            $lines = preg_split('/\R/', $contents) ?: [];

            foreach ($lines as $i => $line) {
                if (!str_contains($line, '/32 host LOCAL')) {
                    continue;
                }

                for ($back = $i - 1; $back >= 0 && $back >= $i - 3; $back--) {
                    if (preg_match('/\|--\s+(\d+\.\d+\.\d+\.\d+)/', $lines[$back], $m)) {
                        $addresses[$m[1]] = true;
                        break;
                    }
                }
            }
        }

        return $this->hostAddresses = $addresses;
    }

    /**
     * Suricata timestamps carry sub-second precision and an offset; the spool
     * stores whole seconds. Truncating here keeps both sides on one clock.
     */
    private function alertTime(array $alert): ?int
    {
        $raw = $this->flow($alert)['ts'];

        if (!is_string($raw) || trim($raw) === '') {
            return null;
        }

        $ts = strtotime($raw);

        return $ts === false ? null : $ts;
    }

    /** @return array<string, true> for tests and diagnostics */
    public function knownHostAddresses(): array
    {
        return $this->hostAddresses();
    }
}

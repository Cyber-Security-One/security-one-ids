<?php

namespace App\Services\Network;

/**
 * Turns osquery socket rows into the shared normalised event shape.
 *
 * Two things in here are not obvious and both were established by looking at
 * what a real host actually emits rather than at the schema.
 *
 * **The event clock is `ntime`, never `unixTime`.** Measured across 25,148
 * socket events, the result row's `unixTime` carried only 18 distinct values,
 * because it is the query flush time and every event in a batch shares it.
 * Anything derived from it — above all the inter-arrival gaps beacon detection
 * needs — describes this sensor's own schedule. `ntime` is the kernel's
 * nanosecond clock and had 25,148 distinct values for the same events.
 *
 * **`local_port` is 0 on every row.** Measured across 38,219 events, all four
 * syscalls: connect, accept, bind and listen. It is carried through as null
 * rather than 0 so nothing downstream mistakes it for a real port, and
 * listener detection is fed from the `listening_ports` snapshot instead.
 */
class SocketEventNormalizer
{
    /** Binaries belonging to this product; their sockets are our own noise. */
    private const AGENT_BINARIES = [
        'osqueryd', 'osqueryi', 'suricata', 'snort', 'clamscan', 'freshclam', 'clamd',
    ];

    /**
     * @param array $row     the whole osquery result object
     * @param array $columns its `columns` member
     * @return array|null the normalised event, or null when the row is not a
     *                    socket operation we model
     */
    public function normalize(array $row, array $columns): ?array
    {
        if (($row['action'] ?? '') !== 'added') {
            return null;
        }

        $action = match ((string) ($columns['syscall'] ?? '')) {
            'connect' => 'net_connect',
            'accept' => 'net_accept',
            'bind' => 'net_bind',
            'listen' => 'net_listen',
            // Anything else is a syscall this class does not model. Guessing
            // would put an event of unknown meaning into the rule engine.
            default => null,
        };

        if ($action === null) {
            return null;
        }

        $remote = $this->cleanAddress($columns['remote_address'] ?? null);
        $local = $this->cleanAddress($columns['local_address'] ?? null);
        $uid = isset($columns['uid']) && $columns['uid'] !== '' ? (int) $columns['uid'] : -1;

        return [
            'ts' => $this->eventTime($row, $columns),
            'host' => (string) ($row['hostIdentifier'] ?? gethostname()),
            'action' => $action,
            'sensor' => 'osquery-socket',
            'pid' => isset($columns['pid']) ? (int) $columns['pid'] : 0,
            'ppid' => isset($columns['parent']) ? (int) $columns['parent'] : 0,
            'uid' => $uid,
            'username' => '',
            'path' => (string) ($columns['path'] ?? ''),
            // Socket events carry no command line. Attribution beyond the
            // executable path comes from correlating with process events.
            'cmdline' => '',
            'cwd' => '',
            'container_id' => (string) ($columns['cid'] ?? ''),
            'syscall' => (string) ($columns['syscall'] ?? ''),
            'network' => [
                'remote_address' => $remote,
                'remote_port' => $this->cleanPort($columns['remote_port'] ?? null),
                'local_address' => $local,
                // Deliberately null rather than 0: measured, this field is
                // always 0, and a downstream `> 0` check reading 0 as a port
                // is how the first listener rule came to be unsatisfiable.
                'local_port' => $this->cleanPort($columns['local_port'] ?? null),
                'family' => isset($columns['family']) ? (string) $columns['family'] : null,
                'protocol' => isset($columns['protocol']) ? (int) $columns['protocol'] : null,
                'scope' => $this->classifyScope($remote),
                'count' => 1,
                'first_seen' => $this->eventTime($row, $columns),
                'last_seen' => $this->eventTime($row, $columns),
                'intervals' => [],
                // Sub-second event time on the raw monotonic kernel clock,
                // seconds since boot. Carried separately from `ts` because the
                // shared event shape uses whole seconds while a 30-second
                // beacon period needs finer resolution than that to tell
                // jitter from rhythm.
                //
                // The name says `monotonic` because this value must never
                // become a timestamp. It is seconds since boot — 301,098 on
                // this host — so read as a wall clock it lands in January 1970,
                // wrong by the boot instant and with nothing to indicate it.
                // The only legitimate use is subtracting two of them, where
                // the offset cancels. `ts` above is the anchored equivalent.
                //
                // Null when ntime was absent (the audit backend does not supply
                // it), in which case the aggregator falls back to whole seconds
                // and regularity simply cannot be established — the correct
                // outcome, not a gap to paper over.
                'event_time_monotonic' => $this->eventTimeFloat($row, $columns),
            ],
        ];
    }

    /**
     * Turn a `listening_ports` row into a listener event.
     *
     * A separate entry point because a listener is a state rather than an
     * event: it comes from a snapshot query, has no syscall, and — unlike the
     * socket event stream — actually carries a port.
     */
    public function normalizeListener(array $row, array $columns): ?array
    {
        $port = $this->cleanPort($columns['port'] ?? null);
        $path = (string) ($columns['path'] ?? '');

        if ($port === null) {
            return null;
        }

        // The join can miss a path for a process that exited between the two
        // halves of the query; the process name is a usable fallback and better
        // than discarding the listener.
        if ($path === '') {
            $name = (string) ($columns['name'] ?? '');
            $path = $name !== '' ? $name : '';
        }

        if ($path === '') {
            return null;
        }

        $address = $this->cleanAddress($columns['address'] ?? null);

        return [
            'ts' => (int) ($row['unixTime'] ?? time()),
            'host' => (string) ($row['hostIdentifier'] ?? gethostname()),
            'action' => 'net_listener',
            'sensor' => 'osquery-listeners',
            'pid' => isset($columns['pid']) ? (int) $columns['pid'] : 0,
            'ppid' => 0,
            'uid' => -1,
            'username' => '',
            'path' => $path,
            'cmdline' => '',
            'cwd' => '',
            'container_id' => '',
            'syscall' => 'listen',
            'network' => [
                'remote_address' => null,
                'remote_port' => null,
                'local_address' => $address,
                'local_port' => $port,
                'family' => isset($columns['family']) ? (string) $columns['family'] : null,
                'protocol' => isset($columns['protocol']) ? (int) $columns['protocol'] : null,
                'scope' => 'unknown',
                'count' => 1,
                'first_seen' => (int) ($row['unixTime'] ?? time()),
                'last_seen' => (int) ($row['unixTime'] ?? time()),
                'intervals' => [],
            ],
        ];
    }

    /**
     * The kernel event time, in seconds.
     *
     * `ntime` is a monotonic nanosecond counter since boot, so it is converted
     * to a wall-clock second by anchoring it against this process's view of
     * boot time. Precision matters far more than absolute accuracy here: the
     * value is used for inter-arrival gaps, and a constant offset cancels out
     * of a difference.
     */
    public function eventTime(array $row, array $columns): int
    {
        $ntime = $columns['ntime'] ?? null;

        if ($ntime !== null && $ntime !== '' && ctype_digit((string) $ntime)) {
            $seconds = (int) ((int) $ntime / 1_000_000_000);
            $bootTime = $this->bootTime();

            if ($bootTime !== null && $seconds > 0) {
                return $bootTime + $seconds;
            }
        }

        // Falling back to the flush time loses ordering within a batch, which
        // is why beacon detection also requires a minimum interval count: a
        // batch of identical timestamps produces zero usable gaps rather than
        // a spurious perfect rhythm.
        return (int) ($row['unixTime'] ?? time());
    }

    /**
     * Sub-second event time, for inter-arrival gaps.
     *
     * Returned separately from `ts` because the shared event shape uses whole
     * seconds, while beacon periods on the order of 30 seconds need better
     * resolution than that to distinguish jitter from regularity.
     */
    public function eventTimeFloat(array $row, array $columns): ?float
    {
        $ntime = $columns['ntime'] ?? null;

        if ($ntime === null || $ntime === '' || !ctype_digit((string) $ntime)) {
            return null;
        }

        return ((int) $ntime) / 1_000_000_000;
    }

    private ?int $bootTime = null;
    private bool $bootTimeResolved = false;

    private function bootTime(): ?int
    {
        if ($this->bootTimeResolved) {
            return $this->bootTime;
        }

        $this->bootTimeResolved = true;

        $stat = @file_get_contents('/proc/stat');

        if ($stat !== false && preg_match('/^btime\s+(\d+)/m', $stat, $m)) {
            $this->bootTime = (int) $m[1];
        }

        return $this->bootTime;
    }

    /**
     * Where an address sits relative to this host.
     *
     * IPv4-mapped IPv6 has to be unwrapped first. Measured on a real host,
     * 1,326 socket events carried addresses in the compressed hex form
     * `::ffff:ac12:5`, which is 172.18.0.5 — a container address. PHP's
     * private-range filter does not recognise the mapped form as private, and
     * its reserved-range filter rejects *all* mapped addresses, so relying on
     * either alone misclassifies in both directions: container traffic as
     * external, and a genuine external destination reached over a v6 socket as
     * internal.
     */
    public function classifyScope(?string $address): string
    {
        if ($address === null || $address === '') {
            return 'unknown';
        }

        $address = $this->unmapIpv4($address);

        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            // AF_UNIX sockets put a filesystem path here — 2,424 events on the
            // measured host. Not an address, and not an error.
            return 'unknown';
        }

        if ($this->isLoopback($address)) {
            return 'loopback';
        }

        $routable = filter_var(
            $address,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );

        return $routable !== false ? 'external' : 'private';
    }

    /**
     * Unwrap an IPv4-mapped IPv6 address to its IPv4 form.
     *
     * Done through inet_pton rather than string matching, so it handles the
     * compressed hex form (`::ffff:ac12:5`) that real data uses as well as the
     * dotted one that documentation shows.
     */
    public function unmapIpv4(string $address): string
    {
        $binary = @inet_pton($address);

        if ($binary === false || strlen($binary) !== 16) {
            return $address;
        }

        if (substr($binary, 0, 10) !== str_repeat("\0", 10) || substr($binary, 10, 2) !== "\xff\xff") {
            return $address;
        }

        $v4 = @inet_ntop(substr($binary, 12, 4));

        return $v4 === false ? $address : $v4;
    }

    private function isLoopback(string $address): bool
    {
        if ($address === '::1') {
            return true;
        }

        $binary = @inet_pton($address);

        return $binary !== false && strlen($binary) === 4 && ord($binary[0]) === 127;
    }

    /**
     * Whether this event is worth carrying any further.
     *
     * Loopback goes unconditionally: 28% of the measured stream, all of it
     * local plumbing between processes on the same box.
     *
     * Private goes by default, which is an explicit trade rather than a claim
     * that internal traffic does not matter — lateral movement is exactly
     * internal traffic. It is 32% of the stream on a host where nearly all of
     * it is container bridge chatter between php-fpm, redis and mysql, and
     * carrying it would put the aggregate near a million rows a day. The Hub
     * can turn it on per agent for hosts where lateral movement is the concern.
     */
    public function shouldDrop(array $event, array $options = []): bool
    {
        $scope = (string) ($event['network']['scope'] ?? 'unknown');

        if ($scope === 'loopback') {
            return true;
        }

        if ($scope === 'private' && empty($options['include_private'])) {
            return true;
        }

        // `unknown` is kept: an accept event often reports family -1 while the
        // address is perfectly usable, and dropping it would lose inbound
        // connection visibility entirely.
        return false;
    }

    public function isAgentNoise(array $event): bool
    {
        $path = (string) ($event['path'] ?? '');

        if ($path === '') {
            return true;
        }

        return in_array(basename($path), self::AGENT_BINARIES, true);
    }

    private function cleanAddress(mixed $value): ?string
    {
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        return trim($value);
    }

    private function cleanPort(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        $port = (int) $value;

        return $port > 0 && $port <= 65535 ? $port : null;
    }
}

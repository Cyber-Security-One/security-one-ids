<?php

namespace App\Services\Network;

/**
 * Behaviour rules for per-process network activity.
 *
 * The reason this module exists is one question Suricata cannot answer: which
 * process made the connection. Suricata sees the packets and can tell you a
 * host talked to a known-bad address; it cannot tell you it was php-fpm, or
 * that a bash process opened the socket. These rules are written around that
 * difference, so anything expressible from packets alone is deliberately
 * absent — it is already covered better upstream.
 *
 * Every threshold here is set against measurements from a real, busy host:
 * 4.1 million socket events a day, of which 28% are loopback and 32% private,
 * and where php-fpm legitimately connects to 8.8.8.8:53 199 times a day and
 * nginx reaches its origin servers thousands of times on a regular cadence.
 * That last fact is the single most important constraint in this file: naive
 * periodicity detection fires on all of it.
 */
class NetworkRuleEngine
{
    /**
     * Interpreters and shells. A socket opened *by* one of these is the
     * network half of a reverse shell, and it catches the case process
     * telemetry misses — a payload that connects programmatically without a
     * `/dev/tcp` redirect on its command line to give it away.
     */
    private const INTERPRETERS = [
        'bash', 'sh', 'dash', 'zsh', 'ksh', 'csh',
        'python', 'python2', 'python3', 'perl', 'ruby', 'lua', 'tclsh',
        'nc', 'ncat', 'netcat', 'socat', 'telnet',
    ];

    /** Web-tier accounts, for the outbound-from-web-tier rule. */
    private const WEB_ACCOUNTS = [
        'www-data', 'nginx', 'apache', 'apache2', 'httpd', 'php-fpm', 'www', 'caddy',
    ];

    /**
     * Ports whose use as a destination is worth noticing.
     *
     * 4444 is the Metasploit default and also the Selenium Grid default, which
     * is exactly why this is graded low on its own: on any host that runs
     * browser tests it is background noise. It is here to corroborate, not to
     * wake anybody.
     */
    private const SUSPICIOUS_PORTS = [
        4444 => 'metasploit default (also Selenium Grid)',
        1337 => 'common C2',
        31337 => 'common C2',
        6666 => 'common C2 / IRC',
        6667 => 'IRC',
        8888 => 'common C2 (also Jupyter)',
        9001 => 'common C2 (also Tor)',
        12345 => 'common C2',
    ];

    /** Beacon detection needs enough samples for regularity to mean anything. */
    private const BEACON_MIN_INTERVALS = 8;

    /** Coefficient of variation below which intervals count as regular. */
    private const BEACON_MAX_CV = 0.15;

    /**
     * Below this, the timing is too perfect to have crossed a network.
     *
     * A narrow guard, and worth being precise about what it does and does not
     * do. It rejects intervals that are effectively identical, which real
     * network round-trips never are — they carry scheduling and routing
     * jitter — but which a batching artifact or a placeholder value produces
     * exactly.
     *
     * It is not what fixed the false beacons. Deriving intervals from the
     * osquery result row's `unixTime` produced fourteen of them out of
     * twenty-seven candidates on a healthy host, and those sat at a CV of
     * 0.022 — above this floor, so this would not have caught them. The fix
     * for that was reading the kernel event clock instead, and this exists
     * only as a second line against a future regression to a batched clock,
     * plus the reminder that the genuine periodic connection on the same host
     * measured 0.044, twice as jittery as the artifact it was competing with.
     */
    private const BEACON_MIN_CV = 0.005;

    /** Beacons slower than this are indistinguishable from a cron job. */
    private const BEACON_MAX_PERIOD = 3600;

    /** Days of history before "this destination is new" means anything. */
    private const MIN_HISTORY_DAYS = 3;

    private NetworkBaselineStore $baseline;

    public function __construct(NetworkBaselineStore $baseline)
    {
        $this->baseline = $baseline;
    }

    /**
     * @param array $event an aggregated connection event
     * @return array<int, array>
     */
    public function evaluate(array $event): array
    {
        $action = (string) ($event['action'] ?? '');

        if (!str_starts_with($action, 'net_')) {
            return [];
        }

        $net = is_array($event['network'] ?? null) ? $event['network'] : [];
        $path = (string) ($event['path'] ?? '');
        $binary = $path !== '' ? basename($path) : '';
        $user = (string) ($event['username'] ?? '');
        $address = $net['remote_address'] ?? null;
        $scope = (string) ($net['scope'] ?? 'unknown');
        $port = $net['remote_port'] ?? null;

        $findings = [];

        /* NET-001 — a shell or interpreter opened an outbound socket ---------
         * The network half of a reverse shell. Process telemetry catches the
         * `/dev/tcp/` form because the construct is visible on the command
         * line; this catches the payload that opens the socket itself, where
         * there is nothing to read in argv. */
        if ($action === 'net_connect'
            && $scope === 'external'
            && $binary !== ''
            && in_array($binary, self::INTERPRETERS, true)
        ) {
            $findings[] = $this->finding(
                'NET-001',
                'Interpreter opened an outbound connection',
                'critical',
                'T1059',
                "{$binary} connected to {$address}:{$port} — a shell or interpreter holding an "
                . 'outbound socket is the network half of a reverse shell'
            );
        }

        /* NET-002 — outbound connection from the web tier --------------------
         * Distinct from the process rule that catches a web account spawning
         * curl: this fires when the web runtime itself opens the socket, with
         * no new process to notice. For a WAF vendor that is the other half of
         * "the request got through" — but it is also how every PHP application
         * that calls an API behaves, so it leans on the baseline rather than on
         * the account alone. */
        if ($action === 'net_connect'
            && $scope === 'external'
            && in_array($user, self::WEB_ACCOUNTS, true)
            && $address !== null
        ) {
            $history = $this->baseline->destinationHistory($path, (string) $address, $this->servicePort($event));
            $historyDays = $this->baseline->historyDaysFor($path);

            if ($historyDays >= self::MIN_HISTORY_DAYS && $history['days'] === 0) {
                $findings[] = $this->finding(
                    'NET-002',
                    'Web tier connected to a destination it has never used',
                    'high',
                    'T1071',
                    "{$binary} running as '{$user}' connected to {$address}:{$port}, which it has not "
                    . "reached in {$historyDays} days of recorded history"
                );
            }
        }

        /* NET-003 — a process is listening on a port it has not used before --
         * A new listener is the shape of a backdoor. Held to the same standard
         * as everywhere else here: without a record of what this process used
         * to listen on, "new" only means "not seen yet", and a freshly
         * deployed agent would alert on every service on the host.
         *
         * Fed from the `listening_ports` snapshot, not from bind/listen socket
         * events. The first version of this rule read `local_port` off those
         * events and could never fire: measured on a real host, that field is
         * 0 on 100% of bpf_socket_events rows across all four syscalls, and
         * bind/listen also report local_address as 0.0.0.0. A rule that
         * silently never fires is worse than no rule, because the coverage
         * appears on the list either way. */
        if ($action === 'net_listener') {
            $localPort = isset($net['local_port']) ? (int) $net['local_port'] : 0;

            if ($localPort > 0
                && $this->baseline->listenerCount() > 0
                && !$this->baseline->isKnownListener($path, $localPort)
            ) {
                $exposure = ($net['local_address'] ?? '') === '0.0.0.0' || ($net['local_address'] ?? '') === '::'
                    ? 'reachable from any interface'
                    : 'bound to ' . $net['local_address'];

                $findings[] = $this->finding(
                    'NET-003',
                    'Process is listening on a port it has not used before',
                    'high',
                    'T1571',
                    "{$binary} is listening on port {$localPort} ({$exposure}), which is not in "
                    . "this host's recorded listener set"
                );
            }
        }

        /* NET-004 — periodic outbound connections (beaconing) ---------------
         * The detection this module exists for: it needs per-process
         * aggregation over time, which packet inspection cannot do.
         *
         * Also the rule with the worst false-positive profile in the file.
         * Measured on a real host, php-fpm reaches 8.8.8.8:53 199 times a day
         * and nginx polls its origins on a fixed cadence — both perfectly
         * regular, neither an intrusion. So regularity alone is not enough:
         * the destination also has to be one this process has not settled
         * into. An established destination beaconing regularly is
         * infrastructure doing its job. */
        if ($action === 'net_connect' && $scope === 'external' && $address !== null) {
            $regularity = $this->assessRegularity((array) ($net['intervals'] ?? []));

            if ($regularity !== null
                && !$this->baseline->isEstablishedDestination($path, (string) $address, $this->servicePort($event))
            ) {
                $findings[] = $this->finding(
                    'NET-004',
                    'Periodic outbound connections to an unestablished destination',
                    'high',
                    'T1071.001',
                    sprintf(
                        '%s connected to %s:%s %d times at a near-constant interval of ~%ds '
                        . '(variation %.0f%%). Regular timing to a destination this process has not '
                        . 'settled into is the shape of command-and-control polling',
                        $binary,
                        $address,
                        $port,
                        (int) ($net['count'] ?? 0),
                        $regularity['period'],
                        $regularity['cv'] * 100
                    )
                );
            }
        }

        /* NET-005 — destination port associated with C2 tooling -------------
         * Deliberately low. 4444 is Metasploit's default and Selenium Grid's,
         * 8888 is Jupyter, 9001 is Tor. On its own this is a coincidence; next
         * to NET-001 or NET-004 it is corroboration. */
        if ($action === 'net_connect' && $scope === 'external' && $port !== null) {
            $portInt = (int) $port;

            if (isset(self::SUSPICIOUS_PORTS[$portInt])) {
                $findings[] = $this->finding(
                    'NET-005',
                    'Outbound connection to a port commonly used by C2 tooling',
                    'low',
                    'T1571',
                    "{$binary} connected to {$address}:{$portInt} — " . self::SUSPICIOUS_PORTS[$portInt]
                );
            }
        }

        /* NET-006 — a new process reached a local socket that confers root -----
         * The container-escape primitive, and until now nothing in this product
         * looked at it. A writable handle on the Docker socket will start a
         * privileged container with the host root filesystem mounted, which is
         * root by another name; containerd, CRI-O and the libvirt socket are the
         * same capability at different layers.
         *
         * It is not theoretical on the host this was written against, where
         * /var/run/docker.sock is mode 666. Every account on the box already
         * holds that capability, `www-data` included, so the distance between a
         * web shell and root is one connect() call. That is also why the rule
         * matters more than the volume it costs: this was the one part of the
         * unclassifiable socket traffic worth keeping, and dropping all of it
         * would have removed a real detection before it was ever built.
         *
         * Held to the same standard as the rest of this file. Docker's own CLI
         * talks to that socket constantly and legitimately, so novelty is the
         * signal, not access. And novelty needs a basis: without recorded
         * history for this executable, "has not used it before" only means "not
         * seen yet", which on a freshly deployed agent is every process on the
         * host. */
        if ($action === 'net_connect' && $scope === 'ipc' && $address !== null) {
            $history = $this->baseline->destinationHistory($path, (string) $address, null);
            $historyDays = $this->baseline->historyDaysFor($path);

            if ($historyDays >= self::MIN_HISTORY_DAYS && $history['days'] === 0) {
                $findings[] = $this->finding(
                    'NET-006',
                    'Process reached a privileged local socket for the first time',
                    'high',
                    'T1610',
                    "{$binary} connected to {$address}, which grants control of the container "
                    . "runtime, and has not done so in {$historyDays} days of recorded history"
                );
            }
        }

        return $findings;
    }

    /**
     * Whether a set of inter-arrival gaps is regular enough to look automated,
     * using the coefficient of variation.
     *
     * **The intervals must be derived from the kernel event clock**, meaning
     * `bpf_socket_events.ntime`, and never from the osquery result row's
     * `unixTime`. Measured on a real host: 25,148 socket events carried only
     * 18 distinct `unixTime` values, because that field is the query flush
     * time and every event in a batch shares it. Intervals built from it
     * describe this sensor's schedule, not the host's network behaviour, and
     * reported fourteen false beacons out of twenty-seven candidates. With
     * `ntime` the same data yields four candidates out of forty-eight, and
     * real application traffic separates cleanly: it is bursty, with CV
     * between 1.0 and 4.9, against a beacon threshold of 0.15.
     *
     * Standard deviation over mean rather than a raw spread, because the same
     * jitter means very different things at a 5-second period and a 30-minute
     * one. Sub-5-second repetition is excluded — measured, that is what busy
     * application clients look like, not beacons — and anything slower than an
     * hour is indistinguishable from a cron job.
     *
     * @param array<int, float|int> $intervals seconds between consecutive
     *                                         connections, from the event clock
     * @return array{period:float, cv:float}|null
     */
    public function assessRegularity(array $intervals): ?array
    {
        $intervals = array_values(array_filter(
            array_map('floatval', $intervals),
            static fn (float $i): bool => $i > 0
        ));

        if (count($intervals) < self::BEACON_MIN_INTERVALS) {
            return null;
        }

        $mean = array_sum($intervals) / count($intervals);

        if ($mean < 5 || $mean > self::BEACON_MAX_PERIOD) {
            return null;
        }

        $variance = 0.0;
        foreach ($intervals as $interval) {
            $variance += ($interval - $mean) ** 2;
        }
        $variance /= count($intervals);

        $cv = sqrt($variance) / $mean;

        // Too perfect to have crossed a network — almost certainly a clock or
        // batching artifact rather than a beacon.
        if ($cv < self::BEACON_MIN_CV) {
            return null;
        }

        return $cv <= self::BEACON_MAX_CV ? ['period' => $mean, 'cv' => $cv] : null;
    }

    /**
     * The port that identifies the service being talked to.
     *
     * For an outbound connection that is the remote port. For an accepted one
     * the remote port is the client's ephemeral port and changes every time,
     * so it must not be used — keying accept events on it collapses the
     * aggregation ratio from 51:1 to 2:1, measured.
     *
     * On this platform the local port is not available either: bpf_socket_events
     * reports it as 0 on 100% of rows. So accept events legitimately have no
     * service port, and this returns null for them. The aggregation key falls
     * back to the process path, which discriminates in practice because
     * different services are different executables — but it is the path doing
     * that work, not the port, and pretending otherwise would misrepresent
     * what the grouping actually means.
     */
    public function servicePort(array $event): ?int
    {
        $net = is_array($event['network'] ?? null) ? $event['network'] : [];
        $action = (string) ($event['action'] ?? '');

        $port = $action === 'net_connect'
            ? ($net['remote_port'] ?? null)
            : ($net['local_port'] ?? null);

        return $port === null || $port === '' ? null : (int) $port;
    }

    /**
     * Fold an aggregated event into the baseline.
     *
     * Called for every event, alerting or not: the baseline is a record of what
     * happens here, and excluding the things that alerted would mean a genuine
     * destination could never become established.
     */
    public function learn(array $event): void
    {
        $net = is_array($event['network'] ?? null) ? $event['network'] : [];
        $path = (string) ($event['path'] ?? '');
        $action = (string) ($event['action'] ?? '');

        if ($path === '') {
            return;
        }

        if ($action === 'net_listener') {
            $localPort = isset($net['local_port']) ? (int) $net['local_port'] : 0;

            if ($localPort > 0) {
                $this->baseline->recordListener($path, $localPort, (int) ($event['ts'] ?? time()));
            }

            return;
        }

        $address = $net['remote_address'] ?? null;

        if (!is_string($address) || $address === '') {
            return;
        }

        $this->baseline->recordDestination(
            $path,
            $address,
            $this->servicePort($event),
            (int) ($net['count'] ?? 1),
            (int) ($event['ts'] ?? time())
        );
    }

    private function finding(string $rule, string $name, string $severity, string $mitre, string $reason): array
    {
        return [
            'rule' => $rule,
            'name' => $name,
            'severity' => $severity,
            'mitre' => $mitre,
            'reason' => $reason,
        ];
    }
}

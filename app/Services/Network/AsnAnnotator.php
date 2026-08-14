<?php

namespace App\Services\Network;

use Illuminate\Support\Facades\Log;

/**
 * Adds whatever destination context we can honestly obtain for an outbound
 * connection, without a GeoIP database and without talking to anybody's API.
 *
 * About the name: this class does not return ASNs, and cannot. An AS number is
 * only knowable from a BGP-derived dataset (MaxMind, IPtoASN, a local BGP
 * feed), the agent ships none of them, vendor/ is installed --no-dev so we
 * cannot add one, and an isolated customer host may have no egress at all.
 * Every remaining option for producing an AS number is a guess dressed as a
 * fact, so this class produces none. The name is kept because it is the slot in
 * the pipeline where ASN data belongs once an offline dataset is bundled; see
 * setOfflineOnly() for the intended seam.
 *
 * The governing rule, which is why several keys are conditionally absent: a
 * missing key means "we do not know", and that is a useful thing to tell a rule
 * engine. A key filled with null, 0, '' or 'unknown' is indistinguishable from
 * a real finding at the call site and quietly turns absence of evidence into
 * evidence. So keys appear only when they carry a claim we can defend.
 *
 * Measured against this host's real bpf_socket_events, the two traps worth
 * knowing about before reading further:
 *
 *  - gethostbyaddr() does not return false when there is no PTR record. It
 *    returns the input string unchanged. The naive `if ($n !== false)` puts the
 *    IP address in as its own hostname and makes is_bare_ip_destination false
 *    for every destination on the network. See reverseDns().
 *  - accept events carry local_port = 0 in 100% of sampled rows (9,122/9,122),
 *    and their remote_port is the client's ephemeral port (6,710 distinct
 *    values). Neither is a service port, so accept events get no port_service
 *    at all rather than a label derived from a random high port. See
 *    servicePortFor().
 */
class AsnAnnotator
{
    /**
     * Scope values, as set upstream by the normaliser. Only 'external' earns
     * the full annotation: reverse DNS on RFC1918 container addresses resolves
     * to nothing on every host we have measured, which would stamp
     * is_bare_ip_destination = true on all internal traffic — a true statement
     * that means nothing, on 32% of events.
     */
    private const SCOPE_EXTERNAL = 'external';
    private const SCOPE_PRIVATE = 'private';

    /**
     * Coarse cloud allocations, deliberately partial.
     *
     * These are large, long-lived, well-known blocks only. A complete map is a
     * multi-megabyte dataset that changes weekly, and half-remembering it here
     * would produce confident wrong provider names. Longest-prefix wins at
     * match time, which is what lets Azure's 52.224.0.0/11 sit correctly inside
     * the coarse AWS 52.0.0.0/8 without depending on array order.
     *
     * Consequence for callers, stated plainly: a match is good evidence, a
     * non-match is no evidence. That asymmetry is why no is_cloud_provider
     * key is emitted when nothing matches — this list cannot support a
     * negative claim. See buildAnnotation().
     *
     * @var array<string, string> CIDR => provider label
     */
    private const CLOUD_PREFIXES = [
        // AWS
        '3.0.0.0/8' => 'aws',
        '13.32.0.0/12' => 'aws',
        '15.177.0.0/16' => 'aws',
        '18.32.0.0/11' => 'aws',
        '18.64.0.0/10' => 'aws',
        '35.152.0.0/13' => 'aws',
        '52.0.0.0/8' => 'aws',
        '54.0.0.0/8' => 'aws',
        '99.77.0.0/16' => 'aws',
        '205.251.192.0/19' => 'aws',
        '2600:1f00::/24' => 'aws',

        // Google Cloud and Google services (same operator, one label each so a
        // hit on public DNS is not reported as a customer's GCE project)
        '34.0.0.0/8' => 'gcp',
        '35.184.0.0/13' => 'gcp',
        '35.192.0.0/12' => 'gcp',
        '104.196.0.0/14' => 'gcp',
        '130.211.0.0/16' => 'gcp',
        '8.34.208.0/20' => 'gcp',
        '8.8.4.0/24' => 'google',
        '8.8.8.0/24' => 'google',
        '74.125.0.0/16' => 'google',
        '142.250.0.0/15' => 'google',
        '172.217.0.0/16' => 'google',
        '216.58.192.0/19' => 'google',
        '216.239.32.0/19' => 'google',
        '2607:f8b0::/32' => 'google',

        // Azure
        '13.64.0.0/11' => 'azure',
        '20.0.0.0/8' => 'azure',
        '40.64.0.0/10' => 'azure',
        '52.224.0.0/11' => 'azure',
        '104.40.0.0/13' => 'azure',
        '168.61.0.0/16' => 'azure',
        '191.232.0.0/13' => 'azure',
        '2603:1000::/24' => 'azure',

        // DigitalOcean. More /16s than the others because DO has no single
        // large block, and this is the provider actually seen in our traffic.
        '64.23.0.0/16' => 'digitalocean',
        '46.101.0.0/16' => 'digitalocean',
        '68.183.0.0/16' => 'digitalocean',
        '104.131.0.0/16' => 'digitalocean',
        '128.199.0.0/16' => 'digitalocean',
        '134.209.0.0/16' => 'digitalocean',
        '137.184.0.0/16' => 'digitalocean',
        '138.197.0.0/16' => 'digitalocean',
        '143.198.0.0/16' => 'digitalocean',
        '146.190.0.0/16' => 'digitalocean',
        '157.245.0.0/16' => 'digitalocean',
        '159.65.0.0/16' => 'digitalocean',
        '159.89.0.0/16' => 'digitalocean',
        '161.35.0.0/16' => 'digitalocean',
        '164.90.0.0/16' => 'digitalocean',
        '165.227.0.0/16' => 'digitalocean',
        '167.71.0.0/16' => 'digitalocean',
        '167.99.0.0/16' => 'digitalocean',
        '167.172.0.0/16' => 'digitalocean',
        '170.64.0.0/16' => 'digitalocean',
        '174.138.0.0/16' => 'digitalocean',
        '178.62.0.0/16' => 'digitalocean',
        '188.166.0.0/16' => 'digitalocean',
        '192.241.128.0/17' => 'digitalocean',
        '206.189.0.0/16' => 'digitalocean',
        '209.97.0.0/16' => 'digitalocean',
        '2604:a880::/32' => 'digitalocean',

        // Cloudflare
        '1.1.1.0/24' => 'cloudflare',
        '103.21.244.0/22' => 'cloudflare',
        '103.22.200.0/22' => 'cloudflare',
        '103.31.4.0/22' => 'cloudflare',
        '104.16.0.0/12' => 'cloudflare',
        '108.162.192.0/18' => 'cloudflare',
        '131.0.72.0/22' => 'cloudflare',
        '141.101.64.0/18' => 'cloudflare',
        '162.158.0.0/15' => 'cloudflare',
        '172.64.0.0/13' => 'cloudflare',
        '173.245.48.0/20' => 'cloudflare',
        '188.114.96.0/20' => 'cloudflare',
        '190.93.240.0/20' => 'cloudflare',
        '197.234.240.0/22' => 'cloudflare',
        '198.41.128.0/17' => 'cloudflare',
        '2606:4700::/32' => 'cloudflare',
    ];

    /**
     * Service names for ports a human analyst would recognise on sight. The
     * point is to save the reader a lookup, not to be an /etc/services clone,
     * so unmapped ports simply produce no port_service key — the raw port is
     * already in the event, so omitting the label loses nothing.
     *
     * @var array<int, string>
     */
    private const PORT_SERVICES = [
        20 => 'ftp-data',
        21 => 'ftp',
        22 => 'ssh',
        23 => 'telnet',
        25 => 'smtp',
        53 => 'dns',
        67 => 'dhcp',
        69 => 'tftp',
        80 => 'http',
        110 => 'pop3',
        111 => 'rpcbind',
        123 => 'ntp',
        135 => 'msrpc',
        137 => 'netbios-ns',
        139 => 'netbios-ssn',
        143 => 'imap',
        161 => 'snmp',
        389 => 'ldap',
        443 => 'https',
        445 => 'smb',
        465 => 'smtps',
        514 => 'syslog',
        587 => 'smtp-submission',
        636 => 'ldaps',
        873 => 'rsync',
        993 => 'imaps',
        995 => 'pop3s',
        1080 => 'socks-proxy',
        1433 => 'mssql',
        1521 => 'oracle',
        2049 => 'nfs',
        2375 => 'docker-api-plaintext',
        2376 => 'docker-api-tls',
        2379 => 'etcd',
        3128 => 'squid-proxy',
        3306 => 'mysql',
        3389 => 'rdp',
        5432 => 'postgresql',
        5672 => 'amqp',
        5900 => 'vnc',
        5985 => 'winrm',
        5986 => 'winrm-tls',
        6379 => 'redis',
        8000 => 'http-alt',
        8080 => 'http-proxy',
        8443 => 'https-alt',
        9000 => 'http-alt',
        9200 => 'elasticsearch',
        11211 => 'memcached',
        27017 => 'mongodb',
        // Kubernetes / orchestration, worth naming because a process that
        // should not be talking to them is a finding in itself
        6443 => 'kubernetes-api',
        10250 => 'kubelet',
    ];

    /**
     * Ports whose reputation, not whose protocol, is the interesting part.
     * These are tool defaults — metasploit's 4444, the folkloric 1337/31337 —
     * so the label describes why it is notable rather than naming a service.
     *
     * A caveat that has to be honoured at the call site: these are legal ports
     * that legitimate software does use. The label is a prior, not a verdict,
     * and it is only ever applied to a port we are confident is a *service*
     * port. Applying it to an ephemeral source port would manufacture alerts;
     * servicePortFor() is what prevents that.
     *
     * @var array<int, true>
     */
    private const SUSPICIOUS_C2_PORTS = [
        1337 => true,
        4444 => true,
        4445 => true,
        5554 => true,
        5555 => true,
        6666 => true,
        6667 => true,
        8888 => true,
        9001 => true,
        9050 => true,
        9051 => true,
        12345 => true,
        31337 => true,
        54321 => true,
    ];

    private const C2_LABEL = 'suspicious_common_c2';

    /**
     * A single lookup that blocks longer than this is treated as evidence the
     * resolver is not answering. /etc/resolv.conf on this host lists four
     * nameservers; glibc defaults to a 5s timeout and 2 attempts each, so one
     * unanswerable address can block for ~40s. PHP's gethostbyaddr() exposes no
     * timeout parameter, so latency measured after the fact is the only signal
     * available.
     */
    private const SLOW_LOOKUP_MS = 1000.0;

    /**
     * Consecutive slow lookups before reverse DNS is abandoned for the rest of
     * this object's life. Set low on purpose: this runs inside a collector that
     * has a whole spool to drain, and a dead resolver would otherwise cost
     * ~40s per distinct address forever. Losing reverse DNS degrades the
     * annotation; blocking the collector loses the telemetry entirely.
     */
    private const SLOW_LOOKUP_BUDGET = 3;

    /**
     * Resolved names by address, including negative results.
     *
     * Caching the misses is the load-bearing half. On a sample of 7,482
     * external events there were only 130 distinct destinations, and an
     * unresolvable address is the slow case — so re-querying misses is both
     * the common path and the expensive one.
     *
     * @var array<string, string|null>
     */
    private array $reverseDnsCache = [];

    private bool $offlineOnly = true;

    private bool $reverseDnsEnabled = true;

    private int $consecutiveSlowLookups = 0;

    private bool $resolverAbandoned = false;

    private int $lookups = 0;

    private int $cacheHits = 0;

    /**
     * Attach destination context to a normalised connection event.
     *
     * The event is returned unchanged when there is nothing defensible to say —
     * no network block, no routable remote address, or a scope where the
     * annotation would be noise. Callers should treat the absence of
     * $event['network']['annotation'] as normal, not as a failure.
     *
     * @param  array  $event  a normalised socket event; only $event['network']
     *                        and $event['syscall'] are read
     * @return array the same event, with $event['network']['annotation'] added
     *               only if at least one key could be established
     */
    public function annotate(array $event): array
    {
        try {
            $network = $event['network'] ?? null;
            if (! is_array($network)) {
                return $event;
            }

            $annotation = $this->buildAnnotation($network, $this->syscallOf($event));
            if ($annotation === []) {
                return $event;
            }

            $event['network']['annotation'] = $annotation;

            return $event;
        } catch (\Throwable $e) {
            // A best-effort enrichment must never cost the caller the event
            // itself. Unannotated telemetry is still telemetry.
            Log::warning('AsnAnnotator: annotation failed, passing event through unannotated', [
                'error' => $e->getMessage(),
            ]);

            return $event;
        }
    }

    /**
     * Restrict this annotator to sources that need no network egress.
     *
     * Currently a declaration of intent rather than a switch over two code
     * paths, because there is no online path to disable: no API is called at
     * any setting. It exists as the seam for a bundled offline GeoIP/ASN
     * dataset later — when that lands, this flag is what keeps the online
     * fallback off by default.
     *
     * Default true, and it should stay true. An online lookup is unavailable on
     * an isolated host and is unrequested egress from a customer's network on
     * every other one; a security agent that phones out to enrich its own logs
     * is a finding in someone else's audit.
     *
     * Note the one honest exception, which this flag does not govern: reverse
     * DNS is a network query. It goes to the host's own configured resolver
     * rather than to a third party, which is why it is treated as local
     * context, but on an air-gapped host it simply returns nothing and the
     * reverse_dns key is omitted. Use setReverseDnsEnabled(false) to stop the
     * attempt outright.
     *
     * @param  bool  $offline  true to stay offline-only
     * @return void
     */
    public function setOfflineOnly(bool $offline): void
    {
        $this->offlineOnly = $offline;

        if (! $offline) {
            // Loud because the flag currently changes nothing, so a caller who
            // set it false is expecting enrichment that will not arrive.
            Log::warning('AsnAnnotator: offline-only disabled, but no online enrichment exists; annotations are unchanged');
        }
    }

    /**
     * Whether this annotator is restricted to offline sources.
     *
     * @return bool
     */
    public function isOfflineOnly(): bool
    {
        return $this->offlineOnly;
    }

    /**
     * Enable or disable reverse DNS resolution.
     *
     * Worth turning off for air-gapped or DNS-filtered hosts, where every
     * lookup pays the resolver's full timeout before failing. The annotator
     * detects that case by itself (see SLOW_LOOKUP_BUDGET) but only after
     * spending the budget; disabling up front skips the cost entirely.
     *
     * @param  bool  $enabled  false to skip all PTR lookups
     * @return void
     */
    public function setReverseDnsEnabled(bool $enabled): void
    {
        $this->reverseDnsEnabled = $enabled;
    }

    /**
     * Counters for the caller's own logging.
     *
     * `resolver_abandoned` is the one to watch: once true, later events in the
     * same run carry no reverse_dns or is_bare_ip_destination, so a drop in
     * those keys is explained here rather than by a change in traffic.
     *
     * @return array{lookups: int, cache_hits: int, cached_addresses: int, resolver_abandoned: bool}
     */
    public function stats(): array
    {
        return [
            'lookups' => $this->lookups,
            'cache_hits' => $this->cacheHits,
            'cached_addresses' => count($this->reverseDnsCache),
            'resolver_abandoned' => $this->resolverAbandoned,
        ];
    }

    /**
     * Assemble the annotation for one network block.
     *
     * @param  array  $network  the event's `network` sub-array
     * @param  string  $syscall  connect|accept|bind|listen
     * @return array possibly empty, in which case no key is attached
     */
    private function buildAnnotation(array $network, string $syscall): array
    {
        $annotation = [];
        $scope = is_string($network['scope'] ?? null) ? $network['scope'] : '';

        // port_service is a static array lookup, so it is worth doing for
        // private destinations too: a container reaching an internal host on
        // 4444 is exactly the lateral-movement shape we want named, and it
        // costs nothing. Loopback and scopeless events are skipped — a process
        // talking to itself needs no destination context.
        if ($scope === self::SCOPE_EXTERNAL || $scope === self::SCOPE_PRIVATE) {
            $port = $this->servicePortFor($network, $syscall);
            if ($port !== null) {
                $service = $this->serviceLabelFor($port);
                if ($service !== null) {
                    $annotation['port_service'] = $service;
                }
            }
        }

        // Everything below is about the identity of a remote party, which only
        // means something for a destination outside this machine's networks.
        if ($scope !== self::SCOPE_EXTERNAL) {
            return $annotation;
        }

        $address = $this->routableAddress($network['remote_address'] ?? null);
        if ($address === null) {
            return $annotation;
        }

        $provider = $this->cloudProviderFor($address);
        if ($provider !== null) {
            // Emitted only on a match. The prefix list is admittedly partial,
            // so `false` here would assert "not cloud" on evidence we do not
            // have; absence of the key is the truthful form of "no match".
            $annotation['is_cloud_provider'] = true;
            $annotation['cloud_provider'] = $provider;
        }

        // Both remaining keys come from the same lookup, and both are omitted
        // when no lookup happened — an unattempted PTR query tells us nothing
        // about whether the destination is a bare IP.
        if ($this->canResolve($address)) {
            $name = $this->reverseDns($address);
            if ($name !== null) {
                $annotation['reverse_dns'] = $name;
                $annotation['is_bare_ip_destination'] = false;
            } else {
                $annotation['is_bare_ip_destination'] = true;
            }
        }

        return $annotation;
    }

    /**
     * The syscall for an event, preferring the explicit field.
     *
     * Falls back to deriving it from `action` because the two are set by
     * different stages upstream and a normaliser change should degrade the
     * annotation, not silently mislabel ports.
     *
     * @param  array  $event  the whole event
     * @return string lowercase syscall name, or '' when undeterminable
     */
    private function syscallOf(array $event): string
    {
        $syscall = $event['syscall'] ?? null;
        if (is_string($syscall) && $syscall !== '') {
            return strtolower($syscall);
        }

        $action = $event['action'] ?? null;
        if (is_string($action) && str_starts_with($action, 'net_')) {
            return substr($action, 4);
        }

        return '';
    }

    /**
     * Which port on this event names a service, if either does.
     *
     * This is the same asymmetry that decides the aggregation key upstream, and
     * getting it wrong here is worse than getting it wrong there. For connect,
     * the service is what we dialled: remote_port. For accept/bind/listen the
     * service is ours, so remote_port is the client's ephemeral port and must
     * never be labelled — 6,710 distinct values across 9,122 sampled accepts,
     * every one of them meaningless as a service name.
     *
     * Returning null is the expected outcome for accept on this platform:
     * bpf_socket_events reported local_port = 0 on all 9,122 sampled accept
     * rows, and 0 is not a port. Rather than reach for the only other number
     * present, we say nothing.
     *
     * @param  array  $network  the event's `network` sub-array
     * @param  string  $syscall  connect|accept|bind|listen
     * @return int|null the service port, or null when this event has none
     */
    private function servicePortFor(array $network, string $syscall): ?int
    {
        $key = match ($syscall) {
            'connect' => 'remote_port',
            'accept', 'bind', 'listen' => 'local_port',
            // An unrecognised syscall gives no basis for choosing, and
            // guessing has a wrong answer half the time.
            default => null,
        };

        if ($key === null) {
            return null;
        }

        $port = $network[$key] ?? null;
        if (! is_int($port) && ! (is_string($port) && $port !== '' && ctype_digit($port))) {
            return null;
        }

        $port = (int) $port;

        return ($port > 0 && $port <= 65535) ? $port : null;
    }

    /**
     * The label for a service port, C2 reputation taking precedence.
     *
     * @param  int  $port  a port already established to be a service port
     * @return string|null null when the port is not one we name
     */
    private function serviceLabelFor(int $port): ?string
    {
        if (isset(self::SUSPICIOUS_C2_PORTS[$port])) {
            return self::C2_LABEL;
        }

        return self::PORT_SERVICES[$port] ?? null;
    }

    /**
     * Validate that a remote_address is an IP we should reason about.
     *
     * Not paranoia: 6.7% of sampled rows carry a filesystem path here rather
     * than an address (AF_UNIX sockets — /var/run/mysqld/mysqld.sock,
     * /var/run/docker.sock), and family arrives as the string "-1" on many
     * accepts. Anything that is not a parseable literal is rejected before it
     * can reach a resolver.
     *
     * @param  mixed  $address  the raw remote_address
     * @return string|null the trimmed address, or null if not usable
     */
    private function routableAddress(mixed $address): ?string
    {
        if (! is_string($address)) {
            return null;
        }

        $address = trim($address);
        if ($address === '' || @inet_pton($address) === false) {
            return null;
        }

        return $address;
    }

    /**
     * Longest-prefix match against the built-in cloud allocations.
     *
     * Longest-prefix rather than first-match so that a specific block nested
     * inside a coarse one wins regardless of declaration order — otherwise
     * Azure's 52.224.0.0/11 would report as AWS purely because 52.0.0.0/8 is
     * listed first.
     *
     * @param  string  $address  a validated IP literal
     * @return string|null provider label, or null when nothing matches
     */
    private function cloudProviderFor(string $address): ?string
    {
        $binary = @inet_pton($address);
        if ($binary === false) {
            return null;
        }

        $provider = null;
        $bestBits = -1;

        foreach (self::CLOUD_PREFIXES as $cidr => $label) {
            $bits = $this->prefixLength($cidr);
            if ($bits <= $bestBits) {
                continue;
            }
            if ($this->addressInCidr($binary, $cidr)) {
                $provider = $label;
                $bestBits = $bits;
            }
        }

        return $provider;
    }

    /**
     * The mask length declared by a CIDR string.
     *
     * @param  string  $cidr  e.g. 52.224.0.0/11
     * @return int -1 when malformed, so it can never win a longest-prefix race
     */
    private function prefixLength(string $cidr): int
    {
        $slash = strrpos($cidr, '/');
        if ($slash === false) {
            return -1;
        }

        $bits = substr($cidr, $slash + 1);

        return ctype_digit($bits) ? (int) $bits : -1;
    }

    /**
     * Whether a packed address falls inside a CIDR block.
     *
     * Compares packed bytes, which makes one implementation cover IPv4 and
     * IPv6 and avoids the 32-bit integer overflow that ip2long-based masking
     * hits. Mixing families is a non-match rather than an error: inet_pton
     * yields 4 bytes against 16, and a length mismatch simply fails.
     *
     * @param  string  $binary  packed address from inet_pton
     * @param  string  $cidr  network in CIDR notation
     * @return bool
     */
    private function addressInCidr(string $binary, string $cidr): bool
    {
        $slash = strrpos($cidr, '/');
        if ($slash === false) {
            return false;
        }

        $network = @inet_pton(substr($cidr, 0, $slash));
        if ($network === false || strlen($network) !== strlen($binary)) {
            return false;
        }

        $bits = $this->prefixLength($cidr);
        if ($bits < 0 || $bits > strlen($binary) * 8) {
            return false;
        }

        $wholeBytes = intdiv($bits, 8);
        if ($wholeBytes > 0 && strncmp($binary, $network, $wholeBytes) !== 0) {
            return false;
        }

        $remainingBits = $bits % 8;
        if ($remainingBits === 0) {
            return true;
        }

        // Safe to index: $remainingBits > 0 implies $wholeBytes < strlen().
        $mask = chr((0xFF << (8 - $remainingBits)) & 0xFF);

        return ($binary[$wholeBytes] & $mask) === ($network[$wholeBytes] & $mask);
    }

    /**
     * Whether a PTR lookup is permitted for this address right now.
     *
     * A cached address is always answerable, including a cached miss, so the
     * cache is checked ahead of the circuit breaker: abandoning the resolver
     * must not discard knowledge already paid for.
     *
     * @param  string  $address  a validated IP literal
     * @return bool
     */
    private function canResolve(string $address): bool
    {
        if (array_key_exists($address, $this->reverseDnsCache)) {
            return true;
        }

        return $this->reverseDnsEnabled && ! $this->resolverAbandoned;
    }

    /**
     * Best-effort PTR lookup, cached for this object's lifetime.
     *
     * Best-effort is not a disclaimer here, it is the contract: DNS may be
     * firewalled, the resolver may be down, and a destination may legitimately
     * have no PTR record. All three produce null, and null means "no name
     * established" — never "not a hostname".
     *
     * The critical detail is the return-value check. gethostbyaddr() returns
     * the *unmodified input address* when there is no PTR record, not false.
     * Measured on this host: 167.172.226.55 returns the string
     * '167.172.226.55' after 150ms. So the test is whether the result still
     * parses as an IP literal — a real hostname does not — rather than a
     * comparison against false, which would never fire, or a string comparison
     * against the input, which misses IPv6 written in a different but
     * equivalent textual form.
     *
     * @param  string  $address  a validated IP literal
     * @return string|null the hostname, or null when none was established
     */
    private function reverseDns(string $address): ?string
    {
        if (array_key_exists($address, $this->reverseDnsCache)) {
            $this->cacheHits++;

            return $this->reverseDnsCache[$address];
        }

        if (! $this->reverseDnsEnabled || $this->resolverAbandoned) {
            return null;
        }

        $startedAt = microtime(true);
        $result = @gethostbyaddr($address);
        $elapsedMs = (microtime(true) - $startedAt) * 1000;
        $this->lookups++;

        $name = null;
        if (is_string($result) && $result !== '') {
            $candidate = rtrim($result, '.');
            // Still an IP literal => no PTR record was found.
            if ($candidate !== '' && @inet_pton($candidate) === false) {
                $name = $candidate;
            }
        }

        $this->reverseDnsCache[$address] = $name;
        $this->noteLookupLatency($elapsedMs);

        return $name;
    }

    /**
     * Track resolver health and trip the breaker when it looks unreachable.
     *
     * Consecutive rather than cumulative: one slow lookup is a cold cache or a
     * slow authoritative server, several in a row is the resolver itself. A
     * single fast answer resets the count, so a healthy resolver never trips
     * no matter how long the run.
     *
     * @param  float  $elapsedMs  wall time of the lookup just performed
     * @return void
     */
    private function noteLookupLatency(float $elapsedMs): void
    {
        if ($elapsedMs < self::SLOW_LOOKUP_MS) {
            $this->consecutiveSlowLookups = 0;

            return;
        }

        $this->consecutiveSlowLookups++;
        if ($this->consecutiveSlowLookups < self::SLOW_LOOKUP_BUDGET) {
            return;
        }

        $this->resolverAbandoned = true;
        Log::warning('AsnAnnotator: reverse DNS abandoned for this run, resolver appears unreachable', [
            'consecutive_slow_lookups' => $this->consecutiveSlowLookups,
            'threshold_ms' => self::SLOW_LOOKUP_MS,
            'last_lookup_ms' => round($elapsedMs, 1),
        ]);
    }
}

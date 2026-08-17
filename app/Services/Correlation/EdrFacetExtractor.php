<?php

namespace App\Services\Correlation;

/**
 * Decomposes one normalised event into six categorical facets.
 *
 * A facet is a low-cardinality description of *one structural dimension* of
 * what happened — who launched what, which binary it was, what the argument
 * vector looked like, whose identity it ran under, whether privilege changed,
 * and where it talked to. The correlator never asks "is this string bad"; it
 * asks "has this host ever seen this shape before". That question is only
 * answerable if the shape is coarse enough to recur, which is what every
 * bucketing decision in this class is for.
 *
 * Two properties are load-bearing and worth stating up front:
 *
 *  - **Renaming a binary is not an evasion here, it is the maximum charge.**
 *    A payload dropped as `/tmp/.systemd-helper` produces an F1 and an F2
 *    value this host has never seen. The stateless rules can be walked around
 *    by choosing a name they do not match; the facet model gets *louder*.
 *
 *  - **Cardinality is capped by construction.** Every facet value is drawn
 *    from a bounded vocabulary (8 directory classes, 7 argc buckets, a 10-bit
 *    mask, 10 port classes, 3 address scopes) crossed with binary basenames.
 *    Anything unbounded — a full path, a raw argument, a destination address —
 *    is deliberately excluded from the key and kept for the evidence payload,
 *    because a facet that can never recur can never become familiar, and a
 *    facet that can never become familiar is a permanent false-positive
 *    generator.
 *
 * Pure: no I/O, no clock, no state. Everything here is a deterministic
 * function of the event, so the whole scoring path stays unit-testable.
 */
final class EdrFacetExtractor
{
    public const KIND_LINEAGE = 1;
    public const KIND_IMAGE = 2;
    public const KIND_ARGSHAPE = 3;
    public const KIND_IDENTITY = 4;
    public const KIND_PRIVTRANS = 5;
    public const KIND_EGRESS = 6;

    /**
     * Default facet weights, in "surprise points" (sp). These are the price of
     * a completely unseen value on that dimension.
     *
     * The ordering encodes a judgement about what novelty means: a privilege
     * transition nobody has made before is the most expensive single thing an
     * actor can do (4.0), because escalation is the step an intrusion cannot
     * skip and an ordinary workload rarely invents. A new working directory
     * for an existing user is the cheapest (1.5), because that is what people
     * do all day.
     */
    public const DEFAULT_WEIGHTS = [
        self::KIND_LINEAGE => 3.0,
        self::KIND_IMAGE => 2.5,
        self::KIND_ARGSHAPE => 2.0,
        self::KIND_IDENTITY => 1.5,
        self::KIND_PRIVTRANS => 4.0,
        self::KIND_EGRESS => 3.0,
    ];

    /**
     * The directory vocabulary in use.
     *
     * Set from the platform profile at start of cycle rather than compiled in:
     * a prefix list that still says `/usr/bin` on a Mac does not fail, it
     * silently files every Homebrew binary under "other" and the novelty model
     * loses a dimension without anything reporting a problem.
     */
    private static ?\App\Services\Platform\EdrPlatformProfile $profile = null;

    /** @var array<string, string[]>|null */
    private static ?array $dirPrefixes = null;

    /** @var array<string, string>|null */
    private static ?array $containerPatterns = null;

    public static function usePlatform(\App\Services\Platform\EdrPlatformProfile $profile): void
    {
        self::$profile = $profile;
        self::$dirPrefixes = $profile->directoryClasses();
        self::$containerPatterns = $profile->containerPathPatterns();
    }

    /** @return array<string, string[]> */
    private static function dirPrefixes(): array
    {
        if (self::$dirPrefixes === null) {
            self::usePlatform(\App\Services\Platform\EdrPlatformProfile::current());
        }

        return self::$dirPrefixes;
    }

    /** @return array<string, string> */
    private static function containerPatterns(): array
    {
        if (self::$containerPatterns === null) {
            self::usePlatform(\App\Services\Platform\EdrPlatformProfile::current());
        }

        return self::$containerPatterns;
    }

    private static function platform(): \App\Services\Platform\EdrPlatformProfile
    {
        if (self::$profile === null) {
            self::usePlatform(\App\Services\Platform\EdrPlatformProfile::current());
        }

        return self::$profile;
    }

    /* Argument-shape bits. Stable numbering: these end up in persisted facet
     * values, so renumbering them silently invalidates every host's baseline. */
    public const ARG_PIPE = 1;
    public const ARG_REDIRECT = 2;
    public const ARG_SUBSHELL = 4;
    public const ARG_CHAIN = 8;
    public const ARG_B64TOKEN = 16;
    public const ARG_HIENT = 32;
    public const ARG_IPLITERAL = 64;
    public const ARG_URL = 128;
    public const ARG_DASHDASH = 256;
    public const ARG_QUOTEDEPTH = 512;

    /** Ports worth distinguishing by name. Everything else buckets. */
    private const NAMED_PORTS = [22, 53, 80, 123, 443, 3306, 5432, 6379];

    /**
     * Placeholder used when the parent could not be resolved.
     *
     * Every orphan shares this one token on purpose. If each unresolved parent
     * minted its own value, orphaned execs — which are common, because
     * fork-without-exec is invisible to the sensor — would be permanently
     * novel and would alert forever on a perfectly healthy host.
     */
    public const UNKNOWN_PARENT = 'none:‹unknown›';

    /**
     * Actions that describe a network relationship rather than an execution.
     *
     * More than one spelling on purpose. The raw sensor emits `connect`; the
     * network module emits `net_connect` and `net_accept` for *aggregated*
     * relationships, which is the same fact at a thousandth of the volume.
     * Matching only the first spelling would have meant the egress stage of
     * every chain silently never lit once aggregation landed — no error, no
     * missing alert, just every intrusion scored one stage short.
     */
    public const NETWORK_ACTIONS = ['connect', 'net_connect', 'net_accept'];

    /** The subset that means "this host reached out". */
    public const OUTBOUND_ACTIONS = ['connect', 'net_connect'];

    public static function isNetworkAction(string $action): bool
    {
        return in_array($action, self::NETWORK_ACTIONS, true);
    }

    public static function isOutbound(string $action): bool
    {
        return in_array($action, self::OUTBOUND_ACTIONS, true);
    }

    /**
     * Every facet for one event, ready to price.
     *
     * @param  array      $event    normalised event
     * @param  array|null $parent   resolved parent row from `procs`, or null
     * @param  string[]   $webRoots Hub-pushed document roots
     * @param  array<int, float>|null $weights override for the default table
     * @return array<int, array{kind:int, weight:float, value:string, fid:string}>
     */
    public static function facetsFor(
        array $event,
        ?array $parent,
        array $webRoots = [],
        ?array $weights = null
    ): array {
        $weights = $weights ?? self::DEFAULT_WEIGHTS;
        $action = (string) ($event['action'] ?? 'exec');

        $image = self::imageToken((string) ($event['path'] ?? ''), $webRoots);

        // A network event says nothing about lineage, arguments or privilege —
        // it is one tuple about where a process reached. Charging it the exec
        // facets would price the same process twice for one action.
        //
        // Direction is part of the key. "This image has talked out on 443
        // before" and "this image has been connected TO on 443 before" are
        // different facts about a host, and collapsing them would let a
        // familiar outbound pattern vouch for a listener that has never
        // existed here — which is what a bind shell looks like.
        if (self::isNetworkAction($action)) {
            $network = is_array($event['network'] ?? null) ? $event['network'] : [];
            $port = (int) ($event['remote_port'] ?? $network['remote_port'] ?? 0);
            $address = (string) ($event['remote_address'] ?? $network['remote_address'] ?? '');

            return [self::facet(
                self::KIND_EGRESS,
                $weights[self::KIND_EGRESS] ?? 0.0,
                $image
                    . '|' . self::portClass($port)
                    . '|' . self::addressScope($address)
                    . '|' . (self::isOutbound($action) ? 'out' : 'in')
            )];
        }

        $parentImage = $parent !== null && ($parent['image'] ?? '') !== ''
            ? (string) $parent['image']
            : self::UNKNOWN_PARENT;

        $uid = (int) ($event['uid'] ?? -1);

        // 'same' and 'unknown' are distinct on purpose. 'same' is the
        // overwhelmingly common case and becomes familiar within days, so it
        // costs nothing; 'unknown' means we could not observe the parent and
        // must not be scored as if we had proved no transition happened.
        $privTrans = $parent === null
            ? 'unknown'
            : ((int) $parent['uid'] === $uid ? 'same' : $parent['uid'] . '>' . $uid);

        return [
            self::facet($k = self::KIND_LINEAGE, $weights[$k] ?? 0.0, $parentImage . '>' . $image),
            self::facet($k = self::KIND_IMAGE, $weights[$k] ?? 0.0, $image),
            self::facet($k = self::KIND_ARGSHAPE, $weights[$k] ?? 0.0, self::argShape((string) ($event['cmdline'] ?? ''))),
            self::facet(
                $k = self::KIND_IDENTITY,
                $weights[$k] ?? 0.0,
                $uid . ':' . self::dirclass((string) ($event['cwd'] ?? ''), $webRoots)
            ),
            self::facet($k = self::KIND_PRIVTRANS, $weights[$k] ?? 0.0, $privTrans),
        ];
    }

    /**
     * The token a binary is known by: its directory class plus its basename.
     *
     * Not the full path — `/usr/bin/curl` and `/bin/curl` are the same fact
     * about this host, and keeping the path would make every distro layout
     * difference look like novelty.
     */
    public static function imageToken(string $path, array $webRoots = []): string
    {
        if ($path === '') {
            return 'none:';
        }

        $path = self::normalisePath($path);

        return self::dirclass($path, $webRoots) . ':' . basename($path);
    }

    /**
     * Collapse container-layer paths.
     *
     * Without this every container start mints a fresh set of never-seen
     * values, because the overlay hash is unique per layer. That is a
     * guaranteed alert storm on any host that runs containers, and it says
     * nothing about the workload.
     */
    public static function normalisePath(string $path): string
    {
        // Fold first, so everything downstream — prefix matching, facet
        // values, the signature — sees one spelling of a given path. On
        // Windows that means lowercase with forward slashes: the filesystem
        // treats C:\WINDOWS\ and c:\windows\ as one directory, and carrying
        // both through would mint two facet values for one fact and halve the
        // familiarity count of each.
        $path = self::platform()->foldPath($path);

        foreach (self::containerPatterns() as $pattern => $replacement) {
            $path = preg_replace($pattern, $replacement, $path, 1) ?? $path;
        }

        return $path;
    }

    /**
     * Which class of directory a path lives in.
     *
     * `web` is checked first and comes from Hub-pushed document roots: a
     * binary executing from inside the web root is the single most meaningful
     * location signal this product has, and it would otherwise be swallowed by
     * the `etc` (/var/www) or `other` buckets.
     */
    public static function dirclass(string $path, array $webRoots = []): string
    {
        if ($path === '') {
            return 'none';
        }

        $path = self::normalisePath($path);

        foreach ($webRoots as $root) {
            $root = rtrim((string) $root, '/');
            if ($root !== '' && (str_starts_with($path, $root . '/') || $path === $root)) {
                return 'web';
            }
        }

        // Compare against "path + /" so that /root matches the /root/ prefix
        // and /rootkit does not.
        $probe = rtrim($path, '/') . '/';

        // Longest prefix wins, not first.
        //
        // The classes overlap by nature — c:/windows/temp/ sits inside
        // c:/windows/, /Library/WebServer/ inside /Library/ — and first-match
        // meant the answer depended on which order the profile happened to
        // list them in. That is a silent misclassification, and it lands
        // precisely on the cases worth seeing: a binary in c:/windows/temp/ is
        // interesting *because* it is user-writable, and reporting it as the
        // system directory says the opposite of the truth.
        $best = '';
        $bestClass = null;

        foreach (self::dirPrefixes() as $class => $prefixes) {
            foreach ($prefixes as $prefix) {
                if (strlen($prefix) > strlen($best) && str_starts_with($probe, $prefix)) {
                    $best = $prefix;
                    $bestClass = $class;
                }
            }
        }

        if ($bestClass !== null) {
            return $bestClass;
        }

        return 'other';
    }

    /**
     * The shape of an argument vector, with every actual value thrown away.
     *
     * `curl https://a.example/x -o /tmp/a` and `curl https://b.example/y -o
     * /tmp/b` must produce the *same* value — they are the same behaviour, and
     * a model that treats them as different has infinite cardinality and
     * learns nothing. What survives is the argument count bucket and ten bits
     * about structure.
     */
    public static function argShape(string $cmdline): string
    {
        $trimmed = trim($cmdline);

        if ($trimmed === '') {
            return 'n0|0';
        }

        $tokens = preg_split('/\s+/', $trimmed) ?: [];
        $argc = max(0, count($tokens) - 1);

        $bucket = match (true) {
            $argc <= 3 => (string) $argc,
            $argc <= 6 => '4-6',
            $argc <= 12 => '7-12',
            default => '13+',
        };

        $mask = 0;

        if (str_contains($cmdline, '|')) {
            $mask |= self::ARG_PIPE;
        }

        if (preg_match('/[<>]/', $cmdline) === 1) {
            $mask |= self::ARG_REDIRECT;
        }

        if (str_contains($cmdline, '$(') || str_contains($cmdline, '`')) {
            $mask |= self::ARG_SUBSHELL;
        }

        if (preg_match('/&&|\|\||;/', $cmdline) === 1) {
            $mask |= self::ARG_CHAIN;
        }

        // A long unbroken base64-alphabet run is the shape of an encoded
        // payload regardless of what it decodes to.
        if (preg_match('#[A-Za-z0-9+/=]{20,}#', $cmdline) === 1) {
            $mask |= self::ARG_B64TOKEN;
        }

        if (preg_match('#\bhttps?://#i', $cmdline) === 1) {
            $mask |= self::ARG_URL;
        }

        if (preg_match('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $cmdline) === 1) {
            $mask |= self::ARG_IPLITERAL;
        }

        if (preg_match('/(?:^|\s)--\S/', $cmdline) === 1) {
            $mask |= self::ARG_DASHDASH;
        }

        if (substr_count($cmdline, '"') >= 4 || substr_count($cmdline, "'") >= 4) {
            $mask |= self::ARG_QUOTEDEPTH;
        }

        if (self::maxTokenEntropy($tokens) >= 4.0) {
            $mask |= self::ARG_HIENT;
        }

        return 'n' . $bucket . '|' . $mask;
    }

    /**
     * Shannon entropy, in bits per character, of the longest token.
     *
     * High entropy in the longest argument is what an encoded blob, a packed
     * payload or a generated key looks like. Short tokens are skipped because
     * entropy over a handful of characters is noise.
     */
    private static function maxTokenEntropy(array $tokens): float
    {
        $longest = '';

        foreach ($tokens as $token) {
            if (strlen((string) $token) > strlen($longest)) {
                $longest = (string) $token;
            }
        }

        $length = strlen($longest);

        if ($length < 16) {
            return 0.0;
        }

        $counts = count_chars($longest, 1);
        $entropy = 0.0;

        foreach ($counts as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }

    /**
     * Destination port, bucketed.
     *
     * The exact high port a connection went to is not a fact about behaviour —
     * ephemeral ports are effectively random. What matters is whether it was a
     * well-known service, a privileged port, or something else entirely.
     */
    public static function portClass(int $port): string
    {
        if (in_array($port, self::NAMED_PORTS, true)) {
            return (string) $port;
        }

        return $port > 0 && $port < 1024 ? 'lo1024' : 'hi';
    }

    /**
     * Where an address sits relative to this host.
     *
     * Deliberately three values, not a prefix. Keying the egress facet on the
     * destination network would make every CDN, object-store endpoint and NTP
     * pool a permanently novel value that can never accumulate the distinct
     * days it needs to become familiar — a standing false-positive generator
     * on any internet-connected host. The actual address travels in the
     * evidence payload, where an analyst needs it.
     */
    public static function addressScope(string $address): string
    {
        $address = trim($address);

        if ($address === '') {
            return 'loopback';
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            if (str_starts_with($address, '127.') || $address === '0.0.0.0') {
                return 'loopback';
            }

            if (filter_var(
                $address,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            ) === false) {
                // Covers RFC1918, link-local, multicast and the other reserved
                // ranges in one check.
                return 'private';
            }

            return 'public';
        }

        if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $lower = strtolower($address);

            if ($lower === '::1' || $lower === '::') {
                return 'loopback';
            }

            // fc00::/7 unique-local, fe80::/10 link-local.
            if (str_starts_with($lower, 'fc') || str_starts_with($lower, 'fd')
                || str_starts_with($lower, 'fe8') || str_starts_with($lower, 'fe9')
                || str_starts_with($lower, 'fea') || str_starts_with($lower, 'feb')
            ) {
                return 'private';
            }

            return 'public';
        }

        // Unparseable — treat as loopback so a malformed row cannot charge
        // egress novelty it has not earned.
        return 'loopback';
    }

    /**
     * Stable id for a facet value.
     *
     * crc32b rather than a cryptographic hash: this is a dictionary key, not a
     * security boundary, and it is computed six times per event on a host that
     * sees half a million events a day. The `\x1f` separator keeps kinds from
     * colliding with each other's value space.
     */
    public static function fid(int $kind, string $value): string
    {
        return hash('crc32b', $kind . "\x1f" . $value);
    }

    /**
     * Fingerprint of the whole event shape — the charge-once ledger key.
     *
     * Two events with the same signature are the same behaviour by every
     * dimension this model can see, so the second one has told us nothing new.
     *
     * @param array<int, array{kind:int, weight:float, value:string, fid:string}> $facets
     */
    public static function signature(array $facets): string
    {
        $values = [];

        foreach ($facets as $facet) {
            $values[(int) $facet['kind']] = (string) $facet['value'];
        }

        ksort($values);

        return hash('crc32b', implode('|', $values));
    }

    /**
     * @return array{kind:int, weight:float, value:string, fid:string}
     */
    private static function facet(int $kind, float $weight, string $value): array
    {
        return [
            'kind' => $kind,
            'weight' => $weight,
            'value' => $value,
            'fid' => self::fid($kind, $value),
        ];
    }
}

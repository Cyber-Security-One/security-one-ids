<?php

namespace App\Services\Correlation;

/**
 * Maps one event onto the kill-chain classes it lights.
 *
 * A class is *what an event is for*, not how suspicious it is. The score never
 * asks "how bad was that"; it asks "how many different stages of an intrusion
 * has this actor now touched". That reframing is what makes the false-positive
 * bound arithmetic instead of tuned — a single noisy behaviour, repeated a
 * million times, still lights one class and one class can never reach the
 * threshold.
 *
 * Each class is lit either by **structural** evidence (a facet this host has
 * never seen, a directory, a privilege transition) or by an **existing rule
 * finding**. Nothing here adds a new regex: the eleven behaviour rules, the
 * file-integrity rules and everything the governance layer chooses to suppress
 * all feed in as evidence, and the classifier's only job is to decide which
 * stage they speak to.
 *
 * The class *caps* live in the scorer, not here. This class answers "which",
 * the scorer answers "how much", and keeping those apart is what lets the
 * bound in `EdrActorScorer` be stated as a property of the arithmetic.
 *
 * Pure: no I/O, no clock, no state.
 */
final class EdrIntentClassifier
{
    public const ENTRY = 1;
    public const DISCOVERY = 2;
    public const STAGING = 3;
    public const PRIVESC = 4;
    public const CRED = 5;
    public const COLLECT = 6;
    public const PERSIST = 7;
    public const EGRESS = 8;
    public const OBFUSCATION = 9;
    public const ANTIFORENSIC = 10;

    public const CLASSES = [
        self::ENTRY => 'ENTRY',
        self::DISCOVERY => 'DISCOVERY',
        self::STAGING => 'STAGING',
        self::PRIVESC => 'PRIVESC',
        self::CRED => 'CRED',
        self::COLLECT => 'COLLECT',
        self::PERSIST => 'PERSIST',
        self::EGRESS => 'EGRESS',
        self::OBFUSCATION => 'OBFUSCATION',
        self::ANTIFORENSIC => 'ANTIFORENSIC',
    ];

    /**
     * Position in the kill chain, for the ordering bonus.
     *
     * Obfuscation and anti-forensics are deliberately 0 — they are excluded
     * from the ordering calculation entirely. Destroying logs is not a step
     * toward an objective, it is a statement about intent, and it can happen
     * at any point without saying anything about progression.
     */
    public const ORDER = [
        self::ENTRY => 1,
        self::DISCOVERY => 2,
        self::STAGING => 3,
        self::PRIVESC => 4,
        self::CRED => 5,
        self::COLLECT => 6,
        self::PERSIST => 7,
        self::EGRESS => 8,
        self::OBFUSCATION => 0,
        self::ANTIFORENSIC => 0,
    ];

    /** Mirrors EdrRuleEngine::DISCOVERY_BINARIES; overridable from the Hub. */
    private const DEFAULT_DISCOVERY_BINARIES = [
        'whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ip', 'netstat', 'ss',
        'ps', 'w', 'last', 'lastlog', 'arp', 'route', 'lsblk', 'mount',
        'getent', 'groups', 'sudo',
    ];

    /**
     * Archiving and dumping tools. Only counted with at least one positional
     * argument: `tar` with no operand is a usage message, not collection.
     */
    private const DEFAULT_COLLECT_BINARIES = [
        'tar', 'zip', 'gzip', 'bzip2', 'xz', '7z', '7za', 'zstd',
        'mysqldump', 'pg_dump', 'pg_dumpall', 'mongodump', 'rsync',
    ];

    /** Rule id prefix => class it lights. Suffix-matched on the id. */
    private const RULE_CLASSES = [
        'EDR-001' => self::ENTRY,
        'EDR-002' => self::EGRESS,
        'EDR-003' => self::STAGING,
        'EDR-004' => self::STAGING,
        'EDR-005' => self::STAGING,
        'EDR-006' => self::CRED,
        'EDR-007' => self::ANTIFORENSIC,
        'EDR-008' => self::PERSIST,
        'EDR-009' => self::PRIVESC,
        'EDR-010' => self::PRIVESC,
        'EDR-011' => self::STAGING,
        'EDR-012' => self::DISCOVERY,
        'FIM-002' => self::PERSIST,
        'FIM-003' => self::STAGING,
        'FIM-004' => self::PERSIST,
        'FIM-005' => self::ANTIFORENSIC,
    ];

    private const MITRE = [
        self::ENTRY => ['T1505.003'],
        self::DISCOVERY => ['T1082'],
        self::STAGING => ['T1105', 'T1036'],
        self::PRIVESC => ['T1548'],
        self::CRED => ['T1552'],
        self::COLLECT => ['T1560'],
        self::PERSIST => ['T1053'],
        self::EGRESS => ['T1071'],
        self::OBFUSCATION => ['T1027'],
        self::ANTIFORENSIC => ['T1070'],
    ];

    /** @var string[] */
    private array $discoveryBinaries;

    /** @var string[] */
    private array $collectBinaries;

    /** Familiarity below which a facet counts as "never seen here". */
    private float $novelHard = 0.25;

    /** Familiarity below which a facet counts as "unusual here". */
    private float $novelSoft = 0.5;

    public function __construct(array $config = [])
    {
        $discovery = $config['discovery_binaries'] ?? null;
        $this->discoveryBinaries = is_array($discovery) && $discovery !== []
            ? array_map('strval', $discovery)
            : self::DEFAULT_DISCOVERY_BINARIES;

        $collect = $config['collect_binaries'] ?? null;
        $this->collectBinaries = is_array($collect) && $collect !== []
            ? array_slice(array_map('strval', $collect), 0, 128)
            : self::DEFAULT_COLLECT_BINARIES;
    }

    /**
     * Which classes this event lights.
     *
     * @param  array $event    normalised event
     * @param  array $facets   this event's facets, from EdrFacetExtractor
     * @param  array $fam      familiarity by fid
     * @param  array $findings rule hits on this event, INCLUDING suppressed ones
     * @param  array $context  anchor_kind, parent
     * @return int[] lit class ids, ascending
     */
    public function classify(array $event, array $facets, array $fam, array $findings, array $context = []): array
    {
        $lit = [];

        $byKind = [];
        foreach ($facets as $facet) {
            $byKind[(int) $facet['kind']] = $facet;
        }

        $famFor = function (int $kind) use ($byKind, $fam): float {
            $facet = $byKind[$kind] ?? null;

            return $facet === null ? 1.0 : (float) ($fam[$facet['fid']] ?? 0.0);
        };

        /* Rule-backed classes ------------------------------------------------
         * A finding lights its class regardless of novelty. This is what lets
         * a mature host — where every facet is familiar — still assemble a
         * chain out of rule hits alone. Without it the model would go blind
         * on exactly the hosts it has learned best. */
        foreach ($findings as $finding) {
            $rule = (string) ($finding['rule'] ?? '');
            $class = self::RULE_CLASSES[$rule] ?? null;

            if ($class !== null) {
                $lit[$class] = true;
            }
        }

        $action = (string) ($event['action'] ?? 'exec');
        $path = (string) ($event['path'] ?? '');
        $binary = $path !== '' ? basename($path) : '';
        $anchorKind = (string) ($context['anchor_kind'] ?? 'unknown');

        // File-integrity events describe a *file*, not a process. Everything
        // below reads `path` as the thing that executed, so running them
        // through it would classify by filename: a document called `id` or
        // `ps` lights DISCOVERY, and anything written under /tmp or a web root
        // lights STAGING. On a host with user uploads that is a permanent
        // false-positive source. Their rule findings above already carry them
        // into the right stage, which is the only signal they legitimately
        // provide here.
        if ($action !== 'exec' && !EdrFacetExtractor::isNetworkAction($action)) {
            ksort($lit);

            return array_keys($lit);
        }

        if (EdrFacetExtractor::isNetworkAction($action)) {
            // Reaching a public address with an egress shape this host has not
            // seen before. Private and loopback destinations are excluded:
            // internal service chatter is the bulk of every host's traffic.
            //
            // Inbound is deliberately not egress. An accepted connection is
            // something arriving, and calling that "data leaving" would put a
            // web server's ordinary traffic in the last stage of every chain.
            $network = is_array($event['network'] ?? null) ? $event['network'] : [];
            $scope = EdrFacetExtractor::addressScope(
                (string) ($event['remote_address'] ?? $network['remote_address'] ?? '')
            );

            if (EdrFacetExtractor::isOutbound($action)
                && $scope === 'public'
                && $famFor(EdrFacetExtractor::KIND_EGRESS) < $this->novelHard
            ) {
                $lit[self::EGRESS] = true;
            }

            ksort($lit);

            return array_keys($lit);
        }

        /* K1 ENTRY ----------------------------------------------------------
         * The web tier spawning something it has not spawned before. The rule
         * engine catches the known-bad binaries; this catches the ones nobody
         * put on a list. */
        if ($anchorKind === 'web' && $famFor(EdrFacetExtractor::KIND_LINEAGE) < $this->novelHard) {
            $lit[self::ENTRY] = true;
        }

        /* K2 DISCOVERY ------------------------------------------------------ */
        if ($binary !== '' && in_array($binary, $this->discoveryBinaries, true)) {
            $lit[self::DISCOVERY] = true;
        }

        /* K3 STAGING --------------------------------------------------------
         * Either the binary itself is one this host has never run, or it is
         * running from somewhere anyone can write to. */
        if ($famFor(EdrFacetExtractor::KIND_IMAGE) < $this->novelHard) {
            $lit[self::STAGING] = true;
        } elseif (in_array(EdrFacetExtractor::dirclass($path, $context['web_roots'] ?? []), ['tmp', 'home', 'web'], true)) {
            $lit[self::STAGING] = true;
        }

        /* K4 PRIVESC --------------------------------------------------------
         * A uid transition nobody has made here before. `sudo` by an admin who
         * sudoes daily is familiar and costs nothing; the same transition the
         * first time is the most expensive single act on the host. */
        $parent = $context['parent'] ?? null;

        if ($parent !== null
            && (int) $parent['uid'] !== (int) ($event['uid'] ?? -1)
            && $famFor(EdrFacetExtractor::KIND_PRIVTRANS) < $this->novelSoft
        ) {
            $lit[self::PRIVESC] = true;
        }

        /* K6 COLLECT -------------------------------------------------------- */
        if ($binary !== ''
            && in_array($binary, $this->collectBinaries, true)
            && self::hasPositionalArgument((string) ($event['cmdline'] ?? ''))
        ) {
            $lit[self::COLLECT] = true;
        }

        /* K9 OBFUSCATION ---------------------------------------------------- */
        $argShape = $byKind[EdrFacetExtractor::KIND_ARGSHAPE]['value'] ?? '';
        $mask = self::maskFromArgShape((string) $argShape);
        $obfuscated = EdrFacetExtractor::ARG_B64TOKEN | EdrFacetExtractor::ARG_HIENT | EdrFacetExtractor::ARG_SUBSHELL;

        if (($mask & $obfuscated) !== 0 && $famFor(EdrFacetExtractor::KIND_ARGSHAPE) < $this->novelSoft) {
            $lit[self::OBFUSCATION] = true;
        }

        ksort($lit);

        return array_keys($lit);
    }

    /**
     * ATT&CK techniques for an incident, from its classes and its findings.
     *
     * @param  int[] $classIds
     * @return string[]
     */
    public function mitreFor(array $classIds, array $findings): array
    {
        $out = ['T1059'];

        foreach ($classIds as $classId) {
            foreach (self::MITRE[$classId] ?? [] as $technique) {
                $out[] = $technique;
            }
        }

        foreach ($findings as $finding) {
            $mitre = (string) ($finding['mitre'] ?? '');
            if ($mitre !== '' && $mitre !== '-') {
                $out[] = $mitre;
            }
        }

        $out = array_values(array_unique($out));
        sort($out);

        return $out;
    }

    public static function name(int $classId): string
    {
        return self::CLASSES[$classId] ?? ('K' . $classId);
    }

    /**
     * Does the command line carry an operand, as opposed to only flags?
     *
     * `tar --version` is documentation. `tar czf x.tgz /etc` is collection.
     */
    private static function hasPositionalArgument(string $cmdline): bool
    {
        $tokens = preg_split('/\s+/', trim($cmdline)) ?: [];

        // Skip the binary itself.
        foreach (array_slice($tokens, 1) as $token) {
            if ($token !== '' && !str_starts_with($token, '-')) {
                return true;
            }
        }

        return false;
    }

    /** Recover the bitmask half of an `n{bucket}|{mask}` argshape value. */
    private static function maskFromArgShape(string $argShape): int
    {
        $pipe = strrpos($argShape, '|');

        return $pipe === false ? 0 : (int) substr($argShape, $pipe + 1);
    }
}

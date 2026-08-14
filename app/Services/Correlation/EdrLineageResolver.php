<?php

namespace App\Services\Correlation;

use App\Services\EdrEventSpool;

/**
 * Reconstructs causality, and decides which durable *actor* an event belongs
 * to.
 *
 * ## Why the actor key is the whole design
 *
 * The obvious way to group events is by process tree. It does not work here,
 * for two reasons that are both fatal.
 *
 * The first is the webshell. A compromised PHP site runs one process tree
 * *per HTTP request*: `php-fpm → sh → whoami`, then a completely separate
 * `php-fpm → sh → curl`, then another for `chmod`. Every tree-rooted
 * correlator sees five unrelated one-event trees and correlates nothing at
 * all, which is precisely backwards — that shape is the single highest-value
 * host signal this product has.
 *
 * The second is time. A tree is only a live object while its processes exist.
 * An intrusion that returns four hours later has no tree left to attach to.
 *
 * So the unit of attribution is not the tree but the **entry point the causal
 * chain descends from**: the web pool, the ssh session class, a specific cron
 * job, a container. That key is computed once, when a chain anchors, and
 * inherited unchanged down the whole subtree. Every request through the same
 * webshell lands in the same bucket, days apart if necessary.
 *
 * ## Why this survives daemonisation
 *
 * A double-forking payload re-parents itself to init, and every correlator
 * that reads `/proc` afterwards sees an orphan. This one does not read
 * `/proc`: the sensor reports the exec event with the parent that existed *at
 * that instant*, and the re-parenting happens strictly after the only
 * observation that matters. `setsid`, `nohup` and background daemons stay
 * attached to the actor that started them.
 *
 * ## Pid reuse
 *
 * A pid is a small integer the kernel recycles. Linking a child to whatever
 * currently holds its ppid would eventually splice two unrelated lineages
 * together. Every observed exec consumes a monotone sequence number, and a
 * parent link is only accepted from a row whose sequence is *below* the
 * child's — so a recycled pid can never adopt a process that predates it.
 */
final class EdrLineageResolver
{
    /** Longest a lineage row stays eligible as a parent. */
    public const PROC_TTL = 604800;

    /** Depth beyond which a chain is treated as a new anchor rather than grown. */
    public const MAX_DEPTH = 24;

    /** Spool lookups allowed per cycle when a parent is missing from `procs`. */
    public const MAX_SPOOL_PARENT_LOOKUPS = 64;

    /**
     * The process vocabulary is NOT compiled in here.
     *
     * It comes from {@see \App\Services\Platform\EdrPlatformProfile}, because
     * it is entirely platform-specific and stating it in two places is the
     * failure this branch has spent its time on: `systemd` anchors nothing on
     * a Mac and `launchd` anchors everything, and a stale list does not throw
     * — every chain would simply anchor as an orphan, the actor key would fall
     * into a five-minute time bucket, and the property this whole design
     * exists for would be gone with nothing reporting it.
     */

    private EdrCorrelatorStore $store;
    private ?EdrEventSpool $spool;

    /**
     * Process vocabulary for the platform being watched.
     *
     * `systemd` anchors nothing on a Mac and `launchd` anchors everything, so
     * a compiled-in list is not a default — it is a silent failure on the
     * other platform: every chain would anchor as an orphan, the actor key
     * would fall into a five-minute time bucket, and the one property this
     * design exists for would be gone with nothing reporting it.
     */
    private array $anchorImages;
    private array $anchorKinds;
    private array $spawnerImages;
    private array $transparentWrappers;

    /** @var string[] Hub-supplied additions to ANCHOR_IMAGES. */
    private array $extraAnchors = [];

    /** @var array<int, array<int, array>> pid => candidate rows, newest seq first */
    private array $byPid = [];

    /** @var array<int, array> rows staged this cycle, keyed by pid */
    private array $pending = [];

    /** @var array<int, array> rows to write at flush */
    private array $toWrite = [];

    /** @var array<int, bool> pids referenced as a parent by this cycle's events */
    private array $referenced = [];

    /** @var array<int, int> seq => newest ts at which that row was used as a parent */
    private array $touched = [];

    private int $seqCursor = 0;
    private int $anchorCursor = 0;
    private int $spoolLookups = 0;

    public function __construct(EdrCorrelatorStore $store, ?EdrEventSpool $spool = null, array $config = [])
    {
        $this->store = $store;
        $this->spool = $spool;

        $extra = $config['anchor_extra'] ?? [];
        if (is_array($extra)) {
            $this->extraAnchors = array_slice(array_map('strval', $extra), 0, 64);
        }

        $profile = ($config['platform'] ?? null) instanceof \App\Services\Platform\EdrPlatformProfile
            ? $config['platform']
            : \App\Services\Platform\EdrPlatformProfile::current();

        $this->anchorImages = $profile->anchorImages();
        $this->anchorKinds = $profile->anchorKinds();
        $this->spawnerImages = $profile->spawnerImages();
        $this->transparentWrappers = $profile->transparentWrappers();
    }

    /**
     * Batch-load every parent this cycle could need, in one query.
     *
     * @param array<int, array> $events
     */
    public function prime(array $events): void
    {
        $pids = [];

        foreach ($events as $event) {
            $ppid = (int) ($event['ppid'] ?? 0);
            $pid = (int) ($event['pid'] ?? 0);

            if ($ppid > 0) {
                $pids[$ppid] = true;
                $this->referenced[$ppid] = true;
            }

            if ($pid > 0) {
                // The pid's own history matters too: a second exec on the same
                // pid is the shell replacing itself, not a new process.
                $pids[$pid] = true;
            }

            // Every pid an aggregated relationship names, so the owner lookup
            // stays inside the one batched query rather than issuing one
            // statement per candidate.
            foreach ((array) ($event['network']['pids'] ?? []) as $candidate) {
                $candidate = (int) $candidate;

                if ($candidate > 0) {
                    $pids[$candidate] = true;
                }
            }
        }

        if ($pids !== []) {
            $this->byPid = $this->store->loadProcs(array_keys($pids));
        }

        $this->seqCursor = max(
            $this->seqCursor,
            (int) ($this->store->getMeta('global_seq') ?? '0'),
            $this->store->maxProcSeq()
        );
        $this->anchorCursor = max($this->anchorCursor, (int) ($this->store->getMeta('anchor_seq') ?? '0'));
        $this->spoolLookups = 0;
    }

    /**
     * Resolve one event's parent, actor and anchor.
     *
     * @return array{parent: ?array, actor_key: string, anchor_kind: string,
     *               anchor_id: int, depth: int, anchored: bool, seq: int,
     *               lineage: string}
     */
    public function resolve(array $event, array $webRoots = []): array
    {
        $seq = ++$this->seqCursor;

        $ts = (int) ($event['ts'] ?? 0);
        $pid = (int) ($event['pid'] ?? 0);
        $ppid = (int) ($event['ppid'] ?? 0);
        $uid = (int) ($event['uid'] ?? -1);
        $host = (string) ($event['host'] ?? '');
        $containerId = (string) ($event['container_id'] ?? '');

        // An aggregated network relationship names every process that took
        // part, not just one. Attributing it through a single representative
        // pid throws away the other candidates — and the representative is
        // often the least useful one, because pids are allocated in ascending
        // order so the lowest is the oldest and therefore the least likely to
        // still have an exec on record. Try them all and take the first that
        // resolves; the process that actually made the connection is the right
        // owner of it, so this looks up the pid itself rather than its parent.
        $owner = $this->resolveNetworkOwner($event, $seq, $ts);

        if ($owner !== null) {
            $this->stage($event, $owner, $webRoots);

            return $owner;
        }

        $parent = $this->findParent($ppid, $seq, $ts, true);

        // Same-pid exec: a shell replacing itself in place. The kernel keeps
        // the pid, so this is the same process continuing, not a new child.
        // Its ppid is unchanged, so the ordinary parent lookup already gives
        // the right answer — but the previous exec on this pid carries the
        // actor we must stay inside, and it is the better answer when the
        // real parent has aged out. No spool recovery on this path: a query
        // for this pid would match the event we are currently scoring.
        if ($parent === null) {
            $parent = $this->findParent($pid, $seq, $ts, false);
        }

        $parentImage = $parent !== null ? (string) $parent['image'] : '';
        $parentBase = $parentImage !== '' ? substr($parentImage, (int) strpos($parentImage, ':') + 1) : '';

        // A parent recovered from the spool was never scored, so it has no
        // actor to hand down. It can still say which image and uid the parent
        // had — which is what the lineage and privilege facets need — but its
        // child has to start a chain of its own.
        $anchored = $parent === null
            || !empty($parent['recovered'])
            || $this->isAnchorImage($parentBase)
            || (int) $parent['depth'] >= self::MAX_DEPTH;

        if (!$anchored) {
            $result = [
                'parent' => $parent,
                'actor_key' => (string) $parent['actor_key'],
                'anchor_kind' => $this->kindFromActorKey((string) $parent['actor_key']),
                'anchor_id' => (int) $parent['anchor_id'],
                'depth' => (int) $parent['depth'] + 1,
                'anchored' => false,
                'seq' => $seq,
                'lineage' => 'linked',
            ];
        } else {
            $kind = $parent === null ? 'orphan' : $this->classifyAnchor($parentBase);
            $anchorId = ++$this->anchorCursor;

            $result = [
                'parent' => $parent,
                'actor_key' => $this->actorKey($host, $uid, $kind, $event, $containerId, $ts),
                'anchor_kind' => $kind,
                'anchor_id' => $anchorId,
                'depth' => 0,
                'anchored' => true,
                'seq' => $seq,
                'lineage' => $parent === null ? 'partial' : 'anchored',
            ];
        }

        $this->stage($event, $result, $webRoots);

        return $result;
    }

    /**
     * Attribute an aggregated network relationship to the process that made it.
     *
     * Returns null for anything that is not a network event, or when none of
     * the named pids is known to us — in which case the ordinary parent path
     * runs and the event may end up orphaned, which is the honest answer.
     *
     * @return array|null the same shape resolve() returns
     */
    private function resolveNetworkOwner(array $event, int $seq, int $ts): ?array
    {
        if (!EdrFacetExtractor::isNetworkAction((string) ($event['action'] ?? ''))) {
            return null;
        }

        foreach ($this->networkPidCandidates($event) as $candidate) {
            // The pid's own row, not its parent's: a connection belongs to the
            // process that opened it.
            $row = $this->findParent($candidate, $seq, $ts, false);

            if ($row === null || (string) ($row['actor_key'] ?? '') === '' || !empty($row['recovered'])) {
                continue;
            }

            return [
                'parent' => $row,
                'actor_key' => (string) $row['actor_key'],
                'anchor_kind' => $this->kindFromActorKey((string) $row['actor_key']),
                'anchor_id' => (int) $row['anchor_id'],
                'depth' => (int) $row['depth'],
                'anchored' => false,
                'seq' => $seq,
                'lineage' => 'linked',
            ];
        }

        return null;
    }

    /**
     * Every pid the relationship names, representative first.
     *
     * @return int[]
     */
    private function networkPidCandidates(array $event): array
    {
        $candidates = [];

        $pid = (int) ($event['pid'] ?? 0);
        if ($pid > 0) {
            $candidates[] = $pid;
        }

        foreach ((array) ($event['network']['pids'] ?? []) as $candidate) {
            $candidate = (int) $candidate;

            if ($candidate > 0) {
                $candidates[] = $candidate;
            }
        }

        return array_values(array_unique($candidates));
    }

    /**
     * Which entry point a parent image represents.
     *
     * This cannot be delegated to the governance layer's host-role detection:
     * that answers "what kind of machine is this" once a day from `ps`, while
     * this answers "what launched this particular chain" per event. The
     * exposure multiplier swings by more than a factor of two between `web`
     * and `desktop`, so the distinction is load-bearing rather than cosmetic.
     */
    public function classifyAnchor(string $parentImage): string
    {
        $base = $this->baseName($parentImage);

        // Exact names win over prefixes, and that ordering is load-bearing.
        // Prefix matching exists so `php-fpm8.4` resolves like `php-fpm`, but
        // it also means `loginwindow` — macOS's desktop session manager — is
        // swallowed by `login` in the ssh list. The kind feeds the exposure
        // multiplier and the actor key, so getting it wrong misprices every
        // chain under it and files desktop activity as a remote session.
        foreach ($this->anchorKinds as $kind => $images) {
            if (in_array($base, $images, true)) {
                return $kind;
            }
        }

        foreach ($this->anchorKinds as $kind => $images) {
            foreach ($images as $image) {
                if (str_starts_with($base, $image)) {
                    return $kind;
                }
            }
        }

        return 'unknown';
    }

    /**
     * Build the durable actor identity.
     *
     * Note what is *not* in the key: the working directory. An earlier
     * iteration included a directory class, which meant `cd /var/tmp` between
     * two steps split one intrusion into two actors — no root required, no
     * patience required. Splitting must cost the attacker a genuinely separate
     * foothold, not a shell builtin.
     */
    private function actorKey(string $host, int $uid, string $kind, array $event, string $containerId, int $ts): string
    {
        return sprintf(
            '%s|%d|%s|%s|%s',
            $host,
            $uid,
            $kind,
            $this->anchorJob($kind, $event, $ts),
            $containerId
        );
    }

    /**
     * Distinguishes one scheduled job from another.
     *
     * `cron` is long-lived, so without this every cron job on the host anchors
     * to the identical key: the backup job's archiving pools with the log
     * shipper's egress and the updater's downloads, three innocent programs
     * add up to three kill-chain classes, and the 3 a.m. cron cluster defeats
     * any half-life you pick. Keying on the normalised anchoring command line
     * separates them *without* a time bucket, so a job whose own steps span
     * hours still correlates with itself.
     */
    private function anchorJob(string $kind, array $event, int $ts): string
    {
        // Schedulers only.
        //
        // 'unknown' was briefly included here to stop depth-limited chains
        // pooling, and it was a bad trade: any anchor image we cannot classify
        // — including ones the Hub adds — would then key on the *child's* own
        // command line, so every distinct command under it minted its own
        // actor and no chain beneath it could ever correlate. Pooling a rare
        // depth-limited chain is a much smaller problem than shattering every
        // chain under an unrecognised parent.
        if ($kind === 'cron' || $kind === 'init') {
            return hash('crc32b', self::normaliseCommandLine((string) ($event['cmdline'] ?? '')));
        }

        if ($kind === 'orphan') {
            // Fork-without-exec is invisible to the sensor, so a double-forked
            // payload arrives with a ppid that never appeared in the stream.
            // Bucketing orphans by time recovers grouping for the common case.
            return 'o' . intdiv($ts, 300);
        }

        return '';
    }

    /**
     * Newest lineage row for a pid that is old enough to be a parent and young
     * enough not to have aged out.
     */
    private function findParent(int $pid, int $seq, int $ts, bool $allowSpool): ?array
    {
        if ($pid <= 0) {
            return null;
        }

        $candidates = [];

        if (isset($this->pending[$pid])) {
            $candidates[] = $this->pending[$pid];
        }

        foreach ($this->byPid[$pid] ?? [] as $row) {
            $candidates[] = $row;
        }

        $best = null;

        foreach ($candidates as $row) {
            $rowSeq = (int) $row['seq'];

            // Strictly older in the event stream — this is the pid-reuse
            // guard, and it is also what stops an event from adopting itself.
            if ($rowSeq >= $seq) {
                continue;
            }

            if ((int) $row['last_seen'] < $ts - self::PROC_TTL) {
                continue;
            }

            // A parent cannot start after its child. Sequence ordering usually
            // implies this, but osquery batches are not strictly ordered and a
            // row that arrived out of order would otherwise be accepted as an
            // ancestor of something that predates it.
            if ((int) $row['ts'] > $ts) {
                continue;
            }

            if ($best === null || $rowSeq > (int) $best['seq']) {
                $best = $row;
            }
        }

        if ($best !== null) {
            // Being used as a parent is proof the process is still alive.
            //
            // Without this, a long-lived daemon's lineage row ages out on the
            // TTL measured from the moment it started — and nginx, php-fpm,
            // sshd and systemd all run for months. A week after boot, every
            // web request would stop resolving its parent, become an orphan,
            // and fall into a five-minute time bucket: the actor key would
            // change every five minutes and the one property this whole design
            // exists for would silently stop working. Refreshing on use is
            // what keeps a live daemon in the table while still letting a
            // genuinely dead process expire.
            $this->markAlive($best, $ts);

            return $best;
        }

        return $allowSpool ? $this->recoverFromSpool($pid, $seq, $ts) : null;
    }

    /**
     * Record that a lineage row was still in use at `ts`.
     *
     * Updates the in-memory copies too, so a second child in the same cycle
     * sees the refreshed row rather than the stale one.
     */
    private function markAlive(array $row, int $ts): void
    {
        $seq = (int) $row['seq'];
        $pid = (int) $row['pid'];

        if ($seq <= 0 || !empty($row['recovered'])) {
            return;
        }

        if ($ts <= (int) $row['last_seen']) {
            return;
        }

        $this->touched[$seq] = max($this->touched[$seq] ?? 0, $ts);

        foreach ($this->byPid[$pid] ?? [] as $index => $candidate) {
            if ((int) $candidate['seq'] === $seq) {
                $this->byPid[$pid][$index]['last_seen'] = $ts;
            }
        }

        if (isset($this->pending[$pid]) && (int) $this->pending[$pid]['seq'] === $seq) {
            $this->pending[$pid]['last_seen'] = $ts;
        }
    }

    /**
     * Last resort: the spool holds every exec, including ones this component
     * chose not to keep a lineage row for.
     *
     * Bounded per cycle. A host whose parents are systematically missing —
     * because the sensor was restarted, or because the BPF probe dropped them
     * under load — must not turn every event into a database query.
     *
     * **How far back this reaches is a function of the host, not a constant,
     * and on a busy machine it is measured in hours.** The spool is a ring
     * buffer, so the horizon is `edr_spool_max_rows / events-per-day`. This
     * host was measured holding **1.4 hours** of process telemetry against a
     * configured retention of seven days: the row ceiling bites more than a
     * hundred times sooner than the day ceiling, and most of the buffer was
     * raw connect events that no rule could evaluate. Treat this as
     * best-effort recovery of a very recent gap and nothing more. An operator
     * who needs a longer horizon raises `edr_spool_max_rows` from the Hub, at
     * roughly 254 bytes a row.
     *
     * The lineage that actually matters does not depend on any of this: it
     * lives in `procs`, which has its own TTL, its own row ceiling and its own
     * liveness refresh precisely so it does not inherit the telemetry buffer's
     * horizon.
     */
    private function recoverFromSpool(int $pid, int $seq, int $ts): ?array
    {
        if ($this->spool === null || $this->spoolLookups >= self::MAX_SPOOL_PARENT_LOOKUPS) {
            return null;
        }

        $this->spoolLookups++;

        $rows = $this->spool->query([
            'pid' => $pid,
            'until' => $ts,
            'action' => 'exec',
            'limit' => 1,
        ]);

        if ($rows === []) {
            return null;
        }

        $row = $rows[0];
        $rowTs = (int) ($row['ts'] ?? 0);

        if ($rowTs > $ts || $rowTs < $ts - self::PROC_TTL) {
            return null;
        }

        // Recovered rows are synthesised with a sequence just below the
        // child's, because the true ordering is unknown but the causal
        // direction is not: the parent existed first.
        $recovered = [
            'seq' => max(0, $seq - 1),
            'pid' => $pid,
            'ts' => $rowTs,
            'uid' => (int) ($row['uid'] ?? -1),
            'image' => EdrFacetExtractor::imageToken((string) ($row['path'] ?? '')),
            'anchor_id' => 0,
            'actor_key' => '',
            'depth' => 0,
            'last_seen' => $rowTs,
            'recovered' => true,
        ];

        // A recovered row has no actor of its own — it was never scored. It
        // can still answer "what image was the parent, and under which uid",
        // which is what the lineage and privilege facets need; but it cannot
        // hand down an actor, so its child anchors.
        $this->byPid[$pid][] = $recovered;

        return $recovered;
    }

    /**
     * Decide whether this event deserves a persisted lineage row.
     */
    private function stage(array $event, array $result, array $webRoots): void
    {
        $pid = (int) ($event['pid'] ?? 0);

        if ($pid <= 0 || ($event['action'] ?? 'exec') !== 'exec') {
            return;
        }

        $image = EdrFacetExtractor::imageToken((string) ($event['path'] ?? ''), $webRoots);
        $base = $this->baseName($image);

        $worthKeeping = $result['anchored']
            || isset($this->referenced[$pid])
            || $this->isSpawnerImage($base);

        if (!$worthKeeping) {
            return;
        }

        $row = [
            'seq' => (int) $result['seq'],
            'pid' => $pid,
            'ts' => (int) ($event['ts'] ?? 0),
            'uid' => (int) ($event['uid'] ?? -1),
            'image' => $image,
            'anchor_id' => (int) $result['anchor_id'],
            'actor_key' => (string) $result['actor_key'],
            'depth' => (int) $result['depth'],
            'last_seen' => (int) ($event['ts'] ?? 0),
        ];

        $this->pending[$pid] = $row;
        $this->toWrite[] = $row;
    }

    /**
     * Persist this cycle's lineage rows and the counters that make them
     * comparable across process restarts.
     *
     * @return int rows written
     */
    public function flush(): int
    {
        if ($this->toWrite !== []) {
            $this->store->insertProcs($this->toWrite);
        }

        // Rows written this cycle already carry the right last_seen.
        foreach ($this->toWrite as $row) {
            unset($this->touched[(int) $row['seq']]);
        }

        if ($this->touched !== []) {
            $this->store->touchProcs($this->touched);
            $this->touched = [];
        }

        $written = count($this->toWrite);

        $this->store->setMeta('global_seq', (string) $this->seqCursor);
        $this->store->setMeta('anchor_seq', (string) $this->anchorCursor);

        $this->toWrite = [];
        $this->pending = [];
        $this->byPid = [];
        $this->referenced = [];

        return $written;
    }

    public function prune(int $now, int $cap = 100000): int
    {
        return $this->store->pruneProcs($now, self::PROC_TTL, $cap);
    }

    public function spoolLookupsUsed(): int
    {
        return $this->spoolLookups;
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                             */
    /* ------------------------------------------------------------------ */

    private function isAnchorImage(string $base): bool
    {
        $base = $this->baseName($base);

        foreach (array_merge($this->anchorImages, $this->extraAnchors) as $image) {
            if ($base === $image || str_starts_with($base, $image)) {
                return true;
            }
        }

        return false;
    }

    private function isSpawnerImage(string $base): bool
    {
        $base = $this->baseName($base);

        foreach ($this->spawnerImages as $image) {
            if ($base === $image || str_starts_with($base, $image)) {
                return true;
            }
        }

        return false;
    }

    /** Accepts either a bare basename or a `dirclass:basename` image token. */
    private function baseName(string $image): string
    {
        $colon = strpos($image, ':');

        return $colon === false ? $image : substr($image, $colon + 1);
    }

    private function kindFromActorKey(string $actorKey): string
    {
        $parts = explode('|', $actorKey);

        return $parts[2] ?? 'unknown';
    }

    /**
     * Reduce a command line to its shape, so two runs of the same job match.
     *
     * Kept local rather than borrowed from the governance layer: this value is
     * baked into persisted actor keys, and an unrelated change to that class's
     * normalisation would silently re-partition every host's history.
     */
    public static function normaliseCommandLine(string $cmdline): string
    {
        $value = preg_replace('/\b\d{4,}\b/', 'N', $cmdline) ?? $cmdline;
        $value = preg_replace('#/tmp/[A-Za-z0-9._-]+#', '/tmp/X', $value) ?? $value;
        $value = preg_replace('/[0-9a-f]{16,}/i', 'H', $value) ?? $value;
        $value = preg_replace('/\s+/', ' ', $value) ?? $value;

        return trim(mb_substr($value, 0, 200));
    }
}

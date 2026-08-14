<?php

namespace App\Services\Correlation;

use Illuminate\Support\Facades\Log;
use PDO;
use PDOException;

/**
 * Persistent state for the behaviour correlator.
 *
 * This class holds SQL and nothing else — no scoring, no policy, no clock
 * except in the prune paths, which take the current time as an argument so the
 * whole algorithm stays testable without sleeping.
 *
 * **Why this must be persisted at all.** The agent is not a daemon. The
 * watchdog runs `ids:sync-edr` in a `while true; sleep 30` loop, so the PHP
 * process exits every thirty seconds. Anything held in memory — a process
 * table, an LRU of learned behaviour, an accumulating score — is gone before
 * the next event arrives. A correlator that keeps its state in RAM would
 * silently degrade to exactly what the existing batch rule already does:
 * correlation inside one cycle and nothing across them. The whole value of
 * this component is that a chain spanning four hours and eight cycles is still
 * one chain, and that requires disk.
 *
 * **Why a fourth SQLite file.** The spool, the governance store and this one
 * are separate databases because SQLite takes a database-wide write lock. The
 * spool is the highest-write component on the box; parking the correlator's
 * per-cycle writes behind that lock would make both slower. Separation also
 * contains corruption: a truncated correlator file must not be able to take
 * the retro-hunt corpus with it.
 */
class EdrCorrelatorStore
{
    /**
     * Bumped when the meaning of a stored column changes. A version the code
     * does not recognise resets to cold rather than scoring against state it
     * cannot interpret — silence is a safe failure, a mis-scored baseline is
     * not.
     */
    public const SCHEMA_VERSION = 1;

    private ?PDO $pdo = null;
    private string $path;

    /** Set when the state has been reset this cycle, for the caller's stats. */
    private ?string $resetReason = null;

    public function __construct(?string $path = null)
    {
        $this->path = $path ?? storage_path('app/edr/novelty.sqlite');
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function close(): void
    {
        $this->pdo = null;
    }

    public function isAvailable(): bool
    {
        try {
            $this->pdo();

            return true;
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] State unavailable: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * @throws PDOException when the state file cannot be opened
     */
    private function pdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            throw new PDOException("Cannot create correlator directory: {$dir}");
        }

        $pdo = new PDO('sqlite:' . $this->path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ]);

        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA busy_timeout = 10000');

        $this->pdo = $pdo;
        $this->migrate();

        // The evidence ring holds command lines. They are redacted before they
        // get here, but this file still describes the host's behaviour in
        // enough detail to plan an intrusion around, so it stays root-only.
        @chmod($this->path, 0600);

        return $this->pdo;
    }

    private function migrate(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS facets (
                fid         TEXT PRIMARY KEY,
                kind        INTEGER NOT NULL,
                first_seen  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                -- Rolling 32-bit mask of the distinct UTC days this value was
                -- seen on. This is the entire poisoning defence: the mask has
                -- room for 32 days and one bit per day, so running something a
                -- million times in an hour sets exactly one bit.
                days_mask   INTEGER NOT NULL DEFAULT 1,
                -- Reporting only. Never enters the familiarity calculation.
                occ         INTEGER NOT NULL DEFAULT 0,
                -- Learned before the model matured; familiarity stays capped.
                bootstrap   INTEGER NOT NULL DEFAULT 0,
                anchor_day  INTEGER NOT NULL DEFAULT 0,
                anchor_set  TEXT
            )
        SQL);
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_facets_evict ON facets (last_seen)');

        // Evicting a facet must not make its value novel again. Without these
        // rows a host that churns through more values than the cap produces
        // periodic alert waves with no attacker anywhere near it.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS facet_tombstones (
                fid        TEXT PRIMARY KEY,
                first_seen INTEGER NOT NULL,
                support    INTEGER NOT NULL,
                evicted_at INTEGER NOT NULL
            )
        SQL);

        // The lineage memory. `seq` is a global monotone counter and is what
        // makes pid reuse safe: a child claiming a recycled pid as its parent
        // is refused because the row it would link to has a *higher* seq than
        // the child's own.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS procs (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                pid        INTEGER NOT NULL,
                ts         INTEGER NOT NULL,
                uid        INTEGER NOT NULL,
                image      TEXT NOT NULL,
                anchor_id  INTEGER NOT NULL,
                actor_key  TEXT NOT NULL,
                depth      INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL
            )
        SQL);
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_procs_pid ON procs (pid, seq DESC)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_procs_seen ON procs (last_seen)');

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS actors (
                actor_key        TEXT PRIMARY KEY,
                anchor_kind      TEXT NOT NULL,
                -- JSON {classId: float}: the decayed accumulation per
                -- kill-chain class. Capped per class when scored, which is
                -- what makes the false-positive bound arithmetic.
                acc              TEXT NOT NULL DEFAULT '{}',
                class_first_ts   TEXT NOT NULL DEFAULT '{}',
                first_ts         INTEGER NOT NULL,
                last_ts          INTEGER NOT NULL,
                nov              REAL NOT NULL DEFAULT 0,
                day_charges      REAL NOT NULL DEFAULT 0,
                day_key          INTEGER NOT NULL DEFAULT 0,
                event_count      INTEGER NOT NULL DEFAULT 0,
                max_charge       REAL NOT NULL DEFAULT 0,
                contributors     TEXT NOT NULL DEFAULT '[]',
                evidence         TEXT NOT NULL DEFAULT '[]',
                last_alert_ts    INTEGER NOT NULL DEFAULT 0,
                last_alert_score REAL NOT NULL DEFAULT 0,
                taught_today     INTEGER NOT NULL DEFAULT 0,
                taught_day       INTEGER NOT NULL DEFAULT 0,
                -- End of a package-manager window. An upgrade crosses many
                -- collection cycles, so the discount has to be persisted or it
                -- would only apply to the cycle that saw `apt` itself.
                pkg_until        INTEGER NOT NULL DEFAULT 0
            )
        SQL);
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_actors_seen ON actors (last_ts)');

        // The charge-once ledger. Repetition is free and worth nothing, so an
        // actor pays for a given event shape once per TTL and never again.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS sigs (
                actor_key TEXT NOT NULL,
                sig       TEXT NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (actor_key, sig)
            ) WITHOUT ROWID
        SQL);
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_sigs_seen ON sigs (last_seen)');

        // Incident recurrence, in this component's own table.
        //
        // The governance store cannot do this job: its baseline suppression is
        // skipped entirely for high and critical findings, and it only records
        // observations during the 7-day learning window — which closes long
        // before this correlator finishes its 14-day warm-up. Relying on it
        // would mean shipping a recurrence defence that is unreachable in
        // every case that matters.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS incident_baseline (
                signature   TEXT PRIMARY KEY,
                occurrences INTEGER NOT NULL DEFAULT 1,
                first_seen  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                sample      TEXT
            )
        SQL);

        $this->pdo->exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)');

        $version = (int) ($this->getMeta('schema_version') ?? 0);

        if ($version === 0) {
            $this->setMeta('schema_version', (string) self::SCHEMA_VERSION);
        } elseif ($version !== self::SCHEMA_VERSION) {
            Log::warning('[EDR correlator] State schema mismatch, resetting to cold', [
                'found' => $version,
                'expected' => self::SCHEMA_VERSION,
            ]);
            $this->wipe();
            $this->setMeta('schema_version', (string) self::SCHEMA_VERSION);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Transactions                                                        */
    /* ------------------------------------------------------------------ */

    public function begin(): void
    {
        $pdo = $this->pdo();

        if (!$pdo->inTransaction()) {
            $pdo->beginTransaction();
        }
    }

    public function commit(): void
    {
        $pdo = $this->pdo();

        if ($pdo->inTransaction()) {
            $pdo->commit();
        }
    }

    public function rollBack(): void
    {
        if ($this->pdo instanceof PDO && $this->pdo->inTransaction()) {
            $this->pdo->rollBack();
        }
    }

    /* ------------------------------------------------------------------ */
    /* Facets                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * Load facet rows by id.
     *
     * Chunked because SQLite has a bound-parameter limit and a cycle can
     * reference a few thousand distinct facet values on a busy host.
     *
     * @param  string[] $fids
     * @return array<string, array>
     */
    public function loadFacets(array $fids): array
    {
        $fids = array_values(array_unique(array_filter($fids)));

        if ($fids === []) {
            return [];
        }

        $out = [];

        try {
            foreach (array_chunk($fids, 500) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '?'));
                $stmt = $this->pdo()->prepare("SELECT * FROM facets WHERE fid IN ({$placeholders})");
                $stmt->execute($chunk);

                foreach ($stmt->fetchAll() as $row) {
                    $out[(string) $row['fid']] = $row;
                }
            }
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Facet load failed: ' . $e->getMessage());

            return [];
        }

        return $out;
    }

    /**
     * @param array<int, array> $rows
     */
    public function upsertFacets(array $rows): void
    {
        if ($rows === []) {
            return;
        }

        $stmt = $this->pdo()->prepare(<<<'SQL'
            INSERT INTO facets (fid, kind, first_seen, last_seen, days_mask, occ, bootstrap, anchor_day, anchor_set)
            VALUES (:fid, :kind, :first_seen, :last_seen, :days_mask, :occ, :bootstrap, :anchor_day, :anchor_set)
            ON CONFLICT(fid) DO UPDATE SET
                last_seen  = excluded.last_seen,
                days_mask  = excluded.days_mask,
                occ        = excluded.occ,
                anchor_day = excluded.anchor_day,
                anchor_set = excluded.anchor_set
        SQL);

        foreach ($rows as $row) {
            $stmt->execute([
                ':fid' => $row['fid'],
                ':kind' => (int) $row['kind'],
                ':first_seen' => (int) $row['first_seen'],
                ':last_seen' => (int) $row['last_seen'],
                ':days_mask' => (int) $row['days_mask'],
                ':occ' => (int) ($row['occ'] ?? 0),
                ':bootstrap' => (int) ($row['bootstrap'] ?? 0),
                ':anchor_day' => (int) ($row['anchor_day'] ?? 0),
                ':anchor_set' => $row['anchor_set'] ?? null,
            ]);
        }
    }

    /**
     * Recover eviction history for facet values that are being re-created.
     *
     * @param  string[] $fids
     * @return array<string, array{first_seen:int, support:int}>
     */
    public function restoreTombstones(array $fids): array
    {
        $fids = array_values(array_unique(array_filter($fids)));

        if ($fids === []) {
            return [];
        }

        $found = [];

        try {
            foreach (array_chunk($fids, 500) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '?'));
                $stmt = $this->pdo()->prepare(
                    "SELECT fid, first_seen, support FROM facet_tombstones WHERE fid IN ({$placeholders})"
                );
                $stmt->execute($chunk);

                foreach ($stmt->fetchAll() as $row) {
                    $found[(string) $row['fid']] = [
                        'first_seen' => (int) $row['first_seen'],
                        'support' => (int) $row['support'],
                    ];
                }

                if ($found !== []) {
                    $del = $this->pdo()->prepare(
                        "DELETE FROM facet_tombstones WHERE fid IN ({$placeholders})"
                    );
                    $del->execute($chunk);
                }
            }
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Tombstone restore failed: ' . $e->getMessage());
        }

        return $found;
    }

    /**
     * Trim the facet table to 90% of its cap, keeping what is both
     * well-supported and recent.
     *
     * Eviction writes tombstones rather than forgetting outright — see the
     * table comment. It fails toward *more* alerting, never less: a value we
     * dropped comes back with its history, not with a clean slate that would
     * make an established behaviour look brand new.
     */
    public function evictFacets(int $cap, int $now): int
    {
        $cap = max(1000, $cap);

        try {
            $pdo = $this->pdo();
            $total = (int) $pdo->query('SELECT COUNT(*) FROM facets')->fetchColumn();

            if ($total <= $cap) {
                return 0;
            }

            $surplus = $total - (int) ($cap * 0.9);

            // Rank by support first, recency second: a value seen on many
            // distinct days is expensive to relearn, a value seen once last
            // month is not.
            $select = $pdo->prepare(<<<'SQL'
                SELECT fid, first_seen, days_mask FROM facets
                ORDER BY (
                    (((days_mask >>  0) & 1) + ((days_mask >>  1) & 1) + ((days_mask >>  2) & 1) + ((days_mask >>  3) & 1) +
                     ((days_mask >>  4) & 1) + ((days_mask >>  5) & 1) + ((days_mask >>  6) & 1) + ((days_mask >>  7) & 1) +
                     ((days_mask >>  8) & 1) + ((days_mask >>  9) & 1) + ((days_mask >> 10) & 1) + ((days_mask >> 11) & 1) +
                     ((days_mask >> 12) & 1) + ((days_mask >> 13) & 1) + ((days_mask >> 14) & 1) + ((days_mask >> 15) & 1) +
                     ((days_mask >> 16) & 1) + ((days_mask >> 17) & 1) + ((days_mask >> 18) & 1) + ((days_mask >> 19) & 1) +
                     ((days_mask >> 20) & 1) + ((days_mask >> 21) & 1) + ((days_mask >> 22) & 1) + ((days_mask >> 23) & 1) +
                     ((days_mask >> 24) & 1) + ((days_mask >> 25) & 1) + ((days_mask >> 26) & 1) + ((days_mask >> 27) & 1) +
                     ((days_mask >> 28) & 1) + ((days_mask >> 29) & 1) + ((days_mask >> 30) & 1) + ((days_mask >> 31) & 1)
                    ) * 1000 + (last_seen / 86400)
                ) ASC
                LIMIT ?
            SQL);
            $select->bindValue(1, $surplus, PDO::PARAM_INT);
            $select->execute();
            $doomed = $select->fetchAll();

            if ($doomed === []) {
                return 0;
            }

            $tomb = $pdo->prepare(
                'INSERT INTO facet_tombstones (fid, first_seen, support, evicted_at) VALUES (?, ?, ?, ?)
                 ON CONFLICT(fid) DO UPDATE SET
                    first_seen = MIN(first_seen, excluded.first_seen),
                    support    = MAX(support, excluded.support),
                    evicted_at = excluded.evicted_at'
            );
            $drop = $pdo->prepare('DELETE FROM facets WHERE fid = ?');

            foreach ($doomed as $row) {
                $tomb->execute([
                    $row['fid'],
                    (int) $row['first_seen'],
                    self::popcount((int) $row['days_mask']),
                    $now,
                ]);
                $drop->execute([$row['fid']]);
            }

            // Tombstones are cheap but not free.
            $tombTotal = (int) $pdo->query('SELECT COUNT(*) FROM facet_tombstones')->fetchColumn();
            if ($tombTotal > 400000) {
                $trim = $pdo->prepare(
                    'DELETE FROM facet_tombstones WHERE fid IN
                     (SELECT fid FROM facet_tombstones ORDER BY evicted_at ASC LIMIT ?)'
                );
                $trim->bindValue(1, $tombTotal - 400000, PDO::PARAM_INT);
                $trim->execute();
            }

            return count($doomed);
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Facet eviction failed: ' . $e->getMessage());

            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Lineage                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Candidate parent rows for each referenced pid, newest sequence first.
     *
     * Deliberately *not* "the newest row per pid". A child observed while its
     * parent's pid has already been recycled by a newer, unrelated exec must
     * link to the row that was current when the child was born, which is the
     * newest row whose sequence is still below the child's own. Collapsing to
     * MAX(seq) in SQL would hand back the recycled process and silently splice
     * two unrelated lineages together — the exact failure the sequence counter
     * exists to prevent.
     *
     * @param  int[] $pids
     * @return array<int, array<int, array>>
     */
    public function loadProcs(array $pids, int $perPid = 8): array
    {
        $pids = array_values(array_unique(array_filter(
            array_map('intval', $pids),
            static fn (int $p): bool => $p > 0
        )));

        if ($pids === []) {
            return [];
        }

        $out = [];

        try {
            foreach (array_chunk($pids, 500) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '?'));
                $stmt = $this->pdo()->prepare(
                    "SELECT * FROM procs WHERE pid IN ({$placeholders}) ORDER BY pid ASC, seq DESC"
                );
                $stmt->execute($chunk);

                foreach ($stmt->fetchAll() as $row) {
                    $pid = (int) $row['pid'];

                    if (count($out[$pid] ?? []) >= $perPid) {
                        continue;
                    }

                    $out[$pid][] = $row;
                }
            }
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Proc load failed: ' . $e->getMessage());

            return [];
        }

        return $out;
    }

    /**
     * Write lineage rows with explicit sequence numbers.
     *
     * The sequence is assigned by the resolver, not by AUTOINCREMENT, so that
     * a row's ordering is the ordering of the *event stream* rather than of
     * the database writes. Tests and the replay command depend on that: the
     * same event stream must produce the same lineage decisions regardless of
     * how it was batched into cycles.
     *
     * @param array<int, array> $rows
     */
    public function insertProcs(array $rows): void
    {
        if ($rows === []) {
            return;
        }

        $stmt = $this->pdo()->prepare(
            'INSERT OR REPLACE INTO procs (seq, pid, ts, uid, image, anchor_id, actor_key, depth, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );

        foreach ($rows as $row) {
            $stmt->execute([
                (int) $row['seq'],
                (int) $row['pid'],
                (int) $row['ts'],
                (int) $row['uid'],
                (string) $row['image'],
                (int) $row['anchor_id'],
                (string) $row['actor_key'],
                (int) $row['depth'],
                (int) ($row['last_seen'] ?? $row['ts']),
            ]);
        }
    }

    /**
     * Refresh the liveness stamp of rows that were used as a parent.
     *
     * `ts` records when a process started; `last_seen` records when it was
     * last known to be alive, and only the second one is safe to expire on.
     * A daemon that has been running since boot must not age out of the
     * lineage table while it is still spawning children.
     *
     * @param array<int, int> $seqToTs
     */
    public function touchProcs(array $seqToTs): void
    {
        if ($seqToTs === []) {
            return;
        }

        $stmt = $this->pdo()->prepare('UPDATE procs SET last_seen = ? WHERE seq = ? AND last_seen < ?');

        foreach ($seqToTs as $seq => $ts) {
            $stmt->execute([(int) $ts, (int) $seq, (int) $ts]);
        }
    }

    /**
     * Highest sequence number ever written, so a restarted process continues
     * the counter instead of colliding with rows already on disk.
     */
    public function maxProcSeq(): int
    {
        try {
            return (int) $this->pdo()->query('SELECT COALESCE(MAX(seq), 0) FROM procs')->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    public function pruneProcs(int $now, int $ttl, int $cap): int
    {
        try {
            $pdo = $this->pdo();

            $stmt = $pdo->prepare('DELETE FROM procs WHERE last_seen < ?');
            $stmt->execute([$now - $ttl]);
            $removed = $stmt->rowCount();

            $total = (int) $pdo->query('SELECT COUNT(*) FROM procs')->fetchColumn();

            if ($total > $cap) {
                // Ordered by last_seen, NOT by seq.
                //
                // Birth order is exactly backwards here: the oldest sequence
                // numbers belong to systemd, php-fpm and sshd — the long-lived
                // daemons whose rows are refreshed on use precisely so they
                // survive. Trimming by seq deleted them first and reintroduced
                // the orphaning bug the liveness refresh exists to prevent,
                // only under row pressure instead of on a timer.
                $trim = $pdo->prepare(
                    'DELETE FROM procs WHERE seq IN (SELECT seq FROM procs ORDER BY last_seen ASC, seq ASC LIMIT ?)'
                );
                $trim->bindValue(1, $total - $cap, PDO::PARAM_INT);
                $trim->execute();
                $removed += $trim->rowCount();
            }

            return $removed;
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Proc prune failed: ' . $e->getMessage());

            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Actors                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * @param  string[] $keys
     * @return array<string, array>
     */
    public function loadActors(array $keys): array
    {
        $keys = array_values(array_unique(array_filter($keys)));

        if ($keys === []) {
            return [];
        }

        $out = [];

        try {
            foreach (array_chunk($keys, 500) as $chunk) {
                $placeholders = implode(',', array_fill(0, count($chunk), '?'));
                $stmt = $this->pdo()->prepare("SELECT * FROM actors WHERE actor_key IN ({$placeholders})");
                $stmt->execute($chunk);

                foreach ($stmt->fetchAll() as $row) {
                    $out[(string) $row['actor_key']] = $row;
                }
            }
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Actor load failed: ' . $e->getMessage());

            return [];
        }

        return $out;
    }

    /**
     * @param array<int, array> $rows
     */
    public function upsertActors(array $rows): void
    {
        if ($rows === []) {
            return;
        }

        $stmt = $this->pdo()->prepare(<<<'SQL'
            INSERT INTO actors
                (actor_key, anchor_kind, acc, class_first_ts, first_ts, last_ts, nov, day_charges,
                 day_key, event_count, max_charge, contributors, evidence, last_alert_ts,
                 last_alert_score, taught_today, taught_day, pkg_until)
            VALUES
                (:actor_key, :anchor_kind, :acc, :class_first_ts, :first_ts, :last_ts, :nov, :day_charges,
                 :day_key, :event_count, :max_charge, :contributors, :evidence, :last_alert_ts,
                 :last_alert_score, :taught_today, :taught_day, :pkg_until)
            ON CONFLICT(actor_key) DO UPDATE SET
                anchor_kind      = excluded.anchor_kind,
                acc              = excluded.acc,
                class_first_ts   = excluded.class_first_ts,
                last_ts          = excluded.last_ts,
                nov              = excluded.nov,
                day_charges      = excluded.day_charges,
                day_key          = excluded.day_key,
                event_count      = excluded.event_count,
                max_charge       = excluded.max_charge,
                contributors     = excluded.contributors,
                evidence         = excluded.evidence,
                last_alert_ts    = excluded.last_alert_ts,
                last_alert_score = excluded.last_alert_score,
                taught_today     = excluded.taught_today,
                taught_day       = excluded.taught_day,
                pkg_until        = excluded.pkg_until
        SQL);

        foreach ($rows as $row) {
            $stmt->execute([
                ':actor_key' => (string) $row['actor_key'],
                ':anchor_kind' => (string) $row['anchor_kind'],
                ':acc' => (string) $row['acc'],
                ':class_first_ts' => (string) $row['class_first_ts'],
                ':first_ts' => (int) $row['first_ts'],
                ':last_ts' => (int) $row['last_ts'],
                ':nov' => (float) $row['nov'],
                ':day_charges' => (float) $row['day_charges'],
                ':day_key' => (int) $row['day_key'],
                ':event_count' => (int) $row['event_count'],
                ':max_charge' => (float) $row['max_charge'],
                ':contributors' => (string) ($row['contributors'] ?? '[]'),
                ':evidence' => (string) ($row['evidence'] ?? '[]'),
                ':last_alert_ts' => (int) $row['last_alert_ts'],
                ':last_alert_score' => (float) $row['last_alert_score'],
                ':taught_today' => (int) $row['taught_today'],
                ':taught_day' => (int) $row['taught_day'],
                ':pkg_until' => (int) ($row['pkg_until'] ?? 0),
            ]);
        }
    }

    /**
     * @param string $hostActorKey never evicted — it is the split-detection lane
     */
    public function pruneActors(int $now, int $cap, string $hostActorKey = '__host__'): int
    {
        try {
            $pdo = $this->pdo();

            $stmt = $pdo->prepare('DELETE FROM actors WHERE last_ts < ? AND actor_key <> ?');
            $stmt->execute([$now - 30 * 86400, $hostActorKey]);
            $removed = $stmt->rowCount();

            $total = (int) $pdo->query('SELECT COUNT(*) FROM actors')->fetchColumn();

            if ($total > $cap) {
                $trim = $pdo->prepare(
                    'DELETE FROM actors WHERE actor_key IN
                     (SELECT actor_key FROM actors WHERE actor_key <> ? ORDER BY last_ts ASC LIMIT ?)'
                );
                $trim->bindValue(1, $hostActorKey, PDO::PARAM_STR);
                $trim->bindValue(2, $total - $cap, PDO::PARAM_INT);
                $trim->execute();
                $removed += $trim->rowCount();
            }

            return $removed;
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Actor prune failed: ' . $e->getMessage());

            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Charge-once ledger                                                  */
    /* ------------------------------------------------------------------ */

    /**
     * @param  array<int, array{0:string, 1:string}> $pairs [actor_key, sig]
     * @return array<string, int> "actor_key\x1fsig" => last_seen
     */
    public function loadSigs(array $pairs): array
    {
        if ($pairs === []) {
            return [];
        }

        $out = [];

        try {
            foreach (array_chunk($pairs, 250) as $chunk) {
                $where = implode(' OR ', array_fill(0, count($chunk), '(actor_key = ? AND sig = ?)'));
                $params = [];

                foreach ($chunk as $pair) {
                    $params[] = $pair[0];
                    $params[] = $pair[1];
                }

                $stmt = $this->pdo()->prepare("SELECT actor_key, sig, last_seen FROM sigs WHERE {$where}");
                $stmt->execute($params);

                foreach ($stmt->fetchAll() as $row) {
                    $out[$row['actor_key'] . "\x1f" . $row['sig']] = (int) $row['last_seen'];
                }
            }
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Signature load failed: ' . $e->getMessage());

            return [];
        }

        return $out;
    }

    /**
     * @param array<int, array{actor_key:string, sig:string, last_seen:int}> $rows
     */
    public function upsertSigs(array $rows): void
    {
        if ($rows === []) {
            return;
        }

        $stmt = $this->pdo()->prepare(
            'INSERT INTO sigs (actor_key, sig, last_seen) VALUES (?, ?, ?)
             ON CONFLICT(actor_key, sig) DO UPDATE SET last_seen = excluded.last_seen'
        );

        foreach ($rows as $row) {
            $stmt->execute([(string) $row['actor_key'], (string) $row['sig'], (int) $row['last_seen']]);
        }
    }

    public function pruneSigs(int $now, int $ttl, int $cap): int
    {
        try {
            $pdo = $this->pdo();

            $stmt = $pdo->prepare('DELETE FROM sigs WHERE last_seen < ?');
            $stmt->execute([$now - $ttl]);
            $removed = $stmt->rowCount();

            $total = (int) $pdo->query('SELECT COUNT(*) FROM sigs')->fetchColumn();

            if ($total > $cap) {
                // `sigs` is WITHOUT ROWID, so it has no `rowid` to select on —
                // a trim written that way throws every time it runs, and
                // because the failure is caught and logged the cap silently
                // stops existing. Delete by the real primary key instead.
                $trim = $pdo->prepare(
                    'DELETE FROM sigs WHERE (actor_key, sig) IN
                     (SELECT actor_key, sig FROM sigs ORDER BY last_seen ASC LIMIT ?)'
                );
                $trim->bindValue(1, $total - $cap, PDO::PARAM_INT);
                $trim->execute();
                $removed += $trim->rowCount();
            }

            return $removed;
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Signature prune failed: ' . $e->getMessage());

            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Incident recurrence                                                 */
    /* ------------------------------------------------------------------ */

    public function observeIncident(string $signature, ?string $sample, int $now): void
    {
        try {
            $stmt = $this->pdo()->prepare(
                'INSERT INTO incident_baseline (signature, occurrences, first_seen, last_seen, sample)
                 VALUES (?, 1, ?, ?, ?)
                 ON CONFLICT(signature) DO UPDATE SET
                    occurrences = occurrences + 1,
                    last_seen   = excluded.last_seen'
            );
            $stmt->execute([$signature, $now, $now, $sample]);
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Incident baseline write failed: ' . $e->getMessage());
        }
    }

    public function incidentOccurrences(string $signature): int
    {
        try {
            $stmt = $this->pdo()->prepare('SELECT occurrences FROM incident_baseline WHERE signature = ?');
            $stmt->execute([$signature]);

            return (int) $stmt->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Meta                                                                */
    /* ------------------------------------------------------------------ */

    public function getMeta(string $key, ?string $default = null): ?string
    {
        try {
            $stmt = $this->pdo()->prepare('SELECT value FROM meta WHERE key = ?');
            $stmt->execute([$key]);
            $value = $stmt->fetchColumn();

            return $value === false ? $default : (string) $value;
        } catch (PDOException $e) {
            return $default;
        }
    }

    public function setMeta(string $key, string $value): void
    {
        try {
            $stmt = $this->pdo()->prepare(
                'INSERT INTO meta (key, value) VALUES (?, ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value'
            );
            $stmt->execute([$key, $value]);
        } catch (PDOException $e) {
            Log::warning('[EDR correlator] Meta write failed: ' . $e->getMessage());
        }
    }

    public function bumpMeta(string $key, int $by = 1): int
    {
        $value = (int) ($this->getMeta($key) ?? '0') + $by;
        $this->setMeta($key, (string) $value);

        return $value;
    }

    /* ------------------------------------------------------------------ */
    /* Failure handling                                                    */
    /* ------------------------------------------------------------------ */

    /**
     * Throw away everything and start the warm-up again.
     *
     * This is the fail-closed path. Corrupt or unreadable state must not put
     * the correlator into a scoring free-for-all where every facet is novel
     * and every actor is over threshold — it puts it back behind the warm-up
     * gate, which means silent. The reset is recorded so the Hub can alarm on
     * it: an attacker deleting this file is itself a signal.
     */
    public function resetToCold(string $reason): bool
    {
        Log::warning('[EDR correlator] Resetting state to cold', ['reason' => $reason]);
        $this->resetReason = $reason;

        try {
            $this->rollBack();
            $this->wipe();
            $this->setMeta('schema_version', (string) self::SCHEMA_VERSION);
            $this->setMeta('state_reset_at', (string) time());
            $this->setMeta('state_reset_reason', $reason);

            return true;
        } catch (PDOException $e) {
            // Even the reset failed — the file itself is the problem. Drop it
            // and let the next cycle recreate the schema from scratch.
            Log::error('[EDR correlator] Reset failed, removing state file: ' . $e->getMessage());
            $this->close();

            foreach (['', '-wal', '-shm'] as $suffix) {
                @unlink($this->path . $suffix);
            }

            return false;
        }
    }

    public function consumeResetReason(): ?string
    {
        $reason = $this->resetReason;
        $this->resetReason = null;

        return $reason;
    }

    private function wipe(): void
    {
        foreach (['facets', 'facet_tombstones', 'procs', 'actors', 'sigs', 'incident_baseline', 'meta'] as $table) {
            $this->pdo->exec("DELETE FROM {$table}");
        }

        // AUTOINCREMENT keeps a high-water mark in sqlite_sequence; without
        // clearing it, `seq` would continue from the old counter and the
        // pid-reuse guard would compare against sequence numbers that no
        // longer have rows behind them.
        $this->pdo->exec("DELETE FROM sqlite_sequence WHERE name = 'procs'");
    }

    /* ------------------------------------------------------------------ */
    /* Status                                                              */
    /* ------------------------------------------------------------------ */

    public function stats(): array
    {
        $stats = [
            'available' => false,
            'path' => $this->path,
            'schema_version' => self::SCHEMA_VERSION,
            'facets' => 0,
            'tombstones' => 0,
            'procs' => 0,
            'actors' => 0,
            'sigs' => 0,
            'incidents_seen' => 0,
            'size_bytes' => 0,
            'state_reset_at' => null,
        ];

        try {
            $pdo = $this->pdo();
            $stats['available'] = true;

            foreach ([
                'facets' => 'facets',
                'tombstones' => 'facet_tombstones',
                'procs' => 'procs',
                'actors' => 'actors',
                'sigs' => 'sigs',
                'incidents_seen' => 'incident_baseline',
            ] as $key => $table) {
                $stats[$key] = (int) $pdo->query("SELECT COUNT(*) FROM {$table}")->fetchColumn();
            }

            $reset = $this->getMeta('state_reset_at');
            $stats['state_reset_at'] = $reset !== null ? (int) $reset : null;
        } catch (PDOException $e) {
            Log::debug('[EDR correlator] Stats failed: ' . $e->getMessage());
        }

        foreach (['', '-wal', '-shm'] as $suffix) {
            $file = $this->path . $suffix;
            if (is_file($file)) {
                $stats['size_bytes'] += (int) filesize($file);
            }
        }

        return $stats;
    }

    /**
     * Number of set bits in a 32-bit day mask.
     */
    public static function popcount(int $mask): int
    {
        $mask &= 0xFFFFFFFF;
        $count = 0;

        while ($mask !== 0) {
            $mask &= $mask - 1;
            $count++;
        }

        return $count;
    }
}

<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use PDO;
use PDOException;

/**
 * EDR Event Spool
 *
 * A local, durable buffer for normalised endpoint events.
 *
 * Without this the collector is stateless: it tails the sensor log, ships rule
 * hits, and forgets everything else. Three consequences we cannot live with —
 * a Hub outage silently drops the window, an agent restart loses whatever was
 * in flight, and there is nothing on disk to hunt through when new intel
 * arrives tomorrow about what happened last week.
 *
 * Deliberately its OWN SQLite file rather than the application database:
 *  - the app DB already carries cache/jobs/signatures and SQLite takes a
 *    database-wide write lock, so a busy spool would stall the agent's other
 *    work;
 *  - retention here is aggressive and destructive (ring buffer), which has no
 *    business running inside the app schema;
 *  - it must keep working when the app DB is misconfigured, because losing
 *    telemetry is worse than losing config.
 *
 * WAL is on so the uploader can read while the collector writes.
 */
class EdrEventSpool
{
    /**
     * Bumped whenever the stored event shape changes. Rows carry the version
     * they were written with, so an agent upgrade can still read — and ship —
     * events captured by the previous release instead of discarding them.
     */
    public const SCHEMA_VERSION = 2;

    /** Retention floor/ceiling, so a bad Hub value cannot disable retention. */
    private const MIN_RETENTION_DAYS = 1;
    private const MAX_RETENTION_DAYS = 90;

    private ?PDO $pdo = null;
    private string $path;
    private EdrSecretRedactor $redactor;

    /**
     * Optional field encryption for the command line. Off by default and
     * documented as such: the key lives in .env on the same host, so this
     * defends against a stolen disk or an exfiltrated backup, not against an
     * attacker with root. Redaction is the control that actually removes the
     * exposure; this exists for deployments that need the compliance
     * checkbox on top.
     */
    private bool $encrypt = false;

    public function __construct(?string $path = null, ?EdrSecretRedactor $redactor = null)
    {
        $this->path = $path ?? storage_path('app/edr/spool.sqlite');
        $this->redactor = $redactor ?? new EdrSecretRedactor();
    }

    public function setEncryption(bool $enabled): void
    {
        $this->encrypt = $enabled;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    /* ------------------------------------------------------------------ */
    /* Connection & schema                                                 */
    /* ------------------------------------------------------------------ */

    /**
     * @throws PDOException when the spool cannot be opened
     */
    private function pdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            throw new PDOException("Cannot create spool directory: {$dir}");
        }

        $pdo = new PDO('sqlite:' . $this->path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ]);

        // WAL lets the uploader read while the collector writes. NORMAL
        // synchronous trades a crash-window of a few events for a large write
        // throughput win — the right trade for telemetry, not for money.
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA synchronous = NORMAL');
        $pdo->exec('PRAGMA busy_timeout = 10000');

        $this->pdo = $pdo;
        $this->migrate();

        // The spool can contain full command lines, which routinely carry
        // passwords and tokens passed as arguments. Keep it root-only.
        @chmod($this->path, 0600);

        return $this->pdo;
    }

    private function migrate(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS events (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                schema_version INTEGER NOT NULL DEFAULT 1,
                ts             INTEGER NOT NULL,
                captured_at    INTEGER NOT NULL,
                action         TEXT    NOT NULL,
                sensor         TEXT,
                host           TEXT,
                pid            INTEGER,
                ppid           INTEGER,
                uid            INTEGER,
                username       TEXT,
                path           TEXT,
                cmdline        TEXT,
                cwd            TEXT,
                container_id   TEXT,
                syscall        TEXT,
                extra          TEXT,
                severity       TEXT,
                rule_hits      TEXT,
                -- 1 = destined for the Hub, 0 = kept locally for retro-hunt only.
                -- Most rows are 0 by design: shipping every exec would be
                -- ~330 MB/day per host, which is why detection runs on the
                -- endpoint in the first place.
                deliver        INTEGER NOT NULL DEFAULT 0,
                sent_at        INTEGER
            )
        SQL);

        // Older spool files predate the deliver column.
        $columns = $this->pdo->query('PRAGMA table_info(events)')->fetchAll();
        $hasDeliver = false;
        foreach ($columns as $column) {
            if (($column['name'] ?? '') === 'deliver') {
                $hasDeliver = true;
                break;
            }
        }
        if (!$hasDeliver) {
            $this->pdo->exec('ALTER TABLE events ADD COLUMN deliver INTEGER NOT NULL DEFAULT 0');
            // Pre-v2 rows only ever carried severity when they alerted.
            $this->pdo->exec('UPDATE events SET deliver = 1 WHERE severity IS NOT NULL');
        }

        // Partial index on the delivery queue. Without the deliver predicate
        // this index would cover every row on the box — the overwhelming
        // majority of which are never destined for the Hub at all.
        $this->pdo->exec(
            'CREATE INDEX IF NOT EXISTS idx_events_pending ON events (id) WHERE deliver = 1 AND sent_at IS NULL'
        );
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_events_pid ON events (pid)');
        // Retro-hunt entry points: "did this binary ever run here", and
        // "show me everything that alerted".
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_events_path ON events (path)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity) WHERE severity IS NOT NULL');
    }

    /**
     * Release the connection.
     *
     * In production the agent restarts between releases, so the upgrade path
     * never has a stale handle. Maintenance work that rewrites the file —
     * and any test that manipulates the schema underneath us — needs this,
     * because SQLite in WAL mode will not alter a table while a connection
     * is open against it.
     */
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
            Log::warning('[EDR spool] Unavailable: ' . $e->getMessage());

            return false;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Writing                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Persist a batch of normalised events.
     *
     * Never throws: a spool failure must degrade the agent to its previous
     * stateless behaviour, not take down the collection cycle.
     *
     * @param  array<int, array> $events      normalised events
     * @param  array<int, array> $findings    rule hits keyed by the event's array index
     * @param  array<int, bool>  $deliverable which of those hits may go to the Hub,
     *                                        keyed the same way. A finding that
     *                                        governance suppressed is still stored —
     *                                        retro-hunt and rule tuning both need to
     *                                        see what was held back — but it is not
     *                                        queued for delivery.
     * @return int number of rows written
     */
    public function store(array $events, array $findings = [], array $deliverable = []): int
    {
        if ($events === []) {
            return 0;
        }

        try {
            $pdo = $this->pdo();
        } catch (PDOException $e) {
            Log::warning('[EDR spool] Store skipped, spool unavailable: ' . $e->getMessage());

            return 0;
        }

        $sql = <<<'SQL'
            INSERT INTO events
                (schema_version, ts, captured_at, action, sensor, host, pid, ppid, uid,
                 username, path, cmdline, cwd, container_id, syscall, extra, severity, rule_hits, deliver)
            VALUES
                (:schema_version, :ts, :captured_at, :action, :sensor, :host, :pid, :ppid, :uid,
                 :username, :path, :cmdline, :cwd, :container_id, :syscall, :extra, :severity, :rule_hits, :deliver)
        SQL;

        $written = 0;
        $now = time();

        try {
            $pdo->beginTransaction();
            $stmt = $pdo->prepare($sql);

            foreach ($events as $index => $event) {
                $hits = $findings[$index] ?? [];

                // Secrets are removed before anything touches disk, so they
                // never reach the spool, the Hub, a support bundle, or a
                // backup. Detection already ran against the raw value.
                $cmdline = $this->redactor->redact($event['cmdline'] ?? null);

                $stmt->execute([
                    ':schema_version' => self::SCHEMA_VERSION,
                    ':ts' => (int) ($event['ts'] ?? $now),
                    ':captured_at' => $now,
                    ':action' => (string) ($event['action'] ?? 'exec'),
                    ':sensor' => $event['sensor'] ?? null,
                    ':host' => $event['host'] ?? null,
                    ':pid' => isset($event['pid']) ? (int) $event['pid'] : null,
                    ':ppid' => isset($event['ppid']) ? (int) $event['ppid'] : null,
                    ':uid' => isset($event['uid']) ? (int) $event['uid'] : null,
                    ':username' => $event['username'] ?? null,
                    ':path' => $event['path'] ?? null,
                    ':cmdline' => $this->encode($cmdline),
                    ':cwd' => $event['cwd'] ?? null,
                    ':container_id' => ($event['container_id'] ?? '') !== '' ? $event['container_id'] : null,
                    ':syscall' => $event['syscall'] ?? null,
                    ':extra' => $this->encodeExtra($event),
                    ':severity' => $hits !== [] ? EdrRuleEngine::worstSeverity($hits) : null,
                    ':rule_hits' => $hits !== [] ? json_encode($hits, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : null,
                    // Only rule hits are queued for the Hub, and only those
                    // governance let through. Everything else stays here so a
                    // retro-hunt has something to hunt through.
                    ':deliver' => ($hits !== [] && ($deliverable[$index] ?? true)) ? 1 : 0,
                ]);

                $written++;
            }

            $pdo->commit();
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            Log::error('[EDR spool] Store failed: ' . $e->getMessage());

            return 0;
        }

        return $written;
    }

    /** Marks a stored value as encrypted, so mixed-mode files stay readable. */
    private const ENCRYPTED_PREFIX = 'enc:v1:';

    private function encode(?string $value): ?string
    {
        if ($value === null || $value === '' || !$this->encrypt) {
            return $value;
        }

        try {
            return self::ENCRYPTED_PREFIX . \Illuminate\Support\Facades\Crypt::encryptString($value);
        } catch (\Throwable $e) {
            // Never lose the event because encryption failed — the value is
            // already redacted, so storing it plain is an acceptable
            // degradation and far better than a gap in the corpus.
            Log::warning('[EDR spool] Encryption failed, storing redacted plaintext: ' . $e->getMessage());

            return $value;
        }
    }

    /**
     * Rows written before encryption was switched on stay plaintext, so this
     * decides per value rather than per file.
     */
    private function decode(?string $value): ?string
    {
        if ($value === null || !str_starts_with($value, self::ENCRYPTED_PREFIX)) {
            return $value;
        }

        try {
            return \Illuminate\Support\Facades\Crypt::decryptString(substr($value, strlen(self::ENCRYPTED_PREFIX)));
        } catch (\Throwable $e) {
            Log::warning('[EDR spool] Decryption failed (key rotated?): ' . $e->getMessage());

            return '[UNDECRYPTABLE]';
        }
    }

    /**
     * @param array<int, array> $rows
     * @return array<int, array>
     */
    private function decodeRows(array $rows): array
    {
        foreach ($rows as &$row) {
            if (array_key_exists('cmdline', $row)) {
                $row['cmdline'] = $this->decode($row['cmdline']);
            }
        }

        return $rows;
    }

    /**
     * Sensor-specific fields that do not deserve a column of their own —
     * socket tuples today, whatever the ETW and ESF sensors add tomorrow.
     */
    private function encodeExtra(array $event): ?string
    {
        $known = [
            'ts', 'action', 'sensor', 'host', 'pid', 'ppid', 'uid', 'gid',
            'username', 'path', 'cmdline', 'cwd', 'container_id', 'syscall', 'exit_code',
        ];

        $extra = array_diff_key($event, array_flip($known));

        if ($extra === []) {
            return null;
        }

        $json = json_encode($extra, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        return $json === false ? null : $json;
    }

    /* ------------------------------------------------------------------ */
    /* Reading                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Oldest-first batch of events queued for the Hub that have not been
     * delivered yet. Rows kept only for local retro-hunt are never returned —
     * they are not a backlog and must not read as one.
     *
     * @return array<int, array>
     */
    public function pending(int $limit = 500): array
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT * FROM events WHERE deliver = 1 AND sent_at IS NULL ORDER BY id ASC LIMIT :limit'
            );
            $stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
            $stmt->execute();

            return $this->decodeRows($stmt->fetchAll());
        } catch (PDOException $e) {
            Log::warning('[EDR spool] Pending query failed: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * Mark rows as delivered. Called only after the Hub has acknowledged.
     */
    public function markSent(array $ids): int
    {
        $ids = array_values(array_filter(array_map('intval', $ids), static fn (int $id): bool => $id > 0));

        if ($ids === []) {
            return 0;
        }

        try {
            $pdo = $this->pdo();
            $placeholders = implode(',', array_fill(0, count($ids), '?'));
            $stmt = $pdo->prepare("UPDATE events SET sent_at = ? WHERE id IN ({$placeholders})");
            $stmt->execute(array_merge([time()], $ids));

            return $stmt->rowCount();
        } catch (PDOException $e) {
            Log::warning('[EDR spool] markSent failed: ' . $e->getMessage());

            return 0;
        }
    }

    /**
     * Retro-hunt query surface. Deliberately narrow and parameterised — this
     * is reachable from Hub-driven commands, so it must not grow into
     * arbitrary SQL.
     *
     * @param array $filters since, until, pid, path_like, cmdline_like, severity, action, limit
     * @return array<int, array>
     */
    public function query(array $filters = []): array
    {
        $where = [];
        $params = [];

        if (!empty($filters['since'])) {
            $where[] = 'ts >= ?';
            $params[] = (int) $filters['since'];
        }

        if (!empty($filters['until'])) {
            $where[] = 'ts <= ?';
            $params[] = (int) $filters['until'];
        }

        if (!empty($filters['pid'])) {
            $where[] = 'pid = ?';
            $params[] = (int) $filters['pid'];
        }

        if (!empty($filters['path_like'])) {
            $where[] = 'path LIKE ?';
            $params[] = '%' . $filters['path_like'] . '%';
        }

        // Encrypted command lines cannot be matched in SQL. Rather than
        // silently returning nothing — which would read as "this binary never
        // ran here" during an investigation — the filter is applied in PHP
        // after decryption, at the cost of scanning more rows.
        $postFilterCmdline = null;

        if (!empty($filters['cmdline_like'])) {
            if ($this->encrypt) {
                $postFilterCmdline = (string) $filters['cmdline_like'];
            } else {
                $where[] = 'cmdline LIKE ?';
                $params[] = '%' . $filters['cmdline_like'] . '%';
            }
        }

        if (!empty($filters['severity'])) {
            $where[] = 'severity = ?';
            $params[] = (string) $filters['severity'];
        }

        if (!empty($filters['action'])) {
            $where[] = 'action = ?';
            $params[] = (string) $filters['action'];
        }

        if (!empty($filters['alerts_only'])) {
            $where[] = 'severity IS NOT NULL';
        }

        $sql = 'SELECT * FROM events';
        if ($where !== []) {
            $sql .= ' WHERE ' . implode(' AND ', $where);
        }
        $limit = max(1, min(10000, (int) ($filters['limit'] ?? 100)));

        $sql .= ' ORDER BY ts DESC, id DESC LIMIT ?';
        // Over-fetch when filtering after decryption, so the caller still
        // gets a full page of matches.
        $params[] = $postFilterCmdline !== null ? min(50000, $limit * 20) : $limit;

        try {
            $stmt = $this->pdo()->prepare($sql);
            $stmt->execute($params);
            $rows = $this->decodeRows($stmt->fetchAll());

            if ($postFilterCmdline !== null) {
                $rows = array_values(array_filter(
                    $rows,
                    static fn (array $row): bool => stripos((string) ($row['cmdline'] ?? ''), $postFilterCmdline) !== false
                ));
                $rows = array_slice($rows, 0, $limit);
            }

            return $rows;
        } catch (PDOException $e) {
            Log::warning('[EDR spool] Query failed: ' . $e->getMessage());

            return [];
        }
    }

    /* ------------------------------------------------------------------ */
    /* Retention                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Ring-buffer retention on two independent ceilings — age and row count.
     *
     * Age alone is not enough: one noisy host can blow past any disk budget
     * inside a single retention window. Rows alone are not enough either,
     * because a quiet host would then hold events for months. Whichever
     * ceiling is hit first wins.
     *
     * Unsent rows are preserved unless the spool is genuinely over the row
     * ceiling — losing telemetry we have not delivered yet is the one outcome
     * worse than using the disk.
     *
     * @return array{deleted_by_age:int, deleted_by_count:int, remaining:int}
     */
    public function prune(int $retentionDays = 7, int $maxRows = 2000000): array
    {
        $retentionDays = max(self::MIN_RETENTION_DAYS, min(self::MAX_RETENTION_DAYS, $retentionDays));
        $maxRows = max(10000, $maxRows);

        $result = ['deleted_by_age' => 0, 'deleted_by_count' => 0, 'remaining' => 0];

        try {
            $pdo = $this->pdo();

            // Age-based pruning spares only rows still queued for the Hub.
            // Locally-retained rows are the bulk and are exactly what the
            // retention window is meant to expire.
            $cutoff = time() - ($retentionDays * 86400);
            $stmt = $pdo->prepare(
                'DELETE FROM events WHERE captured_at < ? AND NOT (deliver = 1 AND sent_at IS NULL)'
            );
            $stmt->execute([$cutoff]);
            $result['deleted_by_age'] = $stmt->rowCount();

            $total = (int) $pdo->query('SELECT COUNT(*) FROM events')->fetchColumn();

            if ($total > $maxRows) {
                // Drop the oldest surplus regardless of send state: at this
                // point the disk ceiling is the binding constraint and the
                // alternative is filling the customer's filesystem.
                $surplus = $total - $maxRows;
                $stmt = $pdo->prepare(
                    'DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id ASC LIMIT ?)'
                );
                $stmt->bindValue(1, $surplus, PDO::PARAM_INT);
                $stmt->execute();
                $result['deleted_by_count'] = $stmt->rowCount();

                Log::warning('[EDR spool] Row ceiling hit, dropped oldest events', [
                    'dropped' => $result['deleted_by_count'],
                    'max_rows' => $maxRows,
                ]);
            }

            $result['remaining'] = (int) $pdo->query('SELECT COUNT(*) FROM events')->fetchColumn();

            // WAL keeps growing until checkpointed; deleting rows alone does
            // not return the space.
            if ($result['deleted_by_age'] + $result['deleted_by_count'] > 0) {
                $pdo->exec('PRAGMA wal_checkpoint(TRUNCATE)');
            }
        } catch (PDOException $e) {
            Log::error('[EDR spool] Prune failed: ' . $e->getMessage());
        }

        return $result;
    }

    /**
     * Reclaim disk after a large prune. VACUUM rewrites the whole file, so it
     * is deliberately separate from prune() and meant for the maintenance
     * cycle, not the collection cycle.
     */
    public function vacuum(): bool
    {
        try {
            $this->pdo()->exec('VACUUM');

            return true;
        } catch (PDOException $e) {
            Log::warning('[EDR spool] Vacuum failed: ' . $e->getMessage());

            return false;
        }
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
            'total' => 0,
            // Queued for the Hub but not yet acknowledged. This is the only
            // number that means "backlog"; local_only is not a backlog.
            'pending' => 0,
            'sent' => 0,
            'local_only' => 0,
            'alerts' => 0,
            'oldest_ts' => null,
            'newest_ts' => null,
            'size_bytes' => 0,
        ];

        try {
            $pdo = $this->pdo();
            $stats['available'] = true;

            $row = $pdo->query(
                'SELECT COUNT(*) AS total,
                        SUM(CASE WHEN deliver = 1 AND sent_at IS NULL THEN 1 ELSE 0 END) AS pending,
                        SUM(CASE WHEN deliver = 1 AND sent_at IS NOT NULL THEN 1 ELSE 0 END) AS sent,
                        SUM(CASE WHEN deliver = 0 THEN 1 ELSE 0 END) AS local_only,
                        SUM(CASE WHEN severity IS NOT NULL THEN 1 ELSE 0 END) AS alerts,
                        MIN(ts) AS oldest_ts,
                        MAX(ts) AS newest_ts
                 FROM events'
            )->fetch();

            $stats['total'] = (int) ($row['total'] ?? 0);
            $stats['pending'] = (int) ($row['pending'] ?? 0);
            $stats['sent'] = (int) ($row['sent'] ?? 0);
            $stats['local_only'] = (int) ($row['local_only'] ?? 0);
            $stats['alerts'] = (int) ($row['alerts'] ?? 0);
            $stats['oldest_ts'] = $row['oldest_ts'] !== null ? (int) $row['oldest_ts'] : null;
            $stats['newest_ts'] = $row['newest_ts'] !== null ? (int) $row['newest_ts'] : null;
        } catch (PDOException $e) {
            Log::debug('[EDR spool] Stats failed: ' . $e->getMessage());
        }

        // Include the WAL, which can be a large share of on-disk footprint.
        foreach (['', '-wal', '-shm'] as $suffix) {
            $file = $this->path . $suffix;
            if (is_file($file)) {
                $stats['size_bytes'] += (int) filesize($file);
            }
        }

        return $stats;
    }
}

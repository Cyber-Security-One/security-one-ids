<?php

namespace App\Services\Response;

use Illuminate\Support\Facades\Log;
use PDO;
use PDOException;

/**
 * Durable record of every response action taken on this endpoint.
 *
 * Response is the most dangerous thing this product does: it kills processes,
 * moves files and cuts network access on machines we do not own. The ledger
 * is what makes that defensible — after an incident, someone will ask who did
 * what, when, why, and whether it was undone. An action that happened without
 * a record here did not happen safely.
 *
 * It also carries three properties the response layer depends on:
 *
 *  - **Idempotency.** The Hub may resend a command it never saw acknowledged.
 *    Actions are keyed by a Hub-assigned id so a redelivery is a no-op rather
 *    than a second kill.
 *  - **Reversal.** Everything needed to undo an action is stored with it, so
 *    a rollback works after an agent restart, without the Hub, and without
 *    the original alert.
 *  - **Deferred reporting.** Actions taken while the Hub was unreachable stay
 *    queued for acknowledgement instead of vanishing.
 *
 * Unlike the telemetry spool this runs with synchronous=FULL. Telemetry can
 * afford to lose the last few events in a crash; a record saying "this host
 * is network-isolated" cannot.
 */
class EdrActionLedger
{
    /* Action lifecycle. */
    public const STATE_PENDING = 'pending';     // recorded, not yet executed
    public const STATE_APPLIED = 'applied';     // executed successfully, in effect
    public const STATE_FAILED = 'failed';       // execution failed, nothing in effect
    public const STATE_REVERTED = 'reverted';   // executed then undone
    public const STATE_EXPIRED = 'expired';     // auto-reverted because it was never confirmed

    private ?PDO $pdo = null;
    private string $path;

    public function __construct(?string $path = null)
    {
        $this->path = $path ?? storage_path('app/edr/actions.sqlite');
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function close(): void
    {
        $this->pdo = null;
    }

    /**
     * @throws PDOException when the ledger cannot be opened
     */
    private function pdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            throw new PDOException("Cannot create ledger directory: {$dir}");
        }

        $pdo = new PDO('sqlite:' . $this->path, null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ]);

        $pdo->exec('PRAGMA journal_mode = WAL');
        // Durability over throughput: the ledger is small and every row
        // matters. A lost "isolated" record leaves a host cut off with
        // nothing knowing why.
        $pdo->exec('PRAGMA synchronous = FULL');
        $pdo->exec('PRAGMA busy_timeout = 10000');

        $this->pdo = $pdo;
        $this->migrate();

        @chmod($this->path, 0600);

        return $this->pdo;
    }

    private function migrate(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS actions (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                action_id     TEXT    NOT NULL UNIQUE,
                type          TEXT    NOT NULL,
                target        TEXT    NOT NULL,
                reason        TEXT,
                requested_by  TEXT,
                state         TEXT    NOT NULL,
                reversible    INTEGER NOT NULL DEFAULT 1,
                expires_at    INTEGER,
                restore_data  TEXT,
                result        TEXT,
                error         TEXT,
                created_at    INTEGER NOT NULL,
                applied_at    INTEGER,
                reverted_at   INTEGER,
                reported_at   INTEGER
            )
        SQL);

        // Added after the ceiling on a confirmation replay was found missing.
        // ALTER rather than a bumped CREATE, because an existing ledger on a
        // live host holds the record of what has been done to it and must not
        // be recreated to gain a column.
        $columns = [];

        foreach ($this->pdo->query('PRAGMA table_info(actions)')->fetchAll(PDO::FETCH_ASSOC) as $column) {
            $columns[(string) ($column['name'] ?? '')] = true;
        }

        if (!isset($columns['last_confirmed_at'])) {
            $this->pdo->exec('ALTER TABLE actions ADD COLUMN last_confirmed_at INTEGER');
        }

        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_actions_state ON actions (state)');
        // The two hot lookups: what needs auto-reverting, and what the Hub
        // has not been told about yet.
        $this->pdo->exec(
            'CREATE INDEX IF NOT EXISTS idx_actions_expiring ON actions (expires_at)
             WHERE state = \'applied\' AND expires_at IS NOT NULL'
        );
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_actions_unreported ON actions (id) WHERE reported_at IS NULL');
    }

    public function isAvailable(): bool
    {
        try {
            $this->pdo();

            return true;
        } catch (PDOException $e) {
            Log::error('[EDR response] Ledger unavailable: ' . $e->getMessage());

            return false;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Recording                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Record an action before it is executed.
     *
     * Recording first is deliberate. If the agent dies between "we killed the
     * process" and "we wrote it down", the ledger must still show that we
     * tried — an untracked side effect on a customer's machine is worse than
     * a spurious pending row.
     *
     * @return bool false when this action_id has already been seen
     */
    public function record(
        string $actionId,
        string $type,
        array $target,
        ?string $reason,
        ?string $requestedBy,
        bool $reversible,
        ?int $expiresAt
    ): bool {
        try {
            $stmt = $this->pdo()->prepare(
                'INSERT INTO actions
                    (action_id, type, target, reason, requested_by, state, reversible, expires_at, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
            );

            $stmt->execute([
                $actionId,
                $type,
                json_encode($target, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
                $reason,
                $requestedBy,
                self::STATE_PENDING,
                $reversible ? 1 : 0,
                $expiresAt,
                time(),
            ]);

            return true;
        } catch (PDOException $e) {
            // A duplicate action_id is the Hub redelivering a command it
            // never saw acknowledged. Not an error — the point of the key.
            if ($this->isUniqueViolation($e)) {
                Log::info('[EDR response] Duplicate action ignored', ['action_id' => $actionId]);

                return false;
            }

            Log::error('[EDR response] Failed to record action: ' . $e->getMessage());

            return false;
        }
    }

    private function isUniqueViolation(PDOException $e): bool
    {
        return str_contains($e->getMessage(), 'UNIQUE constraint failed');
    }

    public function markApplied(string $actionId, array $result, ?array $restoreData = null): void
    {
        $this->update($actionId, [
            'state' => self::STATE_APPLIED,
            'applied_at' => time(),
            'result' => json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'restore_data' => $restoreData !== null
                ? json_encode($restoreData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)
                : null,
            'reported_at' => null,
        ]);
    }

    public function markFailed(string $actionId, string $error): void
    {
        $this->update($actionId, [
            'state' => self::STATE_FAILED,
            'error' => substr($error, 0, 1000),
            'reported_at' => null,
        ]);
    }

    /**
     * @param string $state STATE_REVERTED for a deliberate undo,
     *                      STATE_EXPIRED when the rollback timer fired
     */
    public function markReverted(string $actionId, string $state, array $result = []): void
    {
        $this->update($actionId, [
            'state' => $state,
            'reverted_at' => time(),
            'result' => json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
            'reported_at' => null,
        ]);
    }

    public function markReported(array $actionIds): int
    {
        $actionIds = array_values(array_filter($actionIds, 'is_string'));

        if ($actionIds === []) {
            return 0;
        }

        try {
            $placeholders = implode(',', array_fill(0, count($actionIds), '?'));
            $stmt = $this->pdo()->prepare(
                "UPDATE actions SET reported_at = ? WHERE action_id IN ({$placeholders})"
            );
            $stmt->execute(array_merge([time()], $actionIds));

            return $stmt->rowCount();
        } catch (PDOException $e) {
            Log::warning('[EDR response] markReported failed: ' . $e->getMessage());

            return 0;
        }
    }

    /**
     * Extend the deadline of an applied action — how a Hub confirmation keeps
     * an isolation in place instead of letting it auto-revert.
     */
    /**
     * Push an action's deadline out, recording the authority that did it.
     *
     * `confirmedAt` is the Hub's `issued_at` for the confirmation, stored so a
     * later confirmation carrying the same or an older value can be recognised
     * as a replay rather than treated as fresh intent.
     */
    public function extendExpiry(string $actionId, ?int $expiresAt, ?int $confirmedAt = null): void
    {
        $fields = ['expires_at' => $expiresAt];

        if ($confirmedAt !== null) {
            $fields['last_confirmed_at'] = $confirmedAt;
        }

        $this->update($actionId, $fields);
    }

    private function update(string $actionId, array $fields): void
    {
        if ($fields === []) {
            return;
        }

        try {
            $set = implode(', ', array_map(static fn (string $k): string => "{$k} = ?", array_keys($fields)));
            $stmt = $this->pdo()->prepare("UPDATE actions SET {$set} WHERE action_id = ?");
            $stmt->execute(array_merge(array_values($fields), [$actionId]));
        } catch (PDOException $e) {
            Log::error('[EDR response] Ledger update failed: ' . $e->getMessage());
        }
    }

    /* ------------------------------------------------------------------ */
    /* Reading                                                             */
    /* ------------------------------------------------------------------ */

    public function find(string $actionId): ?array
    {
        try {
            $stmt = $this->pdo()->prepare('SELECT * FROM actions WHERE action_id = ?');
            $stmt->execute([$actionId]);
            $row = $stmt->fetch();

            return $row === false ? null : $this->hydrate($row);
        } catch (PDOException $e) {
            Log::warning('[EDR response] Lookup failed: ' . $e->getMessage());

            return null;
        }
    }

    /**
     * Actions still in effect. Used to reconcile reality on startup and to
     * tell the Hub what this host currently has applied to it.
     *
     * @return array<int, array>
     */
    public function applied(?string $type = null): array
    {
        try {
            $sql = 'SELECT * FROM actions WHERE state = ?';
            $params = [self::STATE_APPLIED];

            if ($type !== null) {
                $sql .= ' AND type = ?';
                $params[] = $type;
            }

            $sql .= ' ORDER BY id ASC';

            $stmt = $this->pdo()->prepare($sql);
            $stmt->execute($params);

            return array_map([$this, 'hydrate'], $stmt->fetchAll());
        } catch (PDOException $e) {
            Log::warning('[EDR response] Applied query failed: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * Actions stuck in `pending`, which is the state that means we do not know.
     *
     * A row is written as pending before the action runs, deliberately: an
     * effect applied without a record is worse than a record without an effect,
     * because only one of them is recoverable. But nothing ever looked at rows
     * that stayed pending, and that left a gap with teeth.
     *
     * If the process dies between the write and `markApplied()` — a window that
     * for isolation contains the actual iptables calls — the outcome was: the
     * rules may be fully or partly in place, so the host may be cut off;
     * `dueForExpiry()` ignores the row because it only selects `applied`, so the
     * safety timer never fires; `stats()` excludes pending from `unreported`, so
     * the Hub sees nothing wrong; and re-issuing the same command is skipped as
     * `already_seen`, so it cannot be retried. Recovery was console-only.
     *
     * The grace period exists so an action that is legitimately mid-flight is
     * not yanked out from under itself by a concurrent cycle. A dispatch takes
     * seconds; anything pending for minutes is not running any more.
     *
     * @return array<int, array>
     */
    public function stuckPending(int $graceSeconds = 300, ?int $now = null): array
    {
        $cutoff = ($now ?? time()) - max(60, $graceSeconds);

        try {
            $stmt = $this->pdo()->prepare(
                'SELECT * FROM actions
                 WHERE state = ? AND created_at <= ?
                 ORDER BY id ASC'
            );
            $stmt->execute([self::STATE_PENDING, $cutoff]);

            return array_map([$this, 'hydrate'], $stmt->fetchAll());
        } catch (PDOException $e) {
            Log::warning('[EDR response] Stuck-pending query failed: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * Applied actions whose deadline has passed and which must be undone.
     *
     * @return array<int, array>
     */
    public function dueForExpiry(?int $now = null): array
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT * FROM actions
                 WHERE state = ? AND expires_at IS NOT NULL AND expires_at <= ?
                 ORDER BY id ASC'
            );
            $stmt->execute([self::STATE_APPLIED, $now ?? time()]);

            return array_map([$this, 'hydrate'], $stmt->fetchAll());
        } catch (PDOException $e) {
            Log::warning('[EDR response] Expiry query failed: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * Outcomes the Hub has not been told about yet — the offline queue.
     *
     * @return array<int, array>
     */
    public function unreported(int $limit = 100): array
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT * FROM actions
                 WHERE reported_at IS NULL AND state != ?
                 ORDER BY id ASC LIMIT :limit'
            );
            $stmt->bindValue(1, self::STATE_PENDING);
            $stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
            $stmt->execute();

            return array_map([$this, 'hydrate'], $stmt->fetchAll());
        } catch (PDOException $e) {
            Log::warning('[EDR response] Unreported query failed: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * Actions recorded but never resolved — the shape a crash mid-execution
     * leaves behind. They need a human or a reconciliation pass, not a
     * silent retry, because we do not know whether the side effect landed.
     *
     * @return array<int, array>
     */
    public function stalePending(int $olderThanSeconds = 300): array
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT * FROM actions WHERE state = ? AND created_at < ? ORDER BY id ASC'
            );
            $stmt->execute([self::STATE_PENDING, time() - $olderThanSeconds]);

            return array_map([$this, 'hydrate'], $stmt->fetchAll());
        } catch (PDOException $e) {
            Log::warning('[EDR response] Stale query failed: ' . $e->getMessage());

            return [];
        }
    }

    /**
     * @return array<int, array>
     */
    public function recent(int $limit = 50): array
    {
        try {
            $stmt = $this->pdo()->prepare('SELECT * FROM actions ORDER BY id DESC LIMIT :limit');
            $stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
            $stmt->execute();

            return array_map([$this, 'hydrate'], $stmt->fetchAll());
        } catch (PDOException $e) {
            return [];
        }
    }

    private function hydrate(array $row): array
    {
        foreach (['target', 'restore_data', 'result'] as $field) {
            if (isset($row[$field]) && is_string($row[$field])) {
                $decoded = json_decode($row[$field], true);
                $row[$field] = is_array($decoded) ? $decoded : null;
            }
        }

        $row['reversible'] = (bool) ($row['reversible'] ?? false);

        return $row;
    }

    public function stats(): array
    {
        $stats = [
            'available' => false,
            'path' => $this->path,
            'total' => 0,
            'applied' => 0,
            'reverted' => 0,
            'failed' => 0,
            'pending' => 0,
            'unreported' => 0,
        ];

        try {
            $row = $this->pdo()->query(
                "SELECT COUNT(*) AS total,
                        SUM(CASE WHEN state = 'applied'  THEN 1 ELSE 0 END) AS applied,
                        SUM(CASE WHEN state IN ('reverted','expired') THEN 1 ELSE 0 END) AS reverted,
                        SUM(CASE WHEN state = 'failed'   THEN 1 ELSE 0 END) AS failed,
                        SUM(CASE WHEN state = 'pending'  THEN 1 ELSE 0 END) AS pending,
                        SUM(CASE WHEN reported_at IS NULL AND state != 'pending' THEN 1 ELSE 0 END) AS unreported
                 FROM actions"
            )->fetch();

            $stats['available'] = true;
            foreach (['total', 'applied', 'reverted', 'failed', 'pending', 'unreported'] as $key) {
                $stats[$key] = (int) ($row[$key] ?? 0);
            }
        } catch (PDOException $e) {
            Log::debug('[EDR response] Ledger stats failed: ' . $e->getMessage());
        }

        return $stats;
    }
}

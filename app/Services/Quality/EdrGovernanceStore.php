<?php

namespace App\Services\Quality;

use Illuminate\Support\Facades\Log;
use PDO;
use PDOException;

/**
 * Per-rule quality state for this endpoint.
 *
 * Detection content is not static and is not equally trustworthy. A rule that
 * has never fired here has no track record; a rule that fires forty times a
 * day on this particular host is describing that host's normal behaviour, not
 * an intrusion. This store is where that history lives, so decisions about
 * whether a rule may alert — or may trigger a response — are grounded in what
 * actually happened rather than in the rule author's optimism.
 *
 * It holds three things:
 *
 *  - **Rule stage.** observe -> alert -> enforce. A rule only reaches the
 *    stage where it can kill a process by being promoted there deliberately.
 *  - **Counters.** Hits, alerts emitted, suppressions, and analyst verdicts,
 *    which together give a false-positive rate per rule per host.
 *  - **Baseline.** What this host was doing during its learning window, which
 *    is what turns "curl ran from /tmp" into "curl runs from /tmp here forty
 *    times a day and always has".
 */
class EdrGovernanceStore
{
    /** Matches are counted but never alert. Where unproven rules start. */
    public const STAGE_OBSERVE = 'observe';

    /** Matches alert, but may not drive a response action. */
    public const STAGE_ALERT = 'alert';

    /** Matches alert and are allowed to trigger response. Earned, not default. */
    public const STAGE_ENFORCE = 'enforce';

    /** Rule was retired because it produced too much noise here. */
    public const STAGE_DISABLED = 'disabled';

    private ?PDO $pdo = null;
    private string $path;

    public function __construct(?string $path = null)
    {
        $this->path = $path ?? storage_path('app/edr/governance.sqlite');
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function close(): void
    {
        $this->pdo = null;
    }

    private function pdo(): PDO
    {
        if ($this->pdo instanceof PDO) {
            return $this->pdo;
        }

        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
            throw new PDOException("Cannot create governance directory: {$dir}");
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

        @chmod($this->path, 0600);

        return $this->pdo;
    }

    private function migrate(): void
    {
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS rule_state (
                rule            TEXT PRIMARY KEY,
                stage           TEXT NOT NULL,
                hits            INTEGER NOT NULL DEFAULT 0,
                alerts          INTEGER NOT NULL DEFAULT 0,
                suppressed      INTEGER NOT NULL DEFAULT 0,
                true_positives  INTEGER NOT NULL DEFAULT 0,
                false_positives INTEGER NOT NULL DEFAULT 0,
                first_seen      INTEGER,
                last_seen       INTEGER,
                promoted_at     INTEGER,
                note            TEXT
            )
        SQL);

        // The baseline: distinct (rule, signature) pairs seen while learning.
        // Signature is a coarse description of the match — the same shape
        // recurring is what makes something normal rather than notable.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS baseline_observations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule        TEXT NOT NULL,
                signature   TEXT NOT NULL,
                sample      TEXT,
                occurrences INTEGER NOT NULL DEFAULT 1,
                first_seen  INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                UNIQUE (rule, signature)
            )
        SQL);

        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_baseline_rule ON baseline_observations (rule)');
        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_baseline_freq ON baseline_observations (occurrences DESC)');

        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT
            )
        SQL);

        // Known-good digests for monitored files. "This file changed" is a
        // weak statement — package updates change /etc/ssh/sshd_config all
        // the time. "This file no longer matches what it has been since we
        // started watching, and here is the previous digest" is something an
        // analyst can act on.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS file_baseline (
                path        TEXT PRIMARY KEY,
                sha256      TEXT NOT NULL,
                size        INTEGER,
                established INTEGER NOT NULL,
                last_seen   INTEGER NOT NULL,
                changes     INTEGER NOT NULL DEFAULT 0
            )
        SQL);
    }

    /* ------------------------------------------------------------------ */
    /* File baseline                                                       */
    /* ------------------------------------------------------------------ */

    /**
     * Compare a file's digest against what we have seen before.
     *
     * @return array{known:bool, changed:bool, previous:?string, established:?int, changes:int}
     */
    public function checkFileDigest(string $path, string $sha256, ?int $size = null): array
    {
        $unknown = ['known' => false, 'changed' => false, 'previous' => null, 'established' => null, 'changes' => 0];

        if ($path === '' || $sha256 === '') {
            return $unknown;
        }

        try {
            $stmt = $this->pdo()->prepare('SELECT * FROM file_baseline WHERE path = ?');
            $stmt->execute([$path]);
            $row = $stmt->fetch();

            if ($row === false) {
                return $unknown;
            }

            return [
                'known' => true,
                'changed' => (string) $row['sha256'] !== $sha256,
                'previous' => (string) $row['sha256'],
                'established' => (int) $row['established'],
                'changes' => (int) $row['changes'],
            ];
        } catch (PDOException $e) {
            return $unknown;
        }
    }

    /**
     * Record the current digest as the reference for this path.
     */
    public function recordFileDigest(string $path, string $sha256, ?int $size = null, bool $countChange = false): void
    {
        if ($path === '' || $sha256 === '') {
            return;
        }

        try {
            $now = time();
            $stmt = $this->pdo()->prepare(
                'INSERT INTO file_baseline (path, sha256, size, established, last_seen, changes)
                 VALUES (?, ?, ?, ?, ?, 0)
                 ON CONFLICT(path) DO UPDATE SET
                    sha256 = excluded.sha256,
                    size = excluded.size,
                    last_seen = excluded.last_seen,
                    changes = file_baseline.changes + ?'
            );
            $stmt->execute([$path, $sha256, $size, $now, $now, $countChange ? 1 : 0]);
        } catch (PDOException $e) {
            Log::debug('[EDR quality] recordFileDigest failed: ' . $e->getMessage());
        }
    }

    public function fileBaselineCount(): int
    {
        try {
            return (int) $this->pdo()->query('SELECT COUNT(*) FROM file_baseline')->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    public function isAvailable(): bool
    {
        try {
            $this->pdo();

            return true;
        } catch (PDOException $e) {
            Log::warning('[EDR quality] Governance store unavailable: ' . $e->getMessage());

            return false;
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
            Log::warning('[EDR quality] setMeta failed: ' . $e->getMessage());
        }
    }

    /* ------------------------------------------------------------------ */
    /* Rule state                                                          */
    /* ------------------------------------------------------------------ */

    public function getStage(string $rule, string $default = self::STAGE_ALERT): string
    {
        try {
            $stmt = $this->pdo()->prepare('SELECT stage FROM rule_state WHERE rule = ?');
            $stmt->execute([$rule]);
            $stage = $stmt->fetchColumn();

            return $stage === false ? $default : (string) $stage;
        } catch (PDOException $e) {
            return $default;
        }
    }

    public function setStage(string $rule, string $stage, ?string $note = null): void
    {
        try {
            $stmt = $this->pdo()->prepare(
                'INSERT INTO rule_state (rule, stage, promoted_at, note) VALUES (?, ?, ?, ?)
                 ON CONFLICT(rule) DO UPDATE SET
                    stage = excluded.stage,
                    promoted_at = excluded.promoted_at,
                    note = COALESCE(excluded.note, rule_state.note)'
            );
            $stmt->execute([$rule, $stage, time(), $note]);
        } catch (PDOException $e) {
            Log::warning('[EDR quality] setStage failed: ' . $e->getMessage());
        }
    }

    /**
     * Record that a rule matched, and whether that match reached anyone.
     */
    public function recordHit(string $rule, bool $emitted): void
    {
        try {
            $now = time();
            $stmt = $this->pdo()->prepare(
                'INSERT INTO rule_state (rule, stage, hits, alerts, suppressed, first_seen, last_seen)
                 VALUES (?, ?, 1, ?, ?, ?, ?)
                 ON CONFLICT(rule) DO UPDATE SET
                    hits = rule_state.hits + 1,
                    alerts = rule_state.alerts + ?,
                    suppressed = rule_state.suppressed + ?,
                    last_seen = ?'
            );

            $alert = $emitted ? 1 : 0;
            $suppressed = $emitted ? 0 : 1;

            $stmt->execute([
                $rule, self::STAGE_ALERT, $alert, $suppressed, $now, $now,
                $alert, $suppressed, $now,
            ]);
        } catch (PDOException $e) {
            Log::debug('[EDR quality] recordHit failed: ' . $e->getMessage());
        }
    }

    /**
     * An analyst's verdict on a rule's output. This is the only input that
     * turns a hit count into a false-positive rate — everything else is
     * guesswork about whether the rule was right.
     */
    public function recordVerdict(string $rule, bool $falsePositive, int $count = 1): void
    {
        $column = $falsePositive ? 'false_positives' : 'true_positives';

        try {
            $stmt = $this->pdo()->prepare(
                "INSERT INTO rule_state (rule, stage, {$column}) VALUES (?, ?, ?)
                 ON CONFLICT(rule) DO UPDATE SET {$column} = rule_state.{$column} + ?"
            );
            $stmt->execute([$rule, self::STAGE_ALERT, max(1, $count), max(1, $count)]);
        } catch (PDOException $e) {
            Log::warning('[EDR quality] recordVerdict failed: ' . $e->getMessage());
        }
    }

    /**
     * @return array<int, array>
     */
    public function allRuleState(): array
    {
        try {
            $rows = $this->pdo()->query('SELECT * FROM rule_state ORDER BY hits DESC')->fetchAll();

            return array_map(static function (array $row): array {
                $judged = (int) $row['true_positives'] + (int) $row['false_positives'];

                // Only judged output can produce a rate. A rule with a
                // thousand hits and no verdicts has an unknown FP rate, not a
                // zero one, and reporting zero would be the more dangerous lie.
                $row['fp_rate'] = $judged > 0 ? round((int) $row['false_positives'] / $judged, 4) : null;
                $row['judged'] = $judged;

                return $row;
            }, $rows);
        } catch (PDOException $e) {
            return [];
        }
    }

    public function findRuleState(string $rule): ?array
    {
        foreach ($this->allRuleState() as $row) {
            if ($row['rule'] === $rule) {
                return $row;
            }
        }

        return null;
    }

    /* ------------------------------------------------------------------ */
    /* Baseline                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Record a match seen during learning. The signature is what makes a
     * recurrence recognisable later.
     */
    public function observe(string $rule, string $signature, ?string $sample = null): void
    {
        try {
            $now = time();
            $stmt = $this->pdo()->prepare(
                'INSERT INTO baseline_observations (rule, signature, sample, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(rule, signature) DO UPDATE SET
                    occurrences = baseline_observations.occurrences + 1,
                    last_seen = ?'
            );
            $stmt->execute([$rule, $signature, $sample, $now, $now, $now]);
        } catch (PDOException $e) {
            Log::debug('[EDR quality] observe failed: ' . $e->getMessage());
        }
    }

    public function hasObservation(string $rule, string $signature, int $minOccurrences = 1): bool
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT occurrences FROM baseline_observations WHERE rule = ? AND signature = ?'
            );
            $stmt->execute([$rule, $signature]);
            $occurrences = $stmt->fetchColumn();

            return $occurrences !== false && (int) $occurrences >= $minOccurrences;
        } catch (PDOException $e) {
            return false;
        }
    }

    /**
     * The recurring shapes, most frequent first — the raw material for
     * exclusion suggestions.
     *
     * @return array<int, array>
     */
    public function frequentObservations(int $minOccurrences = 5, int $limit = 50): array
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT * FROM baseline_observations
                 WHERE occurrences >= :min
                 ORDER BY occurrences DESC LIMIT :limit'
            );
            $stmt->bindValue(':min', max(1, $minOccurrences), PDO::PARAM_INT);
            $stmt->bindValue(':limit', max(1, $limit), PDO::PARAM_INT);
            $stmt->execute();

            return $stmt->fetchAll();
        } catch (PDOException $e) {
            return [];
        }
    }

    public function observationCount(): int
    {
        try {
            return (int) $this->pdo()->query('SELECT COUNT(*) FROM baseline_observations')->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    public function stats(): array
    {
        $rules = $this->allRuleState();

        $byStage = [];
        foreach ($rules as $rule) {
            $stage = (string) $rule['stage'];
            $byStage[$stage] = ($byStage[$stage] ?? 0) + 1;
        }

        return [
            'available' => $this->isAvailable(),
            'path' => $this->path,
            'rules_tracked' => count($rules),
            'by_stage' => $byStage,
            'baseline_observations' => $this->observationCount(),
            'total_hits' => array_sum(array_column($rules, 'hits')),
            'total_alerts' => array_sum(array_column($rules, 'alerts')),
            'total_suppressed' => array_sum(array_column($rules, 'suppressed')),
        ];
    }
}

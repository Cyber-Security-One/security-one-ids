<?php

namespace App\Services\Network;

use Illuminate\Support\Facades\Log;
use PDO;
use PDOException;

/**
 * What this host's network behaviour normally looks like.
 *
 * Network rules need a baseline more badly than any other kind. Measured on a
 * real host: php-fpm opens 199 connections a day to 8.8.8.8:53 and nginx
 * connects to its origin servers thousands of times, all of it on a regular
 * cadence. A beacon rule with no notion of "this destination is established
 * here" fires on every one of them, which is how periodicity detection gets
 * switched off within a day of being enabled.
 *
 * Its own store rather than the event spool, for a measured reason: socket
 * events run at 4.1 million a day on that host, against 630,000 process
 * events. Sharing the spool's ring buffer would evict the baseline in about
 * three hours — the same class of silent failure that broke the identity
 * baselines, and it is cheaper to not repeat it than to detect it again.
 */
class NetworkBaselineStore
{
    /** Distinct days a destination must appear on before it counts as established. */
    private const ESTABLISHED_DAYS = 3;

    private ?PDO $pdo = null;
    private string $path;

    public function __construct(?string $path = null)
    {
        $this->path = $path ?? storage_path('app/edr/network.sqlite');
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
            throw new PDOException("Cannot create network baseline directory: {$dir}");
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
        // Destinations, counted by distinct calendar day rather than by hit.
        // A thousand connections in one afternoon is one deploy; the same
        // destination on five separate days is infrastructure.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS destinations (
                process_path   TEXT NOT NULL,
                remote_address TEXT NOT NULL,
                service_port   INTEGER,
                days_seen      INTEGER NOT NULL DEFAULT 0,
                last_day       TEXT,
                total_count    INTEGER NOT NULL DEFAULT 0,
                first_seen     INTEGER NOT NULL,
                last_seen      INTEGER NOT NULL,
                PRIMARY KEY (process_path, remote_address, service_port)
            )
        SQL);

        // Listening sockets. A process that starts listening on a port it has
        // never listened on is the shape of a backdoor, and that is only
        // meaningful against a record of what it used to listen on.
        $this->pdo->exec(<<<'SQL'
            CREATE TABLE IF NOT EXISTS listeners (
                process_path TEXT NOT NULL,
                local_port   INTEGER NOT NULL,
                days_seen    INTEGER NOT NULL DEFAULT 0,
                last_day     TEXT,
                first_seen   INTEGER NOT NULL,
                last_seen    INTEGER NOT NULL,
                PRIMARY KEY (process_path, local_port)
            )
        SQL);

        $this->pdo->exec('CREATE INDEX IF NOT EXISTS idx_dest_addr ON destinations (remote_address)');
    }

    public function isAvailable(): bool
    {
        try {
            $this->pdo();

            return true;
        } catch (PDOException $e) {
            Log::warning('[EDR network] Baseline store unavailable: ' . $e->getMessage());

            return false;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Destinations                                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Record that a process talked to a destination.
     *
     * `days_seen` only advances when the calendar day changes, which is what
     * stops a single busy afternoon from looking like established
     * infrastructure.
     */
    public function recordDestination(string $processPath, string $address, ?int $port, int $count, int $ts): void
    {
        if ($processPath === '' || $address === '') {
            return;
        }

        $day = date('Y-m-d', $ts);

        try {
            $stmt = $this->pdo()->prepare(
                'INSERT INTO destinations
                    (process_path, remote_address, service_port, days_seen, last_day, total_count, first_seen, last_seen)
                 VALUES (?, ?, ?, 1, ?, ?, ?, ?)
                 ON CONFLICT(process_path, remote_address, service_port) DO UPDATE SET
                    days_seen = destinations.days_seen + CASE WHEN destinations.last_day = excluded.last_day THEN 0 ELSE 1 END,
                    last_day = excluded.last_day,
                    total_count = destinations.total_count + excluded.total_count,
                    last_seen = excluded.last_seen'
            );
            $stmt->execute([$processPath, $address, $port, $day, max(1, $count), $ts, $ts]);
        } catch (PDOException $e) {
            Log::debug('[EDR network] recordDestination failed: ' . $e->getMessage());
        }
    }

    /**
     * @return array{known:bool, days:int, total:int}
     */
    public function destinationHistory(string $processPath, string $address, ?int $port): array
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT days_seen, total_count FROM destinations
                 WHERE process_path = ? AND remote_address = ? AND service_port IS ?'
            );
            $stmt->execute([$processPath, $address, $port]);
            $row = $stmt->fetch();

            if ($row === false) {
                return ['known' => false, 'days' => 0, 'total' => 0];
            }

            return [
                'known' => true,
                'days' => (int) $row['days_seen'],
                'total' => (int) $row['total_count'],
            ];
        } catch (PDOException $e) {
            return ['known' => false, 'days' => 0, 'total' => 0];
        }
    }

    /**
     * Whether this destination is settled infrastructure for this process.
     */
    public function isEstablishedDestination(string $processPath, string $address, ?int $port): bool
    {
        return $this->destinationHistory($processPath, $address, $port)['days'] >= self::ESTABLISHED_DAYS;
    }

    /**
     * How many distinct calendar days of network history this process has at
     * all — the "do we have any basis" question, which has to be answered
     * before "is this destination new" means anything.
     */
    public function historyDaysFor(string $processPath): int
    {
        try {
            $stmt = $this->pdo()->prepare('SELECT MAX(days_seen) FROM destinations WHERE process_path = ?');
            $stmt->execute([$processPath]);
            $days = $stmt->fetchColumn();

            return $days === false || $days === null ? 0 : (int) $days;
        } catch (PDOException $e) {
            return 0;
        }
    }

    /* ------------------------------------------------------------------ */
    /* Listeners                                                           */
    /* ------------------------------------------------------------------ */

    public function recordListener(string $processPath, int $port, int $ts): void
    {
        if ($processPath === '' || $port <= 0) {
            return;
        }

        $day = date('Y-m-d', $ts);

        try {
            $stmt = $this->pdo()->prepare(
                'INSERT INTO listeners (process_path, local_port, days_seen, last_day, first_seen, last_seen)
                 VALUES (?, ?, 1, ?, ?, ?)
                 ON CONFLICT(process_path, local_port) DO UPDATE SET
                    days_seen = listeners.days_seen + CASE WHEN listeners.last_day = excluded.last_day THEN 0 ELSE 1 END,
                    last_day = excluded.last_day,
                    last_seen = excluded.last_seen'
            );
            $stmt->execute([$processPath, $port, $day, $ts, $ts]);
        } catch (PDOException $e) {
            Log::debug('[EDR network] recordListener failed: ' . $e->getMessage());
        }
    }

    public function isKnownListener(string $processPath, int $port): bool
    {
        try {
            $stmt = $this->pdo()->prepare(
                'SELECT 1 FROM listeners WHERE process_path = ? AND local_port = ?'
            );
            $stmt->execute([$processPath, $port]);

            return $stmt->fetchColumn() !== false;
        } catch (PDOException $e) {
            // Failing closed here would alert on every listener on the box.
            return true;
        }
    }

    public function listenerCount(): int
    {
        try {
            return (int) $this->pdo()->query('SELECT COUNT(*) FROM listeners')->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    public function destinationCount(): int
    {
        try {
            return (int) $this->pdo()->query('SELECT COUNT(*) FROM destinations')->fetchColumn();
        } catch (PDOException $e) {
            return 0;
        }
    }

    /**
     * Drop destinations nothing has touched for a while, so a decommissioned
     * service does not keep vouching for an address forever.
     */
    public function prune(int $retentionDays = 90): int
    {
        $cutoff = time() - (max(7, $retentionDays) * 86400);

        try {
            $pdo = $this->pdo();

            $stmt = $pdo->prepare('DELETE FROM destinations WHERE last_seen < ?');
            $stmt->execute([$cutoff]);
            $removed = $stmt->rowCount();

            $stmt = $pdo->prepare('DELETE FROM listeners WHERE last_seen < ?');
            $stmt->execute([$cutoff]);

            return $removed + $stmt->rowCount();
        } catch (PDOException $e) {
            Log::warning('[EDR network] Baseline prune failed: ' . $e->getMessage());

            return 0;
        }
    }

    public function stats(): array
    {
        return [
            'available' => $this->isAvailable(),
            'path' => $this->path,
            'destinations' => $this->destinationCount(),
            'listeners' => $this->listenerCount(),
            'established_after_days' => self::ESTABLISHED_DAYS,
        ];
    }
}

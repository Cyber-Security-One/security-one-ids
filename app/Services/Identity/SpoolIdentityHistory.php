<?php

namespace App\Services\Identity;

use App\Services\EdrEventSpool;

/**
 * Identity history backed by the event spool.
 *
 * The spool already holds every authentication event this agent has seen and
 * survives restarts, so the window rules get their history for free rather
 * than needing a second store that could disagree with the first.
 *
 * Results are memoised per instance. A single collection cycle asks the same
 * question repeatedly — every failure from one address re-runs the same
 * window query — and a cycle is short enough that the answer cannot
 * meaningfully change inside it.
 */
class SpoolIdentityHistory implements IdentityHistory
{
    private EdrEventSpool $spool;

    /**
     * Events from the cycle being evaluated, which are not in the spool yet.
     *
     * They have to be counted. A burst of forty failures usually arrives in
     * one batch, and history that only knew what had already been committed
     * would see the fortieth attempt as the first — the thresholds would
     * never be reached and the rules would never fire.
     *
     * @var array<int, array>
     */
    private array $batch;

    /** @var array<string, array> */
    private array $cache = [];

    /**
     * @param array<int, array> $batch the events being evaluated this cycle
     */
    public function __construct(EdrEventSpool $spool, array $batch = [])
    {
        $this->spool = $spool;
        $this->batch = $batch;
    }

    public function failuresFrom(string $sourceIp, int $since, int $until): array
    {
        return $this->remember("fail:{$sourceIp}:{$since}", function () use ($sourceIp, $since, $until): array {
            $stored = $this->spool->identityEventsSince($since, [
                'actions' => ['login_failure'],
                'source_ip' => $sourceIp,
            ]);

            return array_merge($stored, $this->fromBatch(
                fn (array $e): bool => ($e['action'] ?? '') === 'login_failure'
                    && ($e['source_ip'] ?? null) === $sourceIp,
                $since,
                $until
            ));
        });
    }

    /**
     * @param callable(array):bool $matches
     * @return array<int, array>
     */
    private function fromBatch(callable $matches, int $since, int $until): array
    {
        return array_values(array_filter($this->batch, static function (array $event) use ($matches, $since, $until): bool {
            $ts = (int) ($event['ts'] ?? 0);

            return $ts >= $since && $ts <= $until && $matches($event);
        }));
    }

    public function privilegeFailuresBy(string $actor, int $since, int $until): array
    {
        return $this->remember("priv:{$actor}:{$since}", function () use ($actor, $since, $until): array {
            $rows = $this->spool->identityEventsSince($since, ['actions' => ['privilege_failure']]);

            // The acting account lives in the extra blob, so it is filtered
            // here rather than in SQL — the volume in a fifteen-minute window
            // makes that a non-issue.
            $stored = array_values(array_filter(
                $rows,
                static fn (array $row): bool => (string) ($row['actor'] ?? '') === $actor
            ));

            return array_merge($stored, $this->fromBatch(
                static fn (array $e): bool => ($e['action'] ?? '') === 'privilege_failure'
                    && (string) ($e['actor'] ?? '') === $actor,
                $since,
                $until
            ));
        });
    }

    public function sourcesFor(string $username, int $since, int $until): array
    {
        return $this->remember("src:{$username}:{$since}", function () use ($username, $since, $until): array {
            $rows = $this->spool->identityEventsSince($since, [
                'actions' => ['login_success'],
                'username' => $username,
            ]);

            $rows = array_merge($rows, $this->fromBatch(
                static fn (array $e): bool => ($e['action'] ?? '') === 'login_success'
                    && (string) ($e['username'] ?? '') === $username,
                $since,
                $until
            ));

            return array_values(array_filter(array_map(
                static fn (array $row): ?string => $row['source_ip'] ?? null,
                $rows
            )));
        });
    }

    public function knownSourcesFor(string $username, int $before): array
    {
        $key = "known:{$username}:{$before}";

        if (!array_key_exists($key, $this->knownSources)) {
            // Deliberately a long lookback: "a device this account uses" is a
            // fact about weeks, not about the last quarter of an hour. Bounded
            // by whatever the spool still holds.
            $rows = $this->spool->identityEventsSince($before - (86400 * 30), [
                'actions' => ['login_success'],
                'username' => $username,
            ], 500);

            $sources = [];

            foreach ($rows as $row) {
                if ((int) ($row['ts'] ?? 0) >= $before) {
                    continue;
                }

                $ip = $row['source_ip'] ?? null;

                if (is_string($ip) && $ip !== '') {
                    $sources[$ip] = true;
                }
            }

            $this->knownSources[$key] = array_keys($sources);
        }

        return $this->knownSources[$key];
    }

    /** @var array<string, array<int, string>> */
    private array $knownSources = [];

    private function remember(string $key, callable $resolve): array
    {
        return $this->cache[$key] ??= $resolve();
    }
}

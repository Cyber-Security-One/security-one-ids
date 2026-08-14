<?php

namespace App\Services\Correlation;

/**
 * Turns alert volume from an emergent property into a configured contract.
 *
 * A detection surface that is new — and this one is: it fires on behaviour
 * nobody wrote a rule for — cannot be allowed to decide for itself how many
 * alerts a host produces. The failure mode is not a bad detection, it is a
 * good detection that arrives two hundred times a day until someone switches
 * the feature off. That is how anomaly-detection bolt-ons die, and it is the
 * single biggest threat to an MDR service's margin.
 *
 * So novelty-only incidents are spent out of a token bucket: a few per day,
 * with a burst allowance. When the bucket is empty, candidates are not
 * discarded — they go into a bounded max-heap and the *highest-scoring* ones
 * are released as tokens refill. The budget therefore costs you the weakest
 * candidates, never the strongest, and what was withheld is counted and
 * reported rather than silently dropped.
 *
 * Two deliberate design choices:
 *
 *  - **Rule-backed incidents bypass the bucket entirely.** If the incident
 *    contains a finding the governance layer already agreed to raise, the
 *    alert was going to be sent anyway; the correlator is only adding context
 *    to it. Budgeting those would mean this component could *suppress*
 *    existing coverage, which it must never do.
 *
 *  - **The bucket never raises the threshold.** A tempting variant prices
 *    alerts by making the bar rise as the budget drains. That hands the
 *    attacker a suppression primitive: generate cheap novel noise, drain the
 *    bucket, then act under a raised bar. Here an empty bucket can only delay
 *    and re-rank; it can never make an intrusion cheaper.
 */
final class EdrEmissionBudget
{
    public const DEFAULT_CAPACITY = 6;
    public const DEFAULT_PER_DAY = 4;
    public const DEFAULT_DAILY_CAP = 20;

    /** Deferred candidates kept. Beyond this the lowest-scoring is dropped. */
    public const HEAP_SLOTS = 32;

    /** A deferred candidate older than this is stale evidence, not an alert. */
    public const MAX_DEFERRAL = 21600;

    private EdrCorrelatorStore $store;

    private float $capacity;
    private float $perDay;
    private int $dailyCap;
    private float $halfLife;

    private float $tokens = 0.0;
    private int $bucketTs = 0;
    private int $dailyCount = 0;
    private int $dailyDay = 0;
    private int $deferredDropped = 0;

    /** @var array<int, array> deferred candidates, unordered */
    private array $deferred = [];

    private bool $loaded = false;

    public function __construct(EdrCorrelatorStore $store, array $config = [])
    {
        $this->store = $store;
        $this->capacity = (float) max(1, min(50, (int) ($config['bucket_capacity'] ?? self::DEFAULT_CAPACITY)));
        $this->perDay = (float) max(1, min(100, (int) ($config['bucket_per_day'] ?? self::DEFAULT_PER_DAY)));
        $this->dailyCap = max(1, min(200, (int) ($config['daily_cap'] ?? self::DEFAULT_DAILY_CAP)));
        $this->halfLife = (float) max(6, min(336, (int) ($config['half_life_h'] ?? 72))) * 3600.0;
    }

    private function load(): void
    {
        if ($this->loaded) {
            return;
        }

        $this->tokens = (float) ($this->store->getMeta('bucket_tokens') ?? (string) $this->capacity);
        $this->bucketTs = (int) ($this->store->getMeta('bucket_ts') ?? '0');
        $this->dailyCount = (int) ($this->store->getMeta('daily_emit_count') ?? '0');
        $this->dailyDay = (int) ($this->store->getMeta('daily_emit_day') ?? '0');
        $this->deferredDropped = (int) ($this->store->getMeta('deferred_dropped') ?? '0');

        $decoded = json_decode((string) ($this->store->getMeta('deferred') ?? '[]'), true);
        $this->deferred = is_array($decoded) ? $decoded : [];

        $this->loaded = true;
    }

    /**
     * Advance the bucket to `ts`.
     */
    public function refill(int $ts): void
    {
        $this->load();

        if ($this->bucketTs === 0) {
            $this->bucketTs = $ts;

            return;
        }

        $elapsed = $ts - $this->bucketTs;

        if ($elapsed <= 0) {
            return;
        }

        $this->tokens = min($this->capacity, $this->tokens + $this->perDay * ($elapsed / 86400.0));
        $this->bucketTs = $ts;

        $day = intdiv($ts, 86400);

        if ($day !== $this->dailyDay) {
            $this->dailyCount = 0;
            $this->dailyDay = $day;
        }
    }

    /**
     * May this incident be emitted now?
     *
     * @param array $candidate must carry score, threshold, ts, actor_key
     */
    public function admit(array $candidate, bool $ruleBacked, int $ts): bool
    {
        $this->load();

        if ($this->dailyCount >= $this->dailyCap) {
            // The daily ceiling is a circuit breaker, not a budget. Something
            // has gone wrong on this host — a mass rollout, a state reset, an
            // actual storm — and the answer is one summary, not two hundred
            // alerts.
            $this->defer($candidate);

            return false;
        }

        if ($ruleBacked) {
            $this->dailyCount++;

            return true;
        }

        if ($this->tokens >= 1.0) {
            $this->tokens -= 1.0;
            $this->dailyCount++;

            return true;
        }

        $this->defer($candidate);

        return false;
    }

    /**
     * Release the strongest deferred candidates that tokens now allow.
     *
     * The caller supplies the shaper, and a token is spent only when that
     * shaper actually produces an incident. Spending first and asking later
     * threw the alert away *and* charged the host for it: a deferred actor is
     * usually not part of the current cycle, so the caller very often could
     * not rebuild it — which quietly consumed the entire daily budget on
     * incidents nobody ever saw.
     *
     * @param  callable(array): ?array $shaper turns a candidate into an incident, or null
     * @return array<int, array>
     */
    public function release(int $ts, callable $shaper): array
    {
        $this->load();

        if ($this->deferred === []) {
            return [];
        }

        // Highest score first — the budget must cost us the weakest evidence.
        usort($this->deferred, static fn (array $a, array $b): int => ($b['score'] ?? 0) <=> ($a['score'] ?? 0));

        // Drained into a local, so the queue can only be rebuilt from what
        // this pass decides to keep. Merging survivors back into a list that
        // still held them doubled the queue on every cycle that ran out of
        // budget — which is precisely the cycle where that happens.
        $remaining = $this->deferred;
        $this->deferred = [];

        $released = [];
        $kept = [];

        while ($remaining !== []) {
            if ($this->tokens < 1.0 || $this->dailyCount >= $this->dailyCap) {
                $kept = array_merge($kept, $remaining);
                break;
            }

            $candidate = array_shift($remaining);
            $age = $ts - (int) ($candidate['ts'] ?? $ts);

            if ($age > self::MAX_DEFERRAL) {
                $this->deferredDropped++;

                continue;
            }

            // Decay the score forward to now. A chain that went quiet while it
            // waited in the queue is no longer worth an alert, and releasing
            // it later would report an incident that has already ended.
            //
            // The decayed value is used for THIS decision only. The stored
            // candidate keeps its original score and timestamp: writing the
            // decayed score back and requeuing would apply the same decay
            // again next cycle, compounding it once every thirty seconds and
            // killing a candidate in minutes instead of the six hours
            // MAX_DEFERRAL promises.
            $decayed = (float) ($candidate['score'] ?? 0.0) * (2 ** (-max(0, $age) / $this->halfLife));

            if ($decayed < (float) ($candidate['threshold'] ?? 0.0)) {
                $this->deferredDropped++;

                continue;
            }

            $shaped = $shaper(['released' => true] + ['score' => $decayed] + $candidate);

            if ($shaped === null) {
                // The caller could not rebuild it this cycle — most often
                // because the actor has not been seen again yet. Keep it in
                // the queue, unmodified, and keep the token.
                $kept[] = $candidate;

                continue;
            }

            $this->tokens -= 1.0;
            $this->dailyCount++;
            $released[] = $shaped;
        }

        $this->deferred = $kept;

        return $released;
    }

    private function defer(array $candidate): void
    {
        $entry = [
            'actor_key' => (string) ($candidate['actor_key'] ?? ''),
            'score' => (float) ($candidate['score'] ?? 0.0),
            'threshold' => (float) ($candidate['threshold'] ?? 0.0),
            'ts' => (int) ($candidate['ts'] ?? 0),
        ];

        // One entry per actor. A chain sitting over its threshold with an
        // empty bucket is re-evaluated and re-deferred every thirty seconds —
        // the cooldown and escalation gates cannot stop it, because it has
        // never actually emitted — so without this the queue fills with copies
        // of one incident and then releases every copy as a separate alert.
        foreach ($this->deferred as $index => $existing) {
            if (($existing['actor_key'] ?? '') !== $entry['actor_key']) {
                continue;
            }

            // Keep the strongest observation, and the earliest timestamp so
            // the deferral deadline is measured from when it first qualified.
            $this->deferred[$index] = [
                'actor_key' => $entry['actor_key'],
                'score' => max((float) $existing['score'], $entry['score']),
                'threshold' => $entry['threshold'],
                'ts' => min((int) $existing['ts'], $entry['ts']),
            ];

            return;
        }

        $this->deferred[] = $entry;

        if (count($this->deferred) <= self::HEAP_SLOTS) {
            return;
        }

        // Over capacity: drop the weakest, not the oldest.
        usort($this->deferred, static fn (array $a, array $b): int => ($b['score'] ?? 0) <=> ($a['score'] ?? 0));

        while (count($this->deferred) > self::HEAP_SLOTS) {
            array_pop($this->deferred);
            $this->deferredDropped++;
        }
    }

    /**
     * Drop any queued candidate for an actor that has just been reported.
     *
     * Belt and braces alongside the shaper's cooldown check: an incident that
     * has already reached an analyst has nothing left to say from the queue.
     */
    public function forget(string $actorKey): void
    {
        $this->load();

        $this->deferred = array_values(array_filter(
            $this->deferred,
            static fn (array $entry): bool => ($entry['actor_key'] ?? '') !== $actorKey
        ));
    }

    /**
     * True when the daily ceiling is holding incidents back, so the caller can
     * raise one summary instead of staying silent about a storm.
     */
    public function isStorming(): bool
    {
        $this->load();

        return $this->dailyCount >= $this->dailyCap && $this->deferred !== [];
    }

    public function persist(): void
    {
        if (!$this->loaded) {
            return;
        }

        $this->store->setMeta('bucket_tokens', (string) round($this->tokens, 4));
        $this->store->setMeta('bucket_ts', (string) $this->bucketTs);
        $this->store->setMeta('daily_emit_count', (string) $this->dailyCount);
        $this->store->setMeta('daily_emit_day', (string) $this->dailyDay);
        $this->store->setMeta('deferred_dropped', (string) $this->deferredDropped);
        $this->store->setMeta('deferred', (string) json_encode(array_values($this->deferred)));
    }

    /**
     * What the budget did, for the cycle rollup.
     *
     * `deferred_dropped` is reported rather than hidden on purpose: a product
     * that says "this host is allowed six novelty alerts a day, here is what
     * was withheld and what it scored" is answerable. One that silently
     * truncates reads as full coverage when it is not.
     */
    public function counters(): array
    {
        $this->load();

        return [
            'tokens' => round($this->tokens, 2),
            'capacity' => $this->capacity,
            'per_day' => $this->perDay,
            'deferred' => count($this->deferred),
            'deferred_dropped' => $this->deferredDropped,
            'emitted_today' => $this->dailyCount,
            'daily_cap' => $this->dailyCap,
        ];
    }
}

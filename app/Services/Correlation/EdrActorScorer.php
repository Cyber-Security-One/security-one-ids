<?php

namespace App\Services\Correlation;

/**
 * The arithmetic of the correlator: decay, accumulate, cap, score, threshold.
 *
 * ## The false-positive bound is a property of the algebra, not of tuning
 *
 * Every class has a hard cap, the score is the **sum of capped
 * accumulations** plus a bounded ordering bonus, and *nothing multiplies the
 * sum from outside*. That last clause is the whole reason the bound holds. An
 * earlier design applied rarity and ordering as multipliers around the total,
 * which meant a bag of entirely ordinary events could be lifted over the
 * threshold by factors that had nothing to do with how much evidence there
 * was; the proof its author had written did not survive simulation.
 *
 * With the additive form, and the default caps:
 *
 *  - **One class lit:** `S ≤ 8.0` (the heaviest single cap) and `C = 1`. The
 *    emission gate needs `C ≥ 3`. It cannot alert.
 *  - **Two classes lit:** `S ≤ 8.0 + 8.0 = 16.0`, and the ordering bonus is
 *    zero below three classes. `16.0 < 18.0`, the threshold floor. It cannot
 *    alert — **at any event volume, for any length of time, forever.**
 *
 * That is the classic correlator death — one noisy rule fires ten thousand
 * times and blows through the threshold — removed by construction rather than
 * suppressed by an exclusion list. It is also a one-line unit assertion, which
 * is why it is stated here rather than in a design document nobody reads.
 *
 * ## The threshold adapts slower than the score decays, deliberately
 *
 * Score half-life is 72 hours. The threshold tracks a ~10-day EWMA of the
 * actor's own daily novelty. The score therefore decays roughly 24× faster
 * than the bar rises, so an attacker trying to buy headroom by generating
 * novelty first produces exactly the burst that alerts. Most adaptive-
 * threshold schemes use one time constant for both and are self-defeating:
 * sustained noise raises the bar as fast as it raises the score.
 *
 * Pure: no I/O, no clock. Every function of time takes the event's own
 * timestamp, which is what makes the whole model replayable and unit-testable
 * without sleeping.
 */
final class EdrActorScorer
{
    /** Score half-life, seconds. Chains cool down when the actor stops. */
    public const DEFAULT_HALF_LIFE = 259200;

    /** Accumulation below which a class is not considered lit. */
    public const LIT_MIN = 1.0;

    /** Per-class ceilings, in surprise points. */
    public const DEFAULT_CAPS = [
        EdrIntentClassifier::ENTRY => 6.0,
        EdrIntentClassifier::DISCOVERY => 4.0,
        EdrIntentClassifier::STAGING => 6.0,
        EdrIntentClassifier::PRIVESC => 8.0,
        EdrIntentClassifier::CRED => 8.0,
        EdrIntentClassifier::COLLECT => 6.0,
        EdrIntentClassifier::PERSIST => 7.0,
        EdrIntentClassifier::EGRESS => 7.0,
        EdrIntentClassifier::OBFUSCATION => 4.0,
        EdrIntentClassifier::ANTIFORENSIC => 5.0,
    ];

    public const DEFAULT_K = 4.0;
    public const DEFAULT_T_FLOOR = 18.0;

    /**
     * The adaptive threshold ceiling.
     *
     * This has to sit below what a *real* intrusion can actually score, not
     * below the theoretical maximum. Summing every cap gives 61, but no chain
     * lights all ten classes; a thorough six-stage intrusion — entry,
     * discovery, staging, privilege, credentials, egress — reaches
     * 6+4+6+8+8+7 = 39 plus the ordering bonus. A ceiling of 45 would
     * therefore have made a noisy actor *structurally* undetectable: its bar
     * would sit above anything an attacker could reach on it, and no amount of
     * intrusion would ever cross. 32 leaves a four-to-five stage chain able to
     * cross even on the noisiest host on the fleet.
     */
    public const DEFAULT_T_CEIL = 32.0;

    public const DEFAULT_T_FLOOR_HOST = 24.0;

    /**
     * The host lane's ceiling, held to its own gate rather than to the actor
     * lane's.
     *
     * EDR-101 requires four lit classes, so the most a qualifying incident can
     * score is the four heaviest caps plus the ordering bonus: 8+8+7+7+3 = 33.
     * A ceiling at 36 was therefore above anything the lane could ever produce
     * — the same mistake as the actor lane's original 45, one gate further in.
     */
    public const DEFAULT_T_CEIL_HOST = 30.0;

    /** Maximum ordering bonus, awarded only for a perfectly forward chain. */
    public const B_ORD_MAX = 3.0;

    /** Classes needed before the ordering bonus applies at all. */
    public const MIN_CLASSES_FOR_ORDERING = 3;

    /** EWMA weight for a day's novelty. 0.1 gives a ~10-day time constant. */
    public const NOV_ALPHA = 0.1;

    private float $halfLife;
    private array $caps;
    private float $k;
    private float $tFloor;
    private float $tCeil;
    private float $tFloorHost;
    private float $tCeilHost;

    public function __construct(array $config = [])
    {
        $this->halfLife = (float) max(6, min(336, (int) ($config['half_life_h'] ?? 72))) * 3600.0;
        $this->k = max(1.0, min(10.0, (float) ($config['k'] ?? self::DEFAULT_K)));
        // The floors are clamped under their own ceilings, or a raised floor
        // would drag the effective ceiling back up through the max() below.
        $this->tFloor = max(8.0, min(self::DEFAULT_T_CEIL, (float) ($config['t_floor'] ?? self::DEFAULT_T_FLOOR)));
        // The ceilings may be lowered from the Hub but never raised.
        //
        // Both defaults are *derived* from what their own gate can reach —
        // 32 sits under a six-stage actor chain, 30 under a four-class host
        // chain — so any value above them switches detection off for the
        // noisiest hosts, which is the worst failure available here because
        // those are also the hosts nobody is watching by hand. A clamp at some
        // larger round number was not a bound at all; the derived value is.
        $this->tCeil = max($this->tFloor, min(self::DEFAULT_T_CEIL, (float) ($config['t_ceiling'] ?? self::DEFAULT_T_CEIL)));
        $this->tFloorHost = max(12.0, min(self::DEFAULT_T_CEIL_HOST, (float) ($config['t_floor_host'] ?? self::DEFAULT_T_FLOOR_HOST)));
        $this->tCeilHost = max(
            $this->tFloorHost,
            min(self::DEFAULT_T_CEIL_HOST, (float) ($config['t_ceiling_host'] ?? self::DEFAULT_T_CEIL_HOST))
        );

        $this->caps = self::DEFAULT_CAPS;

        if (is_array($config['class_caps'] ?? null)) {
            foreach ($config['class_caps'] as $classId => $cap) {
                $classId = (int) $classId;

                if (isset($this->caps[$classId])) {
                    $this->caps[$classId] = max(0.0, min(12.0, (float) $cap));
                }
            }
        }

        $this->enforceTwoClassBound();
    }

    /**
     * Keep the two-class bound true for *any* configuration, not just the
     * defaults.
     *
     * "Two classes can never alert" is the load-bearing claim of this design,
     * and with the shipped caps it holds by inspection: 8 + 8 < 18. But the
     * caps are Hub-tunable, and two values raised to 12 would put the pair at
     * 24 — above the floor — turning the guarantee into an accident of the
     * default configuration. A property that only holds until someone edits a
     * config value is not a property. So the caps are scaled down here until
     * the arithmetic holds again, and the operator gets the tuning they asked
     * for in proportion rather than a silently broken bound.
     */
    private function enforceTwoClassBound(): void
    {
        $sorted = $this->caps;
        rsort($sorted);

        $heaviestPair = ($sorted[0] ?? 0.0) + ($sorted[1] ?? 0.0);

        // Room for the ordering bonus is not needed: it is only awarded at
        // three or more lit classes.
        if ($heaviestPair < $this->tFloor || $heaviestPair <= 0.0) {
            return;
        }

        $scale = ($this->tFloor * 0.95) / $heaviestPair;

        foreach ($this->caps as $classId => $cap) {
            $this->caps[$classId] = $cap * $scale;
        }
    }

    /**
     * A fresh actor.
     */
    public function newActor(string $actorKey, string $anchorKind, int $ts): array
    {
        return [
            'actor_key' => $actorKey,
            'anchor_kind' => $anchorKind,
            'acc' => [],
            'class_first_ts' => [],
            'first_ts' => $ts,
            'last_ts' => $ts,
            'nov' => 0.0,
            'day_charges' => 0.0,
            'day_key' => intdiv($ts, 86400),
            'event_count' => 0,
            'max_charge' => 0.0,
            'contributors' => [],
            'evidence' => [],
            'last_alert_ts' => 0,
            'last_alert_score' => 0.0,
            'taught_today' => 0,
            'taught_day' => intdiv($ts, 86400),
        ];
    }

    /**
     * Age every class accumulation forward to `ts`.
     *
     * A timestamp older than the actor's last is treated as no elapsed time at
     * all rather than as negative decay: osquery batches are not strictly
     * ordered, and an out-of-order row must never *amplify* a score.
     */
    public function decay(array $actor, int $ts): array
    {
        $elapsed = $ts - (int) $actor['last_ts'];

        if ($elapsed > 0) {
            $q = 2 ** (-$elapsed / $this->halfLife);

            foreach ($actor['acc'] as $classId => $value) {
                $actor['acc'][$classId] = $value * $q;
            }

            $actor['last_ts'] = $ts;
        }

        return $actor;
    }

    /**
     * Add one event's charge to every class it lit.
     *
     * @param int[] $classIds
     */
    public function apply(array $actor, float $charge, array $classIds, int $ts): array
    {
        foreach ($classIds as $classId) {
            // Capped on WRITE, not only when scoring.
            //
            // Letting the raw accumulation run past the cap builds a hidden
            // reservoir: a class charged to 31 against a cap of 6 still scores
            // 6, but it now needs five half-lives to fall below the lit floor
            // instead of two and a half. The chain would go on looking active
            // for a fortnight after the attacker stopped, which is precisely
            // the cooling-down property this design promises.
            $actor['acc'][$classId] = min(
                (float) ($actor['acc'][$classId] ?? 0.0) + $charge,
                $this->capFor((int) $classId)
            );
        }

        // Re-evaluate which classes are lit. A class that has decayed back
        // below the floor forgets when it first lit, so a chain that went cold
        // and restarted is scored as a new chain rather than inheriting an
        // ordering it no longer has evidence for.
        foreach ($actor['acc'] as $classId => $value) {
            $capped = min((float) $value, $this->capFor((int) $classId));

            if ($capped >= self::LIT_MIN) {
                if (empty($actor['class_first_ts'][$classId])) {
                    $actor['class_first_ts'][$classId] = $ts;
                }
            } else {
                unset($actor['class_first_ts'][$classId]);
            }
        }

        if ($charge > 0.0) {
            $actor['event_count'] = (int) $actor['event_count'] + 1;
            $actor['max_charge'] = max((float) $actor['max_charge'], $charge);
            $actor['day_charges'] = (float) $actor['day_charges'] + $charge;
        }

        return $actor;
    }

    /**
     * @return array{score:float, classes:int, lit:int[], sum:float, ordering:float, ratio:float}
     */
    public function score(array $actor): array
    {
        $sum = 0.0;
        $lit = [];

        foreach ($actor['acc'] as $classId => $value) {
            $capped = min((float) $value, $this->capFor((int) $classId));

            // Only LIT classes contribute. Summing sub-threshold residue as
            // well would quietly break the bound this class advertises: ten
            // classes holding 0.99 each are "no stage reached" by every other
            // measure in the design, yet they would add ~10 points — more than
            // half the threshold floor — and the two-class ceiling would stop
            // being 16.0. The bound has to be a property of the arithmetic or
            // it is not a bound.
            if ($capped < self::LIT_MIN) {
                continue;
            }

            $lit[] = (int) $classId;
            $sum += $capped;
        }

        sort($lit);
        $classes = count($lit);
        $ordering = 0.0;
        $ratio = 0.0;

        if ($classes >= self::MIN_CLASSES_FOR_ORDERING) {
            $ratio = $this->concordance($actor, $lit);
            // Calibrated so that randomly ordered evidence (ratio ≈ 0.5) earns
            // nothing at all, and only a chain that actually runs forward
            // through the kill chain earns the full bonus.
            $ordering = self::B_ORD_MAX * max(0.0, ($ratio - 0.5) / 0.5);
        }

        return [
            'score' => $sum + $ordering,
            'classes' => $classes,
            'lit' => $lit,
            'sum' => $sum,
            'ordering' => $ordering,
            'ratio' => $ratio,
        ];
    }

    /**
     * Fraction of class pairs that occurred in kill-chain order.
     *
     * An intrusion moves forward: entry, then discovery, then staging, then
     * escalation. Unrelated activity that happens to light several classes has
     * no reason to line up, so this separates a campaign from a coincidence.
     *
     * @param int[] $lit
     */
    private function concordance(array $actor, array $lit): float
    {
        $ordered = [];

        foreach ($lit as $classId) {
            $order = EdrIntentClassifier::ORDER[$classId] ?? 0;

            if ($order > 0) {
                $ordered[] = [
                    'order' => $order,
                    'ts' => (int) ($actor['class_first_ts'][$classId] ?? 0),
                ];
            }
        }

        $n = count($ordered);

        if ($n < 2) {
            return 0.0;
        }

        usort($ordered, static fn (array $a, array $b): int => $a['ts'] <=> $b['ts']);

        $concordant = 0;
        $pairs = 0;

        for ($i = 0; $i < $n; $i++) {
            for ($j = $i + 1; $j < $n; $j++) {
                // Simultaneous classes say nothing about sequence, so they are
                // excluded from the ratio entirely rather than counted either
                // way.
                //
                // This is not a rare edge case: the sensor stamps every event
                // in a flush batch with the *flush* time, and a single
                // timestamp on this host was measured carrying 8,820 exec
                // events. Breaking ties by kill-chain position — which is what
                // this did — therefore handed the full ordering bonus to any
                // burst that happened to light several classes inside one
                // batch, and three cheap classes plus that bonus is 19.0
                // against a floor of 18.0. A bag of coincidences would have
                // crossed. Excluded, the same burst scores 16.0 and cannot.
                if ($ordered[$i]['ts'] === $ordered[$j]['ts']) {
                    continue;
                }

                $pairs++;

                if ($ordered[$i]['order'] < $ordered[$j]['order']) {
                    $concordant++;
                }
            }
        }

        // No pair was separable in time: no evidence of progression at all.
        return $pairs === 0 ? 0.0 : $concordant / $pairs;
    }

    /**
     * The bar this actor has to clear.
     *
     * Scaled to the actor's own novelty rate, so a chaotic build agent is not
     * held to a quiet database server's standard — but floored and ceilinged,
     * because an actor must never be able to make itself undetectable simply
     * by being noisy. The ceiling sits below the maximum attainable score for
     * that reason.
     */
    public function threshold(array $actor, float $jitter = 1.0, bool $hostLane = false): float
    {
        $floor = $hostLane ? $this->tFloorHost : $this->tFloor;
        $ceil = $hostLane ? $this->tCeilHost : $this->tCeil;

        $adaptive = $this->k * (float) $actor['nov'];

        // The ceiling is absolute and jitter is applied to the floor only.
        //
        // Multiplying the ceiling by the jitter as well put the effective bar
        // up to 25% above the value the clamp had just bounded — which is the
        // whole thing the clamp exists to prevent, since a bar above the
        // reachable score makes an actor undetectable rather than merely less
        // sensitive. Jitter belongs at the floor, where nearly every actor
        // actually sits and where per-host unpredictability is worth having.
        return min($ceil, max($floor * $jitter, $adaptive));
    }

    /**
     * Close out a day and fold it into the novelty EWMA.
     *
     * Days with no activity still decay the average — otherwise an actor that
     * was busy once would keep a raised threshold forever, which is a
     * permanent blind spot rather than an adaptation.
     */
    public function rollDay(array $actor, int $dayKey): array
    {
        $gap = $dayKey - (int) $actor['day_key'];

        if ($gap <= 0) {
            return $actor;
        }

        $nov = (1.0 - self::NOV_ALPHA) * (float) $actor['nov']
            + self::NOV_ALPHA * (float) $actor['day_charges'];

        if ($gap > 1) {
            $nov *= (1.0 - self::NOV_ALPHA) ** ($gap - 1);
        }

        $actor['nov'] = $nov;
        $actor['day_charges'] = 0.0;
        $actor['day_key'] = $dayKey;

        return $actor;
    }

    /**
     * Severity from how far past its own bar the actor is.
     *
     * A ratio, not an absolute score: "twice what this actor has ever needed
     * to be" means the same thing on every host, which an absolute number
     * does not.
     */
    public function severity(float $score, float $threshold, bool $hasCriticalFinding = false): string
    {
        $ratio = $threshold > 0.0 ? $score / $threshold : 0.0;

        $severity = match (true) {
            $ratio >= 2.0 => 'critical',
            $ratio >= 1.2 => 'high',
            default => 'medium',
        };

        // An incident that contains a critical rule hit is never reported as
        // medium just because the actor's own bar happens to be high.
        if ($hasCriticalFinding && $severity === 'medium') {
            return 'high';
        }

        return $severity;
    }

    /**
     * Per-host threshold jitter in [1, 1.25].
     *
     * Deterministic, so tests and replays agree, but unknowable without
     * reading the host id. It only defeats an attacker who has not already
     * looked at the box — which is the honest limit of its value, and is why
     * it is a small factor rather than a load-bearing defence.
     */
    public static function jitterFor(string $hostId): float
    {
        return 1.0 + 0.25 * (hexdec(hash('crc32b', $hostId)) / 4294967296.0);
    }

    public function capFor(int $classId): float
    {
        return $this->caps[$classId] ?? 0.0;
    }

    /** @return array<int, float> */
    public function caps(): array
    {
        return $this->caps;
    }

    /**
     * Highest score any actor could reach. Used to sanity-check thresholds:
     * a ceiling at or above this makes an actor structurally undetectable.
     */
    public function maxAttainableScore(): float
    {
        return array_sum($this->caps) + self::B_ORD_MAX;
    }
}

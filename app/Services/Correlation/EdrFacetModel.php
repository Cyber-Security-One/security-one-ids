<?php

namespace App\Services\Correlation;

/**
 * How familiar a facet value is on this host, and whether an event is allowed
 * to teach the model anything.
 *
 * ## The one idea that matters
 *
 * **Familiarity is measured in distinct calendar days, never in occurrences.**
 *
 * Every frequency-based anomaly model in this space is defeated the same way:
 * the attacker runs their payload a few thousand times during the learning
 * window and it becomes "normal". Counting occurrences makes that a one-line
 * shell loop. Counting *distinct days* makes it a calendar commitment — the
 * floor price of making one facet value free is five distinct days spread over
 * at least ten days of wall clock, per dimension, with no rule findings
 * allowed along the way. Volume buys exactly nothing. That single choice is
 * why the `occ` column exists only for reporting and is never read by `fam()`.
 *
 * The mask is 32 bits, one per day, shifted forward as time passes. A million
 * executions in an hour set one bit. So does one execution.
 *
 * ## The learn gate
 *
 * Being seen is not enough to become familiar; the sighting also has to be
 * unremarkable. An event may teach a facet only when the event was cheap
 * *apart from that one facet* — so an attacker cannot condition six dimensions
 * at once by performing one wholly novel action repeatedly. They must condition
 * them roughly one at a time, over days, which is the same calendar cost again
 * multiplied by the number of dimensions they need.
 *
 * The gate is evaluated **per facet, not per event**, and that is a fix rather
 * than a detail. Any binary this host has never run makes F1 (lineage) and F2
 * (image) novel simultaneously by construction — their combined weight alone
 * exceeds a per-event threshold — so a per-event gate is structurally
 * unreachable for new software. A package installed after the warm-up would
 * stay unfamiliar forever and re-charge every time its ledger entry expired,
 * building a permanent noise floor that grows with everything the host ever
 * installs. Per-facet, F1 and F2 each see the *other* one's cost as the
 * remainder and both teach; an event with four novel facets teaches nothing.
 */
final class EdrFacetModel
{
    /** Distinct days a value needs before it counts as fully supported. */
    public const DEFAULT_SUPPORT_DAYS = 5;

    /** Wall-clock days a value must exist before support counts for anything. */
    public const DEFAULT_MATURITY_DAYS = 10;

    /** Residual cost, in sp, above which an event may not teach a facet. */
    public const DEFAULT_LEARN_GATE = 5.0;

    /** New values one actor may teach in a day, outside the rollout escape hatch. */
    public const DEFAULT_TEACH_CAP = 12;

    /**
     * Familiarity ceiling for values learned before the model matured.
     *
     * Agents get installed on hosts *because* something is already wrong, so
     * the warm-up window is exactly when an intrusion is most likely to be
     * present. A concession of 0.5 means pre-maturity tooling still costs half
     * price forever rather than becoming free — and no bootstrap credit is
     * granted at all to a value introduced by an event that tripped a rule.
     */
    public const BOOTSTRAP_CAP = 0.5;

    private EdrCorrelatorStore $store;

    private int $supportDays;
    private int $maturityDays;
    private float $learnGate;
    private int $teachCap;

    /** Rows loaded this cycle, fid => row. */
    private array $loaded = [];

    /** Rows mutated this cycle and awaiting a batched write. */
    private array $dirty = [];

    /** Facet ids confirmed absent this cycle, so we stop asking for them. */
    private array $absent = [];

    /** Facet ids already checked against the tombstone table this cycle. */
    private array $checkedTombstone = [];

    public function __construct(EdrCorrelatorStore $store, array $config = [])
    {
        $this->store = $store;
        $this->supportDays = max(2, min(16, (int) ($config['support_days'] ?? self::DEFAULT_SUPPORT_DAYS)));
        $this->maturityDays = max(3, min(30, (int) ($config['maturity_days'] ?? self::DEFAULT_MATURITY_DAYS)));
        $this->learnGate = max(1.0, min(12.0, (float) ($config['learn_gate'] ?? self::DEFAULT_LEARN_GATE)));
        $this->teachCap = max(1, min(200, (int) ($config['teach_cap'] ?? self::DEFAULT_TEACH_CAP)));
    }

    /**
     * Pull every facet row this cycle will need in one batched query.
     *
     * @param string[] $fids
     */
    public function prime(array $fids): void
    {
        $missing = [];

        foreach (array_unique($fids) as $fid) {
            if (!isset($this->loaded[$fid]) && !isset($this->absent[$fid])) {
                $missing[] = $fid;
            }
        }

        if ($missing === []) {
            return;
        }

        $rows = $this->store->loadFacets($missing);

        foreach ($missing as $fid) {
            if (isset($rows[$fid])) {
                $this->loaded[$fid] = $rows[$fid];
                unset($this->absent[$fid]);

                continue;
            }

            // Remember the miss. A never-seen value is looked up on every
            // event it appears in, and the overwhelming majority of a cycle's
            // facets are values the host has never had — so without this the
            // same fruitless SELECT runs a few hundred times a cycle, 2880
            // cycles a day, for a row that does not exist.
            $this->absent[$fid] = true;
        }
    }

    /**
     * Familiarity in [0,1] for each requested facet id.
     *
     * An unknown value is 0.0 — never seen here, maximum charge.
     *
     * @param  string[] $fids
     * @return array<string, float>
     */
    public function familiarity(array $fids, int $ts): array
    {
        $this->prime($fids);

        $out = [];

        foreach ($fids as $fid) {
            $out[$fid] = $this->familiarityFor($fid, $ts);
        }

        return $out;
    }

    public function familiarityFor(string $fid, int $ts): float
    {
        $row = $this->loaded[$fid] ?? null;

        if ($row === null) {
            return 0.0;
        }

        $support = EdrCorrelatorStore::popcount((int) $row['days_mask']);
        $ageDays = intdiv(max(0, $ts - (int) $row['first_seen']), 86400);
        $cap = ((int) $row['bootstrap']) === 1 ? self::BOOTSTRAP_CAP : 1.0;

        $fam = min(1.0, $support / $this->supportDays)
            * min(1.0, $ageDays / $this->maturityDays)
            * $cap;

        return max(0.0, min(1.0, $fam));
    }

    /**
     * Decide, per facet, whether this event may teach it.
     *
     * @param  array<int, array{kind:int, weight:float, value:string, fid:string}> $facets
     * @param  array<string, float> $fam         familiarity by fid
     * @param  float                $eRaw        the event's total raw charge
     * @param  bool                 $hadFinding  any rule fired on this event
     * @param  int                  $taughtToday how many values this actor already taught today
     * @param  bool                 $clockAnomaly
     * @return array<string, bool>  fid => may teach
     */
    public function learnDecisions(
        array $facets,
        array $fam,
        float $eRaw,
        bool $hadFinding,
        int $taughtToday,
        bool $clockAnomaly = false,
        int $anchorId = 0,
        int $day = 0
    ): array {
        $out = [];

        foreach ($facets as $facet) {
            $out[$facet['fid']] = false;
        }

        // (a) An event that tripped a rule teaches nothing, ever. Otherwise
        // the attack itself would be the thing that makes the attack normal —
        // repeat a webshell command daily for a week and the model learns it.
        if ($hadFinding) {
            return $out;
        }

        // (d) A cycle whose timestamps moved in a way wall-clock time cannot
        // explain is not evidence about this host's behaviour.
        if ($clockAnomaly) {
            return $out;
        }

        foreach ($facets as $facet) {
            $fid = $facet['fid'];
            $residual = $eRaw - ((float) $facet['weight'] * (1.0 - ($fam[$fid] ?? 0.0)));

            // (b) Was the event unremarkable apart from THIS facet?
            if ($residual >= $this->learnGate) {
                continue;
            }

            // (c) The daily teaching budget, with an escape hatch for a
            // genuine rollout: a value showing up under three or more distinct
            // anchors on the same day is configuration management or a package
            // upgrade, not one actor conditioning the model.
            if ($taughtToday >= $this->teachCap && !$this->seenUnderManyAnchors($fid, $anchorId, $day)) {
                continue;
            }

            $out[$fid] = true;
        }

        return $out;
    }

    /**
     * Record today's sighting for the facets that were allowed to teach, and
     * touch `last_seen`/`occ` for the rest.
     *
     * Being *observed* is separate from being *learned*: an unlearned facet
     * still updates its recency so eviction ranking stays honest, but its day
     * mask does not move, so it gains no familiarity.
     *
     * @param  array<int, array{kind:int, weight:float, value:string, fid:string}> $facets
     * @param  array<string, bool> $decisions
     * @return int number of facets that actually learned
     */
    public function stage(array $facets, array $decisions, int $ts, bool $bootstrap, ?int $day = null): int
    {
        // The caller may supply a clock-guarded day. It is deliberately not
        // derived from `$ts` here: a timestamp that jumped forward must not be
        // able to buy familiarity, and this is the only place a day is turned
        // into support.
        $day = $day ?? intdiv($ts, 86400);
        $taught = 0;

        foreach ($facets as $facet) {
            $fid = $facet['fid'];
            $row = $this->loaded[$fid] ?? null;
            $mayTeach = (bool) ($decisions[$fid] ?? false);

            if ($row === null) {
                if (!$mayTeach) {
                    // Never seen and not allowed to learn: deliberately not
                    // created. Creating a row with an empty day mask would let
                    // its `first_seen` clock start running, and the value
                    // would quietly mature toward familiarity on the strength
                    // of sightings that were never allowed to count.
                    continue;
                }

                $row = [
                    'fid' => $fid,
                    'kind' => (int) $facet['kind'],
                    'first_seen' => $ts,
                    'last_seen' => $ts,
                    'days_mask' => 1,
                    'occ' => 1,
                    'bootstrap' => $bootstrap ? 1 : 0,
                    'anchor_day' => 0,
                    'anchor_set' => null,
                ];

                $this->loaded[$fid] = $row;
                $this->dirty[$fid] = $row;
                unset($this->absent[$fid]);
                $taught++;

                continue;
            }

            // Captured before the update: the mask has to be advanced by the
            // gap since the PREVIOUS sighting, not by zero.
            //
            // Both sides are held to the guarded day. Storing a raw future
            // timestamp here while the mask day arrives clamped left the two
            // permanently inconsistent: `previousDay` would sit ahead of
            // `$day` forever, every gap would clamp to zero, and the facet's
            // mask would freeze — one bad timestamp and that value could never
            // gain or lose support again.
            $dayCeiling = ($day + 1) * 86400 - 1;
            $stampedAt = min($ts, $dayCeiling);
            $previousDay = min(intdiv((int) $row['last_seen'], 86400), $day);

            $row['occ'] = (int) $row['occ'] + 1;
            // Any stored value already ahead of the guarded day is pulled back
            // to it, so the row can recover instead of staying frozen.
            $row['last_seen'] = max(min((int) $row['last_seen'], $dayCeiling), $stampedAt);

            if ($mayTeach) {
                $row['days_mask'] = self::shiftMask((int) $row['days_mask'], $day, $previousDay);
                $taught++;
            }

            $this->loaded[$fid] = $row;
            $this->dirty[$fid] = $row;
        }

        return $taught;
    }

    /**
     * Note that a facet value was seen under a particular anchor today.
     *
     * This is what powers the rollout escape hatch. Kept to at most four
     * anchor ids per value per day — beyond three the answer is already yes.
     */
    public function noteAnchor(string $fid, int $anchorId, int $ts): void
    {
        $row = $this->loaded[$fid] ?? null;

        if ($row === null || $anchorId <= 0) {
            return;
        }

        $day = intdiv($ts, 86400);
        $set = [];

        if ((int) $row['anchor_day'] === $day) {
            $decoded = json_decode((string) ($row['anchor_set'] ?? ''), true);
            $set = is_array($decoded) ? $decoded : [];
        }

        if (in_array($anchorId, $set, true) || count($set) >= 4) {
            return;
        }

        $set[] = $anchorId;
        $row['anchor_day'] = $day;
        $row['anchor_set'] = json_encode(array_values($set));

        $this->loaded[$fid] = $row;
        $this->dirty[$fid] = $row;
    }

    private function seenUnderManyAnchors(string $fid, int $anchorId, int $day): bool
    {
        $row = $this->loaded[$fid] ?? null;

        if ($row === null || (int) $row['anchor_day'] !== $day) {
            return false;
        }

        $decoded = json_decode((string) ($row['anchor_set'] ?? ''), true);
        $set = is_array($decoded) ? $decoded : [];

        if ($anchorId > 0 && !in_array($anchorId, $set, true)) {
            $set[] = $anchorId;
        }

        return count($set) >= 3;
    }

    /**
     * Restore eviction history for values we are about to re-create.
     *
     * @param string[] $fids
     */
    public function applyTombstones(array $facets, int $ts): void
    {
        $kinds = [];

        foreach ($facets as $facet) {
            $fid = is_array($facet) ? (string) $facet['fid'] : (string) $facet;

            if (!isset($this->loaded[$fid]) && !isset($this->checkedTombstone[$fid])) {
                $kinds[$fid] = is_array($facet) ? (int) $facet['kind'] : 0;
                $this->checkedTombstone[$fid] = true;
            }
        }

        if ($kinds === []) {
            return;
        }

        foreach ($this->store->restoreTombstones(array_keys($kinds)) as $fid => $history) {
            // Seed the mask with `support` low bits so a value that had four
            // distinct days before eviction does not come back as brand new.
            //
            // `last_seen` is the current timestamp on purpose. Setting it to
            // the restored `first_seen` — which is what an earlier version
            // did — meant the very next sighting saw a gap of weeks and
            // shifted the whole mask off the end, wiping the support this
            // restore exists to preserve. Eviction would then re-novelise
            // established values in cycles, producing periodic alert waves
            // with no attacker anywhere near the host.
            $this->loaded[$fid] = [
                'fid' => $fid,
                'kind' => $kinds[$fid],
                'first_seen' => $history['first_seen'],
                'last_seen' => $ts,
                'days_mask' => (1 << max(0, min(31, $history['support']))) - 1,
                'occ' => 0,
                'bootstrap' => 0,
                'anchor_day' => 0,
                'anchor_set' => null,
            ];

            $this->dirty[$fid] = $this->loaded[$fid];
            unset($this->absent[$fid]);
        }
    }

    /**
     * Write everything staged this cycle in one batch.
     *
     * @return int rows written
     */
    public function flush(): int
    {
        if ($this->dirty === []) {
            return 0;
        }

        $rows = array_values($this->dirty);
        $this->store->upsertFacets($rows);
        $this->dirty = [];

        return count($rows);
    }

    /**
     * Drop the per-cycle cache. The process exits every thirty seconds, but a
     * replay run walks weeks of events in one process and must not grow
     * without bound.
     */
    public function forget(): void
    {
        $this->loaded = [];
        $this->dirty = [];
        $this->absent = [];
        $this->checkedTombstone = [];
    }

    public function cachedCount(): int
    {
        return count($this->loaded);
    }

    /**
     * Advance a day mask to `today`.
     *
     * A gap of n days shifts the mask left by n, so bits fall off the 32-day
     * end and old support decays naturally. Shifts of 32 or more clear it
     * entirely — a value not seen for a month has no support left, which is
     * the correct answer and also avoids PHP's undefined behaviour for shifts
     * wider than the word.
     */
    public static function shiftMask(int $mask, int $today, int $lastDay): int
    {
        $gap = max(0, $today - $lastDay);

        if ($gap >= 32) {
            return 1;
        }

        return (($mask << $gap) | 1) & 0xFFFFFFFF;
    }
}

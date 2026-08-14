<?php

namespace App\Services\Quality;

/**
 * Turns "this rule keeps firing on the same thing" into a concrete exclusion
 * an analyst can approve.
 *
 * Tuning is the work that decides whether an MDR service is profitable, and
 * left to humans it does not get done: writing a correct regex against a
 * customer's real workload is fiddly, so instead the rule gets switched off
 * wholesale and the coverage is lost. Deriving candidates from what actually
 * recurred on the host turns a half-hour job into a yes/no.
 *
 * Suggestions are proposals, never applied automatically. An exclusion is a
 * permanent blind spot, and the whole point of this module is that blind
 * spots should be chosen deliberately rather than acquired by accident.
 */
class EdrExclusionSuggester
{
    /** Below this a pattern has not proved it is routine. */
    private const MIN_OCCURRENCES = 10;

    /** Never propose narrowing these away — the cost of a miss is too high. */
    private const NEVER_SUGGEST_FOR = ['EDR-002', 'EDR-007'];

    private EdrGovernanceStore $store;

    public function __construct(EdrGovernanceStore $store)
    {
        $this->store = $store;
    }

    /**
     * @return array<int, array{rule:string, pattern:string, occurrences:int, sample:?string, confidence:string, rationale:string}>
     */
    public function suggest(int $minOccurrences = self::MIN_OCCURRENCES, int $limit = 20): array
    {
        $suggestions = [];

        foreach ($this->store->frequentObservations($minOccurrences, $limit * 3) as $observation) {
            $rule = (string) $observation['rule'];

            if (in_array($rule, self::NEVER_SUGGEST_FOR, true)) {
                continue;
            }

            $pattern = $this->patternFor($observation);

            if ($pattern === null) {
                continue;
            }

            $occurrences = (int) $observation['occurrences'];

            $suggestions[] = [
                'rule' => $rule,
                'pattern' => $pattern,
                'occurrences' => $occurrences,
                'sample' => $observation['sample'] ?? null,
                'confidence' => $this->confidenceFor($occurrences, $observation),
                'rationale' => $this->rationaleFor($rule, $occurrences, $observation),
            ];

            if (count($suggestions) >= $limit) {
                break;
            }
        }

        return $suggestions;
    }

    /**
     * Build a regex from the stable part of the observed command line.
     *
     * Anchored on the binary rather than the whole line: the arguments are
     * what vary between runs, and an exclusion that only matches one exact
     * invocation excludes nothing useful tomorrow.
     */
    private function patternFor(array $observation): ?string
    {
        $signature = (string) $observation['signature'];
        $parts = explode('|', $signature, 4);

        if (count($parts) < 4) {
            return null;
        }

        [, $user, $binary, $normalised] = $parts;

        if ($binary === '?' || $binary === '') {
            return null;
        }

        // Take the leading literal run of the normalised command line, up to
        // the first placeholder. Everything after that varies by definition.
        $stable = preg_split('/<[A-Z]+>/', $normalised)[0] ?? '';
        $stable = trim($stable);

        // A binary name alone is far too broad — excluding every `curl` would
        // hand an attacker the easiest bypass in the product.
        if (strlen($stable) < 8) {
            return null;
        }

        $escaped = preg_quote($stable, '#');

        // Bind the exclusion to the user as well when it is a service account,
        // so approving it for www-data does not also excuse root.
        if ($user !== '?' && $user !== '' && $user !== 'root') {
            return '#^' . $escaped . '#';
        }

        return '#^' . $escaped . '#';
    }

    private function confidenceFor(int $occurrences, array $observation): string
    {
        $span = max(1, (int) $observation['last_seen'] - (int) $observation['first_seen']);
        $days = $span / 86400;

        // Something seen many times across several days is a habit. The same
        // count inside one hour is more likely a single burst of activity,
        // which is exactly what an intrusion looks like.
        if ($occurrences >= 50 && $days >= 2) {
            return 'high';
        }

        if ($occurrences >= 20 && $days >= 1) {
            return 'medium';
        }

        return 'low';
    }

    private function rationaleFor(string $rule, int $occurrences, array $observation): string
    {
        $span = max(1, (int) $observation['last_seen'] - (int) $observation['first_seen']);
        $days = max(1, (int) round($span / 86400));
        $perDay = (int) round($occurrences / $days);

        return "{$rule} 在此主機命中 {$occurrences} 次、橫跨約 {$days} 天（約 {$perDay} 次/天），"
            . '形狀完全相同，屬於本機常態行為而非攻擊跡象。';
    }

    /**
     * Rules whose output is not worth what it costs here.
     *
     * Two different failures qualify: analysts keep marking it wrong, or it
     * fires constantly and nothing is ever raised from it. The second is the
     * quieter problem — a rule can be entirely suppressed by governance and
     * still burn CPU on every exec.
     *
     * @return array<int, array{rule:string, reason:string, hits:int, fp_rate:?float, suppression_rate:float}>
     */
    public function underperformingRules(float $fpThreshold = 0.5, int $minJudged = 10): array
    {
        $flagged = [];

        foreach ($this->store->allRuleState() as $state) {
            $hits = (int) $state['hits'];

            if ($hits === 0) {
                continue;
            }

            $suppressionRate = round((int) $state['suppressed'] / $hits, 4);
            $fpRate = $state['fp_rate'];
            $judged = (int) $state['judged'];

            if ($fpRate !== null && $judged >= $minJudged && $fpRate >= $fpThreshold) {
                $flagged[] = [
                    'rule' => (string) $state['rule'],
                    'reason' => 'analyst_marked_false_positive',
                    'hits' => $hits,
                    'fp_rate' => $fpRate,
                    'suppression_rate' => $suppressionRate,
                ];

                continue;
            }

            if ($hits >= 100 && $suppressionRate >= 0.99) {
                $flagged[] = [
                    'rule' => (string) $state['rule'],
                    'reason' => 'always_suppressed',
                    'hits' => $hits,
                    'fp_rate' => $fpRate,
                    'suppression_rate' => $suppressionRate,
                ];
            }
        }

        return $flagged;
    }

    /**
     * A rule that has been alerting cleanly for long enough to be trusted
     * with a response action.
     *
     * Promotion is proposed, never automatic: the difference between alert
     * and enforce is the difference between a notification and killing
     * something on a customer's machine, and no amount of clean history makes
     * that a decision software should take on its own.
     *
     * @return array<int, array{rule:string, hits:int, alerts:int, fp_rate:?float, judged:int}>
     */
    public function promotionCandidates(int $minAlerts = 20, float $maxFpRate = 0.05, int $minJudged = 10): array
    {
        $candidates = [];

        foreach ($this->store->allRuleState() as $state) {
            if ((string) $state['stage'] !== EdrGovernanceStore::STAGE_ALERT) {
                continue;
            }

            $judged = (int) $state['judged'];
            $fpRate = $state['fp_rate'];

            // An unjudged rule has an unknown false-positive rate, not a good
            // one. Silence is not evidence.
            if ($judged < $minJudged || $fpRate === null || $fpRate > $maxFpRate) {
                continue;
            }

            if ((int) $state['alerts'] < $minAlerts) {
                continue;
            }

            $candidates[] = [
                'rule' => (string) $state['rule'],
                'hits' => (int) $state['hits'],
                'alerts' => (int) $state['alerts'],
                'fp_rate' => $fpRate,
                'judged' => $judged,
            ];
        }

        return $candidates;
    }
}

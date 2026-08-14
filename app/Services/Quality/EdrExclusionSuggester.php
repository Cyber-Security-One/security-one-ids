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

            $suggestion = [
                'rule' => $rule,
                'pattern' => $pattern,
                'occurrences' => $occurrences,
                'sample' => $observation['sample'] ?? null,
                'confidence' => $this->confidenceFor($occurrences, $observation),
                'rationale' => $this->rationaleFor($rule, $occurrences, $observation),
            ];

            // Emitted only when the exclusion should be narrowed to one
            // account, so a suggestion for root or an unknown user carries no
            // constraint rather than an empty one that reads like a constraint.
            $user = $this->userFor($observation);

            if ($user !== null) {
                $suggestion['user'] = $user;
            }

            $suggestions[] = $suggestion;

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
    /**
     * Build the exclusion pattern for an observed shape.
     *
     * The anchor is the whole difficulty here, and the first version got it
     * wrong in a way that made every suggestion inert.
     *
     * `EdrRuleEngine::isExcluded()` matches against the executable path and the
     * command line joined by a space, so the start of the haystack is the path.
     * This method takes its stable prefix from the *command line* and then
     * anchored it with `^` — which pinned a command-line fragment to the start
     * of a path. Measured against the real haystack
     * `/bin/sh sh -c -- 'stty 2> /dev/null'`, the emitted
     * `#^sh \-c \-\- .stty#` never matched, and neither did it with an empty
     * path, because the join leaves a leading space.
     *
     * The failure was completely silent. An operator approves a suggestion, the
     * Hub ships it, `setExclusions()` accepts it because the regex is
     * syntactically valid, and nothing is excluded. The only symptom is that the
     * noisy rule keeps firing — which reads as "the exclusion did not work
     * yet", not as "the exclusion cannot ever work".
     *
     * The fix keeps the anchor rather than dropping it, because an unanchored
     * command-line fragment is a bypass: anything that manages to put the
     * approved text anywhere in its own arguments would be excused. Instead the
     * pattern is anchored the way the haystack is actually shaped — an optional
     * directory prefix, the binary this was approved for, a space, then the
     * command-line prefix. Verified against the real sample, and verified to
     * refuse `/tmp/evil --arg="sh -c -- 'stty"`, which an unanchored form
     * accepts.
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

        // `(?:\S*/)?` is the directory part: present for /bin/sh, absent when
        // the sensor recorded a bare name. It cannot span a space, so it cannot
        // run past the path into the command line.
        $pattern = '#^(?:\S*/)?'
            . preg_quote($binary, '#')
            . '\s'
            . preg_quote($stable, '#')
            . '#';

        if (@preg_match($pattern, '') === false) {
            // Should not happen with quoted input, but an unusable pattern must
            // never be published: the Hub would accept it and it would sit in
            // the exclusion list doing nothing.
            return null;
        }

        return $pattern;
    }

    /**
     * The account an exclusion should be bound to, or null for all accounts.
     *
     * Approving a noisy shape for `www-data` must not also excuse the identical
     * command run by root — an attacker who can read the exclusion list would
     * otherwise be handed a way to run an approved command line as root and
     * have every rule ignore it.
     *
     * This was previously promised by a comment and by two branches that
     * returned the same string, so the property did not exist while appearing to.
     * The exclusion format now carries the constraint separately, which is what
     * made it expressible at all: the matched haystack is path plus command
     * line and has never contained the user.
     *
     * Root is deliberately not bound. An exclusion approved for something root
     * does is already as broad as it can be, and pinning it to `root` would
     * only invite the misreading that the binding narrows it.
     */
    private function userFor(array $observation): ?string
    {
        $parts = explode('|', (string) $observation['signature'], 4);

        if (count($parts) < 4) {
            return null;
        }

        $user = $parts[1];

        return ($user === '?' || $user === '' || $user === 'root') ? null : $user;
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

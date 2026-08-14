<?php

namespace App\Services\Correlation;

/**
 * One correlated incident, shaped into the finding contract the rest of the
 * pipeline already speaks.
 *
 * The output of a correlator is not a score. A score tells an analyst nothing
 * they can act on and nothing they can disagree with. What ships is the
 * arithmetic: which stages were reached, when each one first lit, which
 * individual events contributed how much, and how far past this actor's own
 * bar the total landed. Every number in the payload can be checked by hand,
 * which is what makes the detection arguable rather than oracular — and an
 * unarguable alert at 3 a.m. gets the feature switched off.
 *
 * Note which keys this deliberately does **not** set: `stage` and
 * `allow_response` belong to the rule-governance layer and mean something
 * else entirely there (rollout stage, and whether a rule has earned the right
 * to drive a response action). An incident carries `tactic` and `chain_key`
 * instead.
 */
final class EdrIncident
{
    public const RULE_ACTOR = 'EDR-100';
    public const RULE_HOST = 'EDR-101';
    public const RULE_STORM = 'EDR-102';

    private string $rule;
    private string $severity;
    private string $signature;
    private array $payload;
    private array $memberFindings;
    private int $anchorEventIndex;
    private array $absorbedEventIndexes;

    private function __construct(
        string $rule,
        string $severity,
        string $signature,
        array $payload,
        array $memberFindings,
        int $anchorEventIndex,
        array $absorbedEventIndexes
    ) {
        $this->rule = $rule;
        $this->severity = $severity;
        $this->signature = $signature;
        $this->payload = $payload;
        $this->memberFindings = $memberFindings;
        $this->anchorEventIndex = $anchorEventIndex;
        $this->absorbedEventIndexes = $absorbedEventIndexes;
    }

    /**
     * @param array  $actor    persisted actor state
     * @param array  $scored   output of EdrActorScorer::score()
     * @param array  $evidence redacted evidence rows, strongest first
     * @param array  $meta     rule, severity, threshold, mitre, corroboration, lane…
     */
    public static function fromActor(array $actor, array $scored, array $evidence, array $meta): self
    {
        $rule = (string) ($meta['rule'] ?? self::RULE_ACTOR);
        $threshold = (float) ($meta['threshold'] ?? 0.0);
        $score = (float) $scored['score'];

        $classNames = array_map(
            static fn (int $classId): string => EdrIntentClassifier::name($classId),
            $scored['lit']
        );

        $classDetail = [];

        foreach ($scored['lit'] as $classId) {
            $classDetail[] = [
                'class' => EdrIntentClassifier::name($classId),
                'accumulated' => round((float) ($actor['acc'][$classId] ?? 0.0), 3),
                'capped_at' => round((float) ($meta['caps'][$classId] ?? 0.0), 3),
                'first_lit' => (int) ($actor['class_first_ts'][$classId] ?? 0),
            ];
        }

        $payload = [
            'lane' => (string) ($meta['lane'] ?? 'actor'),
            'chain_key' => (string) $actor['actor_key'],
            'anchor_kind' => (string) $actor['anchor_kind'],
            'score' => round($score, 3),
            'threshold' => round($threshold, 3),
            'ratio' => $threshold > 0.0 ? round($score / $threshold, 3) : null,
            'capped_sum' => round((float) $scored['sum'], 3),
            'ordering_bonus' => round((float) $scored['ordering'], 3),
            'ordering_ratio' => round((float) $scored['ratio'], 3),
            'classes' => $classNames,
            'class_detail' => $classDetail,
            'tactic' => $classNames === [] ? null : $classNames[0],
            'events_contributing' => (int) $actor['event_count'],
            'strongest_event_charge' => round((float) $actor['max_charge'], 3),
            'first_seen' => (int) $actor['first_ts'],
            'last_seen' => (int) $actor['last_ts'],
            'novelty_rate' => round((float) $actor['nov'], 3),
            // How much of this incident rests on findings the governance layer
            // was willing to raise on their own. 'weak' means every
            // contributing finding was suppressed — still worth reporting as a
            // pattern, not worth waking anyone for.
            'corroboration' => (string) ($meta['corroboration'] ?? 'none'),
            'member_response_allowed' => (bool) ($meta['member_response_allowed'] ?? false),
            'lineage' => (string) ($meta['lineage'] ?? 'linked'),
            'mitre' => $meta['mitre'] ?? [],
            'evidence' => $evidence,
        ];

        if (!empty($meta['contributors'])) {
            $payload['contributing_actors'] = $meta['contributors'];
        }

        if (!empty($meta['warmup'])) {
            $payload['warmup_withheld'] = true;
        }

        return new self(
            $rule,
            (string) ($meta['severity'] ?? 'medium'),
            (string) ($meta['signature'] ?? ''),
            $payload,
            $meta['member_findings'] ?? [],
            (int) ($meta['anchor_event_index'] ?? -1),
            $meta['absorbed_event_indexes'] ?? []
        );
    }

    /**
     * The finding array, in the same shape every rule produces.
     */
    public function toFinding(): array
    {
        $classes = $this->payload['classes'] ?? [];

        return [
            'rule' => $this->rule,
            'name' => $this->rule === self::RULE_HOST
                ? 'Correlated activity across multiple entry points'
                : 'Correlated intrusion chain',
            'severity' => $this->severity,
            // The finding contract carries one technique; the full set travels
            // in the incident block.
            'mitre' => $this->payload['mitre'][0] ?? 'T1059',
            'reason' => $this->reason(),
            // Namespaced to avoid colliding with the governance layer's keys.
            'chain_key' => $this->payload['chain_key'],
            'tactic' => $this->payload['tactic'],
            'incident' => $this->payload,
        ];
    }

    /**
     * A sentence an analyst can read without opening the payload.
     *
     * Structural only — no command lines. Evidence carries those, and evidence
     * has been through redaction.
     */
    private function reason(): string
    {
        $classes = $this->payload['classes'] ?? [];
        $count = count($classes);

        return sprintf(
            '%s reached %d kill-chain stage%s (%s) scoring %.1f against a threshold of %.1f, '
            . 'across %d contributing event%s since %s',
            $this->payload['lane'] === 'host'
                ? 'Activity on this host, across several entry points,'
                : ucfirst((string) $this->payload['anchor_kind']) . '-anchored activity',
            $count,
            $count === 1 ? '' : 's',
            implode(' → ', $classes),
            $this->payload['score'],
            $this->payload['threshold'],
            $this->payload['events_contributing'],
            $this->payload['events_contributing'] === 1 ? '' : 's',
            date('c', (int) $this->payload['first_seen'])
        );
    }

    public function rule(): string
    {
        return $this->rule;
    }

    public function severity(): string
    {
        return $this->severity;
    }

    public function signature(): string
    {
        return $this->signature;
    }

    public function score(): float
    {
        return (float) $this->payload['score'];
    }

    public function payload(): array
    {
        return $this->payload;
    }

    /** Findings that contributed, for the AND-of-permissions calculation. */
    public function memberFindings(): array
    {
        return $this->memberFindings;
    }

    /** Index of the event the incident should be reported against. */
    public function anchorEventIndex(): int
    {
        return $this->anchorEventIndex;
    }

    /** @return int[] */
    public function absorbedEventIndexes(): array
    {
        return $this->absorbedEventIndexes;
    }
}

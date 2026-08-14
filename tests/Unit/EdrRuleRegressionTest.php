<?php

namespace Tests\Unit;

use App\Services\Quality\EdrRuleRegression;
use Tests\TestCase;

/**
 * The corpus is the safety net for tuning.
 *
 * Every change that narrows a rule to stop a false positive is one edit away
 * from narrowing it past the attack it was written for. That has already
 * happened in this codebase: a `\b` that does not match between a space and a
 * dash meant `--password=` was never redacted at all, and nothing noticed
 * because nothing was checking.
 */
class EdrRuleRegressionTest extends TestCase
{
    public function test_the_whole_corpus_passes(): void
    {
        $result = (new EdrRuleRegression())->run();

        $messages = array_map(
            static fn (array $failure): string => sprintf(
                '%s: %s — expected %s, got %s (%s)',
                $failure['kind'],
                $failure['name'],
                $failure['expected'],
                $failure['actual'],
                $failure['cmdline']
            ),
            $result['failures']
        );

        $this->assertSame(0, $result['failed'], implode("\n", $messages));
        $this->assertGreaterThan(30, $result['total'], 'the corpus should not quietly shrink');
    }

    /**
     * Untested detection content is how a rule set rots: it keeps passing
     * because nothing asks it anything.
     */
    public function test_every_rule_has_at_least_one_case(): void
    {
        $known = [
            'EDR-001', 'EDR-002', 'EDR-003', 'EDR-004', 'EDR-005', 'EDR-006',
            'EDR-007', 'EDR-008', 'EDR-009', 'EDR-010', 'EDR-011', 'EDR-012',
        ];

        $untested = (new EdrRuleRegression())->untestedRules($known);

        $this->assertSame([], $untested, 'rules without a corpus case: ' . implode(', ', $untested));
    }

    /**
     * The corpus is only worth something if it holds both halves of the
     * trade — the attacks and the benign commands that previously misfired.
     */
    public function test_the_corpus_covers_both_directions(): void
    {
        $regression = new EdrRuleRegression();
        $corpus = $regression->corpus();

        $attacks = array_filter($corpus, static fn (array $case): bool => $case['expect'] !== null);
        $benign = array_filter($corpus, static fn (array $case): bool => $case['expect'] === null);

        $this->assertGreaterThanOrEqual(20, count($attacks));
        $this->assertGreaterThanOrEqual(8, count($benign), 'the false-positive half is what stops over-tuning');
    }

    /**
     * Cross-event rules cannot be expressed as single events, and leaving
     * them out would make them the only rules nobody ever checks.
     */
    public function test_batch_rules_are_exercised_in_both_directions(): void
    {
        $batch = (new EdrRuleRegression())->batchCorpus();

        $this->assertNotEmpty($batch);
        $this->assertContains(null, array_column($batch, 'expect'), 'a below-threshold case must exist');
        $this->assertContains('EDR-012', array_column($batch, 'expect'));
    }
}

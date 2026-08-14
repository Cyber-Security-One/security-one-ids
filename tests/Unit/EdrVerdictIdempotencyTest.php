<?php

namespace Tests\Unit;

use App\Services\Quality\EdrGovernanceStore;
use App\Services\WafSyncService;
use Tests\TestCase;

/**
 * Analyst verdicts are counted, and the config blob that carries them is read
 * on every sync cycle.
 *
 * That combination is a trap, and it is the kind that corrupts the one number
 * the whole quality layer rests on. `recordVerdict()` increments; the agent
 * re-reads `addons.edr_rule_verdicts` every thirty seconds; so a single
 * analyst marking a single rule wrong once became 2,880 false positives a day.
 * And the false-positive rate is not decoration — it decides whether a rule
 * keeps running, so one click would have quietly retired a working detection
 * while every dashboard agreed the rule was terrible.
 */
class EdrVerdictIdempotencyTest extends TestCase
{
    private string $path;
    private EdrGovernanceStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-verdict-' . uniqid() . '.sqlite';
        $this->store = new EdrGovernanceStore($this->path);

        $this->app->instance(EdrGovernanceStore::class, $this->store);
    }

    protected function tearDown(): void
    {
        $this->store->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    /**
     * Drive the private applier the way a sync cycle does.
     */
    private function apply(array $verdicts): void
    {
        $sync = app(WafSyncService::class);

        $method = new \ReflectionMethod($sync, 'applyEdrRuleVerdicts');
        $method->setAccessible(true);
        $method->invoke($sync, ['edr_rule_verdicts' => $verdicts]);
    }

    private function falsePositives(string $rule): int
    {
        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);

        $stmt = $pdo->prepare('SELECT false_positives FROM rule_state WHERE rule = ?');
        $stmt->execute([$rule]);

        return (int) $stmt->fetchColumn();
    }

    /**
     * One verdict, a hundred cycles, one false positive.
     */
    public function test_a_verdict_with_an_id_is_counted_once_however_often_it_is_resent(): void
    {
        $verdicts = [['id' => 'v-2026-08-14-001', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 1]];

        for ($cycle = 0; $cycle < 100; $cycle++) {
            $this->apply($verdicts);
        }

        $this->assertSame(
            1,
            $this->falsePositives('EDR-001'),
            'A hundred sync cycles must not turn one analyst click into a hundred false positives'
        );
    }

    /**
     * Distinct verdicts on the same rule are distinct evidence and must all
     * count — the guard is about replay, not about deduplicating opinions.
     */
    public function test_distinct_verdicts_on_the_same_rule_all_count(): void
    {
        $this->apply([['id' => 'v-1', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 1]]);
        $this->apply([['id' => 'v-2', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 1]]);
        $this->apply([['id' => 'v-3', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 2]]);

        $this->assertSame(4, $this->falsePositives('EDR-001'));

        // And resending all three changes nothing.
        $this->apply([
            ['id' => 'v-1', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 1],
            ['id' => 'v-2', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 1],
            ['id' => 'v-3', 'rule' => 'EDR-001', 'false_positive' => true, 'count' => 2],
        ]);

        $this->assertSame(4, $this->falsePositives('EDR-001'));
    }

    /**
     * A Hub that has not adopted ids yet must still be safe by default: the
     * batch is applied once per distinct blob rather than once per cycle.
     */
    public function test_a_batch_without_ids_is_applied_once_per_distinct_batch(): void
    {
        $verdicts = [['rule' => 'EDR-006', 'false_positive' => true, 'count' => 1]];

        for ($cycle = 0; $cycle < 50; $cycle++) {
            $this->apply($verdicts);
        }

        $this->assertSame(
            1,
            $this->falsePositives('EDR-006'),
            'Without ids the blob hash is the only guard, and it must hold'
        );

        // A genuinely different batch still lands.
        $this->apply([['rule' => 'EDR-006', 'false_positive' => true, 'count' => 3]]);

        $this->assertSame(4, $this->falsePositives('EDR-006'));
    }

    /**
     * True positives are counted on their own column and are equally
     * protected — a rule that looks perfect because its confirmations were
     * replayed is as misleading as one that looks broken.
     */
    public function test_true_positives_are_protected_too(): void
    {
        $verdicts = [['id' => 'tp-1', 'rule' => 'EDR-002', 'false_positive' => false, 'count' => 1]];

        for ($cycle = 0; $cycle < 20; $cycle++) {
            $this->apply($verdicts);
        }

        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);
        $stmt = $pdo->prepare('SELECT true_positives, false_positives FROM rule_state WHERE rule = ?');
        $stmt->execute(['EDR-002']);
        $row = $stmt->fetch();

        $this->assertSame(1, (int) $row['true_positives']);
        $this->assertSame(0, (int) $row['false_positives']);
    }
}

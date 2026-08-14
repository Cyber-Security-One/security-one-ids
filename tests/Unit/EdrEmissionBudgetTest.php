<?php

namespace Tests\Unit;

use App\Services\Correlation\EdrCorrelatorStore;
use App\Services\Correlation\EdrEmissionBudget;
use Tests\TestCase;

/**
 * The alert-volume contract.
 *
 * This class is what turns "how many alerts does this host produce" from an
 * emergent property into a configured number, so its failure modes are not
 * subtle: too permissive and the correlator floods an analyst; too aggressive
 * and it silently eats real detections. It also had no test at all until an
 * adversarial review pointed out that four separate fixes had landed in it,
 * including one that doubled its queue on every cycle.
 */
class EdrEmissionBudgetTest extends TestCase
{
    private const T0 = 1700000000;

    private string $path;
    private EdrCorrelatorStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-budget-' . uniqid() . '.sqlite';
        $this->store = new EdrCorrelatorStore($this->path);
    }

    protected function tearDown(): void
    {
        $this->store->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function budget(array $config = []): EdrEmissionBudget
    {
        return new EdrEmissionBudget($this->store, array_merge([
            'bucket_capacity' => 2,
            'bucket_per_day' => 1,
            'daily_cap' => 20,
        ], $config));
    }

    private function candidate(string $actor, float $score = 30.0, int $ts = self::T0): array
    {
        return ['actor_key' => $actor, 'score' => $score, 'threshold' => 18.0, 'ts' => $ts];
    }

    private function queueDepth(): int
    {
        return count((array) json_decode((string) $this->store->getMeta('deferred', '[]'), true));
    }

    /**
     * The critical one: a queue that grows when nothing is happening.
     *
     * Rebuilding the queue by merging survivors into a list that still held
     * them doubled it every cycle, and the break that triggered it was taken
     * on exactly the condition that caused the deferral in the first place.
     * The observed shape was 4, 8, 16 ... 131072 entries and a state blob
     * growing past ten megabytes inside sixteen cycles — at which point the
     * process dies on memory_limit, which is a fatal rather than a Throwable,
     * so the fail-closed handler never even runs.
     */
    public function test_the_deferral_queue_never_grows_while_starved(): void
    {
        $budget = $this->budget();
        $budget->refill(self::T0);

        // Spend the bucket, then defer three distinct actors.
        $this->assertTrue($budget->admit($this->candidate('a'), false, self::T0));
        $this->assertTrue($budget->admit($this->candidate('b'), false, self::T0));

        foreach (['c', 'd', 'e'] as $actor) {
            $this->assertFalse($budget->admit($this->candidate($actor), false, self::T0));
        }

        $budget->persist();
        $depth = $this->queueDepth();

        $this->assertSame(3, $depth, 'Three deferrals, three queue entries');

        // Twenty cycles where nothing can be shaped and no tokens arrive.
        for ($cycle = 1; $cycle <= 20; $cycle++) {
            $budget = $this->budget();
            $budget->refill(self::T0 + $cycle * 30);
            $released = $budget->release(self::T0 + $cycle * 30, static fn (array $c): ?array => null);
            $budget->persist();

            $this->assertSame([], $released);
            $this->assertLessThanOrEqual(
                $depth,
                $this->queueDepth(),
                "Queue grew on cycle {$cycle}"
            );
        }
    }

    /**
     * One entry per actor. A chain sitting over its threshold with an empty
     * bucket is re-evaluated every thirty seconds, and the cooldown gate
     * cannot stop it because it has never actually emitted — so without
     * deduplication the queue fills with copies of one incident and then
     * releases every copy as a separate alert.
     */
    public function test_one_actor_occupies_one_queue_slot(): void
    {
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 1]);
        $budget->refill(self::T0);

        $budget->admit($this->candidate('spender'), false, self::T0);

        for ($i = 0; $i < 50; $i++) {
            $budget->admit($this->candidate('chain', 25.0 + $i, self::T0 + $i * 30), false, self::T0 + $i * 30);
        }

        $budget->persist();

        $this->assertSame(1, $this->queueDepth(), 'Fifty re-deferrals of one chain are one incident');

        $queue = (array) json_decode((string) $this->store->getMeta('deferred', '[]'), true);

        $this->assertEqualsWithDelta(74.0, $queue[0]['score'], 1e-9, 'The strongest observation is kept');
        $this->assertSame(self::T0, (int) $queue[0]['ts'], 'The deadline runs from when it first qualified');
    }

    /**
     * A candidate that cannot be shaped yet must survive to its deadline.
     *
     * Writing the age-decayed score back onto the queued entry applied the
     * decay again on the next cycle, compounding it once every thirty seconds
     * and killing a candidate in minutes instead of the six hours the
     * deferral window promises.
     */
    public function test_a_requeued_candidate_does_not_decay_faster_than_the_clock(): void
    {
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 1]);
        $budget->refill(self::T0);

        $budget->admit($this->candidate('spender'), false, self::T0);
        $budget->admit($this->candidate('patient', 40.0, self::T0), false, self::T0);
        $budget->persist();

        // An hour of cycles where the actor never comes back.
        for ($cycle = 1; $cycle <= 120; $cycle++) {
            $budget = $this->budget();
            $ts = self::T0 + $cycle * 30;
            $budget->refill($ts);
            $budget->release($ts, static fn (array $c): ?array => null);
            $budget->persist();
        }

        $queue = (array) json_decode((string) $this->store->getMeta('deferred', '[]'), true);

        $this->assertCount(1, $queue, 'An hour of waiting must not discard a candidate');
        $this->assertEqualsWithDelta(
            40.0,
            (float) $queue[0]['score'],
            1e-9,
            'The stored score is the observation, not a running decay'
        );
    }

    /**
     * A finding the governance layer already agreed to raise was going to be
     * sent anyway; the correlator is only adding context. Budgeting those
     * would let this component suppress existing coverage, which it must
     * never do.
     */
    public function test_rule_backed_incidents_bypass_the_bucket(): void
    {
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 1]);
        $budget->refill(self::T0);

        $this->assertTrue($budget->admit($this->candidate('novelty'), false, self::T0));
        $this->assertFalse($budget->admit($this->candidate('novelty-2'), false, self::T0));

        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue(
                $budget->admit($this->candidate('rule-backed-' . $i), true, self::T0),
                'A rule-backed incident must never be held by the bucket'
            );
        }
    }

    /**
     * The budget must cost you the weakest evidence, never the strongest.
     */
    public function test_release_prefers_the_strongest_candidates(): void
    {
        // A token an hour, so one refills well inside the deferral window.
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 24]);
        $budget->refill(self::T0);

        $budget->admit($this->candidate('spender'), false, self::T0);

        foreach ([['weak', 19.0], ['strong', 44.0], ['middling', 30.0]] as [$actor, $score]) {
            $budget->admit($this->candidate($actor, $score), false, self::T0);
        }

        $budget->persist();

        // An hour later: one token has refilled, and the candidates are still
        // inside MAX_DEFERRAL.
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 24]);
        $ts = self::T0 + 3600;
        $budget->refill($ts);

        $released = $budget->release($ts, static fn (array $c): ?array => ['actor' => $c['actor_key']]);

        $this->assertNotEmpty($released);
        $this->assertSame('strong', $released[0]['actor'], 'The strongest candidate is released first');
    }

    /**
     * Once an actor has been reported through the direct path, anything queued
     * for it is redundant — and releasing it anyway produced two identical
     * incidents whose only difference was a flag.
     */
    public function test_forget_removes_a_queued_actor(): void
    {
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 1]);
        $budget->refill(self::T0);

        $budget->admit($this->candidate('spender'), false, self::T0);
        $budget->admit($this->candidate('reported'), false, self::T0);
        $budget->persist();

        $this->assertSame(1, $this->queueDepth());

        $budget->forget('reported');
        $budget->persist();

        $this->assertSame(0, $this->queueDepth(), 'A reported actor leaves the queue');
    }

    /**
     * What was withheld has to be countable. A product that says "this host is
     * allowed N alerts a day, and here is what it held back" is answerable; one
     * that silently truncates reads as full coverage when it is not.
     */
    public function test_withheld_work_is_reported(): void
    {
        $budget = $this->budget(['bucket_capacity' => 1, 'bucket_per_day' => 1]);
        $budget->refill(self::T0);

        $budget->admit($this->candidate('spender'), false, self::T0);

        for ($i = 0; $i < 40; $i++) {
            $budget->admit($this->candidate('held-' . $i, 20.0 + $i), false, self::T0);
        }

        $counters = $budget->counters();

        $this->assertLessThanOrEqual(
            EdrEmissionBudget::HEAP_SLOTS,
            $counters['deferred'],
            'The queue is bounded'
        );
        $this->assertGreaterThan(
            0,
            $counters['deferred_dropped'],
            'Anything dropped for want of room must be counted, not hidden'
        );
    }
}

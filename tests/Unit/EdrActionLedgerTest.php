<?php

namespace Tests\Unit;

use App\Services\Response\EdrActionLedger;
use Tests\TestCase;

/**
 * The ledger is what makes response defensible. After an incident someone
 * will ask who did what, when, why, and whether it was undone — an action
 * with no record here did not happen safely.
 */
class EdrActionLedgerTest extends TestCase
{
    private string $path;
    private EdrActionLedger $ledger;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-ledger-' . uniqid() . '.sqlite';
        $this->ledger = new EdrActionLedger($this->path);
    }

    protected function tearDown(): void
    {
        $this->ledger->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    public function test_records_and_reads_back_an_action(): void
    {
        $this->assertTrue($this->ledger->record(
            'a1',
            'kill_process',
            ['pid' => 123],
            'EDR-002 reverse shell',
            'hub',
            false,
            null
        ));

        $action = $this->ledger->find('a1');

        $this->assertNotNull($action);
        $this->assertSame(EdrActionLedger::STATE_PENDING, $action['state']);
        $this->assertSame(123, $action['target']['pid']);
        $this->assertFalse($action['reversible'], 'a kill is not reversible and must say so');
    }

    /**
     * The Hub resends commands it never saw acknowledged. Without the unique
     * key, a redelivery would be a second kill.
     */
    public function test_duplicate_action_id_is_rejected(): void
    {
        $this->ledger->record('a1', 'kill_process', ['pid' => 123], null, 'hub', false, null);

        $this->assertFalse($this->ledger->record('a1', 'kill_process', ['pid' => 123], null, 'hub', false, null));
        $this->assertCount(1, $this->ledger->recent(10));
    }

    public function test_state_transitions_carry_their_evidence(): void
    {
        $this->ledger->record('a1', 'kill_process', ['pid' => 123], null, 'hub', false, null);
        $this->ledger->markApplied('a1', ['killed' => true, 'pid' => 123]);

        $applied = $this->ledger->find('a1');
        $this->assertSame(EdrActionLedger::STATE_APPLIED, $applied['state']);
        $this->assertTrue($applied['result']['killed']);
        $this->assertCount(1, $this->ledger->applied());

        $this->ledger->record('a2', 'quarantine_file', ['path' => '/tmp/x'], null, 'hub', true, null);
        $this->ledger->markFailed('a2', 'permission denied');
        $this->assertSame('permission denied', $this->ledger->find('a2')['error']);
    }

    /**
     * Everything needed to undo an action lives with it, so a rollback works
     * after a restart, without the Hub, and without the original alert.
     */
    public function test_restore_data_survives_for_reversal(): void
    {
        $this->ledger->record('a1', 'isolate_network', ['scope' => 'all'], null, 'hub', true, time() + 600);
        $this->ledger->markApplied('a1', ['chain' => 'SECONE_EDR'], ['chain' => 'SECONE_EDR', 'rules' => 3]);

        $this->assertSame(3, $this->ledger->find('a1')['restore_data']['rules']);
    }

    public function test_only_expired_deadlines_are_due_for_rollback(): void
    {
        $this->ledger->record('past', 'isolate_network', [], null, 'hub', true, time() - 1);
        $this->ledger->markApplied('past', []);

        $this->ledger->record('future', 'isolate_network', [], null, 'hub', true, time() + 600);
        $this->ledger->markApplied('future', []);

        $this->ledger->record('never', 'kill_process', [], null, 'hub', false, null);
        $this->ledger->markApplied('never', []);

        $due = array_column($this->ledger->dueForExpiry(), 'action_id');

        $this->assertContains('past', $due);
        $this->assertNotContains('future', $due);
        $this->assertNotContains('never', $due, 'an action with no deadline must never auto-revert');
    }

    /**
     * A Hub confirmation keeps an isolation in place instead of letting the
     * safety timer undo it.
     */
    public function test_confirmation_extends_the_deadline(): void
    {
        $this->ledger->record('a1', 'isolate_network', [], null, 'hub', true, time() - 1);
        $this->ledger->markApplied('a1', []);

        $this->assertContains('a1', array_column($this->ledger->dueForExpiry(), 'action_id'));

        $this->ledger->extendExpiry('a1', time() + 3600);

        $this->assertNotContains('a1', array_column($this->ledger->dueForExpiry(), 'action_id'));
    }

    /**
     * Actions taken while the Hub was unreachable must stay queued for
     * acknowledgement rather than vanishing.
     */
    public function test_resolved_actions_queue_for_reporting(): void
    {
        $this->ledger->record('done', 'kill_process', [], null, 'hub', false, null);
        $this->ledger->markApplied('done', []);

        $this->ledger->record('waiting', 'kill_process', [], null, 'hub', false, null);

        $unreported = array_column($this->ledger->unreported(), 'action_id');

        $this->assertContains('done', $unreported);
        $this->assertNotContains('waiting', $unreported, 'an unexecuted action has no outcome to report');

        $this->ledger->markReported(['done']);
        $this->assertCount(0, $this->ledger->unreported());
    }

    /**
     * A crash mid-execution leaves a pending row. We do not know whether the
     * side effect landed, so it needs surfacing rather than a silent retry.
     */
    public function test_stale_pending_actions_are_surfaced(): void
    {
        $this->ledger->record('a1', 'kill_process', ['pid' => 999], null, 'hub', false, null);

        $this->assertCount(0, $this->ledger->stalePending(300));

        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->exec('UPDATE actions SET created_at = ' . (time() - 3600));
        $pdo = null;

        $this->assertSame(['a1'], array_column($this->ledger->stalePending(300), 'action_id'));
    }
}

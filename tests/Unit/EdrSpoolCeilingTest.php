<?php

namespace Tests\Unit;

use App\Services\EdrEventSpool;
use Tests\TestCase;

/**
 * The row ceiling must never be met by deleting alerts nobody has seen.
 *
 * This is the spool's whole reason for existing. The collector's job is to get
 * events onto disk so that a Hub outage becomes a delay instead of data loss —
 * and the row ceiling was quietly undoing exactly that. Age-based pruning
 * protected queued alerts; the ceiling did not, and on this host the ceiling
 * fired five hundred times in one day. Queued alerts are the oldest
 * undelivered rows, so during an outage they sit precisely in the range the
 * ceiling deletes first: they would disappear and `pending` would fall back to
 * zero, which is indistinguishable from a successful delivery.
 */
class EdrSpoolCeilingTest extends TestCase
{
    private string $path;
    private EdrEventSpool $spool;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-ceiling-' . uniqid() . '.sqlite';
        $this->spool = new EdrEventSpool($this->path);
    }

    protected function tearDown(): void
    {
        $this->spool->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function event(int $pid, int $ts): array
    {
        return [
            'ts' => $ts,
            'action' => 'exec',
            'sensor' => 'osquery',
            'host' => 'ceiling-01',
            'pid' => $pid,
            'ppid' => 1,
            'uid' => 0,
            'username' => 'root',
            'path' => '/usr/bin/legit',
            'cmdline' => 'legit',
            'cwd' => '/',
            'container_id' => '',
            'syscall' => 'exec',
        ];
    }

    private function finding(): array
    {
        return [[
            'rule' => 'EDR-002',
            'name' => 'Reverse shell pattern',
            'severity' => 'critical',
            'mitre' => 'T1059',
            'reason' => 'test',
        ]];
    }

    /**
     * The oldest rows are the ones the ceiling deletes, and during an outage
     * the oldest rows are the queued alerts.
     */
    public function test_the_row_ceiling_never_deletes_an_undelivered_alert(): void
    {
        $base = time() - 7200;

        // Ten alerts, queued first — so they are the oldest rows in the spool
        // and sit exactly where the ceiling starts deleting.
        for ($i = 0; $i < 10; $i++) {
            $this->spool->store([$this->event(1000 + $i, $base + $i)], [0 => $this->finding()]);
        }

        $this->assertSame(10, $this->spool->stats()['pending'], 'The alerts must start queued');

        // Then a flood of ordinary telemetry, as a busy host produces. The
        // ceiling has a floor of 10,000 rows, so the fixture has to be large
        // enough to actually cross it — on the real host it is crossed every
        // few minutes.
        $batch = [];
        for ($i = 0; $i < 10500; $i++) {
            $batch[] = $this->event(5000 + $i, $base + 100 + $i);
        }
        $this->spool->store($batch);

        $result = $this->spool->prune(7, 10000);

        $stats = $this->spool->stats();

        $this->assertSame(
            10,
            $stats['pending'],
            'Every queued alert must survive — losing one is the failure the spool exists to prevent'
        );
        $this->assertGreaterThan(0, $result['deleted_by_count'], 'Ordinary telemetry is still trimmed');

        // And they are still renderable, not just counted.
        $this->assertCount(10, $this->spool->pending(100));
    }

    /**
     * When the queue alone exceeds the ceiling, the answer is to say so — not
     * to delete the queue until the number looks right.
     */
    public function test_an_unmeetable_ceiling_is_reported_rather_than_forced(): void
    {
        $base = time() - 3600;

        // A delivery queue larger than the ceiling itself: a Hub that has been
        // unreachable long enough for the backlog alone to fill the buffer.
        $batch = [];
        $findings = [];
        for ($i = 0; $i < 10500; $i++) {
            $batch[] = $this->event(2000 + $i, $base + $i);
            $findings[$i] = $this->finding();
        }
        $this->spool->store($batch, $findings);

        $this->spool->prune(7, 10000);

        $stats = $this->spool->stats();

        $this->assertSame(10500, $stats['pending'], 'A backlog larger than the ceiling is still a backlog');
        $this->assertGreaterThan(
            10000,
            $stats['total'],
            'The spool stays over its ceiling rather than discarding undelivered alerts to reach it'
        );
    }

    /**
     * Delivered rows are ordinary history and remain fair game, or the ceiling
     * would stop bounding anything on a host whose Hub is healthy.
     */
    public function test_delivered_alerts_are_still_trimmable(): void
    {
        $base = time() - 3600;

        $batch = [];
        $findings = [];
        for ($i = 0; $i < 10500; $i++) {
            $batch[] = $this->event(3000 + $i, $base + $i);
            $findings[$i] = $this->finding();
        }
        $this->spool->store($batch, $findings);

        $ids = array_column($this->spool->pending(20000), 'id');
        $this->spool->markSent($ids);

        $this->assertSame(0, $this->spool->stats()['pending']);

        $this->spool->prune(7, 10000);

        $this->assertLessThanOrEqual(
            10000,
            $this->spool->stats()['total'],
            'Once delivered, an alert is history and the ceiling applies to it normally'
        );
    }
}

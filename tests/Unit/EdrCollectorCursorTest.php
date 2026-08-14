<?php

namespace Tests\Unit;

use App\Services\Detection\OsqueryEngine;
use App\Services\EdrAlertFactory;
use App\Services\EdrEventCollector;
use App\Services\EdrEventSpool;
use App\Services\EdrRuleEngine;
use Tests\TestCase;

/**
 * The cursor decides which sensor output has been handled. Every bug in it is
 * silent — the agent keeps running and simply stops seeing part of what
 * happened on the host — so each failure mode gets pinned here.
 */
class EdrCollectorCursorTest extends TestCase
{
    private string $dir;
    private string $logPath;
    private string $spoolPath;
    private string $statePath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/edr-cursor-' . uniqid();
        mkdir($this->dir);

        $this->logPath = $this->dir . '/osqueryd.results.log';
        $this->spoolPath = $this->dir . '/spool.sqlite';
        $this->statePath = storage_path('app/edr_log_position.json');

        @unlink($this->statePath);
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
        @unlink($this->statePath);

        parent::tearDown();
    }

    private function engine(): OsqueryEngine
    {
        return new class($this->logPath) extends OsqueryEngine {
            private string $logPath;

            public function __construct(string $logPath)
            {
                parent::__construct();
                $this->logPath = $logPath;
            }

            public function getResultsLogPath(): string
            {
                return $this->logPath;
            }

            public function isRunning(): bool
            {
                return true;
            }

            public function resolveBackend(): string
            {
                return 'bpf';
            }
        };
    }

    private function collector(?string $spoolPath = null): EdrEventCollector
    {
        return new EdrEventCollector(
            $this->engine(),
            new EdrRuleEngine(),
            new EdrEventSpool($spoolPath ?? $this->spoolPath),
            new EdrAlertFactory()
        );
    }

    private function line(int $pid, string $cmdline): string
    {
        return json_encode([
            'name' => 'process_exec',
            'hostIdentifier' => 'test',
            'unixTime' => time(),
            'action' => 'added',
            'columns' => [
                'pid' => $pid,
                'parent' => 1,
                'uid' => 0,
                'gid' => 0,
                'path' => '/bin/testbin',
                'cmdline' => $cmdline,
                'cwd' => '/tmp',
                'cid' => '',
                'syscall' => 'exec',
                'exit_code' => '0',
            ],
        ]) . "\n";
    }

    /**
     * osquery may be mid-write when we read. Advancing past half a JSON
     * object would drop that event permanently.
     */
    public function test_partial_trailing_line_is_not_consumed(): void
    {
        $complete = $this->line(101, 'complete-one');
        $split = $this->line(102, 'now-complete');

        file_put_contents($this->logPath, $complete);
        file_put_contents($this->logPath, substr($split, 0, 40), FILE_APPEND);

        $result = $this->collector()->collect(['spool_enabled' => true]);

        $this->assertSame(1, $result['stats']['events'], 'only the complete line should be read');

        $cursor = json_decode((string) file_get_contents($this->statePath), true);
        $this->assertSame(strlen($complete), $cursor['position'], 'cursor must stop before the partial line');

        // Once the writer finishes the line, the next cycle picks it up.
        file_put_contents($this->logPath, substr($split, 40), FILE_APPEND);

        $result = $this->collector()->collect(['spool_enabled' => true]);
        $this->assertSame(1, $result['stats']['events'], 'the completed line must be read next cycle');
    }

    /**
     * Events written between the last read and a rotation live only in the
     * rotated file. Following the inode is what stops a rotation quietly
     * eating a cycle's worth of telemetry.
     */
    public function test_rotation_drains_the_tail_of_the_old_file(): void
    {
        file_put_contents($this->logPath, $this->line(201, 'before-read'));
        $this->collector()->collect(['spool_enabled' => true]);

        // Written but not yet read, then rotated away.
        file_put_contents($this->logPath, $this->line(202, 'written-then-rotated'), FILE_APPEND);
        rename($this->logPath, $this->logPath . '.1');
        file_put_contents($this->logPath, $this->line(203, 'in-new-file'));

        $result = $this->collector()->collect(['spool_enabled' => true]);

        $this->assertSame(2, $result['stats']['events'], 'old tail plus new file');

        $spool = new EdrEventSpool($this->spoolPath);
        $cmdlines = array_column($spool->query(['limit' => 20]), 'cmdline');
        $spool->close();

        $this->assertContains('written-then-rotated', $cmdlines, 'the rotated tail must not be lost');
        $this->assertContains('in-new-file', $cmdlines);
    }

    /**
     * The cursor is committed only after the batch is durably spooled, so a
     * failed write means re-reading (cheap) rather than a gap (unrecoverable).
     */
    public function test_cursor_does_not_advance_when_the_spool_write_fails(): void
    {
        file_put_contents($this->logPath, $this->line(301, 'must-be-rereadable'));

        $this->collector('/proc/definitely-not-writable/spool.sqlite')
            ->collect(['spool_enabled' => true]);

        $this->assertFileDoesNotExist($this->statePath, 'cursor must not advance past unspooled events');

        $result = $this->collector()->collect(['spool_enabled' => true]);
        $this->assertSame(1, $result['stats']['events'], 'the event must still be readable next cycle');
    }

    public function test_truncation_in_place_restarts_from_the_top(): void
    {
        file_put_contents($this->logPath, $this->line(401, 'first'));
        $this->collector()->collect(['spool_enabled' => true]);

        // Same inode, smaller file — a truncate, not a rotation.
        $handle = fopen($this->logPath, 'r+');
        ftruncate($handle, 0);
        fclose($handle);
        file_put_contents($this->logPath, $this->line(402, 'after-truncate'));

        $result = $this->collector()->collect(['spool_enabled' => true]);

        $this->assertSame(1, $result['stats']['events']);
    }
}

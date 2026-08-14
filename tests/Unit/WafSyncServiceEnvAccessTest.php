<?php

namespace Tests\Unit;

use App\Services\WafSyncService;
use Tests\TestCase;

/**
 * An unreadable .env must not kill the command.
 *
 * The file holds the agent token, so it is root-only by design. But the
 * fallback that reads it guarded on `file_exists()`, which returns true for a
 * file the current user cannot open — so `parse_ini_file` warned, Laravel
 * promoted the warning to an exception, and every command touching this
 * service died for a non-root user. The message named `parse_ini_file` and
 * said nothing about privileges.
 *
 * That matters most on a desktop, where running without sudo is the first
 * thing anyone does, and where the failure looks like a broken install rather
 * than a permission the operator has to grant.
 *
 * **This test only means something when it is not run as root**, because root
 * can read the file whatever its mode, so the condition cannot be created. It
 * skips on the Linux agent, which runs as root, and does its work on a desktop
 * — which is exactly where the defect was found.
 */
class WafSyncServiceEnvAccessTest extends TestCase
{
    private string $envPath;
    private ?string $saved = null;
    private ?int $savedMode = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->envPath = base_path('.env');

        if (is_file($this->envPath)) {
            $this->saved = @file_get_contents($this->envPath) ?: null;
            $this->savedMode = @fileperms($this->envPath) & 0777;
        }
    }

    protected function tearDown(): void
    {
        if ($this->saved !== null) {
            @file_put_contents($this->envPath, $this->saved);

            if ($this->savedMode !== null) {
                @chmod($this->envPath, $this->savedMode);
            }
        }

        parent::tearDown();
    }

    public function test_an_unreadable_env_does_not_abort_the_command(): void
    {
        if (posix_getuid() === 0) {
            // root can read anything, so the condition cannot be reproduced.
            $this->markTestSkipped('Cannot make a file unreadable to root');
        }

        file_put_contents($this->envPath, "WAF_URL=https://hub.test\nAGENT_TOKEN=secret\n");
        chmod($this->envPath, 0000);

        // Construction is the whole test: before the fix this threw, and every
        // artisan command that type-hints this service went with it.
        $service = new WafSyncService();
        $config = $service->getConnectionConfig();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('url', $config);
        $this->assertArrayHasKey('token', $config);
    }

}

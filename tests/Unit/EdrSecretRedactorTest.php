<?php

namespace Tests\Unit;

use App\Services\EdrEventSpool;
use App\Services\EdrSecretRedactor;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Process telemetry is unusually dangerous to store, because argv routinely
 * carries credentials and an EDR captures every exec on the host. These tests
 * pin the two properties that matter: secrets are removed, and ordinary
 * commands survive intact — an over-eager redactor destroys the evidence the
 * product exists to collect.
 */
class EdrSecretRedactorTest extends TestCase
{
    private EdrSecretRedactor $redactor;

    protected function setUp(): void
    {
        parent::setUp();
        $this->redactor = new EdrSecretRedactor();
    }

    /**
     * Not a hypothetical: this exact command line was captured by the sensor
     * during development, complete with a live database password.
     */
    public function test_redacts_the_real_leak_that_prompted_this(): void
    {
        $captured = "docker exec -e MYSQL_PWD=SecureWAFRoot2026! security-one-mysql "
            . "mysql -u root -e 'SHOW REPLICAS;'";

        $redacted = $this->redactor->redact($captured);

        $this->assertStringNotContainsString('SecureWAFRoot2026', $redacted);
        $this->assertStringContainsString('docker exec', $redacted, 'context must survive');
        $this->assertStringContainsString('MYSQL_PWD=', $redacted, 'the flag name is evidence, the value is not');
    }

    public static function secretProvider(): array
    {
        return [
            'long flag'        => ['app --password=hunter2', 'hunter2'],
            'mysql attached'   => ['mysql -u root -phunter2 mydb', 'hunter2'],
            'bearer header'    => ['curl -H "Authorization: Bearer abc123xyz" https://x.test', 'abc123xyz'],
            'basic auth'       => ['curl -u admin:s3cr3t https://x.test', 's3cr3t'],
            'env assignment'   => ['export PGPASSWORD=topsecret', 'topsecret'],
            'aws key id'       => ['aws --api-key AKIAIOSFODNN7EXAMPLE s3 ls', 'AKIAIOSFODNN7EXAMPLE'],
            'slack token'      => ['post --token xoxb-123456789012-abcdef', 'xoxb-123456789012-abcdef'],
            'github token'     => ['gh auth login --with-token ghp_abcdefghijklmnopqrstuvwxyz01', 'ghp_abcdefghijklmnopqrstuvwxyz01'],
        ];
    }

    #[DataProvider('secretProvider')]
    public function test_redacts_credential_shapes(string $cmdline, string $secret): void
    {
        $this->assertStringNotContainsString($secret, $this->redactor->redact($cmdline));
    }

    public static function benignProvider(): array
    {
        return [
            ['ls -la /var/log'],
            ['/usr/bin/curl https://example.test/index.html'],
            ['git commit -m "fix auth bug"'],
            ['ssh -p 22 user@host'],
            ['find /tmp -name "*.log" -print'],
        ];
    }

    #[DataProvider('benignProvider')]
    public function test_leaves_ordinary_commands_untouched(string $cmdline): void
    {
        $this->assertSame($cmdline, $this->redactor->redact($cmdline));
    }

    public function test_detects_whether_a_value_carried_a_secret(): void
    {
        $this->assertTrue($this->redactor->containsSecret('app --password=x'));
        $this->assertFalse($this->redactor->containsSecret('ls -la'));
    }

    /**
     * Redaction has to happen before the write, not on the way out: the point
     * is that the secret never reaches disk, a support bundle or a backup.
     */
    public function test_secrets_never_reach_the_spool_file(): void
    {
        $path = sys_get_temp_dir() . '/edr-redact-' . uniqid() . '.sqlite';
        $spool = new EdrEventSpool($path);

        $spool->store([[
            'ts' => time(),
            'action' => 'exec',
            'pid' => 1,
            'ppid' => 0,
            'uid' => 0,
            'username' => 'root',
            'path' => '/usr/bin/mysql',
            'cmdline' => 'mysql --password=LiveProdPassword123 -h db',
            'cwd' => '/',
            'container_id' => '',
            'syscall' => 'exec',
        ]]);

        $row = $spool->query(['limit' => 1])[0];
        $this->assertStringNotContainsString('LiveProdPassword123', $row['cmdline']);
        $this->assertStringNotContainsString('LiveProdPassword123', (string) file_get_contents($path));

        $spool->close();
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($path . $suffix);
        }
    }

    /**
     * Encryption is optional and secondary — the key lives on the same host,
     * so it defends a stolen disk rather than a compromised one. It must not
     * cost the ability to hunt.
     */
    public function test_optional_encryption_round_trips_and_keeps_search_working(): void
    {
        $path = sys_get_temp_dir() . '/edr-enc-' . uniqid() . '.sqlite';
        $spool = new EdrEventSpool($path);
        $spool->setEncryption(true);

        $spool->store([[
            'ts' => time(),
            'action' => 'exec',
            'pid' => 1,
            'ppid' => 0,
            'uid' => 0,
            'username' => 'root',
            'path' => '/bin/sh',
            'cmdline' => 'sh -c distinctive-marker-string',
            'cwd' => '/',
            'container_id' => '',
            'syscall' => 'exec',
        ]]);

        $this->assertStringNotContainsString(
            'distinctive-marker-string',
            (string) file_get_contents($path),
            'the command line must not be readable in the file'
        );

        $rows = $spool->query(['limit' => 5]);
        $this->assertStringContainsString('distinctive-marker-string', $rows[0]['cmdline']);

        // A search that silently returned nothing would read as "this never
        // ran here" during an investigation, which is worse than being slow.
        $this->assertCount(1, $spool->query(['cmdline_like' => 'distinctive-marker']));

        $spool->close();
        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($path . $suffix);
        }
    }
}

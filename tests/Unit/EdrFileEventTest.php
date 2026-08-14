<?php

namespace Tests\Unit;

use App\Services\EdrRuleEngine;
use Tests\TestCase;

/**
 * File telemetry answers a question process telemetry cannot: what landed on
 * disk. Without it the product cannot see a webshell arrive, a persistence
 * file being installed, or ransomware working through a directory tree.
 *
 * The structural limitation runs through all of this: inotify reports what
 * changed and can hash it, but carries no pid. Attribution is inferred, and
 * these tests pin that it is labelled as inference rather than presented as
 * fact — an analyst acts on the name of the process they are shown.
 */
class EdrFileEventTest extends TestCase
{
    private EdrRuleEngine $rules;

    protected function setUp(): void
    {
        parent::setUp();
        $this->rules = new EdrRuleEngine();
    }

    private function fileEvent(array $overrides = []): array
    {
        $base = [
            'ts' => time(),
            'action' => 'file_create',
            'sensor' => 'osquery-fim',
            'pid' => 0,
            'ppid' => 0,
            'uid' => 33,
            'username' => 'www-data',
            'path' => '/var/www/html/shell.php',
            'cmdline' => '',
            'cwd' => '/var/www/html',
            'container_id' => '',
            'attribution' => null,
        ];

        $file = array_merge(
            ['category' => 'webroot', 'size' => 100, 'sha256' => 'abc', 'mode' => '0644', 'inode' => '1'],
            $overrides['file'] ?? []
        );

        unset($overrides['file']);

        return array_merge($base, $overrides, ['file' => $file]);
    }

    /**
     * The highest-value file detection for a WAF product: this is what a
     * request that got past the WAF looks like once it has landed.
     */
    public function test_a_web_account_dropping_a_script_into_a_web_root_is_critical(): void
    {
        $findings = $this->rules->evaluate($this->fileEvent());

        $this->assertSame('FIM-001', $findings[0]['rule']);
        $this->assertSame('critical', $findings[0]['severity']);
        $this->assertSame('T1505.003', $findings[0]['mitre']);
    }

    /**
     * The same file from an account that is not the web server is still worth
     * seeing, but it is a deploy far more often than an intrusion.
     */
    public function test_the_same_drop_by_another_account_is_graded_lower(): void
    {
        $findings = $this->rules->evaluate($this->fileEvent(['username' => 'root', 'uid' => 0]));

        $this->assertSame('FIM-001', $findings[0]['rule']);
        $this->assertSame('high', $findings[0]['severity']);
    }

    /**
     * Web roots are full of files. Only the ones the server would execute
     * matter, and only in directories the customer told us are web roots —
     * guessing at path shapes would fire on every deploy of every project.
     */
    public function test_non_executable_and_non_web_paths_do_not_fire(): void
    {
        $this->assertSame([], $this->rules->evaluate($this->fileEvent([
            'path' => '/var/www/html/index.html',
        ])));

        $this->assertSame([], $this->rules->evaluate($this->fileEvent([
            'path' => '/opt/app/deploy.php',
            'file' => ['category' => 'startup'],
        ])));
    }

    public static function criticalPathProvider(): array
    {
        return [
            'passwd' => ['/etc/passwd', 'FIM-002'],
            'sudoers drop-in' => ['/etc/sudoers.d/evil', 'FIM-002'],
            'cron job' => ['/etc/cron.d/backdoor', 'FIM-002'],
            'systemd unit' => ['/etc/systemd/system/evil.service', 'FIM-002'],
            'ld preload' => ['/etc/ld.so.preload', 'FIM-002'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('criticalPathProvider')]
    public function test_changes_to_account_and_boot_state_are_detected(string $path, string $rule): void
    {
        $findings = $this->rules->evaluate($this->fileEvent([
            'action' => 'file_write',
            'path' => $path,
            'username' => 'root',
            'uid' => 0,
            'file' => ['category' => 'accounts'],
        ]));

        $this->assertContains($rule, array_column($findings, 'rule'));
    }

    /**
     * Separate from the other critical paths because this one is durable
     * remote access rather than a configuration change: it survives a
     * password reset, so the person cleaning up has to know.
     */
    public function test_authorized_keys_changes_are_critical(): void
    {
        $findings = $this->rules->evaluate($this->fileEvent([
            'action' => 'file_write',
            'path' => '/root/.ssh/authorized_keys',
            'username' => 'root',
            'uid' => 0,
            'file' => ['category' => 'ssh'],
        ]));

        $keys = array_values(array_filter($findings, static fn (array $f): bool => $f['rule'] === 'FIM-004'));

        $this->assertNotEmpty($keys);
        $this->assertSame('critical', $keys[0]['severity']);
    }

    /**
     * A file appearing in /tmp is unremarkable. A file a web account put
     * there is not.
     */
    public function test_staging_in_world_writable_paths_depends_on_who_did_it(): void
    {
        $byWeb = $this->rules->evaluate($this->fileEvent([
            'path' => '/tmp/stage2',
            'file' => ['category' => 'tmp'],
        ]));
        $this->assertContains('FIM-003', array_column($byWeb, 'rule'));

        $byRoot = $this->rules->evaluate($this->fileEvent([
            'path' => '/tmp/build.o',
            'username' => 'root',
            'uid' => 0,
            'file' => ['category' => 'tmp'],
        ]));
        $this->assertSame([], $byRoot, 'ordinary temp file use must not alert');
    }

    public function test_deleting_a_monitored_file_is_detected(): void
    {
        $findings = $this->rules->evaluate($this->fileEvent([
            'action' => 'file_delete',
            'path' => '/etc/cron.d/backup',
            'username' => 'root',
            'uid' => 0,
            'file' => ['category' => 'scheduling'],
        ]));

        $this->assertContains('FIM-005', array_column($findings, 'rule'));
    }

    /**
     * No single write looks like encryption. Volume and spread inside a short
     * window is the only thing that does, and it has to fire while there is
     * still something left to save — waiting to recognise a ransom note means
     * waiting until it is over.
     */
    public function test_mass_file_modification_is_detected_as_ransomware_shaped(): void
    {
        $events = [];
        $now = time();

        for ($i = 0; $i < 60; $i++) {
            $events[] = $this->fileEvent([
                'action' => 'file_write',
                'ts' => $now + ($i % 10),
                'path' => '/home/user/docs/dir' . ($i % 6) . '/file' . $i . '.txt.locked',
                'file' => ['category' => 'home'],
            ]);
        }

        $rules = array_merge(...array_map(
            static fn (array $hit): array => array_column($hit['findings'], 'rule'),
            $this->rules->evaluateBatch($events)
        ));

        $this->assertContains('FIM-006', $rules);
    }

    /**
     * A build or a package install rewrites many files too — inside one tree.
     * Spread across directories is what separates encryption from bulk work.
     */
    public function test_bulk_writes_confined_to_one_tree_do_not_fire(): void
    {
        $events = [];
        $now = time();

        for ($i = 0; $i < 60; $i++) {
            $events[] = $this->fileEvent([
                'action' => 'file_write',
                'ts' => $now,
                'path' => '/var/cache/build/object' . $i . '.o',
                'file' => ['category' => 'cache'],
            ]);
        }

        $rules = array_merge([], ...array_map(
            static fn (array $hit): array => array_column($hit['findings'], 'rule'),
            $this->rules->evaluateBatch($events)
        ));

        $this->assertNotContains('FIM-006', $rules);
    }

    /**
     * Slow, spread-out writes are ordinary activity. The window is what makes
     * the rule mean anything.
     */
    public function test_writes_spread_over_time_do_not_fire(): void
    {
        $events = [];
        $now = time();

        for ($i = 0; $i < 60; $i++) {
            $events[] = $this->fileEvent([
                'action' => 'file_write',
                // Ten minutes of ordinary activity, not one minute of encryption.
                'ts' => $now + ($i * 10),
                'path' => '/home/user/dir' . ($i % 6) . '/file' . $i . '.txt',
                'file' => ['category' => 'home'],
            ]);
        }

        $rules = array_merge([], ...array_map(
            static fn (array $hit): array => array_column($hit['findings'], 'rule'),
            $this->rules->evaluateBatch($events)
        ));

        $this->assertNotContains('FIM-006', $rules);
    }
}

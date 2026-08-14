<?php

namespace Tests\Unit;

use App\Services\Response\EdrActionLedger;
use App\Services\Response\EdrResponder;
use App\Services\Response\FileQuarantine;
use App\Services\Response\NetworkContainment;
use App\Services\Response\ProcessResponder;
use App\Services\WafSyncService;
use Tests\TestCase;

/**
 * Four independent gates stand between a Hub config blob and a destructive
 * act on a customer's machine. Each is tested on its own, because the whole
 * point of having four is that any single one can be got around.
 */
class EdrResponderTest extends TestCase
{
    private string $work;
    private string $ledgerPath;

    /** @var array<int, int> */
    private array $spawned = [];

    private const ALL_CAPABILITIES = [
        'allow_process_control' => true,
        'allow_file_quarantine' => true,
        'allow_network_isolation' => true,
    ];

    protected function setUp(): void
    {
        parent::setUp();

        if (PHP_OS_FAMILY !== 'Linux' || !function_exists('posix_kill')) {
            $this->markTestSkipped('Response is Linux-only and needs ext-posix.');
        }

        $this->work = sys_get_temp_dir() . '/edr-responder-' . uniqid();
        mkdir($this->work);
        $this->ledgerPath = $this->work . '/actions.sqlite';
    }

    protected function tearDown(): void
    {
        foreach ($this->spawned as $pid) {
            @posix_kill($pid, SIGKILL);
        }

        exec('rm -rf ' . escapeshellarg($this->work));

        parent::tearDown();
    }

    /**
     * A fresh responder each time, mirroring how the agent builds one per
     * sync cycle. Containment is pointed at `true` so nothing touches the
     * host firewall — the real rule handling has its own test.
     */
    /**
     * @param string|null $channel override the command channel path. Defaults
     *        to a root-owned mode-0600 file inside the test workspace, because
     *        the provenance gate is now part of every command path and the real
     *        config on a developer host is world-writable — without this, every
     *        test in this file would assert against whatever mode that file
     *        happens to have.
     */
    private function responder(?string $channel = null): EdrResponder
    {
        return new EdrResponder(
            new EdrActionLedger($this->ledgerPath),
            new ProcessResponder(),
            new FileQuarantine($this->work . '/quarantine'),
            new NetworkContainment('true'),
            new WafSyncService(),
            $channel ?? $this->trustedChannel()
        );
    }

    /**
     * A command channel the provenance gate accepts: root-owned, 0600, in a
     * 0700 directory.
     */
    private function trustedChannel(): string
    {
        $path = $this->work . '/trusted-channel.json';

        if (!file_exists($path)) {
            file_put_contents($path, json_encode(['addons' => []]));
        }

        @chmod($this->work, 0700);
        @chmod($path, 0600);

        return $path;
    }

    private function ledger(): EdrActionLedger
    {
        return new EdrActionLedger($this->ledgerPath);
    }

    private function spawn(): int
    {
        $pid = (int) trim((string) shell_exec('setsid sleep 25 >/dev/null 2>&1 & echo $!'));
        usleep(150000);
        $this->spawned[] = $pid;

        return $pid;
    }

    private function state(int $pid): string
    {
        return trim((string) shell_exec("awk '/^State:/{print \$2}' /proc/{$pid}/status 2>/dev/null"));
    }

    private function command(array $overrides): array
    {
        return array_merge(['issued_at' => time(), 'confirm' => true], $overrides);
    }

    /**
     * Gate 1. A customer who bought detection should never implicitly hand us
     * the ability to kill processes on their machines.
     */
    public function test_actions_are_refused_until_the_capability_is_granted(): void
    {
        $command = $this->command(['id' => 'c1', 'type' => 'kill_process', 'target' => ['pid' => 99999]]);

        $result = $this->responder()->processCommands([$command], []);
        $this->assertSame('capability_not_granted', $result['outcomes'][0]['reason']);

        // Granting one capability must not grant another.
        $fileCommand = $this->command(['id' => 'c2', 'type' => 'quarantine_file', 'target' => ['path' => '/tmp/x']]);
        $result = $this->responder()->processCommands([$fileCommand], ['allow_process_control' => true]);
        $this->assertSame('capability_not_granted', $result['outcomes'][0]['reason']);
    }

    /**
     * Gate 2. This is what stops an old config blob — replayed by a rollback,
     * a restored backup or a stale cache — re-triggering yesterday's kill.
     */
    public function test_stale_and_undated_commands_are_refused(): void
    {
        $responder = $this->responder();

        $stale = $this->command([
            'id' => 'c3',
            'type' => 'kill_process',
            'target' => ['pid' => 99999],
            'issued_at' => time() - 3600,
        ]);
        $this->assertSame(
            'command_stale',
            $responder->processCommands([$stale], self::ALL_CAPABILITIES)['outcomes'][0]['reason']
        );

        $undated = ['id' => 'c4', 'type' => 'kill_process', 'target' => ['pid' => 99999], 'confirm' => true];
        $this->assertSame(
            'missing_issued_at',
            $responder->processCommands([$undated], self::ALL_CAPABILITIES)['outcomes'][0]['reason']
        );

        // A command from the future is a clock problem, not an instruction.
        $future = $this->command([
            'id' => 'c5',
            'type' => 'kill_process',
            'target' => ['pid' => 99999],
            'issued_at' => time() + 9999,
        ]);
        $this->assertSame(
            'command_from_the_future',
            $responder->processCommands([$future], self::ALL_CAPABILITIES)['outcomes'][0]['reason']
        );
    }

    /**
     * Gate 4. A partially-populated or merged config must not imply consent.
     */
    public function test_destructive_actions_require_explicit_confirmation(): void
    {
        $unconfirmed = ['id' => 'c6', 'type' => 'kill_process', 'target' => ['pid' => 99999], 'issued_at' => time()];

        $this->assertSame(
            'confirmation_required',
            $this->responder()->processCommands([$unconfirmed], self::ALL_CAPABILITIES)['outcomes'][0]['reason']
        );

        // Suspend is reversible, so it does not carry the same burden.
        $suspend = ['id' => 'c7', 'type' => 'suspend_process', 'target' => ['pid' => 99999], 'issued_at' => time()];
        $this->assertNotSame(
            'confirmation_required',
            $this->responder()->processCommands([$suspend], self::ALL_CAPABILITIES)['outcomes'][0]['reason']
        );
    }

    /**
     * Gate 3. The Hub resends commands it never saw acknowledged.
     */
    public function test_a_redelivered_command_does_not_execute_twice(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $command = $this->command([
            'id' => 'kill-1',
            'type' => 'kill_process',
            'target' => ['pid' => $pid, 'start_time' => $startTime],
        ]);

        $first = $this->responder()->processCommands([$command], self::ALL_CAPABILITIES);
        $this->assertSame(1, $first['executed']);
        $this->assertNull((new ProcessResponder())->inspect($pid));

        $second = $this->responder()->processCommands([$command], self::ALL_CAPABILITIES);
        $this->assertSame(1, $second['skipped']);
        $this->assertSame('already_seen', $second['outcomes'][0]['reason']);
    }

    public function test_the_ledger_records_what_actually_happened(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'kill-2',
                'type' => 'kill_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'reason' => 'EDR-002 reverse shell',
                'requested_by' => 'analyst@example.test',
            ]),
        ], self::ALL_CAPABILITIES);

        $action = $this->ledger()->find('kill-2');

        $this->assertSame(EdrActionLedger::STATE_APPLIED, $action['state']);
        $this->assertTrue($action['result']['confirmed_dead']);
        $this->assertSame('analyst@example.test', $action['requested_by']);
        $this->assertFalse($action['reversible']);
        $this->assertNull($action['expires_at'], 'a kill has nothing to auto-revert to');
    }

    public function test_a_suspended_process_is_resumed_when_its_deadline_passes(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'susp-1',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'ttl_seconds' => 60,
            ]),
        ], self::ALL_CAPABILITIES);

        usleep(200000);
        $this->assertSame('T', $this->state($pid));

        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec('UPDATE actions SET expires_at = ' . (time() - 1) . " WHERE action_id = 'susp-1'");
        $pdo = null;

        $this->assertSame(1, $this->responder()->expireOverdue()['reverted']);

        usleep(200000);
        $this->assertContains($this->state($pid), ['S', 'R'], 'the process must be running again');
        $this->assertSame(EdrActionLedger::STATE_EXPIRED, $this->ledger()->find('susp-1')['state']);
    }

    /**
     * An analyst who wants an action to persist reconfirms it, which is what
     * pushes the safety timer out.
     */
    public function test_a_confirmation_extends_the_deadline(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'susp-2',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'ttl_seconds' => 60,
            ]),
        ], self::ALL_CAPABILITIES);

        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec('UPDATE actions SET expires_at = ' . (time() - 1) . " WHERE action_id = 'susp-2'");
        $pdo = null;

        $this->assertSame(1, $this->responder()->applyConfirmations(
            [['id' => 'susp-2', 'ttl_seconds' => 3600, 'issued_at' => time()]],
            self::ALL_CAPABILITIES
        ));
        $this->assertSame(0, $this->responder()->expireOverdue()['reverted']);
    }

    /**
     * The freshness gate cannot be widened arbitrarily by the payload it is
     * supposed to bound.
     *
     * `edr_command_max_age` arrives in the same blob as the commands, and was
     * read unclamped — so a blob asking for a year-long window revived every
     * command in it for a year, which is not a freshness gate. Gate zero closes
     * the local-attacker path; this closes the compromised-or-buggy-Hub one.
     */
    public function test_the_freshness_window_cannot_be_widened_without_limit(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        // Two hours old, with the Hub asking for a year of tolerance.
        $summary = $this->responder()->processCommands([
            $this->command([
                'id' => 'clamp-1',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'issued_at' => time() - 7200,
            ]),
        ], array_merge(self::ALL_CAPABILITIES, ['max_command_age' => 31536000]));

        $this->assertSame(0, $summary['executed']);
        $this->assertSame('command_stale', $summary['outcomes'][0]['reason']);

        // Inside the ceiling it still works, so the clamp is a bound and not a
        // blanket refusal.
        $ok = $this->responder()->processCommands([
            $this->command([
                'id' => 'clamp-2',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'issued_at' => time() - 1800,
            ]),
        ], array_merge(self::ALL_CAPABILITIES, ['max_command_age' => 31536000]));

        $this->assertSame(1, $ok['executed']);
    }

    /**
     * An action recorded and never resolved must not be invisible.
     *
     * The ledger row is written before the action runs — deliberately, since an
     * effect with no record is worse than a record with no effect. But nothing
     * looked at rows that stayed `pending`, and that combination had teeth: a
     * crash between the write and completion (a window that for isolation
     * contains the iptables calls themselves) left a host that may be cut off,
     * `dueForExpiry()` ignoring the row because it only selects `applied`, the
     * Hub seeing nothing because `unreported` excludes pending, and a retry of
     * the same command skipped as `already_seen`. Console-only recovery.
     */
    public function test_an_action_stuck_in_pending_is_swept_rather_than_left(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'stuck-1',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'ttl_seconds' => 60,
            ]),
        ], self::ALL_CAPABILITIES);

        // Put it back into the state a mid-action crash would have left, and
        // age it. The age has to be real rather than passed in as a grace of
        // zero: `stuckPending()` floors the grace at 60 seconds so a
        // misconfiguration cannot sweep an action that is still running, and a
        // clamp like that silently eating a test parameter is how a test comes
        // to assert nothing at all.
        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec("UPDATE actions SET state = 'pending', applied_at = NULL WHERE action_id = 'stuck-1'");
        $pdo = null;

        // The expiry pass cannot help: it only looks at applied actions.
        $this->assertSame(0, $this->responder()->expireOverdue()['reverted']);

        // Nor is it counted as unreported, which is why the Hub saw nothing.
        $stats = $this->ledger()->stats();
        $this->assertSame(1, $stats['pending']);
        $this->assertSame(0, $stats['unreported']);

        // Inside the grace period nothing is touched — an action legitimately
        // mid-flight must not be yanked out from under itself.
        $this->assertSame(0, $this->responder()->sweepStuckPending(300)['swept']);

        // Age it past the grace period.
        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec('UPDATE actions SET created_at = ' . (time() - 600) . " WHERE action_id = 'stuck-1'");
        $pdo = null;

        // Now the effect is undone and the row stops being invisible.
        $swept = $this->responder()->sweepStuckPending(300);

        $this->assertSame(1, $swept['swept']);
        $this->assertSame(1, $swept['reverted']);

        $action = $this->ledger()->find('stuck-1');
        $this->assertSame('reverted', $action['state']);
        $this->assertSame(0, $this->ledger()->stats()['pending']);
    }

    /**
     * A kill cannot be undone, so a stuck kill is recorded as failed rather
     * than quietly reversed — but it still stops being invisible, and it stops
     * blocking a retry of the same action id.
     */
    public function test_a_stuck_irreversible_action_is_recorded_as_failed(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'stuck-kill',
                'type' => 'kill_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
            ]),
        ], self::ALL_CAPABILITIES);

        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec("UPDATE actions SET state = 'pending', applied_at = NULL, created_at = "
            . (time() - 600) . " WHERE action_id = 'stuck-kill'");
        $pdo = null;

        $swept = $this->responder()->sweepStuckPending(300);

        $this->assertSame(1, $swept['swept']);
        $this->assertSame(1, $swept['failed']);
        $this->assertSame(0, $swept['reverted'], 'a kill is never claimed to be undone');

        $action = $this->ledger()->find('stuck-kill');
        $this->assertSame('failed', $action['state']);
        $this->assertStringContainsString('stuck_pending', (string) $action['error']);
    }

    /**
     * No refusal path may be silent.
     *
     * Five of the seven reasons had no log line, no ledger row and nothing sent
     * to the Hub: malformed_command, unknown_action_type, missing_issued_at,
     * command_from_the_future and confirmation_required. Only capability and
     * staleness announced themselves.
     *
     * The damage is at the console rather than here. An absence of refusal
     * records reads as "nothing was refused", when it may equally mean the
     * command never arrived or the agent is not running — two very different
     * situations that were indistinguishable from the Hub.
     *
     * Asserted over every reason at once, because the fix was to move the
     * logging into `outcome()` rather than add it at five call sites. Five
     * places each having to remember is the failure mode this subsystem keeps
     * producing; this test fails if a future refusal path is added without one.
     */
    public function test_every_refusal_reason_leaves_a_trace(): void
    {
        $target = ['pid' => 999999, 'start_time' => 1];

        $cases = [
            'malformed_command' => ['id' => '', 'type' => ''],
            'unknown_action_type' => ['id' => 'r1', 'type' => 'nonsense'],
            'missing_issued_at' => ['id' => 'r2', 'type' => 'suspend_process', 'target' => $target],
            'command_from_the_future' => [
                'id' => 'r3', 'type' => 'suspend_process', 'target' => $target,
                'issued_at' => time() + 99999,
            ],
            'confirmation_required' => [
                'id' => 'r4', 'type' => 'kill_process', 'target' => $target,
                'issued_at' => time(),
            ],
            'command_stale' => [
                'id' => 'r5', 'type' => 'suspend_process', 'target' => $target,
                'issued_at' => time() - 99999,
            ],
        ];

        foreach ($cases as $expected => $command) {
            $logged = [];

            \Illuminate\Support\Facades\Log::listen(function ($event) use (&$logged): void {
                if (str_contains($event->message, 'Command refused')) {
                    $logged[] = $event->context['reason'] ?? null;
                }
            });

            $summary = $this->responder()->processCommands([$command], self::ALL_CAPABILITIES);

            $this->assertSame($expected, $summary['outcomes'][0]['reason']);
            $this->assertContains($expected, $logged, "{$expected} must not refuse silently");
        }

        // And the capability refusal, which needs the grant withheld.
        $logged = [];

        \Illuminate\Support\Facades\Log::listen(function ($event) use (&$logged): void {
            if (str_contains($event->message, 'Command refused')) {
                $logged[] = $event->context['reason'] ?? null;
            }
        });

        $summary = $this->responder()->processCommands([
            $this->command(['id' => 'r6', 'type' => 'suspend_process', 'target' => $target]),
        ], ['max_command_age' => 900]);

        $this->assertSame('capability_not_granted', $summary['outcomes'][0]['reason']);
        $this->assertContains('capability_not_granted', $logged);
    }

    /**
     * Gate zero: is it really the Hub asking?
     *
     * The other four gates ask whether the Hub is allowed to do this. None of
     * them asked whether the order came from the Hub at all. Commands arrive in
     * storage/app/waf_config.json, and on the host this was written against
     * that file is mode 777 in a mode 777 directory — `www-data` can write it,
     * verified rather than inferred. The root watchdog invokes
     * `artisan ids:sync-edr` every thirty seconds, so those commands execute
     * with root privileges: iptables for isolation, posix_kill against any pid.
     *
     * A compromised web account could therefore write a kill command, grant
     * itself the capability in the same file, set the freshness bound to suit
     * itself, and have root carry it out within half a minute — turning the
     * event this product exists to detect into root. Permissions alone cannot
     * fix it, because the scheduler that writes the file also runs as www-data.
     * So the endpoint refuses the orders instead.
     */
    public function test_commands_from_a_world_writable_channel_are_refused(): void
    {
        $dir = sys_get_temp_dir() . '/edr-provenance-' . uniqid();
        mkdir($dir, 0700, true);
        $channel = $dir . '/waf_config.json';
        file_put_contents($channel, json_encode(['addons' => []]));

        $responder = $this->responder();

        chmod($channel, 0600);
        $tight = $responder->commandChannelProvenance($channel);
        $this->assertTrue($tight['trusted'], 'a root-only file is a trusted channel');

        chmod($channel, 0666);
        $loose = $responder->commandChannelProvenance($channel);
        $this->assertFalse($loose['trusted']);
        $this->assertSame('world_writable', $loose['problem']);

        // A writable directory is a writable file: an attacker replaces rather
        // than edits, so the mode on the file alone proves nothing.
        chmod($channel, 0600);
        chmod($dir, 0777);
        $looseDir = $responder->commandChannelProvenance($channel);
        $this->assertFalse($looseDir['trusted'], 'a writable directory defeats a tight file');
        $this->assertSame($dir, $looseDir['path']);

        chmod($dir, 0700);
        @unlink($channel);
        @rmdir($dir);
    }

    /**
     * A command placed in the general config authorises nothing.
     *
     * This is the property the split channel exists for, and it is stronger than
     * the gate refusing: the command never reaches the responder at all, because
     * the responder does not read that file.
     *
     * The general config has to stay writable by the web-tier account —
     * `waf:heartbeat-dynamic` runs from `php artisan schedule:work` as www-data
     * every ten seconds and writes it, and on this host it is mode 777 in a mode
     * 777 directory. Meanwhile the root watchdog runs `ids:sync-edr`, which
     * executed the commands in that file with root privileges. Tightening the
     * mode was never available as a fix, because the account that must be able
     * to write it is the account being defended against.
     */
    public function test_authorisation_comes_only_from_the_root_only_channel(): void
    {
        $dir = sys_get_temp_dir() . '/edr-split-' . uniqid();
        mkdir($dir, 0700, true);

        // The loose file anyone can write, carrying a forged command.
        $loose = $dir . '/waf_config.json';
        file_put_contents($loose, json_encode(['addons' => [
            'edr_allow_network_isolation' => true,
            'edr_response_commands' => [[
                'id' => 'forged-1',
                'type' => 'isolate_network',
                'target' => [],
                'issued_at' => time(),
                'confirm' => true,
            ]],
        ]]));
        chmod($loose, 0666);

        // The tight channel, carrying nothing.
        $tight = $dir . '/response.json';
        file_put_contents($tight, json_encode(['written_at' => time(), 'addons' => []]));
        chmod($tight, 0600);

        $responder = $this->responder($tight);

        // The gate trusts the channel, so this is not the gate refusing.
        $this->assertTrue($responder->commandChannelProvenance()['trusted']);

        // And the forged command still does nothing, because the authorisation
        // it needs is not in the channel the responder reads.
        $summary = $responder->processCommands([], self::ALL_CAPABILITIES);
        $this->assertSame(0, $summary['executed']);

        $this->assertNull($this->ledger()->find('forged-1'), 'a forged command must never be recorded');

        foreach ([$loose, $tight] as $file) {
            @unlink($file);
        }

        @rmdir($dir);
    }

    /**
     * A tight file in a loose directory is not a tight file: an attacker with
     * write access to the directory replaces it rather than editing it. That is
     * why the channel lives in `storage/app/edr` (750 root:root) and not beside
     * the general config in `storage/app` (777 on this host, and required to
     * stay writable).
     */
    public function test_the_channel_directory_is_checked_as_well_as_the_file(): void
    {
        $dir = sys_get_temp_dir() . '/edr-loosedir-' . uniqid();
        mkdir($dir, 0777, true);
        @chmod($dir, 0777);

        $channel = $dir . '/response.json';
        file_put_contents($channel, json_encode(['written_at' => time(), 'addons' => []]));
        chmod($channel, 0600);

        $provenance = $this->responder($channel)->commandChannelProvenance();

        $this->assertFalse($provenance['trusted'], 'a 0600 file in a 0777 directory is not trusted');
        $this->assertSame($dir, $provenance['path']);

        @unlink($channel);
        @rmdir($dir);
    }

    /**
     * A release is never blocked by a configuration problem.
     *
     * Refusing to apply containment fails safe. Refusing to lift it leaves a
     * host cut off from the network because of a file mode, which is the one
     * outcome worse than executing the command.
     */
    public function test_a_release_is_not_blocked_by_an_untrusted_channel(): void
    {
        // A deliberately loose channel, so the gate is closed for this test
        // regardless of how the host is configured.
        $loose = $this->work . '/loose-channel.json';
        file_put_contents($loose, json_encode(['addons' => []]));
        chmod($loose, 0666);

        $this->assertFalse($this->responder($loose)->commandChannelProvenance()['trusted']);

        $applying = $this->responder($loose)->processCommands([
            $this->command(['id' => 'iso-untrusted', 'type' => 'isolate_network', 'target' => []]),
        ], self::ALL_CAPABILITIES);

        $this->assertSame(0, $applying['executed'], 'containment must not be applied');
        $this->assertSame('untrusted_command_channel', $applying['outcomes'][0]['reason']);

        // The release path reaches the responder rather than being refused at
        // the gate. It has nothing to release here, so it does not execute —
        // what matters is the reason it gives.
        $releasing = $this->responder($loose)->processCommands([
            $this->command(['id' => 'rel-untrusted', 'type' => 'release_network', 'target' => []]),
        ], self::ALL_CAPABILITIES);

        $this->assertNotSame(
            'untrusted_command_channel',
            $releasing['outcomes'][0]['reason'],
            'a release must never be refused for a file mode'
        );
    }

    /**
     * The failure that would have made containment permanent.
     *
     * `runEdrSync()` reads addons from waf_config.json on disk, and that file is
     * only refreshed by a *successful* heartbeat, so an unreachable Hub leaves
     * it frozen. The EDR cycle runs every 30 seconds. A confirmation with no
     * freshness check was therefore re-applied 120 times an hour, each time
     * setting the deadline to now plus its TTL, so `expireOverdue()` never saw
     * an overdue action and a host isolated on a bad call stayed isolated until
     * someone reached a console.
     *
     * What made it worse than an ordinary replay bug: isolation is itself what
     * makes the Hub unreachable, since only the pinned Hub addresses survive the
     * cut. The scenario that needs the safety timer is the scenario that
     * disabled it. And a command in the same payload was correctly refused as
     * stale, so reading the command path made replay look handled.
     */
    public function test_a_replayed_confirmation_cannot_hold_an_action_open(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'susp-replay',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'ttl_seconds' => 60,
            ]),
        ], self::ALL_CAPABILITIES);

        $issuedAt = time();
        $confirmation = [['id' => 'susp-replay', 'ttl_seconds' => 3600, 'issued_at' => $issuedAt]];

        // The Hub speaks once: honoured.
        $this->assertSame(1, $this->responder()->applyConfirmations($confirmation, self::ALL_CAPABILITIES));

        // The same frozen blob, read again on the next cycle: it must change
        // nothing. This is the assertion the bug failed.
        $this->assertSame(0, $this->responder()->applyConfirmations($confirmation, self::ALL_CAPABILITIES));
        $this->assertSame(0, $this->responder()->applyConfirmations($confirmation, self::ALL_CAPABILITIES));

        // Force the deadline past and confirm the timer now fires despite the
        // frozen confirmation still being present in the config.
        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec('UPDATE actions SET expires_at = ' . (time() - 1) . " WHERE action_id = 'susp-replay'");
        $pdo = null;

        $this->assertSame(0, $this->responder()->applyConfirmations($confirmation, self::ALL_CAPABILITIES));
        $this->assertSame(1, $this->responder()->expireOverdue()['reverted'], 'the safety timer must still fire');
    }

    /**
     * A confirmation is held to the same standard as a command. Without an
     * issued_at there is no way to tell a fresh decision from a stale file, and
     * the command path has refused undated payloads from the start.
     */
    public function test_undated_and_stale_confirmations_are_refused(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'susp-dated',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'ttl_seconds' => 60,
            ]),
        ], self::ALL_CAPABILITIES);

        $this->assertSame(0, $this->responder()->applyConfirmations(
            [['id' => 'susp-dated', 'ttl_seconds' => 3600]],
            self::ALL_CAPABILITIES
        ), 'no issued_at');

        $this->assertSame(0, $this->responder()->applyConfirmations(
            [['id' => 'susp-dated', 'ttl_seconds' => 3600, 'issued_at' => time() - 5000]],
            self::ALL_CAPABILITIES
        ), 'older than the age gate');

        $this->assertSame(1, $this->responder()->applyConfirmations(
            [['id' => 'susp-dated', 'ttl_seconds' => 3600, 'issued_at' => time()]],
            self::ALL_CAPABILITIES
        ), 'fresh and dated');
    }

    /**
     * The defence that does not depend on the Hub behaving.
     *
     * Every other guard here assumes the Hub sends sane payloads. This one
     * holds when it does not: no sequence of confirmations, however fresh, can
     * keep an action applied beyond the absolute ceiling measured from when it
     * was applied. That matters because the case the response gates exist for
     * is a Hub that is compromised or wrong, and a host cut off from its
     * management plane cannot be rescued by that plane.
     */
    public function test_no_confirmation_can_extend_past_the_absolute_ceiling(): void
    {
        $pid = $this->spawn();
        $startTime = (new ProcessResponder())->inspect($pid)['start_time'];

        $this->responder()->processCommands([
            $this->command([
                'id' => 'susp-ceiling',
                'type' => 'suspend_process',
                'target' => ['pid' => $pid, 'start_time' => $startTime],
                'ttl_seconds' => 60,
            ]),
        ], self::ALL_CAPABILITIES);

        // Rewind the application to two days ago; the ceiling is three.
        $appliedAt = time() - 2 * 86400;
        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec("UPDATE actions SET applied_at = {$appliedAt} WHERE action_id = 'susp-ceiling'");
        $pdo = null;

        // A fresh confirmation asking for the maximum day-long TTL.
        $this->assertSame(1, $this->responder()->applyConfirmations(
            [['id' => 'susp-ceiling', 'ttl_seconds' => 86400, 'issued_at' => time()]],
            self::ALL_CAPABILITIES
        ));

        $action = $this->ledger()->find('susp-ceiling');
        $this->assertLessThanOrEqual(
            $appliedAt + 259200,
            (int) $action['expires_at'],
            'the deadline may not pass three days from application'
        );

        // Now push application past the ceiling entirely: no confirmation may
        // revive it, and the timer must be free to undo it.
        $pdo = new \PDO('sqlite:' . $this->ledgerPath);
        $pdo->exec('UPDATE actions SET applied_at = ' . (time() - 4 * 86400)
            . ', expires_at = ' . (time() - 1) . " WHERE action_id = 'susp-ceiling'");
        $pdo = null;

        $this->assertSame(0, $this->responder()->applyConfirmations(
            [['id' => 'susp-ceiling', 'ttl_seconds' => 86400, 'issued_at' => time()]],
            self::ALL_CAPABILITIES
        ), 'past the ceiling, a confirmation must not extend');

        $this->assertSame(1, $this->responder()->expireOverdue()['reverted']);
    }

    /**
     * The rollback timer is the backstop for every failure the containment
     * code cannot detect itself, so isolation never gets to be open-ended.
     */
    public function test_isolation_always_carries_a_deadline(): void
    {
        $this->responder()->processCommands([
            $this->command(['id' => 'iso-1', 'type' => 'isolate_network', 'target' => []]),
        ], self::ALL_CAPABILITIES);

        $action = $this->ledger()->find('iso-1');

        $this->assertNotNull($action);
        $this->assertNotNull($action['expires_at'], 'isolation with no deadline must not be possible');
        $this->assertGreaterThan(time(), $action['expires_at']);
    }

    public function test_quarantine_and_restore_round_trip_through_commands(): void
    {
        $victim = $this->work . '/bad.sh';
        file_put_contents($victim, "#!/bin/sh\necho bad\n");
        chmod($victim, 0755);
        $digest = hash_file('sha256', $victim);

        $this->responder()->processCommands([
            $this->command(['id' => 'q-1', 'type' => 'quarantine_file', 'target' => ['path' => $victim]]),
        ], self::ALL_CAPABILITIES);

        $this->assertFileDoesNotExist($victim);

        // Restore is addressed by the id of the quarantine action, because
        // that ledger row is the only complete description of what the file
        // was.
        $restore = $this->responder()->processCommands([
            $this->command(['id' => 'q-2', 'type' => 'restore_file', 'target' => ['action_id' => 'q-1']]),
        ], self::ALL_CAPABILITIES);

        $this->assertSame(1, $restore['executed']);
        $this->assertSame($digest, hash_file('sha256', $victim));
        $this->assertSame(EdrActionLedger::STATE_REVERTED, $this->ledger()->find('q-1')['state']);
    }

    public function test_unknown_and_malformed_commands_are_refused(): void
    {
        $responder = $this->responder();

        $this->assertSame(
            'unknown_action_type',
            $responder->processCommands(
                [$this->command(['id' => 'x-1', 'type' => 'format_disk', 'target' => []])],
                self::ALL_CAPABILITIES
            )['outcomes'][0]['reason']
        );

        $this->assertSame(
            'malformed_command',
            $responder->processCommands([['type' => 'kill_process']], self::ALL_CAPABILITIES)['outcomes'][0]['reason']
        );
    }
}

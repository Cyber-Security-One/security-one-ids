<?php

namespace Tests\Unit;

use App\Services\Correlation\EdrCorrelator;
use App\Services\Correlation\EdrIncident;
use Tests\TestCase;

/**
 * Twenty simulated days of an entirely ordinary server, replayed through the
 * correlator, asserting **zero** incidents.
 *
 * This is the test that decides whether the feature is shippable. Detection
 * lift is easy to demonstrate on a chain you wrote yourself; staying silent on
 * a host doing nothing wrong is the hard part, and it is the part that decides
 * whether a customer leaves the feature switched on. A constant change that
 * breaks this test is a product decision, not a refactor, and it should be
 * argued about rather than fixed by relaxing the assertion.
 *
 * The workload is deliberately the awkward one: a five-minute cron, a web tier
 * that shells out to its own runtime on every request, log rotation, a nightly
 * backup that tars and uploads, two interactive admin sessions, and a package
 * upgrade — every shape that a naive correlator turns into an alert.
 */
class EdrCorrelatorQuietHostTest extends TestCase
{
    private const T0 = 1700000000;
    private const DAYS = 20;

    /** Cycles per simulated day. The agent really runs every 30s; this is a
     *  coarser grid that still checks emission far more often than a day. */
    private const CYCLES_PER_DAY = 48;

    private string $path;
    private EdrCorrelator $correlator;

    /** Deterministic pseudo-randomness — a seeded LCG, so failures reproduce. */
    private int $seed = 20240814;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-quiet-test-' . uniqid() . '.sqlite';

        $this->correlator = EdrCorrelator::make([
            'correlator_enabled' => true,
            'host_id' => 'quiet-01',
            'correlator_web_roots' => ['/var/www/html'],
            // The warm-up event count is lowered so the model actually matures
            // inside the simulation. Everything else is production default —
            // if the defaults only stay quiet because nothing ever matured,
            // the test would be worthless.
            'correlator_warm_events' => 1000,
            'host_profile' => 'server',
        ], $this->path);

        // The simulation compresses twenty days of event time into a couple of
        // seconds of real time, so it has to declare how long this agent has
        // actually been watching — otherwise the wall-clock bound on the
        // maturity span, which exists to stop a crafted timestamp maturing the
        // model in minutes, correctly refuses to let the fixture mature.
        $this->correlator->store()->setMeta('watching_since', (string) (time() - 60 * 86400));
    }

    protected function tearDown(): void
    {
        $this->correlator->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function nextInt(int $bound): int
    {
        // Numerical Recipes LCG. Cheap, deterministic, and good enough to
        // decorrelate the fixture without pulling in a dependency.
        $this->seed = ($this->seed * 1664525 + 1013904223) & 0x7FFFFFFF;

        return $bound > 0 ? $this->seed % $bound : 0;
    }

    private function event(int $ts, array $overrides): array
    {
        return array_merge([
            'ts' => $ts,
            'host' => 'quiet-01',
            'action' => 'exec',
            'sensor' => 'osquery',
            'ppid' => 1,
            'uid' => 0,
            'username' => 'root',
            'cwd' => '/',
            'container_id' => '',
        ], $overrides);
    }

    /**
     * One cycle's worth of the host's ordinary life.
     *
     * @return array<int, array>
     */
    private function ordinaryCycle(int $ts, int $day, int $cycle): array
    {
        $events = [];
        $pid = 10000 + ($day * 5000) + ($cycle * 40);

        // systemd, sshd, nginx and cron, so children have real parents.
        if ($day === 0 && $cycle === 0) {
            $events[] = $this->event($ts, ['pid' => 1, 'ppid' => 0, 'path' => '/usr/lib/systemd/systemd', 'cmdline' => '/sbin/init']);
            $events[] = $this->event($ts, ['pid' => 900, 'path' => '/usr/sbin/nginx', 'cmdline' => '/usr/sbin/nginx -g daemon off;']);
            $events[] = $this->event($ts, ['pid' => 800, 'path' => '/usr/sbin/cron', 'cmdline' => '/usr/sbin/cron -f']);
            $events[] = $this->event($ts, ['pid' => 700, 'path' => '/usr/sbin/sshd', 'cmdline' => '/usr/sbin/sshd -D']);
        }

        // The five-minute cron job. Same shape forever.
        $events[] = $this->event($ts + 1, [
            'pid' => $pid++, 'ppid' => 800,
            'path' => '/bin/sh', 'cmdline' => "sh -c /usr/local/bin/collect-metrics.sh",
        ]);
        $events[] = $this->event($ts + 2, [
            'pid' => $pid++, 'ppid' => 800,
            'path' => '/usr/bin/curl', 'cmdline' => 'curl -s http://127.0.0.1:9100/metrics -o /var/lib/metrics.txt',
        ]);

        // The web tier shelling out to its own runtime, every request.
        for ($i = 0, $n = 2 + $this->nextInt(4); $i < $n; $i++) {
            $events[] = $this->event($ts + 10 + $i, [
                'pid' => $pid++, 'ppid' => 900, 'uid' => 33, 'username' => 'www-data',
                'cwd' => '/var/www/html',
                'path' => '/bin/sh', 'cmdline' => "sh -c '/usr/bin/php8.4 artisan schedule:run'",
            ]);
            $events[] = $this->event($ts + 11 + $i, [
                'pid' => $pid++, 'ppid' => 900, 'uid' => 33, 'username' => 'www-data',
                'cwd' => '/var/www/html',
                'path' => '/usr/bin/php8.4', 'cmdline' => '/usr/bin/php8.4 artisan schedule:run',
            ]);
        }

        // Log rotation, once a day.
        if ($cycle === 4) {
            $events[] = $this->event($ts + 20, [
                'pid' => $pid++, 'ppid' => 800,
                'path' => '/usr/sbin/logrotate', 'cmdline' => '/usr/sbin/logrotate /etc/logrotate.conf',
            ]);
            $events[] = $this->event($ts + 21, [
                'pid' => $pid++, 'ppid' => 800,
                'path' => '/bin/gzip', 'cmdline' => 'gzip /var/log/nginx/access.log.1',
            ]);
        }

        // The nightly backup: archive, then ship it off the box. Collection
        // and egress in the same actor, every single night.
        if ($cycle === 6) {
            $events[] = $this->event($ts + 30, [
                'pid' => $pid++, 'ppid' => 800,
                'path' => '/bin/sh', 'cmdline' => 'sh -c /usr/local/bin/backup.sh',
            ]);
            $events[] = $this->event($ts + 31, [
                'pid' => $pid++, 'ppid' => 800,
                'path' => '/bin/tar', 'cmdline' => 'tar czf /var/backups/nightly.tgz /var/www/html',
            ]);
            $events[] = $this->event($ts + 32, [
                'pid' => $pid++, 'ppid' => 800,
                'path' => '/usr/bin/rsync', 'cmdline' => 'rsync -az /var/backups/nightly.tgz backup@10.0.0.9:/store',
            ]);
            $events[] = $this->event($ts + 33, [
                'pid' => $pid, 'ppid' => 800, 'action' => 'connect',
                'path' => '/usr/bin/rsync', 'cmdline' => 'rsync',
                'remote_address' => '10.0.0.9', 'remote_port' => 22,
            ]);
        }

        return $events;
    }

    /**
     * An administrator logging in and doing their job. Recon commands, a sudo,
     * an editor — the shape that every discovery-burst rule fires on.
     *
     * @return array<int, array>
     */
    private function adminSession(int $ts, int $pid): array
    {
        $events = [];

        $events[] = $this->event($ts, [
            'pid' => $pid, 'ppid' => 700, 'uid' => 1000, 'username' => 'deploy',
            'cwd' => '/home/deploy', 'path' => '/bin/bash', 'cmdline' => '-bash',
        ]);

        foreach (['whoami', 'uname -a', 'id', 'hostname', 'ps aux', 'df -h', 'netstat -tlnp'] as $offset => $command) {
            $binary = explode(' ', $command)[0];

            $events[] = $this->event($ts + $offset + 1, [
                'pid' => $pid + $offset + 1, 'ppid' => $pid, 'uid' => 1000, 'username' => 'deploy',
                'cwd' => '/home/deploy',
                'path' => '/usr/bin/' . $binary, 'cmdline' => $command,
            ]);
        }

        $events[] = $this->event($ts + 20, [
            'pid' => $pid + 30, 'ppid' => $pid, 'uid' => 1000, 'username' => 'deploy',
            'cwd' => '/home/deploy', 'path' => '/usr/bin/sudo', 'cmdline' => 'sudo systemctl restart nginx',
        ]);
        $events[] = $this->event($ts + 21, [
            'pid' => $pid + 31, 'ppid' => $pid + 30, 'uid' => 0, 'username' => 'root',
            'cwd' => '/home/deploy', 'path' => '/usr/bin/systemctl', 'cmdline' => 'systemctl restart nginx',
        ]);

        return $events;
    }

    /**
     * Two hundred packages replaced in five minutes: hundreds of never-seen
     * images, lineages and argument shapes, all at once.
     *
     * @return array<int, array>
     */
    private function packageUpgrade(int $ts, int $pid): array
    {
        $events = [
            $this->event($ts, ['pid' => $pid, 'ppid' => 800, 'path' => '/usr/bin/apt-get', 'cmdline' => 'apt-get -y upgrade']),
        ];

        for ($i = 0; $i < 200; $i++) {
            $events[] = $this->event($ts + 1 + intdiv($i, 4), [
                'pid' => $pid + 1 + $i, 'ppid' => $pid,
                'path' => '/usr/bin/dpkg', 'cmdline' => 'dpkg --unpack /var/cache/apt/archives/pkg' . $i . '.deb',
            ]);
            $events[] = $this->event($ts + 2 + intdiv($i, 4), [
                'pid' => $pid + 300 + $i, 'ppid' => $pid + 1 + $i,
                'path' => '/var/lib/dpkg/info/pkg' . $i . '.postinst', 'cmdline' => '/var/lib/dpkg/info/pkg' . $i . '.postinst configure',
            ]);
        }

        return $events;
    }

    public function test_an_ordinary_host_stays_completely_silent(): void
    {
        $incidents = [];
        $eventCount = 0;
        $matureAt = null;

        for ($day = 0; $day < self::DAYS; $day++) {
            for ($cycle = 0; $cycle < self::CYCLES_PER_DAY; $cycle++) {
                $ts = self::T0 + $day * 86400 + $cycle * intdiv(86400, self::CYCLES_PER_DAY);
                $events = $this->ordinaryCycle($ts, $day, $cycle);

                // Two interactive admin sessions, on days 3 and 9.
                if (($day === 3 || $day === 9) && $cycle === 20) {
                    $events = array_merge($events, $this->adminSession($ts + 40, 30000 + $day * 100));
                }

                // A package upgrade on day 12.
                if ($day === 12 && $cycle === 30) {
                    $events = array_merge($events, $this->packageUpgrade($ts + 50, 40000));
                }

                $eventCount += count($events);
                $found = $this->correlator->correlate($events);

                if ($found !== []) {
                    foreach ($found as $incident) {
                        $incidents[] = [
                            'day' => $day,
                            'cycle' => $cycle,
                            'rule' => $incident['rule'],
                            'severity' => $incident['severity'],
                            'classes' => implode(',', $incident['findings'][0]['incident']['classes'] ?? []),
                            'score' => $incident['findings'][0]['incident']['score'] ?? null,
                            'threshold' => $incident['findings'][0]['incident']['threshold'] ?? null,
                            'chain' => $incident['findings'][0]['incident']['chain_key'] ?? null,
                        ];
                    }
                }

                if ($matureAt === null && $this->correlator->stats()['mature']) {
                    $matureAt = $day;
                }
            }
        }

        // The test only means anything if the model actually woke up.
        $this->assertNotNull($matureAt, 'The model never matured, so silence proves nothing');
        $this->assertLessThan(self::DAYS - 3, $matureAt, 'Maturity must be reached with days left to be wrong in');
        $this->assertGreaterThan(5000, $eventCount, 'The fixture must be a real workload');

        $this->assertSame(
            [],
            $incidents,
            "An ordinary host produced incidents:\n" . json_encode($incidents, JSON_PRETTY_PRINT)
        );
    }

    /**
     * Silence is not enough on its own — an actor sitting just under the bar
     * would pass the test above and alert on the first unusual Tuesday. Every
     * actor should be nowhere near its threshold.
     */
    public function test_ordinary_actors_stay_far_below_their_threshold(): void
    {
        for ($day = 0; $day < 16; $day++) {
            for ($cycle = 0; $cycle < self::CYCLES_PER_DAY; $cycle++) {
                $ts = self::T0 + $day * 86400 + $cycle * intdiv(86400, self::CYCLES_PER_DAY);
                $this->correlator->correlate($this->ordinaryCycle($ts, $day, $cycle));
            }
        }

        $scorer = new \App\Services\Correlation\EdrActorScorer([]);
        $jitter = \App\Services\Correlation\EdrActorScorer::jitterFor('quiet-01');

        $store = $this->correlator->store();
        $pdo = new \PDO('sqlite:' . $this->path);
        $pdo->setAttribute(\PDO::ATTR_DEFAULT_FETCH_MODE, \PDO::FETCH_ASSOC);

        $worst = 0.0;
        $worstKey = '';

        foreach ($pdo->query('SELECT actor_key FROM actors')->fetchAll() as $row) {
            $key = (string) $row['actor_key'];
            $actors = $store->loadActors([$key]);
            $actor = [
                'acc' => (array) json_decode((string) $actors[$key]['acc'], true),
                'class_first_ts' => (array) json_decode((string) $actors[$key]['class_first_ts'], true),
                'nov' => (float) $actors[$key]['nov'],
            ];

            $scored = $scorer->score($actor);
            $threshold = $scorer->threshold($actor, $jitter, $key === EdrCorrelator::HOST_ACTOR);
            $ratio = $scored['score'] / $threshold;

            if ($ratio > $worst) {
                $worst = $ratio;
                $worstKey = $key;
            }
        }

        $this->assertLessThan(
            0.5,
            $worst,
            "Actor {$worstKey} sat at " . round($worst * 100) . '% of its threshold on an ordinary host'
        );
    }

    /**
     * The host lane must not turn ordinary multi-actor activity into an
     * incident just because a busy machine has several entry points.
     */
    public function test_host_lane_stays_quiet_on_an_ordinary_host(): void
    {
        $hostIncidents = [];

        for ($day = 0; $day < 18; $day++) {
            for ($cycle = 0; $cycle < self::CYCLES_PER_DAY; $cycle++) {
                $ts = self::T0 + $day * 86400 + $cycle * intdiv(86400, self::CYCLES_PER_DAY);
                $events = $this->ordinaryCycle($ts, $day, $cycle);

                if ($day === 5 && $cycle === 20) {
                    $events = array_merge($events, $this->adminSession($ts + 40, 50000));
                }

                foreach ($this->correlator->correlate($events) as $incident) {
                    if (($incident['rule'] ?? '') === EdrIncident::RULE_HOST) {
                        $hostIncidents[] = $incident['findings'][0]['incident']['classes'] ?? [];
                    }
                }
            }
        }

        $this->assertSame([], $hostIncidents, 'The host lane fired on ordinary activity');
    }
}

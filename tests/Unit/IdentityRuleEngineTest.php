<?php

namespace Tests\Unit;

use App\Services\Identity\IdentityHistory;
use App\Services\Identity\IdentityRuleEngine;
use Tests\TestCase;

/**
 * Stolen credentials are the most common way into a machine, and they leave a
 * different kind of trace from malware: nothing malicious executes, no file is
 * dropped, and every individual event looks like a person logging in. What
 * gives it away is shape across time, so most of these rules are thresholds —
 * and thresholds are where off-by-one mistakes hide, which is why every one is
 * tested on both sides of its boundary.
 *
 * Two of the tests here exist because the first version of the rule was wrong
 * against real data, not because the case was imagined.
 */
class IdentityRuleEngineTest extends TestCase
{
    private IdentityRuleEngine $rules;
    private object $history;

    protected function setUp(): void
    {
        parent::setUp();

        // History is injected rather than staged in a database: the window
        // rules are the part most worth testing exhaustively, and that is only
        // cheap if a test can simply state what the past looked like.
        $this->history = new class implements IdentityHistory {
            public array $failures = [];
            public array $privFailures = [];
            public array $sources = [];
            public array $knownSources = [];

            public function failuresFrom(string $sourceIp, int $since, int $until): array
            {
                return $this->failures;
            }

            public function privilegeFailuresBy(string $actor, int $since, int $until): array
            {
                return $this->privFailures;
            }

            public function sourcesFor(string $username, int $since, int $until): array
            {
                return $this->sources;
            }

            public function knownSourcesFor(string $username, int $before): array
            {
                return $this->knownSources;
            }

            public array $profile = ['hours' => [], 'days' => 0];

            public function loginHoursFor(string $username, int $before): array
            {
                return $this->profile;
            }
        };

        $this->rules = new IdentityRuleEngine($this->history);
    }

    private function event(array $overrides = []): array
    {
        return array_merge([
            'ts' => time(),
            'sensor' => 'authlog',
            'service' => 'sshd',
            'username' => 'john',
            'actor' => null,
            'source_ip' => '203.0.113.9',
            'method' => 'password',
            'reason' => null,
        ], $overrides);
    }

    /** @return array<int, string> */
    private function rulesFired(array $event): array
    {
        return array_column($this->rules->evaluate($event), 'rule');
    }

    private function finding(array $event, string $rule): ?array
    {
        foreach ($this->rules->evaluate($event) as $finding) {
            if ($finding['rule'] === $rule) {
                return $finding;
            }
        }

        return null;
    }

    public function test_brute_force_threshold_is_exact(): void
    {
        $this->history->failures = array_fill(0, 7, ['username' => 'john']);
        $this->assertNotContains('IAM-001', $this->rulesFired($this->event(['action' => 'login_failure'])));

        $this->history->failures = array_fill(0, 8, ['username' => 'john']);
        $this->assertContains('IAM-001', $this->rulesFired($this->event(['action' => 'login_failure'])));
    }

    /**
     * Spraying deliberately stays under a per-account lockout threshold, which
     * is exactly why counting failures per account misses it. The signal is
     * breadth, not depth — and depth is already covered by IAM-001, so saying
     * both would be saying the same thing twice.
     */
    public function test_spraying_is_breadth_not_depth(): void
    {
        $this->history->failures = [];
        foreach (['a', 'b', 'c', 'd', 'e'] as $user) {
            $this->history->failures[] = ['username' => $user];
            $this->history->failures[] = ['username' => $user];
        }
        $fired = $this->rulesFired($this->event(['action' => 'login_failure']));
        $this->assertContains('IAM-002', $fired);

        $this->history->failures = [];
        foreach (['a', 'b', 'c', 'd', 'e'] as $user) {
            for ($i = 0; $i < 10; $i++) {
                $this->history->failures[] = ['username' => $user];
            }
        }
        $fired = $this->rulesFired($this->event(['action' => 'login_failure']));
        $this->assertContains('IAM-001', $fired);
        $this->assertNotContains('IAM-002', $fired, 'deep and broad is one finding, not two');
    }

    /**
     * The regression that matters. The first version of this rule graded on a
     * yes/no — known address or not — and raised a critical for a developer
     * mistyping their own password from the laptop they use every day, because
     * a freshly deployed agent has no history for anybody and "no history" was
     * being read as "never seen before".
     */
    public function test_success_after_failures_has_three_answers_not_two(): void
    {
        $this->history->failures = array_fill(0, 6, ['username' => 'john']);

        // No history at all: we have no basis for a judgement, and saying so
        // is more useful than guessing.
        $this->history->knownSources = [];
        $noBasis = $this->finding($this->event(['action' => 'login_success']), 'IAM-003');
        $this->assertNotNull($noBasis);
        $this->assertSame('medium', $noBasis['severity'], 'absence of history is not evidence of intrusion');

        // A device this account uses: almost always a person.
        $this->history->knownSources = ['203.0.113.9', '10.0.0.5'];
        $known = $this->finding($this->event(['action' => 'login_success']), 'IAM-003');
        $this->assertSame('medium', $known['severity']);
        $this->assertStringContainsString('mistyped', $known['reason']);

        // A source this account has never used, succeeding after failures.
        $this->history->knownSources = ['10.0.0.5', '10.0.0.6'];
        $unknown = $this->finding($this->event(['action' => 'login_success']), 'IAM-003');
        $this->assertSame('critical', $unknown['severity']);
        $this->assertStringContainsString('compromised', $unknown['reason']);
    }

    public function test_success_after_only_two_failures_does_not_fire(): void
    {
        $this->history->failures = array_fill(0, 2, ['username' => 'john']);
        $this->assertNotContains('IAM-003', $this->rulesFired($this->event(['action' => 'login_success'])));
    }

    /**
     * The other regression. Grading every service-account session as critical
     * produced 48 alerts on a healthy host during development, every one of
     * them an administrator running `sudo -u www-data` to debug a deploy.
     * What distinguishes the dangerous case is that nobody escalated into it.
     */
    public function test_service_account_sessions_are_graded_by_how_they_were_obtained(): void
    {
        $direct = $this->finding(
            $this->event(['action' => 'login_success', 'username' => 'www-data', 'actor' => null]),
            'IAM-004'
        );
        $this->assertSame('critical', $direct['severity'], 'nothing legitimate logs in as a daemon');

        $assumed = $this->finding(
            $this->event(['action' => 'session_open', 'username' => 'www-data', 'actor' => 'vito', 'method' => 'sudo']),
            'IAM-004'
        );
        $this->assertSame('low', $assumed['severity'], 'an administrator assuming the account is routine');

        // A daemon's own cron and logind sessions are it doing its job.
        $this->assertNotContains(
            'IAM-004',
            $this->rulesFired($this->event(['action' => 'session_open', 'username' => 'www-data', 'method' => 'cron']))
        );

        $this->assertNotContains(
            'IAM-004',
            $this->rulesFired($this->event(['action' => 'login_success', 'username' => 'john']))
        );
    }

    public function test_account_changes_are_graded_by_what_they_grant(): void
    {
        $admin = $this->finding($this->event([
            'action' => 'account_change',
            'username' => 'eve',
            'reason' => 'added_to_group',
            'group' => 'sudo',
        ]), 'IAM-005');
        $this->assertSame('critical', $admin['severity']);

        $this->assertNotContains('IAM-005', $this->rulesFired($this->event([
            'action' => 'account_change',
            'username' => 'eve',
            'reason' => 'added_to_group',
            'group' => 'audio',
        ])), 'an unprivileged group is not a privilege change');

        $created = $this->finding($this->event([
            'action' => 'account_change',
            'username' => 'eve',
            'reason' => 'user_created',
        ]), 'IAM-005');
        $this->assertSame('high', $created['severity']);
    }

    /**
     * Somebody typing `sudo` has a terminal. A script, a cron job or a shell
     * spawned through an exploit does not.
     */
    public function test_root_escalation_without_a_terminal_is_flagged(): void
    {
        $this->assertContains('IAM-006', $this->rulesFired($this->event([
            'action' => 'privilege_escalation',
            'username' => 'root',
            'actor' => 'vito',
            'interactive' => false,
        ])));

        $this->assertNotContains('IAM-006', $this->rulesFired($this->event([
            'action' => 'privilege_escalation',
            'username' => 'root',
            'actor' => 'vito',
            'interactive' => true,
        ])));
    }

    public function test_repeated_escalation_failures_threshold_is_exact(): void
    {
        $this->history->privFailures = array_fill(0, 2, ['actor' => 'vito']);
        $this->assertNotContains('IAM-007', $this->rulesFired(
            $this->event(['action' => 'privilege_failure', 'actor' => 'vito'])
        ));

        $this->history->privFailures = array_fill(0, 3, ['actor' => 'vito']);
        $this->assertContains('IAM-007', $this->rulesFired(
            $this->event(['action' => 'privilege_failure', 'actor' => 'vito'])
        ));
    }

    public function test_one_account_from_several_sources_counts_distinct_addresses(): void
    {
        $this->history->sources = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
        $this->assertContains('IAM-008', $this->rulesFired($this->event(['action' => 'login_success'])));

        // Three events, two addresses — repeated logins from the same place
        // are not movement.
        $this->history->sources = ['10.0.0.1', '10.0.0.1', '10.0.0.2'];
        $this->assertNotContains('IAM-008', $this->rulesFired($this->event(['action' => 'login_success'])));
    }

    /**
     * Held to the same standard as IAM-003 about basis. "Unusual" below the
     * profile threshold is just "not seen yet", and a rule that cannot tell
     * those apart raises an alert for every normal login in its first week.
     */
    public function test_anomaly_rules_stay_silent_until_there_is_a_profile(): void
    {
        $this->history->knownSources = [];
        $this->history->profile = ['hours' => [], 'days' => 0];
        $fired = $this->rulesFired($this->event(['action' => 'login_success']));
        $this->assertEmpty(array_intersect(['IAM-009', 'IAM-010'], $fired), 'no history, no claim');

        // Four days is a handful of coincidences, not a routine.
        $this->history->knownSources = ['10.0.0.1'];
        $this->history->profile = ['hours' => [9, 10, 11], 'days' => 4];
        $fired = $this->rulesFired($this->event(['action' => 'login_success']));
        $this->assertEmpty(array_intersect(['IAM-009', 'IAM-010'], $fired), 'below the profile threshold');
    }

    public function test_a_new_source_and_an_unusual_hour_are_reported_separately(): void
    {
        $this->history->knownSources = ['10.0.0.1', '10.0.0.2'];
        $this->history->profile = ['hours' => [9, 10, 11], 'days' => 20];

        $atTwo = mktime(14, 0, 0, 8, 14, 2026);
        $fired = $this->rulesFired($this->event(['action' => 'login_success', 'ts' => $atTwo]));

        $this->assertContains('IAM-009', $fired, 'an address never used before');
        $this->assertContains('IAM-010', $fired, 'an hour never used before');

        // A known address at a usual hour is simply someone working.
        $this->history->knownSources = ['203.0.113.9'];
        $atTen = mktime(10, 0, 0, 8, 14, 2026);
        $fired = $this->rulesFired($this->event(['action' => 'login_success', 'ts' => $atTen]));
        $this->assertEmpty(array_intersect(['IAM-009', 'IAM-010'], $fired));

        // The hour alone is weak, so it is reported alone and graded low.
        $fired = $this->rulesFired($this->event(['action' => 'login_success', 'ts' => $atTwo]));
        $this->assertNotContains('IAM-009', $fired);
        $this->assertContains('IAM-010', $fired);
    }

    /**
     * A new address is a strong signal; an unusual hour is not. People travel
     * and schedules change, so the hour earns its place as corroboration
     * rather than as an alert somebody is woken up for.
     */
    public function test_anomaly_severities_reflect_how_much_each_signal_is_worth(): void
    {
        $this->history->knownSources = ['10.0.0.1'];
        $this->history->profile = ['hours' => [9], 'days' => 20];

        $severities = [];
        foreach ($this->rules->evaluate($this->event([
            'action' => 'login_success',
            'ts' => mktime(14, 0, 0, 8, 14, 2026),
        ])) as $finding) {
            $severities[$finding['rule']] = $finding['severity'];
        }

        $this->assertSame('high', $severities['IAM-009']);
        $this->assertSame('low', $severities['IAM-010']);
    }

    public function test_events_that_are_not_about_identity_are_ignored(): void
    {
        $this->assertSame([], $this->rules->evaluate($this->event(['action' => 'exec'])));
        $this->assertSame([], $this->rules->evaluate($this->event(['action' => 'file_write'])));
        $this->assertSame([], $this->rules->evaluate($this->event(['action' => 'session_close'])));
    }
}

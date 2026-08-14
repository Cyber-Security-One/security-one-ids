<?php

namespace App\Console\Commands;

use App\Services\Quality\EdrExclusionSuggester;
use App\Services\Quality\EdrGovernanceStore;
use App\Services\Quality\EdrRuleGovernor;
use App\Services\Quality\EdrRuleRegression;
use Illuminate\Console\Command;

/**
 * The tuning loop, run by hand.
 *
 * This is the command to sit in front of during a customer's onboarding
 * week: `--rules` to see what is firing, `--suggest` to get exclusions
 * proposed rather than hand-written, `--regression` before shipping any
 * change to the rule set.
 */
class EdrQualityCommand extends Command
{
    protected $signature = 'ids:edr-quality
        {--status : Baseline, environment profile and totals}
        {--rules : Per-rule hits, alerts, suppressions and false-positive rate}
        {--suggest : Proposed exclusions derived from what recurs on this host}
        {--regression : Run the rule set against the known-verdict corpus}
        {--stage= : Set a rule stage, as RULE:stage (observe|alert|enforce|disabled)}
        {--restart-baseline : Restart the learning window}';

    protected $description = 'Inspect and tune EDR rule quality on this endpoint';

    public function handle(
        EdrGovernanceStore $store,
        EdrRuleGovernor $governor,
        EdrExclusionSuggester $suggester
    ): int {
        if ($this->option('regression')) {
            return $this->regression();
        }

        if ($stage = $this->option('stage')) {
            return $this->setStage($store, (string) $stage);
        }

        if ($this->option('restart-baseline')) {
            $governor->restartBaseline();
            $this->info('Baseline learning window restarted.');

            return 0;
        }

        if ($this->option('rules')) {
            return $this->listRules($store);
        }

        if ($this->option('suggest')) {
            return $this->suggest($suggester);
        }

        return $this->status($governor, $store);
    }

    private function status(EdrRuleGovernor $governor, EdrGovernanceStore $store): int
    {
        $status = $governor->getStatus();

        $this->info('EDR Rule Quality');
        $this->line(str_repeat('=', 52));

        $this->line(sprintf('  %-24s %s', 'environment_profile', $status['environment_profile']));
        $this->line(sprintf('  %-24s %s', 'learning', $status['learning'] ? 'YES' : 'no'));

        if ($status['baseline_started_at']) {
            $this->line(sprintf('  %-24s %s', 'baseline_started', date('Y-m-d H:i:s', $status['baseline_started_at'])));
        }

        if ($status['learning']) {
            $hours = (int) round($status['baseline_remaining_seconds'] / 3600);
            $this->line(sprintf('  %-24s %d hours', 'learning_remaining', $hours));
        }

        $s = $status['store'];
        $this->line(sprintf('  %-24s %d', 'rules_tracked', $s['rules_tracked']));
        $this->line(sprintf('  %-24s %d', 'baseline_observations', $s['baseline_observations']));
        $this->line(sprintf('  %-24s %d', 'total_hits', $s['total_hits']));
        $this->line(sprintf('  %-24s %d', 'total_alerts', $s['total_alerts']));
        $this->line(sprintf('  %-24s %d', 'total_suppressed', $s['total_suppressed']));

        if ($s['by_stage'] !== []) {
            $this->newLine();
            $this->line('  Rules by stage:');
            foreach ($s['by_stage'] as $stage => $count) {
                $this->line(sprintf('    %-12s %d', $stage, $count));
            }
        }

        if ($status['learning']) {
            $this->newLine();
            $this->warn('  While learning, low and medium findings are counted but not raised.');
            $this->line('  High and critical still alert — a host compromised on day one');
            $this->line('  will not wait for the baseline to finish.');
        }

        return 0;
    }

    private function listRules(EdrGovernanceStore $store): int
    {
        $rules = $store->allRuleState();

        if ($rules === []) {
            $this->line('No rule activity recorded yet.');

            return 0;
        }

        $this->line(sprintf('  %-10s %-9s %7s %7s %11s %9s', 'RULE', 'STAGE', 'HITS', 'ALERTS', 'SUPPRESSED', 'FP RATE'));
        $this->line('  ' . str_repeat('-', 58));

        foreach ($rules as $rule) {
            // An unjudged rule has an unknown false-positive rate, not a good
            // one — printing 0% there would be the more dangerous lie.
            $fp = $rule['fp_rate'] === null ? '   n/a' : sprintf('%5.1f%%', $rule['fp_rate'] * 100);

            $this->line(sprintf(
                '  %-10s %-9s %7d %7d %11d %9s',
                $rule['rule'],
                $rule['stage'],
                $rule['hits'],
                $rule['alerts'],
                $rule['suppressed'],
                $fp
            ));
        }

        $this->newLine();
        $this->line('  n/a means no analyst has judged this rule\'s output yet.');

        return 0;
    }

    private function suggest(EdrExclusionSuggester $suggester): int
    {
        $suggestions = $suggester->suggest();
        $underperforming = $suggester->underperformingRules();
        $promotions = $suggester->promotionCandidates();

        if ($suggestions === [] && $underperforming === [] && $promotions === []) {
            $this->line('Nothing to propose yet — not enough history on this host.');

            return 0;
        }

        if ($suggestions !== []) {
            $this->info('Proposed exclusions');
            foreach ($suggestions as $suggestion) {
                $this->newLine();
                $this->line("  {$suggestion['rule']}  ({$suggestion['confidence']} confidence)");
                $this->line("    pattern: {$suggestion['pattern']}");
                $this->line("    {$suggestion['rationale']}");
                if (!empty($suggestion['sample'])) {
                    $this->line('    sample:  ' . $suggestion['sample']);
                }
            }
        }

        if ($underperforming !== []) {
            $this->newLine();
            $this->warn('Rules not earning their place');
            foreach ($underperforming as $rule) {
                $this->line(sprintf(
                    '  %-10s %s (hits %d, suppressed %.0f%%)',
                    $rule['rule'],
                    $rule['reason'],
                    $rule['hits'],
                    $rule['suppression_rate'] * 100
                ));
            }
        }

        if ($promotions !== []) {
            $this->newLine();
            $this->info('Candidates for promotion to enforce');
            foreach ($promotions as $rule) {
                $this->line(sprintf(
                    '  %-10s %d alerts, %d judged, %.1f%% false positive',
                    $rule['rule'],
                    $rule['alerts'],
                    $rule['judged'],
                    $rule['fp_rate'] * 100
                ));
            }
            $this->newLine();
            $this->line('  Promotion is never automatic. Enforce means this rule may kill');
            $this->line('  a process on a customer\'s machine; that is a decision for a person.');
        }

        $this->newLine();
        $this->line('Nothing here has been applied. Approve exclusions at the Hub.');

        return 0;
    }

    private function regression(): int
    {
        $result = (new EdrRuleRegression())->run();

        $this->info("Rule regression: {$result['passed']}/{$result['total']} passed");

        if ($result['failed'] === 0) {
            $this->newLine();
            $this->line('  Covered rules: ' . implode(', ', array_keys($result['coverage'])));

            return 0;
        }

        $this->newLine();

        foreach ($result['failures'] as $failure) {
            if ($failure['kind'] === 'missed_detection') {
                $this->error("  MISSED  {$failure['name']}");
                $this->line("    expected {$failure['expected']}, got {$failure['actual']}");
            } else {
                $this->warn("  FALSE POSITIVE  {$failure['name']}");
                $this->line("    expected no detection, got {$failure['actual']}");
            }

            $this->line("    cmd:  {$failure['cmdline']}");
            $this->line("    note: {$failure['note']}");
            $this->newLine();
        }

        return 1;
    }

    private function setStage(EdrGovernanceStore $store, string $argument): int
    {
        if (!str_contains($argument, ':')) {
            $this->error('Expected RULE:stage, for example EDR-004:observe');

            return 1;
        }

        [$rule, $stage] = explode(':', $argument, 2);
        $rule = trim($rule);
        $stage = trim($stage);

        $valid = [
            EdrGovernanceStore::STAGE_OBSERVE,
            EdrGovernanceStore::STAGE_ALERT,
            EdrGovernanceStore::STAGE_ENFORCE,
            EdrGovernanceStore::STAGE_DISABLED,
        ];

        if (!in_array($stage, $valid, true)) {
            $this->error('Stage must be one of: ' . implode(', ', $valid));

            return 1;
        }

        $store->setStage($rule, $stage, 'set locally via CLI');
        $this->info("{$rule} is now at stage '{$stage}'.");

        if ($stage === EdrGovernanceStore::STAGE_ENFORCE) {
            $this->warn('  This rule may now trigger response actions on this host.');
        }

        // A Hub override outranks anything set here, so say so rather than
        // let someone believe a local change is the final word.
        $this->line('  A Hub-issued rule stage will override this on the next sync.');

        return 0;
    }
}

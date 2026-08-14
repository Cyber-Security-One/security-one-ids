<?php

namespace App\Services\Quality;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Decides what a rule match is allowed to do on this host.
 *
 * Detection without governance is what makes an EDR unusable in practice. The
 * first version of the rules in this product produced thirteen alerts on a
 * healthy machine and all thirteen were wrong. That was survivable while the
 * only consequence was a noisy list; now that a rule can end a process or cut
 * a host off the network, the same mistake ends someone's afternoon.
 *
 * So a match passes through three questions before it reaches anyone:
 *
 *  1. **Is this host still learning?** A newly deployed agent does not know
 *     what normal looks like here yet.
 *  2. **Has this rule earned the right?** Rules progress observe -> alert ->
 *     enforce, and only the last of those may drive a response.
 *  3. **Have we seen exactly this before?** A shape that recurred throughout
 *     the baseline is this host's normal behaviour, whatever the rule thinks.
 *
 * The learning window deliberately does not silence everything. A machine
 * that is compromised on its first day will not wait for the baseline to
 * finish, so high and critical findings alert from the moment the agent
 * starts. Only the lower severities — the ones that describe habits rather
 * than attacks — are held back.
 */
class EdrRuleGovernor
{
    private const META_BASELINE_START = 'baseline_started_at';
    private const META_ENV_PROFILE = 'environment_profile';
    private const META_ENV_PROFILED_AT = 'environment_profiled_at';

    /** Default learning window. */
    private const DEFAULT_BASELINE_DAYS = 7;

    /** Severities that alert even while learning. */
    private const ALWAYS_ALERT_SEVERITIES = ['high', 'critical'];

    /** Re-detect the host's role at most this often. */
    private const PROFILE_TTL = 86400;

    /**
     * Rules that are noisy on particular kinds of host. Not a suppression —
     * a demotion to observation, so the traffic is still counted and can be
     * promoted back once tuned.
     */
    private const NOISY_ON_ROLE = [
        'dev' => ['EDR-004', 'EDR-005', 'EDR-011'],
        'build' => ['EDR-004', 'EDR-005', 'EDR-010', 'EDR-011'],
        'container_host' => ['EDR-009'],
    ];

    private EdrGovernanceStore $store;

    /** @var array<string, string> */
    private array $stageCache = [];

    private ?string $profile = null;

    public function __construct(EdrGovernanceStore $store)
    {
        $this->store = $store;
    }

    /* ------------------------------------------------------------------ */
    /* Baseline window                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * Start the clock if it has not started. Called on every cycle; only the
     * first one does anything.
     */
    public function ensureBaselineStarted(): void
    {
        if ($this->store->getMeta(self::META_BASELINE_START) === null) {
            $this->store->setMeta(self::META_BASELINE_START, (string) time());
            Log::info('[EDR quality] Baseline learning window started');
        }
    }

    public function baselineStartedAt(): ?int
    {
        $value = $this->store->getMeta(self::META_BASELINE_START);

        return $value === null ? null : (int) $value;
    }

    public function isLearning(int $baselineDays = self::DEFAULT_BASELINE_DAYS): bool
    {
        $startedAt = $this->baselineStartedAt();

        if ($startedAt === null) {
            return true;
        }

        // Zero disables the window entirely, for a redeployment onto a host
        // whose behaviour is already understood.
        if ($baselineDays <= 0) {
            return false;
        }

        return (time() - $startedAt) < ($baselineDays * 86400);
    }

    public function baselineRemainingSeconds(int $baselineDays = self::DEFAULT_BASELINE_DAYS): int
    {
        $startedAt = $this->baselineStartedAt();

        if ($startedAt === null || $baselineDays <= 0) {
            return 0;
        }

        return max(0, ($startedAt + $baselineDays * 86400) - time());
    }

    /**
     * Restart learning — for a host that has been repurposed, where the old
     * profile describes a machine that no longer exists.
     */
    public function restartBaseline(): void
    {
        $this->store->setMeta(self::META_BASELINE_START, (string) time());
        Log::info('[EDR quality] Baseline learning window restarted');
    }

    /* ------------------------------------------------------------------ */
    /* Decision                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * @param array $finding one rule hit
     * @param array $event   the normalised event it fired on
     * @param array $options quality settings from the Hub
     *
     * @return array{emit:bool, allow_response:bool, stage:string, reason:?string, signature:string}
     */
    public function assess(array $finding, array $event, array $options = []): array
    {
        $rule = (string) ($finding['rule'] ?? '');
        $severity = (string) ($finding['severity'] ?? 'low');
        $signature = $this->signatureFor($finding, $event);

        $stage = $this->stageFor($rule, $options);

        if ($stage === EdrGovernanceStore::STAGE_DISABLED) {
            return $this->decision(false, false, $stage, 'rule_disabled', $signature);
        }

        if ($stage === EdrGovernanceStore::STAGE_OBSERVE) {
            // Counted, not raised. This is where an unproven rule lives until
            // its output has been looked at.
            return $this->decision(false, false, $stage, 'rule_observing', $signature);
        }

        $baselineDays = (int) ($options['baseline_days'] ?? self::DEFAULT_BASELINE_DAYS);
        $learning = $this->isLearning($baselineDays);

        if ($learning && !in_array($severity, self::ALWAYS_ALERT_SEVERITIES, true)) {
            return $this->decision(false, false, $stage, 'baseline_learning', $signature);
        }

        // A shape that recurred through the baseline is this host's normal
        // behaviour. Suppression is capped at the lower severities: if the
        // same reverse-shell construct ran every day during learning, that is
        // a finding about the baseline, not a reason to stop reporting it.
        $minOccurrences = max(2, (int) ($options['baseline_min_occurrences'] ?? 5));

        if (!in_array($severity, self::ALWAYS_ALERT_SEVERITIES, true)
            && $this->store->hasObservation($rule, $signature, $minOccurrences)
        ) {
            return $this->decision(false, false, $stage, 'matches_baseline', $signature);
        }

        // Response requires the rule to have been promoted all the way.
        $allowResponse = $stage === EdrGovernanceStore::STAGE_ENFORCE;

        return $this->decision(true, $allowResponse, $stage, null, $signature);
    }

    private function decision(
        bool $emit,
        bool $allowResponse,
        string $stage,
        ?string $reason,
        string $signature
    ): array {
        return [
            'emit' => $emit,
            'allow_response' => $allowResponse,
            'stage' => $stage,
            'reason' => $reason,
            'signature' => $signature,
        ];
    }

    /**
     * Persist what happened, and keep learning while we are in the window.
     */
    public function record(array $decision, array $finding, array $event, array $options = []): void
    {
        $rule = (string) ($finding['rule'] ?? '');

        if ($rule === '') {
            return;
        }

        $this->store->recordHit($rule, $decision['emit']);

        // Keep building the profile for the whole learning window, including
        // from matches that were allowed through — a high-severity rule that
        // fires constantly here is exactly what an analyst needs to see when
        // the window closes.
        if ($this->isLearning((int) ($options['baseline_days'] ?? self::DEFAULT_BASELINE_DAYS))) {
            $this->store->observe(
                $rule,
                $decision['signature'],
                mb_substr((string) ($event['cmdline'] ?? ''), 0, 300)
            );
        }
    }

    /**
     * Effective stage for a rule, taking the host's role into account.
     */
    public function stageFor(string $rule, array $options = []): string
    {
        if (isset($this->stageCache[$rule])) {
            return $this->stageCache[$rule];
        }

        // Hub overrides win outright — this is how an analyst promotes a rule
        // to enforcing, or takes a bad one out of circulation fleet-wide.
        $overrides = is_array($options['rule_stages'] ?? null) ? $options['rule_stages'] : [];

        if (isset($overrides[$rule]) && is_string($overrides[$rule])) {
            return $this->stageCache[$rule] = $overrides[$rule];
        }

        $default = (string) ($options['default_stage'] ?? EdrGovernanceStore::STAGE_ALERT);
        $stage = $this->store->getStage($rule, $default);

        // Demote rules known to be noisy for this kind of host, unless they
        // have been deliberately promoted here.
        if ($stage === EdrGovernanceStore::STAGE_ALERT) {
            $role = $this->environmentProfile();

            if (in_array($rule, self::NOISY_ON_ROLE[$role] ?? [], true)) {
                $stage = EdrGovernanceStore::STAGE_OBSERVE;
            }
        }

        return $this->stageCache[$rule] = $stage;
    }

    /* ------------------------------------------------------------------ */
    /* Signatures                                                          */
    /* ------------------------------------------------------------------ */

    /**
     * A coarse description of a match, stable across repetitions of the same
     * activity but different between genuinely different activity.
     *
     * Volatile parts — pids, timestamps, temp names, hashes — are normalised
     * away, because otherwise every run of the same cron job looks new and
     * the baseline learns nothing.
     */
    public function signatureFor(array $finding, array $event): string
    {
        $rule = (string) ($finding['rule'] ?? '?');
        $user = (string) ($event['username'] ?? '?');
        $path = (string) ($event['path'] ?? '');
        $binary = $path !== '' ? basename($path) : '?';

        $cmdline = (string) ($event['cmdline'] ?? '');
        $normalised = $this->normaliseCommandLine($cmdline);

        return $rule . '|' . $user . '|' . $binary . '|' . $normalised;
    }

    private function normaliseCommandLine(string $cmdline): string
    {
        // Order matters: collapse the long, high-entropy tokens before the
        // digit rule turns them into something unrecognisable.
        $value = preg_replace('/\b[0-9a-f]{16,}\b/i', '<HEX>', $cmdline) ?? $cmdline;
        $value = preg_replace('/\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2})?\b/', '<DATE>', $value) ?? $value;
        $value = preg_replace('#/tmp/[^\s/]+#', '/tmp/<TMP>', $value) ?? $value;
        $value = preg_replace('#/proc/\d+#', '/proc/<PID>', $value) ?? $value;
        $value = preg_replace('/\b\d+\b/', '<N>', $value) ?? $value;
        $value = preg_replace('/\s+/', ' ', $value) ?? $value;

        return mb_substr(trim($value), 0, 200);
    }

    /* ------------------------------------------------------------------ */
    /* Environment profile                                                 */
    /* ------------------------------------------------------------------ */

    /**
     * What kind of machine is this?
     *
     * The same rule is worth very different amounts on different hosts.
     * Executing from /tmp is a strong signal on a database server and
     * background noise on a build machine, and treating them identically is
     * how a rule set gets switched off wholesale by a frustrated customer.
     */
    public function environmentProfile(): string
    {
        if ($this->profile !== null) {
            return $this->profile;
        }

        $cached = $this->store->getMeta(self::META_ENV_PROFILE);
        $profiledAt = (int) ($this->store->getMeta(self::META_ENV_PROFILED_AT) ?? 0);

        if ($cached !== null && (time() - $profiledAt) < self::PROFILE_TTL) {
            return $this->profile = $cached;
        }

        $profile = $this->detectProfile();

        $this->store->setMeta(self::META_ENV_PROFILE, $profile);
        $this->store->setMeta(self::META_ENV_PROFILED_AT, (string) time());

        return $this->profile = $profile;
    }

    private function detectProfile(): string
    {
        $running = $this->runningProcessNames();

        $has = static fn (array $names): bool => (bool) array_intersect($names, $running);

        // Ordered by how much the classification changes rule behaviour: a
        // build host is the noisiest and most misleading if misclassified.
        if ($has(['gcc', 'cc1', 'ld', 'make', 'ninja', 'cargo', 'rustc', 'javac', 'gradle', 'bazel'])) {
            return 'build';
        }

        if ($has(['dockerd', 'containerd', 'kubelet', 'crio', 'podman'])) {
            return 'container_host';
        }

        if ($has(['mysqld', 'postgres', 'mariadbd', 'mongod', 'redis-server'])) {
            return 'db';
        }

        if ($has(['nginx', 'apache2', 'httpd', 'php-fpm', 'caddy', 'lighttpd'])) {
            return 'web';
        }

        if ($has(['Xorg', 'gnome-shell', 'kwin_x11', 'plasmashell', 'sway', 'wayland'])) {
            return 'desktop';
        }

        if ($has(['sshd', 'systemd'])) {
            return 'server';
        }

        return 'unknown';
    }

    /**
     * @return array<int, string>
     */
    private function runningProcessNames(): array
    {
        try {
            $result = Process::timeout(15)->run("ps -eo comm= 2>/dev/null | sort -u");

            if (!$result->successful()) {
                return [];
            }

            return array_values(array_filter(array_map('trim', explode("\n", $result->output()))));
        } catch (\Exception $e) {
            return [];
        }
    }

    public function getStatus(array $options = []): array
    {
        $baselineDays = (int) ($options['baseline_days'] ?? self::DEFAULT_BASELINE_DAYS);

        return [
            'baseline_started_at' => $this->baselineStartedAt(),
            'baseline_days' => $baselineDays,
            'learning' => $this->isLearning($baselineDays),
            'baseline_remaining_seconds' => $this->baselineRemainingSeconds($baselineDays),
            'environment_profile' => $this->environmentProfile(),
            'store' => $this->store->stats(),
        ];
    }
}

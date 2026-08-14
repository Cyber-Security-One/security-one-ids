<?php

namespace App\Services\Response;

use App\Services\WafSyncService;
use Illuminate\Support\Facades\Log;

/**
 * Executes Hub-issued response commands and keeps the record straight.
 *
 * The Hub does not reach into the endpoint; it publishes commands in the
 * config it already sends, and this class decides whether each one is
 * legitimate, executes it, records the outcome, and undoes it when its
 * deadline passes.
 *
 * Four independent gates stand between a config blob and a destructive act,
 * because any single one of them can be got around:
 *
 *  1. **Capability.** Each action type is off until the Hub explicitly grants
 *     it. A customer who bought detection never hands us the ability to kill
 *     processes on their machines.
 *  2. **Freshness.** Commands carry an issue time and are rejected once stale.
 *     This is what stops an old config blob being replayed — by a rollback, a
 *     restored backup, or a cache — from re-triggering yesterday's kill.
 *  3. **Idempotency.** Actions are keyed by id in the ledger, so a redelivery
 *     the Hub sends because it never saw an acknowledgement is a no-op.
 *  4. **Confirmation.** Destructive types require an explicit flag, so a
 *     partially-populated or merged config cannot imply one.
 *
 * Everything that survives all four still gets a deadline, and the rollback
 * pass undoes anything the Hub has not reconfirmed.
 */
class EdrResponder
{
    /** Commands older than this are refused. */
    private const DEFAULT_MAX_COMMAND_AGE = 900;

    /** Isolation always gets a deadline, whatever the Hub asked for. */
    private const DEFAULT_ISOLATION_TTL = 3600;
    private const MAX_ISOLATION_TTL = 86400;

    /**
     * The hard ceiling on how long an action may stay applied, counted from
     * when it was applied and not from the last confirmation.
     *
     * This exists because every other guard in this file depends on the Hub
     * behaving correctly, and the scenario that needs the safety timer most is
     * the one where the Hub is gone. Network isolation makes the Hub
     * unreachable more likely, not less — only the pinned Hub addresses survive
     * the cut — so "the Hub will stop confirming" is not a safe assumption to
     * build the release on.
     *
     * Three days is deliberately generous. A real incident can justify keeping
     * a host contained for days, and this is not a limit on that: a reachable
     * Hub with an analyst behind it re-authorises well inside the window. What
     * it bounds is how long a host can stay cut off with nothing but a stale
     * config file speaking for the analyst.
     */
    private const ABSOLUTE_MAX_APPLIED_SECONDS = 259200;

    /** Types that change or destroy state, and so need an explicit confirm. */
    private const DESTRUCTIVE_TYPES = ['kill_process', 'quarantine_file', 'isolate_network'];

    /** type => capability flag that must be granted for it to run at all. */
    private const CAPABILITY_MAP = [
        'kill_process' => 'allow_process_control',
        'suspend_process' => 'allow_process_control',
        'resume_process' => 'allow_process_control',
        'quarantine_file' => 'allow_file_quarantine',
        'restore_file' => 'allow_file_quarantine',
        'isolate_network' => 'allow_network_isolation',
        'release_network' => 'allow_network_isolation',
    ];

    private EdrActionLedger $ledger;
    private ProcessResponder $processes;
    private FileQuarantine $quarantine;
    private NetworkContainment $network;
    private WafSyncService $sync;

    public function __construct(
        EdrActionLedger $ledger,
        ProcessResponder $processes,
        FileQuarantine $quarantine,
        NetworkContainment $network,
        WafSyncService $sync
    ) {
        $this->ledger = $ledger;
        $this->processes = $processes;
        $this->quarantine = $quarantine;
        $this->network = $network;
        $this->sync = $sync;
    }

    /* ------------------------------------------------------------------ */
    /* Command intake                                                      */
    /* ------------------------------------------------------------------ */

    /**
     * @param array $commands Hub-issued commands
     * @param array $options  response settings from the Hub
     *
     * @return array{executed:int, refused:int, skipped:int, outcomes:array<int, array>}
     */
    public function processCommands(array $commands, array $options = []): array
    {
        $summary = ['executed' => 0, 'refused' => 0, 'skipped' => 0, 'outcomes' => []];

        foreach ($commands as $command) {
            if (!is_array($command)) {
                continue;
            }

            $outcome = $this->handle($command, $options);
            $summary['outcomes'][] = $outcome;

            match ($outcome['status']) {
                'executed' => $summary['executed']++,
                'refused' => $summary['refused']++,
                default => $summary['skipped']++,
            };
        }

        return $summary;
    }

    /**
     * @return array{action_id:?string, type:?string, status:string, reason:?string}
     */
    private function handle(array $command, array $options): array
    {
        $actionId = isset($command['id']) ? (string) $command['id'] : '';
        $type = isset($command['type']) ? (string) $command['type'] : '';

        if ($actionId === '' || $type === '') {
            return $this->outcome(null, null, 'refused', 'malformed_command');
        }

        if (!array_key_exists($type, self::CAPABILITY_MAP)) {
            return $this->outcome($actionId, $type, 'refused', 'unknown_action_type');
        }

        // Gate 1 — capability.
        $capability = self::CAPABILITY_MAP[$type];
        if (empty($options[$capability])) {
            Log::warning('[EDR response] Command refused, capability not granted', [
                'type' => $type,
                'capability' => $capability,
            ]);

            return $this->outcome($actionId, $type, 'refused', 'capability_not_granted');
        }

        // Gate 2 — freshness. An old config blob replayed by a rollback, a
        // restored backup or a stale cache must not act.
        $maxAge = (int) ($options['max_command_age'] ?? self::DEFAULT_MAX_COMMAND_AGE);
        $issuedAt = isset($command['issued_at']) ? (int) $command['issued_at'] : 0;

        if ($issuedAt <= 0) {
            return $this->outcome($actionId, $type, 'refused', 'missing_issued_at');
        }

        $age = time() - $issuedAt;

        if ($age > $maxAge) {
            Log::warning('[EDR response] Command refused as stale', [
                'type' => $type,
                'age_seconds' => $age,
                'max_age' => $maxAge,
            ]);

            return $this->outcome($actionId, $type, 'refused', 'command_stale');
        }

        // A command from the future is a clock problem, not an instruction.
        if ($age < -300) {
            return $this->outcome($actionId, $type, 'refused', 'command_from_the_future');
        }

        // Gate 4 — explicit confirmation for anything destructive.
        if (in_array($type, self::DESTRUCTIVE_TYPES, true) && empty($command['confirm'])) {
            return $this->outcome($actionId, $type, 'refused', 'confirmation_required');
        }

        $target = is_array($command['target'] ?? null) ? $command['target'] : [];
        $reason = isset($command['reason']) ? (string) $command['reason'] : null;
        $requestedBy = isset($command['requested_by']) ? (string) $command['requested_by'] : 'hub';
        $force = (bool) ($command['force'] ?? false);

        $reversible = !in_array($type, ['kill_process'], true);
        $expiresAt = $this->deadlineFor($type, $command);

        // Gate 3 — idempotency. Recording before execution also means a crash
        // mid-action leaves evidence that we tried.
        if (!$this->ledger->record($actionId, $type, $target, $reason, $requestedBy, $reversible, $expiresAt)) {
            return $this->outcome($actionId, $type, 'skipped', 'already_seen');
        }

        try {
            $result = $this->dispatch($type, $target, $force, $options);
        } catch (\Throwable $e) {
            $this->ledger->markFailed($actionId, 'exception: ' . $e->getMessage());
            Log::error('[EDR response] Action threw', ['type' => $type, 'error' => $e->getMessage()]);

            return $this->outcome($actionId, $type, 'refused', 'exception');
        }

        if (empty($result['success'])) {
            $this->ledger->markFailed($actionId, (string) ($result['error'] ?? 'unknown'));

            return $this->outcome($actionId, $type, 'refused', (string) ($result['error'] ?? 'unknown'));
        }

        $this->ledger->markApplied($actionId, $result['result'] ?? [], $result['restore_data'] ?? null);

        Log::warning('[EDR response] Action applied', [
            'action_id' => $actionId,
            'type' => $type,
            'requested_by' => $requestedBy,
            'reason' => $reason,
        ]);

        return $this->outcome($actionId, $type, 'executed', null);
    }

    /**
     * Isolation is never allowed to be open-ended, whatever the Hub asks for:
     * the rollback timer is the backstop for every failure the containment
     * code cannot detect itself.
     */
    private function deadlineFor(string $type, array $command): ?int
    {
        $ttl = isset($command['ttl_seconds']) ? (int) $command['ttl_seconds'] : 0;

        if ($type === 'isolate_network') {
            if ($ttl <= 0) {
                $ttl = self::DEFAULT_ISOLATION_TTL;
            }

            return time() + min(self::MAX_ISOLATION_TTL, max(60, $ttl));
        }

        return $ttl > 0 ? time() + min(self::MAX_ISOLATION_TTL, max(60, $ttl)) : null;
    }

    /**
     * @return array{success:bool, error:?string, result:?array, restore_data:?array}
     */
    private function dispatch(string $type, array $target, bool $force, array $options): array
    {
        return match ($type) {
            'kill_process' => $this->killProcess($target, $force),
            'suspend_process' => $this->suspendProcess($target, $force),
            'resume_process' => $this->resumeProcess($target),
            'quarantine_file' => $this->quarantineFile($target, $force),
            'restore_file' => $this->restoreFile($target),
            'isolate_network' => $this->isolateNetwork($target, $options),
            'release_network' => $this->releaseNetwork(),
            default => ['success' => false, 'error' => 'unhandled_type', 'result' => null, 'restore_data' => null],
        };
    }

    /* ------------------------------------------------------------------ */
    /* Action wrappers                                                     */
    /* ------------------------------------------------------------------ */

    private function killProcess(array $target, bool $force): array
    {
        $pid = (int) ($target['pid'] ?? 0);
        $startTime = isset($target['start_time']) ? (int) $target['start_time'] : null;

        $result = $this->processes->kill($pid, $startTime, $force, (bool) ($target['graceful'] ?? false));

        return [
            'success' => (bool) $result['success'],
            'error' => $result['error'] ?? null,
            'result' => [
                'pid' => $pid,
                'confirmed_dead' => $result['confirmed_dead'] ?? false,
                'process' => $result['process'] ?? null,
            ],
            'restore_data' => null,
        ];
    }

    private function suspendProcess(array $target, bool $force): array
    {
        $pid = (int) ($target['pid'] ?? 0);
        $startTime = isset($target['start_time']) ? (int) $target['start_time'] : null;

        $result = $this->processes->suspend($pid, $startTime, $force);

        return [
            'success' => (bool) $result['success'],
            'error' => $result['error'] ?? null,
            'result' => ['pid' => $pid, 'process' => $result['process'] ?? null],
            // Enough to resume it later, including after a restart.
            'restore_data' => ['pid' => $pid, 'start_time' => $result['process']['start_time'] ?? $startTime],
        ];
    }

    private function resumeProcess(array $target): array
    {
        $pid = (int) ($target['pid'] ?? 0);
        $startTime = isset($target['start_time']) ? (int) $target['start_time'] : null;

        $result = $this->processes->resume($pid, $startTime);

        return [
            'success' => (bool) $result['success'],
            'error' => $result['error'] ?? null,
            'result' => ['pid' => $pid],
            'restore_data' => null,
        ];
    }

    private function quarantineFile(array $target, bool $force): array
    {
        $path = (string) ($target['path'] ?? '');

        if ($path === '') {
            return ['success' => false, 'error' => 'missing_path', 'result' => null, 'restore_data' => null];
        }

        $result = $this->quarantine->quarantine($path, $force);

        return [
            'success' => (bool) $result['success'],
            'error' => $result['error'] ?? null,
            'result' => $result['result'] ?? null,
            'restore_data' => $result['restore_data'] ?? null,
        ];
    }

    /**
     * Restore is addressed by the id of the quarantine action, not by path:
     * the restore data on that ledger row is the only complete description of
     * what the file was.
     */
    private function restoreFile(array $target): array
    {
        $originalActionId = (string) ($target['action_id'] ?? '');

        if ($originalActionId === '') {
            return ['success' => false, 'error' => 'missing_action_id', 'result' => null, 'restore_data' => null];
        }

        $original = $this->ledger->find($originalActionId);

        if ($original === null || empty($original['restore_data'])) {
            return ['success' => false, 'error' => 'original_action_not_found', 'result' => null, 'restore_data' => null];
        }

        $result = $this->quarantine->restore($original['restore_data']);

        if (!empty($result['success'])) {
            $this->ledger->markReverted($originalActionId, EdrActionLedger::STATE_REVERTED, $result['result'] ?? []);
        }

        return [
            'success' => (bool) $result['success'],
            'error' => $result['error'] ?? null,
            'result' => $result['result'] ?? null,
            'restore_data' => null,
        ];
    }

    private function isolateNetwork(array $target, array $options): array
    {
        $config = $this->sync->getConnectionConfig();

        if (($config['url'] ?? '') === '') {
            // Without a Hub URL there is no allowlist to build and no way to
            // be told to come back.
            return ['success' => false, 'error' => 'hub_url_not_configured', 'result' => null, 'restore_data' => null];
        }

        $extra = [];
        foreach ((array) ($target['allow'] ?? []) as $address) {
            if (is_string($address) && filter_var($address, FILTER_VALIDATE_IP)) {
                $extra[] = $address;
            }
        }

        foreach ((array) ($options['isolation_allowlist'] ?? []) as $address) {
            if (is_string($address) && filter_var($address, FILTER_VALIDATE_IP)) {
                $extra[] = $address;
            }
        }

        return $this->network->isolate($config['url'], $extra);
    }

    private function releaseNetwork(): array
    {
        $result = $this->network->release();

        // Close out whatever isolation was in effect, so the ledger does not
        // keep trying to expire an action that is already undone.
        foreach ($this->ledger->applied('isolate_network') as $action) {
            $this->ledger->markReverted(
                $action['action_id'],
                EdrActionLedger::STATE_REVERTED,
                $result['result'] ?? []
            );
        }

        return [
            'success' => (bool) $result['success'],
            'error' => $result['error'] ?? null,
            'result' => $result['result'] ?? null,
            'restore_data' => null,
        ];
    }

    /* ------------------------------------------------------------------ */
    /* Rollback                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Undo anything whose deadline has passed.
     *
     * This runs regardless of whether the Hub is reachable — in fact it
     * matters most when it is not, because a host cut off by a wrong call
     * would otherwise stay cut off. An analyst who wants an isolation to
     * persist reconfirms it, which extends the deadline.
     *
     * @return array{reverted:int, failed:int}
     */
    public function expireOverdue(): array
    {
        $summary = ['reverted' => 0, 'failed' => 0];

        foreach ($this->ledger->dueForExpiry() as $action) {
            $result = $this->revert($action);

            if (!empty($result['success'])) {
                $this->ledger->markReverted(
                    $action['action_id'],
                    EdrActionLedger::STATE_EXPIRED,
                    $result['result'] ?? []
                );
                $summary['reverted']++;

                Log::warning('[EDR response] Action auto-reverted at deadline', [
                    'action_id' => $action['action_id'],
                    'type' => $action['type'],
                ]);
            } else {
                $summary['failed']++;

                Log::error('[EDR response] Auto-revert failed', [
                    'action_id' => $action['action_id'],
                    'type' => $action['type'],
                    'error' => $result['error'] ?? null,
                ]);
            }
        }

        return $summary;
    }

    /**
     * @return array{success:bool, error:?string, result:?array}
     */
    private function revert(array $action): array
    {
        $restore = is_array($action['restore_data'] ?? null) ? $action['restore_data'] : [];

        return match ($action['type']) {
            'isolate_network' => $this->network->release(),
            'quarantine_file' => $this->quarantine->restore($restore),
            'suspend_process' => $this->processes->resume(
                (int) ($restore['pid'] ?? 0),
                isset($restore['start_time']) ? (int) $restore['start_time'] : null
            ),
            // A kill cannot be undone; the ledger already records it as such,
            // and it never carries a deadline.
            default => ['success' => false, 'error' => 'not_reversible', 'result' => null],
        };
    }

    /**
     * Confirmations from the Hub push the deadline out, which is how an
     * isolation survives past its safety timer.
     *
     * Which makes this the one place in the file where getting it wrong turns
     * the safety timer off, and the first version did.
     *
     * It read only `id` and `ttl_seconds`. No freshness, no single-use, no
     * capability check — while a command in the same payload is refused without
     * an `issued_at` and refused again if it is older than 900 seconds. The
     * asymmetry is what made it dangerous: the replay problem looks solved when
     * you read the command path.
     *
     * The consequence, traced end to end. `runEdrSync()` reads addons from
     * `storage/app/waf_config.json` on disk, and `syncConfigFromHub()` only
     * runs after a *successful* heartbeat, so an unreachable Hub leaves that
     * file frozen with whatever it last contained. The EDR cycle runs every 30
     * seconds. So a frozen confirmation was re-applied 120 times an hour,
     * each time setting the deadline to now plus its TTL, and `expireOverdue()`
     * never saw an overdue action. A host isolated on a bad call would have
     * stayed isolated forever, recoverable only from a console — and isolation
     * is precisely what makes the Hub unreachable, so this failure mode
     * selects for itself. This host has 98 heartbeat exceptions, 49 heartbeat
     * failures and 4 connection errors in four days of logs, and
     * `edr_allow_network_isolation` is currently true.
     *
     * Two independent defences, because one of them must not depend on the Hub:
     *
     * Freshness and monotonicity stop the replay. A confirmation now needs an
     * `issued_at`, is refused when stale by the same age gate as commands, and
     * is refused when its `issued_at` is not strictly newer than the last one
     * recorded for that action. A frozen file therefore extends nothing on its
     * second reading, while a live Hub sending a new confirmation each cycle
     * works exactly as before.
     *
     * The absolute ceiling bounds the damage even if a replay were somehow
     * fresh. No confirmation can push a deadline past `ABSOLUTE_MAX_APPLIED_SECONDS`
     * after the action was applied. This is the defence that survives a
     * compromised or misbehaving Hub, which is the case the four gates exist
     * for in the first place.
     *
     * @param array<int, array> $confirmations [{id, ttl_seconds, issued_at}]
     */
    public function applyConfirmations(array $confirmations, array $options = []): int
    {
        $applied = 0;
        // `max_command_age`, the key the command path uses. Reading a name
        // that is nearly right would have silently pinned this to the default
        // and made the Hub's setting look applied — the same shape as reading
        // `deliver` where the governor returns `emit`.
        $maxAge = max(60, (int) ($options['max_command_age'] ?? self::DEFAULT_MAX_COMMAND_AGE));
        $now = time();

        foreach ($confirmations as $confirmation) {
            if (!is_array($confirmation)) {
                continue;
            }

            $actionId = (string) ($confirmation['id'] ?? '');
            if ($actionId === '') {
                continue;
            }

            $action = $this->ledger->find($actionId);
            if ($action === null || $action['state'] !== EdrActionLedger::STATE_APPLIED) {
                continue;
            }

            $issuedAt = isset($confirmation['issued_at']) ? (int) $confirmation['issued_at'] : 0;

            if ($issuedAt <= 0) {
                // Same standard as a command. Without it there is no way to
                // tell a fresh decision from a frozen file.
                Log::warning('[EDR response] Confirmation refused, no issued_at', ['action_id' => $actionId]);
                continue;
            }

            if ($now - $issuedAt > $maxAge) {
                Log::warning('[EDR response] Confirmation refused as stale', [
                    'action_id' => $actionId,
                    'age_seconds' => $now - $issuedAt,
                    'max_age' => $maxAge,
                ]);
                continue;
            }

            $lastConfirmed = isset($action['last_confirmed_at']) ? (int) $action['last_confirmed_at'] : 0;

            if ($issuedAt <= $lastConfirmed) {
                // The replay case, and the one that actually happens: the same
                // config file read again 30 seconds later. Logged at debug
                // because on a healthy host with a stale file this fires twice
                // a minute and is not itself a problem.
                Log::debug('[EDR response] Confirmation already applied, not extending', [
                    'action_id' => $actionId,
                    'issued_at' => $issuedAt,
                    'last_confirmed_at' => $lastConfirmed,
                ]);
                continue;
            }

            $ttl = (int) ($confirmation['ttl_seconds'] ?? self::DEFAULT_ISOLATION_TTL);
            $requested = $now + min(self::MAX_ISOLATION_TTL, max(60, $ttl));

            $appliedAt = isset($action['applied_at']) ? (int) $action['applied_at'] : 0;

            if ($appliedAt > 0) {
                $ceiling = $appliedAt + self::ABSOLUTE_MAX_APPLIED_SECONDS;

                if ($requested > $ceiling) {
                    Log::warning('[EDR response] Confirmation capped at the absolute ceiling', [
                        'action_id' => $actionId,
                        'requested_expiry' => $requested,
                        'ceiling' => $ceiling,
                        'applied_at' => $appliedAt,
                    ]);

                    $requested = $ceiling;
                }

                if ($ceiling <= $now) {
                    // Already past the ceiling: refuse rather than write a
                    // deadline in the past, and let expireOverdue() undo it.
                    Log::warning('[EDR response] Confirmation refused, action past its absolute ceiling', [
                        'action_id' => $actionId,
                        'applied_at' => $appliedAt,
                    ]);
                    continue;
                }
            }

            $this->ledger->extendExpiry($actionId, $requested, $issuedAt);
            $applied++;
        }

        return $applied;
    }

    /* ------------------------------------------------------------------ */
    /* Reporting                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Push outcomes to the Hub. Anything not acknowledged stays queued, so an
     * action taken during an outage is still accounted for afterwards.
     *
     * @return array{reported:int, remaining:int}
     */
    public function reportOutcomes(int $limit = 100): array
    {
        $pending = $this->ledger->unreported($limit);

        if ($pending === []) {
            return ['reported' => 0, 'remaining' => 0];
        }

        $config = $this->sync->getConnectionConfig();

        if (($config['url'] ?? '') === '' || ($config['token'] ?? '') === '') {
            return ['reported' => 0, 'remaining' => count($pending)];
        }

        $events = [];
        $ids = [];

        foreach ($pending as $action) {
            $events[] = [
                'event_type' => 'edr_response',
                'message' => $this->describe($action),
                'details' => [
                    'action_id' => $action['action_id'],
                    'type' => $action['type'],
                    'state' => $action['state'],
                    'target' => $action['target'],
                    'reason' => $action['reason'],
                    'requested_by' => $action['requested_by'],
                    'result' => $action['result'],
                    'error' => $action['error'],
                    'reversible' => $action['reversible'],
                    'expires_at' => $action['expires_at'],
                    'created_at' => $action['created_at'],
                    'applied_at' => $action['applied_at'],
                    'reverted_at' => $action['reverted_at'],
                ],
                'created_at' => date('c', (int) ($action['applied_at'] ?? $action['created_at'])),
            ];

            $ids[] = $action['action_id'];
        }

        try {
            $response = $this->sync->httpClient(30)->post(
                "{$config['url']}/api/ids/agents/events",
                ['token' => $config['token'], 'events' => $events]
            );

            if (!$response->successful()) {
                Log::warning('[EDR response] Hub rejected outcome report', ['status' => $response->status()]);

                return ['reported' => 0, 'remaining' => count($pending)];
            }
        } catch (\Exception $e) {
            Log::warning('[EDR response] Outcome report failed: ' . $e->getMessage());

            return ['reported' => 0, 'remaining' => count($pending)];
        }

        $this->ledger->markReported($ids);

        return ['reported' => count($ids), 'remaining' => max(0, count($this->ledger->unreported($limit)))];
    }

    private function describe(array $action): string
    {
        $type = (string) $action['type'];
        $state = (string) $action['state'];

        $label = match ($type) {
            'kill_process' => '終止程序',
            'suspend_process' => '凍結程序',
            'resume_process' => '恢復程序',
            'quarantine_file' => '隔離檔案',
            'restore_file' => '還原檔案',
            'isolate_network' => '網路隔離',
            'release_network' => '解除網路隔離',
            default => $type,
        };

        $outcome = match ($state) {
            EdrActionLedger::STATE_APPLIED => '已執行',
            EdrActionLedger::STATE_FAILED => '失敗：' . ($action['error'] ?? 'unknown'),
            EdrActionLedger::STATE_REVERTED => '已復原',
            EdrActionLedger::STATE_EXPIRED => '已逾時自動復原',
            default => $state,
        };

        return "{$label} — {$outcome}";
    }

    /* ------------------------------------------------------------------ */
    /* Reconciliation                                                      */
    /* ------------------------------------------------------------------ */

    /**
     * Check that what the ledger believes is still true.
     *
     * The case that matters: the ledger says this host is isolated but the
     * rules are gone — a reboot, a firewall reload, someone clearing the
     * chains by hand. Left alone, the agent would report a contained host
     * that is in fact wide open.
     *
     * @return array{checked:int, corrected:int}
     */
    public function reconcile(): array
    {
        $summary = ['checked' => 0, 'corrected' => 0];

        foreach ($this->ledger->applied('isolate_network') as $action) {
            $summary['checked']++;

            if (!$this->network->isActive()) {
                Log::warning('[EDR response] Isolation recorded but not in effect, correcting record', [
                    'action_id' => $action['action_id'],
                ]);

                $this->ledger->markReverted(
                    $action['action_id'],
                    EdrActionLedger::STATE_REVERTED,
                    ['note' => 'rules_absent_at_reconcile']
                );
                $summary['corrected']++;
            }
        }

        return $summary;
    }

    public function getStatus(): array
    {
        return [
            'ledger' => $this->ledger->stats(),
            'network' => $this->network->getStatus(),
            'quarantined' => count($this->quarantine->listQuarantined()),
        ];
    }

    private function outcome(?string $actionId, ?string $type, string $status, ?string $reason): array
    {
        return ['action_id' => $actionId, 'type' => $type, 'status' => $status, 'reason' => $reason];
    }
}

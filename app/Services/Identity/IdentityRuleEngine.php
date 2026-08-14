<?php

namespace App\Services\Identity;

/**
 * Behaviour rules for authentication events.
 *
 * Stolen credentials are the most common way in, and they leave a different
 * kind of trace from malware: nothing malicious executes, no file is dropped,
 * and every individual event looks like a person logging in. What gives it
 * away is shape across time — the same source failing repeatedly, one source
 * trying many accounts, a success arriving right after a run of failures, an
 * account that exists to run a daemon suddenly holding an interactive
 * session.
 *
 * So most of these rules are statements about a window rather than about a
 * line, and they take a history provider. A rule engine that could only see
 * one event would miss all of them.
 */
class IdentityRuleEngine
{
    /** Failures from one source before it stops being someone mistyping. */
    private const BRUTE_FORCE_THRESHOLD = 8;

    /** Distinct accounts tried from one source before it is spraying. */
    private const SPRAY_ACCOUNT_THRESHOLD = 5;

    /** How far back the window rules look. */
    private const WINDOW_SECONDS = 900;

    /**
     * Accounts that exist to run something, not to be logged into. An
     * interactive session as one of these is either a misconfiguration or
     * somebody using a service credential.
     */
    private const SERVICE_ACCOUNTS = [
        'www-data', 'nginx', 'apache', 'apache2', 'httpd', 'mysql', 'postgres',
        'redis', 'mongodb', 'nobody', 'daemon', 'bin', 'sys', 'sync', 'games',
        'backup', 'list', 'irc', 'gnats', 'proxy', 'uucp', 'systemd-network',
    ];

    /** Groups whose membership confers administrative power. */
    private const PRIVILEGED_GROUPS = ['sudo', 'wheel', 'root', 'admin', 'adm', 'docker', 'lxd'];

    private IdentityHistory $history;

    public function __construct(IdentityHistory $history)
    {
        $this->history = $history;
    }

    /**
     * @return array<int, array>
     */
    public function evaluate(array $event): array
    {
        $action = (string) ($event['action'] ?? '');

        if (!str_contains($action, 'login') && !str_contains($action, 'privilege')
            && $action !== 'account_change' && $action !== 'session_open'
        ) {
            return [];
        }

        $findings = [];
        $sourceIp = $event['source_ip'] ?? null;
        $username = (string) ($event['username'] ?? '');
        $actor = $event['actor'] ?? null;
        $now = (int) ($event['ts'] ?? time());

        /* IAM-001 — repeated failures from one source ----------------------
         * One failure is a typo. Eight from the same address inside fifteen
         * minutes is a program. */
        if ($action === 'login_failure' && $sourceIp !== null) {
            $failures = $this->history->failuresFrom($sourceIp, $now - self::WINDOW_SECONDS, $now);

            if (count($failures) >= self::BRUTE_FORCE_THRESHOLD) {
                $accounts = count(array_unique(array_filter(array_column($failures, 'username'))));

                $findings[] = $this->finding(
                    'IAM-001',
                    'Repeated authentication failures from one source',
                    'high',
                    'T1110.001',
                    count($failures) . " failed attempts from {$sourceIp} in the last 15 minutes"
                    . ($accounts > 1 ? " across {$accounts} accounts" : " against '{$username}'")
                );
            }
        }

        /* IAM-002 — one source, many accounts, few attempts each ------------
         * Password spraying deliberately stays under a per-account lockout
         * threshold, which is exactly why counting failures per account misses
         * it. The signal is breadth, not depth. */
        if ($action === 'login_failure' && $sourceIp !== null) {
            $failures = $this->history->failuresFrom($sourceIp, $now - self::WINDOW_SECONDS, $now);
            $accounts = array_unique(array_filter(array_column($failures, 'username')));

            if (count($accounts) >= self::SPRAY_ACCOUNT_THRESHOLD) {
                $perAccount = count($failures) / max(1, count($accounts));

                // Many accounts with only a couple of tries each is spraying;
                // many accounts with many tries each is already covered by
                // IAM-001 and does not need saying twice.
                if ($perAccount <= 3) {
                    $sample = implode(', ', array_slice($accounts, 0, 5));

                    $findings[] = $this->finding(
                        'IAM-002',
                        'Password spraying',
                        'high',
                        'T1110.003',
                        count($accounts) . " distinct accounts tried from {$sourceIp} with "
                        . round($perAccount, 1) . ' attempts each (' . $sample . ')'
                    );
                }
            }
        }

        /* IAM-003 — a success arriving after a run of failures --------------
         * This is the one that means the guessing worked, and it is the
         * highest-value identity finding in the set. */
        if ($action === 'login_success' && $sourceIp !== null) {
            $failures = $this->history->failuresFrom($sourceIp, $now - self::WINDOW_SECONDS, $now);

            if (count($failures) >= 3) {
                // Three answers, not two, and the third one matters.
                //
                // A device this account has used before is almost always a
                // person who mistyped. A source it has never used, succeeding
                // after a run of failures, is a cracked password. But if we
                // know of no sources at all for this account, we have no basis
                // for either claim — and a freshly deployed agent knows
                // nothing about anybody, so treating absence of history as
                // evidence of intrusion would raise a critical for every
                // normal login in its first week. That is not a hypothetical:
                // it happened during development, on a developer's own
                // password from the laptop they use every day.
                $knownSources = $this->history->knownSourcesFor($username, $now - self::WINDOW_SECONDS);
                $attempts = count($failures);

                if ($knownSources === []) {
                    $findings[] = $this->finding(
                        'IAM-003',
                        'Successful login after repeated failures, no login history for this account',
                        'medium',
                        'T1110',
                        "'{$username}' authenticated from {$sourceIp} after {$attempts} failed attempts. "
                        . 'No previous successful logins are recorded for this account, so whether this '
                        . 'address is normal cannot be judged yet'
                    );
                } elseif (in_array($sourceIp, $knownSources, true)) {
                    $findings[] = $this->finding(
                        'IAM-003',
                        'Successful login after repeated failures from a known device',
                        'medium',
                        'T1110',
                        "'{$username}' authenticated from {$sourceIp} after {$attempts} failed attempts. "
                        . 'This address has authenticated as this account before, so a mistyped password '
                        . 'is the likelier explanation — confirm with the account holder'
                    );
                } else {
                    $findings[] = $this->finding(
                        'IAM-003',
                        'Successful login after repeated failures from an unrecognised source',
                        'critical',
                        'T1110',
                        "'{$username}' authenticated from {$sourceIp} after {$attempts} failed attempts, "
                        . 'and this account has only ever authenticated from '
                        . implode(', ', array_slice($knownSources, 0, 3))
                        . ' — treat the account as compromised'
                    );
                }
            }
        }

        /* IAM-004 — a session as a service account --------------------------
         * Graded by how the session was obtained, because the two cases are
         * genuinely different and treating them alike makes the rule useless.
         *
         * A service account authenticating on its own — an SSH login as
         * www-data — is a stolen credential, because nothing legitimate logs
         * in as a daemon. An administrator running `sudo -u www-data` to
         * debug a deploy leaves a session opened *by* a named person, and
         * that is ordinary on any machine somebody maintains. Firing critical
         * on both produced 48 alerts on a healthy host during development,
         * every one of them an administrator doing their job. */
        if (in_array($action, ['login_success', 'session_open'], true)
            && in_array($username, self::SERVICE_ACCOUNTS, true)
            // pam session records for cron and systemd units are the daemon
            // doing its job, not somebody logging in as it.
            && !in_array((string) ($event['method'] ?? ''), ['cron', 'systemd-user', 'logind'], true)
        ) {
            $escalatedInto = $actor !== null && $actor !== '' && $actor !== $username;

            if (!$escalatedInto) {
                $findings[] = $this->finding(
                    'IAM-004',
                    'Service account authenticated directly',
                    'critical',
                    'T1078.003',
                    "'{$username}' exists to run a daemon and authenticated on its own"
                    . ($sourceIp !== null ? " from {$sourceIp}" : '')
                    . ' — nothing legitimate logs in as a service account'
                );
            } else {
                $findings[] = $this->finding(
                    'IAM-004',
                    'Administrator assumed a service account',
                    'low',
                    'T1078.003',
                    "'{$actor}' opened a session as '{$username}' — routine for maintenance, "
                    . 'but also what an intruder does after gaining root'
                );
            }
        }

        /* IAM-005 — a new account, or an account gaining admin rights ------- */
        if ($action === 'account_change') {
            $reason = (string) ($event['reason'] ?? '');
            $group = strtolower((string) ($event['group'] ?? ''));

            if ($reason === 'added_to_group' && in_array($group, self::PRIVILEGED_GROUPS, true)) {
                $findings[] = $this->finding(
                    'IAM-005',
                    'Account granted administrative group membership',
                    'critical',
                    'T1098',
                    "'{$username}' was added to '{$group}' — this account can now act as an administrator"
                );
            } elseif ($reason === 'user_created') {
                $findings[] = $this->finding(
                    'IAM-005',
                    'New account created',
                    'high',
                    'T1136.001',
                    "Account '{$username}' was created"
                );
            } elseif ($reason === 'password_changed') {
                $findings[] = $this->finding(
                    'IAM-005',
                    'Account password changed',
                    'medium',
                    'T1098',
                    "Password for '{$username}' was changed"
                );
            }
        }

        /* IAM-006 — privilege escalation with no controlling terminal -------
         * Somebody typing `sudo` has a TTY. A script, a cron job or a shell
         * spawned through an exploit does not, and the second is what an
         * attacker's sudo looks like. */
        if ($action === 'privilege_escalation'
            && array_key_exists('interactive', $event)
            && $event['interactive'] === false
            && (string) ($event['username'] ?? '') === 'root'
        ) {
            $findings[] = $this->finding(
                'IAM-006',
                'Root escalation with no controlling terminal',
                'medium',
                'T1548.003',
                "'{$actor}' escalated to root without a TTY — a script or a non-interactive shell, not a person"
            );
        }

        /* IAM-007 — repeated failures to escalate --------------------------
         * Guessing at a sudo password is the same activity as guessing at a
         * login password, and it is far more often an intruder than a user
         * who has forgotten their own. */
        if ($action === 'privilege_failure' && $actor !== null) {
            $failures = $this->history->privilegeFailuresBy((string) $actor, $now - self::WINDOW_SECONDS, $now);

            if (count($failures) >= 3) {
                $findings[] = $this->finding(
                    'IAM-007',
                    'Repeated privilege escalation failures',
                    'high',
                    'T1548.003',
                    count($failures) . " failed escalation attempts by '{$actor}' in the last 15 minutes"
                );
            }
        }

        /* IAM-008 — the same account authenticating from several sources ----
         * Credentials in more than one place at once is either sharing or
         * theft, and both are worth a look. */
        if ($action === 'login_success' && $username !== '' && $sourceIp !== null) {
            $sources = $this->history->sourcesFor($username, $now - self::WINDOW_SECONDS, $now);
            $distinct = array_unique(array_filter($sources));

            if (count($distinct) >= 3) {
                $findings[] = $this->finding(
                    'IAM-008',
                    'One account authenticating from several sources',
                    'high',
                    'T1078',
                    "'{$username}' logged in from " . count($distinct)
                    . ' distinct addresses within 15 minutes (' . implode(', ', array_slice($distinct, 0, 4)) . ')'
                );
            }
        }

        return $findings;
    }

    private function finding(string $rule, string $name, string $severity, string $mitre, string $reason): array
    {
        return [
            'rule' => $rule,
            'name' => $name,
            'severity' => $severity,
            'mitre' => $mitre,
            'reason' => $reason,
        ];
    }
}

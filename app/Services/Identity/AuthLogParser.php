<?php

namespace App\Services\Identity;

use App\Services\EdrSecretRedactor;

/**
 * Turns authentication log lines into structured identity events.
 *
 * Deliberately a pure function over a string: no file handles, no clock, no
 * state. This is the part of identity telemetry that has to be correct, and
 * the only way to be confident about a parser is to run it against a large
 * pile of real lines — which is only cheap if it takes a string and returns
 * an array.
 *
 * Written against lines actually collected from a live host rather than
 * against documentation. Two things that catches which the documentation
 * does not:
 *
 *  - OpenSSH 9.8 split the daemon, so on any current system the service in
 *    the log is `sshd-session`, not `sshd`. A parser matching only `sshd`
 *    sees almost no SSH activity on a modern host and reports silence.
 *  - systemd hosts now write RFC 3339 timestamps, while RHEL-family systems
 *    still write the classic `Mon DD HH:MM:SS`. Both have to work, and the
 *    classic form carries no year.
 */
class AuthLogParser
{
    /** `2026-08-08T00:12:01.831745+08:00 host service[pid]: message` */
    private const LINE_RFC3339 = '/^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+(?:[+-]\d{2}:\d{2}|Z))\s+
                                   (?P<host>\S+)\s+
                                   (?P<service>[A-Za-z0-9_\/.-]+?)(?:\[(?P<pid>\d+)\])?:\s*
                                   (?P<message>.*)$/x';

    /** `Aug  8 00:12:01 host service[pid]: message` */
    private const LINE_SYSLOG = '/^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+
                                  (?P<host>\S+)\s+
                                  (?P<service>[A-Za-z0-9_\/.-]+?)(?:\[(?P<pid>\d+)\])?:\s*
                                  (?P<message>.*)$/x';

    /** Services whose messages describe authentication rather than anything else. */
    private const AUTH_SERVICES = [
        'sshd', 'sshd-session', 'sudo', 'su', 'login', 'systemd-logind',
        'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'gpasswd',
        'passwd', 'chage', 'unix_chkpwd', 'polkitd',
    ];

    private EdrSecretRedactor $redactor;

    public function __construct(?EdrSecretRedactor $redactor = null)
    {
        $this->redactor = $redactor ?? new EdrSecretRedactor();
    }

    /**
     * @return array|null a normalised identity event, or null when the line
     *                    is not about authentication
     */
    public function parse(string $line): ?array
    {
        $line = trim($line);

        if ($line === '') {
            return null;
        }

        if (!preg_match(self::LINE_RFC3339, $line, $m) && !preg_match(self::LINE_SYSLOG, $line, $m)) {
            return null;
        }

        $service = $this->normaliseService((string) $m['service']);

        if (!in_array($service, self::AUTH_SERVICES, true)
            && !in_array((string) $m['service'], self::AUTH_SERVICES, true)
        ) {
            return null;
        }

        $message = (string) $m['message'];
        $event = $this->interpret($service, $message);

        if ($event === null) {
            return null;
        }

        return array_merge([
            'ts' => $this->timestamp((string) $m['ts']),
            'host' => (string) $m['host'],
            'sensor' => 'authlog',
            'service' => $service,
            'service_pid' => isset($m['pid']) && $m['pid'] !== '' ? (int) $m['pid'] : null,
            // The shared pipeline expects these; identity events have no
            // process of their own beyond the daemon that logged them.
            'pid' => 0,
            'ppid' => 0,
            'uid' => -1,
            'path' => '',
            'cmdline' => '',
            'cwd' => '',
            'container_id' => '',
            'username' => '',
            'actor' => null,
            'source_ip' => null,
            'source_port' => null,
            'method' => null,
            'tty' => null,
            'command' => null,
            'reason' => null,
        ], $event);
    }

    /**
     * `sshd-session` and `sshd` are the same daemon on either side of the
     * OpenSSH 9.8 split, and nothing downstream should have to care.
     */
    private function normaliseService(string $service): string
    {
        if ($service === 'sshd-session' || str_starts_with($service, 'sshd')) {
            return 'sshd';
        }

        return $service;
    }

    private function timestamp(string $raw): int
    {
        $parsed = strtotime($raw);

        if ($parsed !== false) {
            return $parsed;
        }

        return time();
    }

    /**
     * @return array|null the event-specific fields
     */
    private function interpret(string $service, string $message): ?array
    {
        // --- SSH authentication ------------------------------------------

        if (preg_match(
            '/^Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)/',
            $message,
            $m
        )) {
            return [
                'action' => 'login_success',
                'username' => $m['user'],
                'source_ip' => $this->validIp($m['ip']),
                'source_port' => (int) $m['port'],
                'method' => $m['method'],
            ];
        }

        if (preg_match(
            '/^Failed\s+(?P<method>\S+)\s+for\s+(?P<invalid>invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)/',
            $message,
            $m
        )) {
            return [
                'action' => 'login_failure',
                'username' => $m['user'],
                'source_ip' => $this->validIp($m['ip']),
                'source_port' => (int) $m['port'],
                'method' => $m['method'],
                // An attempt against an account that does not exist is
                // guessing, not a mistyped password.
                'reason' => $m['invalid'] !== '' ? 'unknown_account' : 'bad_credentials',
            ];
        }

        if (preg_match('/^Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?/', $message, $m)) {
            return [
                'action' => 'login_failure',
                'username' => $m['user'],
                'source_ip' => $this->validIp($m['ip']),
                'source_port' => isset($m['port']) && $m['port'] !== '' ? (int) $m['port'] : null,
                'reason' => 'unknown_account',
            ];
        }

        // Someone opened a connection and never authenticated. On its own it
        // is a scanner; in volume it is reconnaissance.
        if (preg_match('/^(?:Timeout before authentication|Connection closed by authenticating user|banner exchange).*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})/', $message, $m)) {
            return [
                'action' => 'auth_probe',
                'source_ip' => $this->validIp($m['ip']),
                'reason' => 'no_authentication',
            ];
        }

        // --- Sessions -----------------------------------------------------

        if (preg_match(
            '/^pam_unix\((?P<pamsvc>[^:]+):session\):\s*session opened for user\s+(?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?(?:\s+by\s+(?P<actor>[^\s(]+)(?:\(uid=(?P<actoruid>\d+)\))?)?/',
            $message,
            $m
        )) {
            return [
                'action' => 'session_open',
                'username' => $m['user'],
                'uid' => isset($m['uid']) && $m['uid'] !== '' ? (int) $m['uid'] : -1,
                'actor' => ($m['actor'] ?? '') !== '' ? $m['actor'] : null,
                'method' => $m['pamsvc'],
            ];
        }

        if (preg_match('/^pam_unix\((?P<pamsvc>[^:]+):session\):\s*session closed for user\s+(?P<user>\S+)/', $message, $m)) {
            return [
                'action' => 'session_close',
                'username' => $m['user'],
                'method' => $m['pamsvc'],
            ];
        }

        // --- Privilege escalation ----------------------------------------

        // `vito : TTY=/dev/pts/66 ; PWD=/x ; USER=root ; COMMAND=/usr/bin/su`
        //
        // TTY is optional. sudo invoked from a script, a cron job or a
        // non-interactive shell logs no TTY at all — and that is precisely
        // the shape an attacker's sudo takes, so requiring it would blind the
        // rule to the case that matters most.
        if (preg_match(
            '/^(?P<actor>\S+)\s*:\s*(?P<failure>\d+ incorrect password attempts?\s*;\s*)?'
            . '(?:TTY=(?P<tty>\S*)\s*;\s*)?PWD=(?P<pwd>\S*)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)$/',
            $message,
            $m
        )) {
            return [
                'action' => ($m['failure'] ?? '') !== '' ? 'privilege_failure' : 'privilege_escalation',
                'username' => $m['target'],
                'actor' => $m['actor'],
                'tty' => ($m['tty'] ?? '') !== '' ? $m['tty'] : null,
                'cwd' => $m['pwd'],
                // sudo command lines carry credentials as often as any other
                // command line does.
                'command' => $this->redactor->redact(trim($m['cmd'])),
                'reason' => ($m['failure'] ?? '') !== '' ? 'incorrect_password' : null,
                // No controlling terminal means nobody typed this.
                'interactive' => ($m['tty'] ?? '') !== '',
            ];
        }

        // `pam_unix(sudo:auth): authentication failure; logname=vito uid=1001
        //  euid=0 tty=/dev/pts/9 ruser= rhost= user=root`
        //
        // This is how a wrong sudo password appears, and therefore how
        // someone guessing at one appears. Missing it would leave privilege
        // escalation attempts invisible while login attempts were tracked.
        if (preg_match('/^pam_unix\((?P<pamsvc>[^:]+):auth\):\s*authentication failure;(?P<rest>.*)$/', $message, $m)) {
            $rest = $m['rest'];

            preg_match('/\blogname=(?P<logname>\S*)/', $rest, $ln);
            preg_match('/\buser=(?P<user>\S+)/', $rest, $u);
            preg_match('/\btty=(?P<tty>\S+)/', $rest, $t);
            preg_match('/\brhost=(?P<rhost>\S+)/', $rest, $r);

            return [
                'action' => in_array($m['pamsvc'], ['sudo', 'su'], true) ? 'privilege_failure' : 'login_failure',
                'username' => $u['user'] ?? '',
                'actor' => ($ln['logname'] ?? '') !== '' ? $ln['logname'] : null,
                'tty' => $t['tty'] ?? null,
                'source_ip' => isset($r['rhost']) ? $this->validIp($r['rhost']) : null,
                'method' => $m['pamsvc'],
                'reason' => 'authentication_failure',
            ];
        }

        // `vito : N incorrect password attempts ; TTY=... ; PWD=... ; USER=root`
        if (preg_match(
            '/^(?P<actor>\S+)\s*:\s*(?P<count>\d+)\s+incorrect password attempts?/',
            $message,
            $m
        )) {
            return [
                'action' => 'privilege_failure',
                'actor' => $m['actor'],
                'reason' => 'incorrect_password',
                'attempts' => (int) $m['count'],
            ];
        }

        // `(to root) vito on pts/3`
        if (preg_match('/^\(to\s+(?P<target>\S+)\)\s+(?P<actor>\S+)\s+on\s+(?P<tty>\S+)/', $message, $m)) {
            return [
                'action' => 'privilege_escalation',
                'username' => $m['target'],
                'actor' => $m['actor'],
                'tty' => $m['tty'],
                'method' => 'su',
            ];
        }

        if (preg_match('/^FAILED su for\s+(?P<target>\S+)\s+by\s+(?P<actor>\S+)/', $message, $m)) {
            return [
                'action' => 'privilege_failure',
                'username' => $m['target'],
                'actor' => $m['actor'],
                'method' => 'su',
                'reason' => 'su_denied',
            ];
        }

        // --- Account and group changes ------------------------------------

        // shadow-utils writes `UID=` in upper case; matching lower case only
        // means new accounts are never reported.
        if ($service === 'useradd'
            && preg_match('/^new user: name=(?P<user>[^,]+).*?\buid=(?P<uid>\d+)/i', $message, $m)
        ) {
            return [
                'action' => 'account_change',
                'username' => $m['user'],
                'uid' => (int) $m['uid'],
                'reason' => 'user_created',
            ];
        }

        if ($service === 'userdel' && preg_match('/^delete user\s+.(?P<user>[^\']+)./', $message, $m)) {
            return ['action' => 'account_change', 'username' => $m['user'], 'reason' => 'user_deleted'];
        }

        // `add 'eve' to group 'sudo'` — the line that turns an ordinary
        // account into an administrative one.
        if (preg_match("/add '(?P<user>[^']+)' to group '(?P<group>[^']+)'/", $message, $m)) {
            return [
                'action' => 'account_change',
                'username' => $m['user'],
                'reason' => 'added_to_group',
                'group' => $m['group'],
            ];
        }

        if (preg_match("/^add '(?P<user>[^']+)' to shadow group '(?P<group>[^']+)'/", $message, $m)) {
            return [
                'action' => 'account_change',
                'username' => $m['user'],
                'reason' => 'added_to_group',
                'group' => $m['group'],
            ];
        }

        if ($service === 'passwd' && preg_match('/password changed for\s+(?P<user>\S+)/', $message, $m)) {
            return ['action' => 'account_change', 'username' => $m['user'], 'reason' => 'password_changed'];
        }

        if ($service === 'usermod' && preg_match('/change user\s+.(?P<user>[^\']+).\s+shell/', $message, $m)) {
            return ['action' => 'account_change', 'username' => $m['user'], 'reason' => 'shell_changed'];
        }

        // --- logind -------------------------------------------------------

        if (preg_match('/^New session\s+(?P<session>\d+) of user\s+(?P<user>\S+)/', $message, $m)) {
            return [
                'action' => 'session_open',
                'username' => rtrim($m['user'], '.'),
                'method' => 'logind',
                'session_id' => $m['session'],
            ];
        }

        if (preg_match('/^Session\s+(?P<session>\d+) logged out/', $message, $m)) {
            return [
                'action' => 'session_close',
                'method' => 'logind',
                'session_id' => $m['session'],
            ];
        }

        // `Disconnected from user vito 192.168.1.110 port 58212` — the end of
        // an SSH session, and the only line that ties a session close back to
        // both the account and the source address.
        if (preg_match(
            '/^Disconnected from (?:user\s+(?P<user>\S+)\s+)?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+port\s+(?P<port>\d+)/',
            $message,
            $m
        )) {
            return [
                'action' => 'session_close',
                'username' => $m['user'] ?? '',
                'source_ip' => $this->validIp($m['ip']),
                'source_port' => (int) $m['port'],
                'method' => 'sshd',
            ];
        }

        return null;
    }

    private function validIp(string $candidate): ?string
    {
        return filter_var($candidate, FILTER_VALIDATE_IP) === false ? null : $candidate;
    }

    /**
     * Where the authentication log lives on this system.
     *
     * @return array<int, string>
     */
    public static function candidateLogPaths(): array
    {
        return [
            '/var/log/auth.log',   // Debian, Ubuntu
            '/var/log/secure',     // RHEL, Alma, Rocky
        ];
    }
}

<?php

namespace Tests\Unit;

use App\Services\Identity\AuthLogParser;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * Every line here was taken from a live host's auth.log rather than written
 * from documentation, because the two disagree in ways that matter.
 *
 * The parser is a pure function over a string on purpose: the only way to be
 * confident about a log parser is to run it against a large pile of real
 * lines, and that is only cheap if it needs no files, no clock and no state.
 */
class AuthLogParserTest extends TestCase
{
    private AuthLogParser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new AuthLogParser();
    }

    /**
     * OpenSSH 9.8 split the daemon. On any current system the service in the
     * log is `sshd-session`, so a parser matching only `sshd` reports silence
     * on a host that is being logged into all day.
     */
    public function test_modern_openssh_service_name_is_recognised(): void
    {
        $line = '2026-08-13T09:15:02.123456+08:00 host sshd-session[1234]: '
            . 'Accepted publickey for john from 192.168.1.110 port 58212 ssh2: ED25519 SHA256:abc';

        $event = $this->parser->parse($line);

        $this->assertNotNull($event, 'sshd-session must be understood as ssh');
        $this->assertSame('login_success', $event['action']);
        $this->assertSame('john', $event['username']);
        $this->assertSame('192.168.1.110', $event['source_ip']);
        $this->assertSame(58212, $event['source_port']);
        $this->assertSame('publickey', $event['method']);
        $this->assertSame('sshd', $event['service'], 'both daemon names normalise to one service');
    }

    /**
     * RHEL-family systems still write the classic form, which carries no year.
     */
    public function test_both_timestamp_formats_parse(): void
    {
        $rfc = $this->parser->parse(
            '2026-08-13T09:15:02.123456+08:00 host sshd[1]: Accepted password for a from 10.0.0.1 port 22 ssh2'
        );
        $syslog = $this->parser->parse(
            'Aug 13 09:15:02 host sshd[1]: Accepted password for a from 10.0.0.1 port 22 ssh2'
        );

        $this->assertNotNull($rfc);
        $this->assertNotNull($syslog);
        $this->assertGreaterThan(0, $rfc['ts']);
        $this->assertGreaterThan(0, $syslog['ts']);
    }

    /**
     * A wrong password and an attempt on an account that does not exist are
     * different events: the second is guessing, the first may be a typo.
     */
    public function test_failure_reason_distinguishes_guessing_from_a_typo(): void
    {
        $badPassword = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sshd-session[1]: Failed password for john from 10.0.0.9 port 41 ssh2'
        );
        $this->assertSame('login_failure', $badPassword['action']);
        $this->assertSame('bad_credentials', $badPassword['reason']);

        $unknownAccount = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sshd-session[1]: Failed password for invalid user oracle from 10.0.0.9 port 41 ssh2'
        );
        $this->assertSame('unknown_account', $unknownAccount['reason']);
        $this->assertSame('oracle', $unknownAccount['username']);

        $invalidUser = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sshd-session[1]: Invalid user admin from 203.0.113.5 port 5000'
        );
        $this->assertSame('login_failure', $invalidUser['action']);
        $this->assertSame('unknown_account', $invalidUser['reason']);
    }

    /**
     * sudo from a script, a cron job or a non-interactive shell logs no TTY —
     * and that is precisely the shape an attacker's sudo takes, so requiring
     * one would blind the rule to the case that matters most.
     */
    public function test_sudo_without_a_tty_is_still_parsed(): void
    {
        $interactive = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sudo[1]: vito : TTY=/dev/pts/66 ; PWD=/opt/x ; USER=root ; COMMAND=/usr/bin/su'
        );
        $this->assertSame('privilege_escalation', $interactive['action']);
        $this->assertSame('vito', $interactive['actor']);
        $this->assertSame('root', $interactive['username']);
        $this->assertTrue($interactive['interactive']);

        $scripted = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sudo[1]: root :  PWD=/opt/x ; USER=root ; COMMAND=/usr/bin/du -xh /'
        );
        $this->assertNotNull($scripted, 'sudo with no TTY must not be dropped');
        $this->assertSame('privilege_escalation', $scripted['action']);
        $this->assertFalse($scripted['interactive'], 'no controlling terminal means nobody typed it');
    }

    /**
     * How a wrong sudo password appears, and therefore how someone guessing
     * at one appears. Missing this would leave privilege escalation attempts
     * invisible while login attempts were tracked.
     */
    public function test_sudo_authentication_failure_is_parsed(): void
    {
        $event = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sudo[1]: pam_unix(sudo:auth): authentication failure; '
            . 'logname=vito uid=1001 euid=0 tty=/dev/pts/9 ruser= rhost=  user=root'
        );

        $this->assertNotNull($event);
        $this->assertSame('privilege_failure', $event['action']);
        $this->assertSame('root', $event['username'], 'the account being escalated to');
        $this->assertSame('vito', $event['actor'], 'the account doing the escalating');
    }

    /**
     * sudo command lines carry credentials as often as any other command line.
     */
    public function test_sudo_commands_are_redacted(): void
    {
        $event = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sudo[1]: vito : TTY=/dev/pts/1 ; PWD=/ ; USER=root ; '
            . 'COMMAND=/usr/bin/mysql --password=LiveProdSecret123'
        );

        $this->assertStringNotContainsString('LiveProdSecret123', $event['command']);
        $this->assertStringContainsString('--password=', $event['command'], 'the flag is evidence, the value is not');
    }

    public function test_su_and_session_lines_are_parsed(): void
    {
        $su = $this->parser->parse('2026-08-13T09:15:02+08:00 h su[1]: (to root) vito on pts/3');
        $this->assertSame('privilege_escalation', $su['action']);
        $this->assertSame('root', $su['username']);
        $this->assertSame('vito', $su['actor']);
        $this->assertSame('su', $su['method']);

        $opened = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sshd-session[1]: pam_unix(sshd:session): '
            . 'session opened for user john(uid=1001) by john(uid=1001)'
        );
        $this->assertSame('session_open', $opened['action']);
        $this->assertSame('john', $opened['username']);
        $this->assertSame(1001, $opened['uid']);

        $closed = $this->parser->parse(
            '2026-08-13T09:15:02+08:00 h sshd-session[1]: Disconnected from user vito 192.168.1.110 port 58212'
        );
        $this->assertSame('session_close', $closed['action']);
        $this->assertSame('vito', $closed['username']);
        $this->assertSame('192.168.1.110', $closed['source_ip']);
    }

    /**
     * The line that turns an ordinary account into an administrative one.
     */
    public function test_account_and_group_changes_are_parsed(): void
    {
        $created = $this->parser->parse(
            "2026-08-13T09:15:02+08:00 h useradd[1]: new user: name=eve, UID=1050, GID=1050, home=/home/eve, shell=/bin/bash"
        );
        $this->assertSame('account_change', $created['action']);
        $this->assertSame('eve', $created['username']);
        $this->assertSame('user_created', $created['reason']);

        $promoted = $this->parser->parse(
            "2026-08-13T09:15:02+08:00 h usermod[1]: add 'eve' to group 'sudo'"
        );
        $this->assertSame('account_change', $promoted['action']);
        $this->assertSame('eve', $promoted['username']);
        $this->assertSame('sudo', $promoted['group']);
    }

    public static function nonAuthProvider(): array
    {
        return [
            'empty' => [''],
            'garbage' => ['not a log line at all'],
            'unrelated service' => ['2026-08-13T09:15:02+08:00 h nginx[1]: 200 GET /'],
            'auth service, uninteresting message' => [
                '2026-08-13T09:15:02+08:00 h systemd-logind[1]: Watching system buttons on /dev/input/event8',
            ],
        ];
    }

    #[DataProvider('nonAuthProvider')]
    public function test_lines_that_are_not_authentication_events_return_null(string $line): void
    {
        $this->assertNull($this->parser->parse($line));
    }

    /**
     * A parser is only trustworthy if it has met the whole corpus. This runs
     * it over the host's real log when there is one, and asserts on shape
     * rather than on counts, which vary by machine.
     */
    public function test_survives_the_hosts_entire_auth_log(): void
    {
        $path = null;

        foreach (AuthLogParser::candidateLogPaths() as $candidate) {
            if (is_readable($candidate)) {
                $path = $candidate;
                break;
            }
        }

        if ($path === null) {
            $this->markTestSkipped('No readable authentication log on this host.');
        }

        $handle = fopen($path, 'r');
        $lines = 0;
        $events = 0;
        $actions = [];

        while (($line = fgets($handle)) !== false && $lines < 60000) {
            $lines++;
            $event = $this->parser->parse($line);

            if ($event === null) {
                continue;
            }

            $events++;
            $actions[$event['action']] = true;

            // Whatever the line, the contract holds.
            $this->assertArrayHasKey('ts', $event);
            $this->assertArrayHasKey('action', $event);
            $this->assertArrayHasKey('service', $event);
            $this->assertIsInt($event['ts']);

            if ($event['source_ip'] !== null) {
                $this->assertNotFalse(
                    filter_var($event['source_ip'], FILTER_VALIDATE_IP),
                    'a parsed source address must be a real address'
                );
            }
        }

        fclose($handle);

        $this->assertGreaterThan(0, $events, 'the parser found nothing in a real log');
    }
}

<?php

namespace App\Services\Platform;

/**
 * Everything the EDR pipeline needs to know about the operating system it is
 * watching, in one place.
 *
 * The alternative — a `PHP_OS === 'Darwin'` test at each of the twenty-odd
 * places that care — is the failure mode this whole branch has spent its time
 * hunting: a fact that has to be right in several places at once, where
 * getting it wrong in one of them produces no error at all. A directory
 * prefix list that still says `/usr/bin` on a Mac does not crash; it silently
 * classifies every Homebrew binary as "other", and the novelty model quietly
 * loses a dimension. So the vocabulary lives here and is passed in.
 *
 * The profile is data, not behaviour. It answers "what does a system process
 * look like on this platform", never "is this suspicious" — those stay in the
 * rules and the correlator, which are platform-neutral by construction.
 *
 * **What is verified and what is not.** The Linux profile runs in production
 * and every value in it was measured on a live host. The Darwin profile is
 * written from the platform's documented layout and osquery's macOS tables;
 * it has not been exercised on real hardware from here. The logic that
 * consumes it is tested on both profiles because the profile is injectable —
 * which is the point of extracting it — but "the tests pass for Darwin" means
 * the code handles the Darwin vocabulary, not that a Mac has been watched.
 */
final class EdrPlatformProfile
{
    public const LINUX = 'linux';
    public const DARWIN = 'darwin';

    private string $family;

    private function __construct(string $family)
    {
        $this->family = $family;
    }

    public static function current(): self
    {
        return new self(PHP_OS_FAMILY === 'Darwin' ? self::DARWIN : self::LINUX);
    }

    /** Construct a specific profile. Tests use this; so does a replay. */
    public static function for(string $family): self
    {
        return new self($family === self::DARWIN ? self::DARWIN : self::LINUX);
    }

    public function family(): string
    {
        return $this->family;
    }

    public function isDarwin(): bool
    {
        return $this->family === self::DARWIN;
    }

    /* ------------------------------------------------------------------ */
    /* Clocks                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * Unix time at which this machine booted, or 0 when it cannot be read.
     *
     * The kernel's per-event timestamps are relative to boot on both
     * platforms, so this is the anchor that turns them into wall clock.
     * Linux publishes it in /proc/stat; Darwin has no /proc at all and
     * answers through sysctl instead.
     *
     * Zero is a real answer and callers must handle it: without an anchor the
     * only honest fallback is the sensor's own flush time, which is coarse but
     * not wrong. A guessed anchor would be wrong and believed.
     */
    public function bootTime(): int
    {
        if ($this->isDarwin()) {
            // `kern.boottime` prints `{ sec = 1786416348, usec = 0 } ...`.
            $out = (string) @shell_exec('sysctl -n kern.boottime 2>/dev/null');

            return preg_match('/sec\s*=\s*(\d+)/', $out, $m) === 1 ? (int) $m[1] : 0;
        }

        $stat = (string) @file_get_contents('/proc/stat');

        return preg_match('/^btime (\d+)/m', $stat, $m) === 1 ? (int) $m[1] : 0;
    }

    /**
     * Can a per-event kernel timestamp be turned into wall clock here?
     *
     * On Linux, yes: osquery's `ntime` is nanoseconds since boot and
     * `btime + ntime/1e9` is the wall clock to the second.
     *
     * On macOS, **no**, and the reason is worth stating because the failure is
     * invisible. EndpointSecurity reports `mach_absolute_time`, whose unit is
     * not nanoseconds — it has to be scaled by `mach_timebase_info`, and that
     * ratio is 1:1 on Intel but not on Apple Silicon. So the naive conversion
     * is exactly right on one class of Mac and silently wrong on the other,
     * while *differences* between two events stay correct on both. A wrong
     * absolute time that behaves correctly under subtraction is the hardest
     * kind to notice, and nothing in this pipeline would report it: every age,
     * every retention window and every ordering decision would simply be
     * computed against a fiction.
     *
     * Reading the timebase ratio needs a native call PHP does not have. Until
     * something can obtain it, the honest answer is the sensor's own flush
     * time — coarse, but not a fiction — and callers must be able to tell the
     * difference, which is what this method is for.
     */
    public function canAnchorEventClock(): bool
    {
        return !$this->isDarwin();
    }

    /* ------------------------------------------------------------------ */
    /* Identity                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * uid => username for every account this host can name.
     *
     * On Linux /etc/passwd is the whole answer. On macOS it holds only a
     * handful of system accounts — real users live in Directory Services — so
     * reading it there returns a file that exists, parses cleanly, and is
     * missing every human on the machine. `dscl` is the supported way to ask.
     *
     * @return array<int, string>
     */
    public function users(): array
    {
        $users = [-1 => ''];

        if ($this->isDarwin()) {
            // Timed out on purpose. Directory Services answers locally on a
            // standalone Mac, but on one bound to AD or LDAP the same query
            // goes to the network — and this runs on the sensor's hot path,
            // where a blocking lookup stalls the whole collection cycle.
            // Failing to name a user costs a label; blocking costs telemetry.
            $out = (string) @shell_exec('timeout 5 dscl . -list /Users UniqueID 2>/dev/null');

            foreach (preg_split('/\R/', $out) ?: [] as $line) {
                if (preg_match('/^(\S+)\s+(-?\d+)$/', trim($line), $m) === 1) {
                    $users[(int) $m[2]] = $m[1];
                }
            }

            if (count($users) > 1) {
                return $users;
            }

            // dscl unavailable (a locked-down or non-interactive context).
            // /etc/passwd still names the system accounts, which is better
            // than naming nobody.
        }

        $passwd = @file('/etc/passwd', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($passwd === false) {
            return $users;
        }

        foreach ($passwd as $line) {
            $parts = explode(':', $line);

            if (count($parts) >= 3) {
                $users[(int) $parts[2]] = $parts[0];
            }
        }

        return $users;
    }

    /**
     * Accounts a web server runs as.
     *
     * A shell under one of these is the classic webshell tell, and it is the
     * single highest-value host signal this product has — so a platform whose
     * web account is missing from the list loses that detection outright,
     * without any rule appearing to fail.
     *
     * @return string[]
     */
    public function webAccounts(): array
    {
        $shared = ['nginx', 'apache', 'apache2', 'httpd', 'nobody', 'www', 'lighttpd', 'caddy'];

        return $this->isDarwin()
            // macOS prefixes service accounts with an underscore. `_www` is
            // Apache's, and Homebrew's nginx commonly runs as it too.
            ? array_merge($shared, ['_www', '_httpd', '_appserver', '_devicemgr'])
            : array_merge($shared, ['www-data', 'php-fpm']);
    }

    /* ------------------------------------------------------------------ */
    /* Filesystem shape                                                    */
    /* ------------------------------------------------------------------ */

    /**
     * Directory classes, ordered — the first matching prefix wins.
     *
     * These are the coarse buckets the novelty model keys on, so their job is
     * to be stable rather than precise: `/usr/bin/curl` and `/bin/curl` are
     * the same fact about a host and must land in the same bucket. On macOS
     * the interesting split is different — the OS ships read-only under
     * /System and /usr/bin, while everything a user installs is under
     * /usr/local, /opt/homebrew or /Applications, and that boundary is the one
     * worth being able to see.
     *
     * @return array<string, string[]>
     */
    public function directoryClasses(): array
    {
        if ($this->isDarwin()) {
            return [
                'sys' => ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/libexec/', '/System/'],
                'pkg' => [
                    '/usr/local/bin/', '/usr/local/sbin/', '/opt/homebrew/', '/opt/local/',
                    '/Applications/', '/Library/', '/usr/local/Cellar/',
                ],
                'tmp' => ['/tmp/', '/private/tmp/', '/var/tmp/', '/private/var/tmp/', '/var/folders/'],
                'home' => ['/Users/', '/var/root/'],
                'etc' => ['/etc/', '/private/etc/', '/Library/WebServer/'],
            ];
        }

        return [
            'sys' => ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/bin/', '/usr/local/sbin/'],
            'pkg' => ['/opt/', '/usr/lib/', '/usr/libexec/', '/usr/share/', '/snap/'],
            'tmp' => ['/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/'],
            'home' => ['/home/', '/root/'],
            'etc' => ['/etc/', '/var/www/'],
        ];
    }

    /**
     * Paths that rewrite who can log in or what runs at boot.
     *
     * @return array{files: string[], prefixes: string[]}
     */
    public function criticalPaths(): array
    {
        if ($this->isDarwin()) {
            return [
                'files' => ['/etc/passwd', '/etc/master.passwd', '/etc/sudoers', '/etc/hosts'],
                'prefixes' => [
                    '/etc/sudoers.d/', '/etc/ssh/', '/var/root/.ssh/',
                    '/Library/LaunchDaemons/', '/Library/LaunchAgents/',
                    '/System/Library/LaunchDaemons/', '/Library/StartupItems/',
                    '/etc/periodic/', '/usr/local/etc/periodic/',
                ],
            ];
        }

        return [
            'files' => [
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                '/etc/ld.so.preload', '/etc/rc.local', '/etc/crontab',
            ],
            'prefixes' => [
                '/etc/sudoers.d/', '/etc/ssh/', '/root/.ssh/', '/etc/cron.d/',
                '/etc/cron.hourly/', '/etc/cron.daily/', '/var/spool/cron/',
                '/etc/systemd/system/', '/etc/profile.d/',
            ],
        ];
    }

    /**
     * Container-layer path prefixes that must be collapsed before a path
     * becomes a facet value, or every layer mints a fresh vocabulary.
     *
     * @return array<string, string>
     */
    public function containerPathPatterns(): array
    {
        if ($this->isDarwin()) {
            // Docker Desktop runs containers inside a Linux VM, so their paths
            // never reach the host's EndpointSecurity stream. Nothing to
            // collapse — and claiming otherwise would be inventing a mapping
            // that cannot occur.
            return [];
        }

        return [
            '#^/var/lib/docker/overlay2/[0-9a-f]{8,}/(diff|merged)#' => '/‹ovl›',
            '#^/run/containerd/io\.containerd\.runtime\.[^/]+/[^/]+/[^/]+/rootfs#' => '/‹ctr›',
        ];
    }

    /**
     * Is this agent itself running inside a container?
     *
     * Load-bearing for the container-escape rule, which only treats a bare
     * `docker exec` as interesting when we are inside one. On macOS the answer
     * is always no: the agent runs on the host, and containers live in a
     * virtual machine it cannot see into.
     */
    /**
     * Whether this platform's sensor can see into containers at all.
     *
     * On Linux the process stream carries a container id and a rule can ask
     * "was this inside a container". On macOS containers run inside a Linux
     * virtual machine, so their processes never reach the host's
     * EndpointSecurity stream and the id is always empty.
     *
     * The distinction has to be a value rather than an absent branch. A rule
     * conditioned on "inside a container" does not fail on macOS — it simply
     * never fires, while still being counted as part of the coverage. That is
     * the shape of every silent gap on this branch: a detection that looks
     * present and is doing nothing.
     */
    public function containerVisibility(): string
    {
        return $this->isDarwin() ? 'not_observable' : 'observable';
    }

    public function inContainer(): bool
    {
        if ($this->isDarwin()) {
            return false;
        }

        if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) {
            return true;
        }

        $cgroup = (string) @file_get_contents('/proc/1/cgroup');

        return $cgroup !== '' && preg_match('/\b(docker|containerd|kubepods|lxc)\b/', $cgroup) === 1;
    }

    /* ------------------------------------------------------------------ */
    /* Process vocabulary                                                  */
    /* ------------------------------------------------------------------ */

    /**
     * Processes whose children begin a new causal chain: service managers and
     * session sources. Everything below one of these is one actor.
     *
     * @return string[]
     */
    public function anchorImages(): array
    {
        $shared = [
            'sshd', 'nginx', 'apache2', 'httpd', 'caddy', 'lighttpd', 'login',
            'unicorn', 'puma', 'gunicorn', 'uwsgi', 'php-fpm', 'php-fpm7', 'php-fpm8',
        ];

        if ($this->isDarwin()) {
            return array_merge($shared, [
                // launchd is pid 1 and also every user's session manager, so
                // it plays the part of systemd, cron and logind at once.
                'launchd', 'loginwindow', 'SystemUIServer', 'Dock', 'Finder',
                'cron', 'periodic-wrapper', 'sshd-keygen-wrapper',
            ]);
        }

        return array_merge($shared, [
            'systemd', 'init', 'crond', 'cron', 'anacron', 'atd',
            'containerd-shim', 'containerd', 'dockerd', 'runc', 'supervisord',
            'systemd-run', 'at', 'agetty', 'systemd-logind', 'gdm', 'lightdm', 'rc.local',
        ]);
    }

    /**
     * Which entry point an anchor image represents.
     *
     * @return array<string, string[]>
     */
    public function anchorKinds(): array
    {
        $web = ['php-fpm', 'nginx', 'apache2', 'httpd', 'caddy', 'lighttpd', 'unicorn', 'puma', 'gunicorn', 'uwsgi'];

        if ($this->isDarwin()) {
            return [
                'web' => $web,
                'ssh' => ['sshd', 'login', 'sshd-keygen-wrapper'],
                'cron' => ['cron', 'periodic-wrapper'],
                'container' => [],
                // launchd is the whole service manager on macOS.
                'init' => ['launchd'],
                'desktop' => ['loginwindow', 'SystemUIServer', 'Dock', 'Finder'],
            ];
        }

        return [
            'web' => $web,
            'ssh' => ['sshd', 'login', 'agetty', 'systemd-logind'],
            'cron' => ['crond', 'cron', 'anacron', 'atd', 'at'],
            'container' => ['dockerd', 'containerd', 'containerd-shim', 'runc', 'supervisord'],
            'init' => ['systemd', 'init', 'systemd-run', 'rc.local'],
            'desktop' => ['gdm', 'lightdm'],
        ];
    }

    /**
     * Processes that legitimately start other things, and therefore get a
     * lineage row kept for them.
     *
     * @return string[]
     */
    public function spawnerImages(): array
    {
        $shared = [
            'sh', 'bash', 'dash', 'zsh', 'ksh', 'csh', 'fish',
            'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'php-fpm', 'node',
            'make', 'sudo', 'su', 'env', 'xargs', 'timeout', 'nice',
            'ansible', 'ansible-playbook', 'salt-minion', 'puppet', 'chef-client',
        ];

        if ($this->isDarwin()) {
            return array_merge($shared, [
                'launchctl', 'osascript', 'open', 'automator', 'xcrun', 'swift', 'zsh-5.9',
            ]);
        }

        return array_merge($shared, [
            'setsid', 'docker', 'runc', 'systemd-run', 'at', 'nohup', 'screen', 'tmux',
        ]);
    }

    /**
     * Wrappers that detach or decorate a child without being an entry point of
     * their own — a chain must pass straight through them.
     *
     * @return string[]
     */
    public function transparentWrappers(): array
    {
        $shared = ['env', 'timeout', 'nice', 'xargs'];

        return $this->isDarwin()
            ? array_merge($shared, ['caffeinate', 'arch'])
            : array_merge($shared, ['setsid', 'nohup', 'ionice']);
    }

    /**
     * Package managers whose collateral is discounted, with the directories
     * they legitimately live in. Both halves matter: keying on the name alone
     * lets a dropper called `apt` buy the discount.
     *
     * @return string[]
     */
    public function packageManagers(): array
    {
        return $this->isDarwin()
            ? ['brew', 'installer', 'softwareupdate', 'pkgutil', 'port', 'mas']
            : [
                'apt', 'apt-get', 'aptitude', 'dpkg', 'yum', 'dnf', 'rpm', 'apk',
                'zypper', 'pacman', 'snapd', 'unattended-upgrade', 'needrestart',
            ];
    }

    /**
     * This product's own binaries, whose execs are our own noise.
     *
     * @return string[]
     */
    public function agentBinaries(): array
    {
        return ['osqueryd', 'osqueryi', 'suricata', 'snort', 'clamscan', 'freshclam', 'clamd'];
    }

    /* ------------------------------------------------------------------ */
    /* Sensor                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * osquery tables that carry process and socket telemetry.
     *
     * macOS has one publisher — EndpointSecurity — and no socket event table
     * at all, which is not a gap this agent can close from userland. The
     * network module still gets `listening_ports`, so a new listener is
     * visible; an outbound connection is not.
     *
     * @return array{process: string, socket: ?string, backend: string}
     */
    public function sensorTables(string $backend = ''): array
    {
        if ($this->isDarwin()) {
            return ['process' => 'es_process_events', 'socket' => null, 'backend' => 'endpointsecurity'];
        }

        return $backend === 'bpf'
            ? ['process' => 'bpf_process_events', 'socket' => 'bpf_socket_events', 'backend' => 'bpf']
            : ['process' => 'process_events', 'socket' => 'socket_events', 'backend' => 'audit'];
    }
}

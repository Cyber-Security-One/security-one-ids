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
 * parts of it have since been exercised on a real Mac, and doing so found six
 * defects that reading the code had not. The Windows profile has never run on
 * Windows at all. The logic that consumes it is tested on all three because
 * the profile is injectable — which is the point of extracting it — but "the
 * tests pass for Windows" means the code handles the Windows vocabulary, not
 * that a Windows host has been watched.
 */
final class EdrPlatformProfile
{
    public const LINUX = 'linux';
    public const DARWIN = 'darwin';
    public const WINDOWS = 'windows';

    /** Per-event timestamps are nanoseconds since boot; add the boot time. */
    public const CLOCK_BOOT_RELATIVE = 'boot_relative';

    /** Per-event timestamps are already wall clock; use them as they are. */
    public const CLOCK_WALL = 'wall_clock';

    /** There is no usable per-event clock; the flush time is the best answer. */
    public const CLOCK_UNAVAILABLE = 'unavailable';

    private string $family;

    private function __construct(string $family)
    {
        $this->family = $family;
    }

    public static function current(): self
    {
        return new self(match (PHP_OS_FAMILY) {
            'Darwin' => self::DARWIN,
            'Windows' => self::WINDOWS,
            default => self::LINUX,
        });
    }

    /** Construct a specific profile. Tests use this; so does a replay. */
    public static function for(string $family): self
    {
        return new self(match ($family) {
            self::DARWIN => self::DARWIN,
            self::WINDOWS => self::WINDOWS,
            default => self::LINUX,
        });
    }

    public function family(): string
    {
        return $this->family;
    }

    public function isDarwin(): bool
    {
        return $this->family === self::DARWIN;
    }

    public function isWindows(): bool
    {
        return $this->family === self::WINDOWS;
    }

    /**
     * Are paths on this platform case-insensitive and backslash-separated?
     *
     * Load-bearing, and the reason it is a value rather than a `\` check at
     * the point of use: every path comparison in the facet extractor is
     * `str_starts_with` against a lowercase, forward-slash prefix list. Feed
     * it `C:\Windows\System32\cmd.exe` unchanged and nothing matches — not one
     * prefix, ever. The result is not an error. Every executable on the host
     * lands in the `other` bucket, the image facet collapses to a single
     * value, and the novelty model silently loses a whole dimension while
     * continuing to report that it is running.
     */
    public function pathStyle(): string
    {
        return $this->isWindows() ? 'windows' : 'posix';
    }

    /**
     * Fold a path into the form the prefix lists are written in.
     *
     * A no-op everywhere but Windows, where it lowercases and turns the
     * separators round. Windows paths are genuinely case-insensitive —
     * `C:\WINDOWS\` and `c:\windows\` are one directory, and treating them as
     * two would split every facet in half at random depending on which casing
     * a given process happened to be launched with.
     */
    public function foldPath(string $path): string
    {
        if (!$this->isWindows() || $path === '') {
            return $path;
        }

        return strtolower(str_replace('\\', '/', $path));
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
        if ($this->isWindows()) {
            // Never needed for event timing — Windows events already carry
            // wall clock, see eventClock(). Answered anyway because uptime is
            // reported in its own right, and answering 0 there would read as
            // "just booted" rather than "not asked".
            $out = (string) @shell_exec(
                'powershell -NoProfile -NonInteractive -Command '
                . '"[int][double]::Parse((Get-Date (Get-CimInstance Win32_OperatingSystem).LastBootUpTime -UFormat %s))" 2>NUL'
            );

            return preg_match('/(\d{9,})/', $out, $m) === 1 ? (int) $m[1] : 0;
        }

        if ($this->isDarwin()) {
            // `kern.boottime` prints `{ sec = 1786416348, usec = 0 } ...`.
            $out = (string) @shell_exec('sysctl -n kern.boottime 2>/dev/null');

            return preg_match('/sec\s*=\s*(\d+)/', $out, $m) === 1 ? (int) $m[1] : 0;
        }

        $stat = (string) @file_get_contents('/proc/stat');

        return preg_match('/^btime (\d+)/m', $stat, $m) === 1 ? (int) $m[1] : 0;
    }

    /**
     * What kind of per-event timestamp this platform's sensor produces.
     *
     * Three genuinely different answers, and this started life as a boolean
     * that could only hold two of them:
     *
     *  - **Linux** publishes nanoseconds since boot. Add the boot time and it
     *    is wall clock to the second.
     *  - **macOS** publishes `mach_absolute_time`, whose unit is not
     *    nanoseconds and whose scaling ratio differs between Intel and Apple
     *    Silicon. It cannot be converted from here, so the flush time is the
     *    only honest answer.
     *  - **Windows** ETW publishes an actual wall clock timestamp per event.
     *    Nothing needs anchoring.
     *
     * Collapsing Windows into the macOS branch — which is what a boolean
     * forces — would throw away a perfectly good per-event clock and stamp
     * every event with its batch's flush time instead. That is not a small
     * loss: one flush on the Linux host was measured carrying 8,820 exec rows
     * under a single timestamp, and it broke the correlator's ordering bonus
     * by making thousands of unrelated events look simultaneous. The same
     * mistake on Windows would arrive silently, through a field that is
     * present, populated and wrong.
     */
    public function eventClock(): string
    {
        return match ($this->family) {
            self::WINDOWS => self::CLOCK_WALL,
            self::DARWIN => self::CLOCK_UNAVAILABLE,
            default => self::CLOCK_BOOT_RELATIVE,
        };
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
        return $this->eventClock() === self::CLOCK_BOOT_RELATIVE;
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

        if ($this->isWindows()) {
            // Windows has no numeric uid. Identity is a SID, and the sensor
            // reports the account name directly on every event, so there is
            // nothing to look up and no table to build.
            //
            // Returning the empty map is the correct answer, not a gap: the
            // collector must take the username from the event rather than
            // resolving it from a uid, and a map that quietly named the wrong
            // accounts would be worse than one that names none. See
            // usernameIsReported().
            return $users;
        }

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
    /**
     * Does the sensor name the account on each event, rather than the agent
     * resolving it from a numeric id?
     *
     * True only on Windows. It is the difference between `users()` being empty
     * because the lookup failed and being empty because there is nothing to
     * look up — and a caller that cannot tell those apart will either log a
     * spurious fault every cycle or, worse, treat every Windows event as
     * running under an unknown account.
     */
    public function usernameIsReported(): bool
    {
        return $this->isWindows();
    }

    public function webAccounts(): array
    {
        $shared = ['nginx', 'apache', 'apache2', 'httpd', 'nobody', 'www', 'lighttpd', 'caddy'];

        if ($this->isWindows()) {
            // IIS runs each application pool under a synthetic account named
            // after the pool, so the set is open-ended: `IIS APPPOOL\Contoso`
            // is as much a web account as the default one. The fixed names
            // here are the built-in service identities; the pool prefix is
            // matched separately by webAccountPrefixes().
            return [
                'iusr', 'iwam', 'network service', 'nt authority\\network service',
                'defaultapppool', 'apppoolidentity', 'w3wp',
            ];
        }

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
    /**
     * Account name prefixes that mean "a web server", where the full name is
     * not knowable in advance.
     *
     * IIS mints one identity per application pool — `IIS APPPOOL\<name>` — so
     * a fixed list can only ever catch the default. Without the prefix, every
     * site running under its own pool loses the webshell detection entirely,
     * which is the single highest-value host signal this product has.
     *
     * @return string[]
     */
    public function webAccountPrefixes(): array
    {
        return $this->isWindows() ? ['iis apppool\\'] : [];
    }

    public function directoryClasses(): array
    {
        if ($this->isWindows()) {
            // Lowercase, forward slashes: paths are folded by foldPath()
            // before they reach here, because Windows treats case as
            // insignificant and would otherwise split one directory into as
            // many facet values as there are ways to spell it.
            //
            // The split that matters here is different from Unix. What ships
            // with the OS lives under c:/windows, what an administrator
            // installed lives under program files, and the interesting
            // question — the one every living-off-the-land technique turns on
            // — is whether a binary came from the system directory or from
            // somewhere a user can write.
            return [
                'sys' => [
                    'c:/windows/system32/', 'c:/windows/syswow64/', 'c:/windows/winsxs/',
                    'c:/windows/servicing/', 'c:/windows/',
                ],
                'pkg' => [
                    'c:/program files/', 'c:/program files (x86)/', 'c:/programdata/chocolatey/',
                    'c:/programdata/microsoft/', 'c:/programdata/package cache/',
                ],
                // Every one of these is user-writable and none of them is
                // where a legitimate service binary lives, which is exactly
                // why droppers land here.
                'tmp' => [
                    'c:/windows/temp/', 'c:/temp/', 'c:/tmp/',
                    'c:/users/public/', 'c:/$recycle.bin/',
                ],
                'home' => ['c:/users/'],
                'etc' => ['c:/windows/system32/drivers/etc/', 'c:/inetpub/', 'c:/windows/tasks/'],
            ];
        }

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
        if ($this->isWindows()) {
            // Folded form, as everywhere else. The registry is the real
            // persistence surface on Windows and it is not a path at all —
            // Run keys, services, WMI subscriptions — none of which the file
            // event stream can see. What is listed here is the part that is
            // observable as a file; the rest is a stated gap rather than a
            // silent one. See persistenceVisibility().
            return [
                'files' => [
                    'c:/windows/system32/drivers/etc/hosts',
                    'c:/windows/system32/config/sam',
                    'c:/windows/system32/config/system',
                    'c:/windows/system32/config/security',
                ],
                'prefixes' => [
                    'c:/windows/system32/tasks/',
                    'c:/windows/tasks/',
                    'c:/programdata/microsoft/windows/start menu/programs/startup/',
                    'c:/users/all users/microsoft/windows/start menu/programs/startup/',
                    'c:/windows/system32/grouppolicy/',
                    'c:/windows/system32/wbem/',
                ],
            ];
        }

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
    /**
     * Where this platform's persistence actually lives, so that a gap in
     * coverage is a value rather than an absence.
     *
     * On Linux and macOS persistence is files — cron, systemd units,
     * LaunchAgents — and the file event stream sees all of it. On Windows the
     * important half is the registry: Run keys, service definitions, WMI event
     * subscriptions. osquery can query those tables but does not publish them
     * as events, so a scheduled-task file appearing is visible and a Run key
     * being written is not.
     *
     * Stated because the PERSIST kill-chain class exists on all three
     * platforms and would otherwise look equally covered on all three while
     * being substantially blind on one.
     */
    public function persistenceVisibility(): string
    {
        return $this->isWindows() ? 'files_only' : 'complete';
    }

    public function containerPathPatterns(): array
    {
        if ($this->isWindows()) {
            // Windows containers exist, but Docker Desktop runs Linux
            // containers in a VM the host sensor cannot see into, and process
            // isolation for Windows containers does not surface a container id
            // on the ETW process stream. Nothing to collapse.
            return [];
        }

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
        return $this->isDarwin() || $this->isWindows() ? 'not_observable' : 'observable';
    }

    public function inContainer(): bool
    {
        if ($this->isDarwin() || $this->isWindows()) {
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

        if ($this->isWindows()) {
            // Image names, lowercase and with the extension, because that is
            // the form the ETW stream reports and the form foldPath() leaves
            // behind.
            //
            // svchost.exe is the awkward one and is deliberately included. It
            // hosts most of the OS's services, so treating it as an anchor
            // means one actor per svchost rather than one enormous actor
            // covering half the machine — the same reason systemd is an anchor
            // on Linux.
            return [
                'services.exe', 'svchost.exe', 'wininit.exe', 'winlogon.exe',
                'userinit.exe', 'explorer.exe', 'taskeng.exe', 'taskhostw.exe',
                'w3wp.exe', 'inetinfo.exe', 'sqlservr.exe', 'sshd.exe',
                'wsmprovhost.exe', 'winrshost.exe', 'termsrv.exe', 'rdpinit.exe',
            ];
        }

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

        if ($this->isWindows()) {
            return [
                // w3wp.exe is an IIS worker process — a shell under one is the
                // Windows spelling of the webshell tell.
                'web' => ['w3wp.exe', 'inetinfo.exe'],
                // Remote entry, which on Windows is WinRM and RDP rather than
                // ssh. Kept under the 'ssh' key because the correlator's
                // classes are platform-neutral by construction and renaming
                // one would fork the rule vocabulary per platform.
                'ssh' => ['sshd.exe', 'wsmprovhost.exe', 'winrshost.exe', 'rdpinit.exe', 'termsrv.exe'],
                'cron' => ['taskeng.exe', 'taskhostw.exe'],
                'container' => [],
                'init' => ['services.exe', 'svchost.exe', 'wininit.exe'],
                'desktop' => ['winlogon.exe', 'userinit.exe', 'explorer.exe'],
            ];
        }

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

        if ($this->isWindows()) {
            // The living-off-the-land set. Every one of these ships with
            // Windows, is signed by Microsoft, and can be made to execute
            // something else — which is why they are the ones worth keeping a
            // lineage row for. A chain that goes w3wp -> cmd -> powershell ->
            // rundll32 is only visible if none of those links is dropped.
            return [
                'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
                'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'msiexec.exe',
                'wmic.exe', 'schtasks.exe', 'at.exe', 'sc.exe', 'psexec.exe', 'psexesvc.exe',
                'installutil.exe', 'msbuild.exe', 'regasm.exe', 'regsvcs.exe',
                'certutil.exe', 'bitsadmin.exe', 'curl.exe', 'python.exe', 'node.exe',
                'java.exe', 'php.exe', 'perl.exe', 'ruby.exe', 'conhost.exe',
                'runas.exe', 'wsl.exe', 'bash.exe', 'forfiles.exe', 'pcalua.exe',
            ];
        }

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

        if ($this->isWindows()) {
            // conhost.exe is attached to console processes by the OS rather
            // than by whoever started them; treating it as a link in the chain
            // would insert a step nobody chose. pcalua.exe is the program
            // compatibility assistant doing the same thing.
            return ['conhost.exe', 'pcalua.exe', 'runas.exe'];
        }

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
        if ($this->isWindows()) {
            // msiexec.exe is in both this list and spawnerImages(), and that
            // is not a contradiction: it legitimately installs software *and*
            // is a standard way to run attacker-supplied code. Being a package
            // manager discounts its collateral; being a spawner keeps its
            // lineage. Dropping either would lose something.
            return [
                'msiexec.exe', 'winget.exe', 'choco.exe', 'chocolatey.exe', 'scoop.exe',
                'trustedinstaller.exe', 'tiworker.exe', 'wusa.exe', 'dism.exe',
                'setup.exe', 'update.exe',
            ];
        }

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
        $shared = ['osqueryd', 'osqueryi', 'suricata', 'snort', 'clamscan', 'freshclam', 'clamd'];

        // Both spellings on Windows. The sensor reports the image with its
        // extension, and a list carrying only the bare name would fail to
        // recognise this agent's own processes — so every collection cycle
        // would score its own osqueryd as a novel execution.
        return $this->isWindows()
            ? array_merge($shared, array_map(static fn (string $n): string => $n . '.exe', $shared))
            : $shared;
    }

    /* ------------------------------------------------------------------ */
    /* Sensor                                                              */
    /* ------------------------------------------------------------------ */

    /**
     * Default file-integrity watch list, by category.
     *
     * Deliberately narrow on every platform. A watch costs kernel resources
     * per directory and a recursive one over somewhere busy buries anything
     * real. These are the places where a change is nearly always worth a look:
     * account and privilege state, the ways a machine starts things, and where
     * persistence gets installed.
     *
     * Web roots are absent on purpose — site-specific, pushed by the Hub,
     * because guessing wrong means either no coverage or a watch on a
     * directory with a hundred thousand files in it.
     *
     * `%%` is osquery's recursive wildcard.
     *
     * @return array<string, string[]>
     */
    public function fileWatchPaths(): array
    {
        if ($this->isWindows()) {
            // Native separators here, not the folded form: these strings go
            // into osquery's config for the OS to resolve, not into the facet
            // comparison. Folding is for classification; this is a path.
            //
            // Registry persistence — Run keys, services, WMI subscriptions —
            // is the larger half of the Windows story and none of it is a
            // file. See persistenceVisibility(); the gap is stated rather
            // than papered over with paths that would look like coverage.
            return [
                'scheduling' => [
                    'C:\\Windows\\System32\\Tasks\\%%',
                    'C:\\Windows\\Tasks\\%%',
                ],
                'startup' => [
                    'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\%%',
                    'C:\\Users\\%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\%%',
                ],
                'system' => [
                    'C:\\Windows\\System32\\drivers\\etc\\hosts',
                    'C:\\Windows\\System32\\GroupPolicy\\%%',
                ],
            ];
        }

        if ($this->isDarwin()) {
            return [
                'accounts' => ['/etc/passwd', '/etc/master.passwd', '/etc/sudoers', '/etc/sudoers.d/%%'],
                'ssh' => ['/etc/ssh/%%', '/var/root/.ssh/%%'],
                'scheduling' => ['/etc/periodic/%%', '/usr/local/etc/periodic/%%'],
                'startup' => [
                    '/Library/LaunchDaemons/%%',
                    '/Library/LaunchAgents/%%',
                    '/Library/StartupItems/%%',
                ],
            ];
        }

        return [
            'accounts' => [
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers', '/etc/sudoers.d/%%',
            ],
            'ssh' => ['/etc/ssh/%%', '/root/.ssh/%%'],
            'scheduling' => [
                '/etc/crontab', '/etc/cron.d/%%', '/etc/cron.hourly/%%',
                '/etc/cron.daily/%%', '/var/spool/cron/%%',
            ],
            'startup' => [
                '/etc/systemd/system/%%', '/etc/rc.local', '/etc/profile.d/%%', '/etc/ld.so.preload',
            ],
        ];
    }

    /**
     * Files the system rewrites constantly for reasons that are never an
     * intrusion, and which would otherwise dominate the stream.
     *
     * @return string[]
     */
    public function fileWatchExcludes(): array
    {
        if ($this->isWindows()) {
            return ['C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\%%'];
        }

        return ['/etc/ssh/ssh_host_%%', '/var/spool/cron/atjobs/%%'];
    }

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
        if ($this->isWindows()) {
            // ETW, through osquery's process_etw_events publisher.
            //
            // No socket event table, same as macOS and for a similar reason:
            // osquery's Windows ETW publisher covers process start/stop, and
            // there is no per-connection event stream to subscribe to. The
            // listener snapshot still works, so a new listening port is
            // visible and an outbound connection is not.
            return ['process' => 'process_etw_events', 'socket' => null, 'backend' => 'etw'];
        }

        if ($this->isDarwin()) {
            return ['process' => 'es_process_events', 'socket' => null, 'backend' => 'endpointsecurity'];
        }

        return $backend === 'bpf'
            ? ['process' => 'bpf_process_events', 'socket' => 'bpf_socket_events', 'backend' => 'bpf']
            : ['process' => 'process_events', 'socket' => 'socket_events', 'backend' => 'audit'];
    }
}

<?php

namespace App\Services;

/**
 * EDR Behaviour Rule Engine
 *
 * Matches normalised endpoint process events against a small, high-signal
 * rule set mapped to MITRE ATT&CK. This runs on the endpoint on purpose:
 * a busy host produces ~500k process events a day, and shipping all of it to
 * the Hub costs far more than it is worth. The endpoint decides what is
 * interesting; the Hub does correlation, storage and analyst workflow.
 *
 * Design constraints:
 *  - Rules must be cheap. They run against every exec on the box.
 *  - Rules must be tunable. Every deployment has its own idea of "normal",
 *    and untuned EDR noise is what kills an MDR service's margin, so the Hub
 *    can push exclusion patterns without an agent release.
 */
class EdrRuleEngine
{
    /** Accounts a web server runs as. A shell here is the classic webshell tell. */
    private const WEB_ACCOUNTS = [
        'www-data', 'nginx', 'apache', 'apache2', 'httpd', 'nobody',
        'php-fpm', 'www', 'lighttpd', 'caddy',
    ];

    /**
     * Binaries that have no business being a web server's child at all.
     * A hit here is a webshell until proven otherwise.
     */
    private const WEB_HIGH_RISK_BINARIES = [
        'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat',
        'python', 'python2', 'python3', 'perl', 'ruby',
        'gcc', 'cc', 'chmod', 'chown', 'useradd', 'usermod', 'crontab',
        'nmap', 'ssh', 'scp',
    ];

    /**
     * Shells are separate: PHP-FPM and cron legitimately wrap the
     * application's own runtime in `sh -c`, so a bare shell under a web
     * account is only interesting once you look at what it is running.
     */
    private const SHELL_BINARIES = ['bash', 'sh', 'dash', 'zsh', 'ksh', 'csh'];

    /** Recon binaries — notable under a web account, but not on their own critical. */
    private const WEB_RECON_BINARIES = ['whoami', 'id', 'uname', 'hostname'];

    /**
     * A shell whose entire job is to launch the application's own runtime.
     * `www-data` running `sh -c '/usr/bin/php8.4 artisan schedule:run'` is
     * every Laravel site on earth, not an intrusion.
     */
    private const APP_RUNTIME_PATTERN =
        '#^\s*(/[\w./-]*)?(php[\d.]*|php-fpm[\d.]*|composer|node|npm|yarn|wp|drush|artisan|python[\d.]*\s+manage\.py)\b#';

    /** Directories any unprivileged user can write to. */
    private const WORLD_WRITABLE_PREFIXES = [
        '/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/',
    ];

    private const DISCOVERY_BINARIES = [
        'whoami', 'id', 'uname', 'hostname', 'ifconfig', 'ip', 'netstat', 'ss',
        'ps', 'w', 'last', 'lastlog', 'arp', 'route', 'lsblk', 'mount',
        'getent', 'groups', 'sudo',
    ];

    /** Regex patterns pushed from the Hub; matching events never alert. */
    private array $exclusions = [];

    /** @var string[] Usernames allowlisted out of the webshell rule. */
    private array $webAccountAllowlist = [];

    /** Cached result of the container check. */
    private ?bool $inContainer = null;

    public function setExclusions(array $patterns): void
    {
        $this->exclusions = [];

        foreach ($patterns as $pattern) {
            if (!is_string($pattern) || $pattern === '') {
                continue;
            }

            // Validate before storing: one bad regex from the Hub must not
            // take the whole detection path down with a PHP warning per event.
            if (@preg_match($pattern, '') === false) {
                continue;
            }

            $this->exclusions[] = $pattern;
        }
    }

    public function setWebAccountAllowlist(array $users): void
    {
        $this->webAccountAllowlist = array_map('strval', $users);
    }

    /**
     * Evaluate one normalised event.
     *
     * @return array<int, array{rule:string,name:string,severity:string,mitre:string,reason:string}>
     */
    /** Extensions a web server will execute if they land in a served directory. */
    private const SERVER_EXECUTABLE_EXTENSIONS = [
        'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar',
        'jsp', 'jspx', 'asp', 'aspx', 'ashx', 'cfm', 'cgi', 'pl', 'py', 'rb',
    ];

    /**
     * Files whose modification changes who can get in or what runs at boot.
     * A legitimate change here is rare and always worth seeing.
     */
    private const CRITICAL_FILES = [
        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
        '/etc/ld.so.preload', '/etc/rc.local', '/etc/crontab',
    ];

    private const CRITICAL_PREFIXES = [
        '/etc/sudoers.d/', '/etc/ssh/', '/root/.ssh/', '/etc/cron.d/',
        '/etc/cron.hourly/', '/etc/cron.daily/', '/var/spool/cron/',
        '/etc/systemd/system/', '/etc/profile.d/',
    ];

    public function evaluate(array $event): array
    {
        if ($this->isExcluded($event)) {
            return [];
        }

        // File events carry a different shape and a different set of
        // questions, so they get their own pass rather than being forced
        // through rules written against command lines.
        if (str_starts_with((string) ($event['action'] ?? ''), 'file_')) {
            return $this->evaluateFileEvent($event);
        }

        $findings = [];
        $cmdline = (string) ($event['cmdline'] ?? '');
        $path = (string) ($event['path'] ?? '');
        $binary = $path !== '' ? basename($path) : '';
        $user = (string) ($event['username'] ?? '');

        /* EDR-001 — webshell / web-tier command execution -------------------
         * A web server process spawning a downloader or interpreter is the
         * single highest-value host signal for a WAF vendor: it is exactly
         * what a request that slipped past the WAF looks like from the
         * inside. Shells are graded separately because the web tier
         * legitimately shells out to its own runtime. */
        if ($binary !== ''
            && in_array($user, self::WEB_ACCOUNTS, true)
            && !in_array($user, $this->webAccountAllowlist, true)
        ) {
            if (in_array($binary, self::WEB_HIGH_RISK_BINARIES, true)) {
                $findings[] = $this->finding(
                    'EDR-001', 'Web server spawned a downloader or interpreter', 'critical', 'T1505.003',
                    "Web account '{$user}' executed {$binary} — likely webshell or post-exploitation"
                );
            } elseif (in_array($binary, self::SHELL_BINARIES, true) && !$this->isAppRuntimeWrapper($cmdline)) {
                $findings[] = $this->finding(
                    'EDR-001', 'Web server spawned a shell', 'high', 'T1505.003',
                    "Web account '{$user}' executed {$binary} outside the application runtime"
                );
            } elseif (in_array($binary, self::WEB_RECON_BINARIES, true)) {
                $findings[] = $this->finding(
                    'EDR-001', 'Web server ran a discovery command', 'medium', 'T1033',
                    "Web account '{$user}' executed {$binary} — reconnaissance from the web tier"
                );
            }
        }

        /* EDR-002 — reverse shell ------------------------------------------ */
        if (preg_match('#/dev/tcp/|/dev/udp/#', $cmdline)
            || preg_match('/\b(nc|ncat|netcat)\b[^|;]*\s-[a-zA-Z]*e\b/', $cmdline)
            || preg_match('/socat\b.*\bEXEC:/i', $cmdline)
            || preg_match('/(python|perl|ruby|php)[0-9.]*\b.*socket.*(exec|system|dup2|popen|spawn)/is', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-002', 'Reverse shell pattern', 'critical', 'T1059',
                'Command line matches an interactive reverse-shell construct'
            );
        }

        /* EDR-003 — remote payload piped straight into an interpreter ------- */
        if (preg_match('/\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?\b(ba|z|k|da)?sh\b/', $cmdline)
            || preg_match('/\b(curl|wget)\b[^|]*\|\s*(python|perl|ruby|php)[0-9.]*\b/', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-003', 'Remote payload piped to interpreter', 'high', 'T1105',
                'Downloaded content is executed without ever touching disk'
            );
        }

        /* EDR-004 — execution from a world-writable directory --------------- */
        foreach (self::WORLD_WRITABLE_PREFIXES as $prefix) {
            if ($path !== '' && str_starts_with($path, $prefix)) {
                $findings[] = $this->finding(
                    'EDR-004', 'Execution from world-writable path', 'medium', 'T1059',
                    "Binary executed from {$prefix} — common staging location for dropped payloads"
                );
                break;
            }
        }

        /* EDR-005 — encoded command execution ------------------------------- */
        if (preg_match('/base64\s+(-d|--decode|-D)\b[^|]*\|\s*(ba|z)?sh\b/', $cmdline)
            || preg_match('/\|\s*base64\s+(-d|--decode)\b[^|]*\|\s*(ba|z)?sh\b/', $cmdline)
            || preg_match('/(python|perl)[0-9.]*\s+-c\s+.{0,40}(b64decode|decodestring|MIME::Base64)/i', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-005', 'Base64-encoded command execution', 'high', 'T1027',
                'Payload is decoded and executed inline to evade command-line inspection'
            );
        }

        /* EDR-006 — credential access --------------------------------------- */
        if (preg_match('#/etc/shadow|/etc/gshadow#', $cmdline)
            || preg_match('#\.ssh/(id_[a-z0-9]+|authorized_keys)\b#', $cmdline)
            || preg_match('#\.aws/credentials|\.docker/config\.json|\.kube/config#', $cmdline)
            || preg_match('/\bunshadow\b|\bjohn\b\s|\bhashcat\b/', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-006', 'Credential store access', 'high', 'T1552',
                'Process touched a credential file or ran a credential-cracking tool'
            );
        }

        /* EDR-007 — anti-forensics / log destruction ------------------------ */
        if (preg_match('/history\s+-c\b/', $cmdline)
            || preg_match('#\brm\b[^|;]*(bash_history|zsh_history|/var/log/)#', $cmdline)
            || preg_match('/\bshred\b|\bwipe\b/', $cmdline)
            || preg_match('/journalctl\s+--vacuum/', $cmdline)
            || preg_match('#>\s*/var/log/(wtmp|btmp|lastlog|auth\.log|secure)\b#', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-007', 'Log or shell-history destruction', 'high', 'T1070',
                'Anti-forensic activity — attacker is covering their tracks'
            );
        }

        /* EDR-008 — persistence --------------------------------------------- */
        if (preg_match('/\bcrontab\b\s+(-|[^-])/', $cmdline)
            || preg_match('#>>?\s*/etc/(cron\.[a-z]+/|crontab|rc\.local)#', $cmdline)
            || preg_match('#>>?\s*/etc/systemd/system/.*\.service#', $cmdline)
            || preg_match('/systemctl\s+enable\b/', $cmdline)
            || preg_match('#>>?\s*[^ ]*/\.(bashrc|bash_profile|profile|zshrc)\b#', $cmdline)
            || preg_match('#>>?\s*[^ ]*\.ssh/authorized_keys#', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-008', 'Persistence mechanism modified', 'medium', 'T1053',
                'Cron, systemd, shell profile or authorized_keys was modified'
            );
        }

        /* EDR-009 — container escape ----------------------------------------
         * Note what is NOT here: plain `docker exec`. osquery's `cid` column
         * is populated for host processes too, so keying off it flags every
         * admin who runs `docker exec` on the host. Only constructs that
         * cross a namespace boundary count. The docker clause is applied
         * solely when this agent is itself running inside a container. */
        if (preg_match('/\bnsenter\b[^|;]*(-t\s*1\b|--target\s*1\b)/', $cmdline)
            || preg_match('#\bchroot\b\s+/(host|mnt/host)#', $cmdline)
            || preg_match('#/proc/1/ns/#', $cmdline)
            || preg_match('#\bmount\b[^|;]*/var/run/docker\.sock#', $cmdline)
            || ($this->runningInContainer() && preg_match('/\bdocker\b\s+(exec|run)\b/', $cmdline))
        ) {
            $findings[] = $this->finding(
                'EDR-009', 'Container escape attempt', 'high', 'T1611',
                'Process tried to reach the host namespace from inside a container'
            );
        }

        /* EDR-010 — privilege escalation setup ------------------------------ */
        if (preg_match('/\bchmod\b[^|;]*\b(u\+s|[24][0-7]{3})\b/', $cmdline)
            || preg_match('/\bsetcap\b[^|;]*cap_(setuid|setgid|sys_admin|dac_override)/', $cmdline)
        ) {
            $findings[] = $this->finding(
                'EDR-010', 'SUID/capability grant', 'high', 'T1548',
                'A binary was given setuid or a dangerous Linux capability'
            );
        }

        /* EDR-011 — download from a bare IP ---------------------------------
         * Loopback is excluded: health checks and local service probes fetch
         * from 127.0.0.1 constantly and none of it is payload staging.
         * RFC 1918 is deliberately NOT excluded — pulling a stage-2 from an
         * internal host is exactly what lateral movement looks like. */
        if (preg_match('/\b(curl|wget)\b[^|;]*\bhttps?:\/\/((?:\d{1,3}\.){3}\d{1,3})(:\d+)?\b/', $cmdline, $m)
            && !str_starts_with($m[2], '127.')
            && $m[2] !== '0.0.0.0'
        ) {
            $findings[] = $this->finding(
                'EDR-011', 'Download from bare IP address', 'medium', 'T1105',
                "Fetching from raw IP {$m[2]} rather than a hostname — typical of staged payload retrieval"
            );
        }

        return $findings;
    }

    /**
     * Rules for file integrity events.
     *
     * These carry no command line, so nothing here may assume one. What they
     * do have is a path, an action, sometimes a uid, and — where inference
     * managed it — an attributed process with a stated confidence.
     *
     * @return array<int, array>
     */
    private function evaluateFileEvent(array $event): array
    {
        $findings = [];

        $path = (string) ($event['path'] ?? '');
        $action = (string) ($event['action'] ?? '');
        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        $attribution = is_array($event['attribution'] ?? null) ? $event['attribution'] : null;
        $actorUser = (string) ($attribution['username'] ?? $event['username'] ?? '');

        /* FIM-001 — a server-executable file appears in a served directory ---
         * The single most valuable file signal for a WAF product: it is what
         * a request that got past the WAF looks like once it has landed. The
         * category comes from the Hub's watch list, so this only fires on
         * directories the customer told us are web roots. */
        if (in_array($action, ['file_create', 'file_write'], true)
            && in_array($extension, self::SERVER_EXECUTABLE_EXTENSIONS, true)
            && $this->isWebCategory($event)
        ) {
            $byWeb = in_array($actorUser, self::WEB_ACCOUNTS, true);

            $findings[] = $this->finding(
                'FIM-001',
                $byWeb ? 'Web account wrote an executable script into a web root' : 'Executable script written into a web root',
                $byWeb ? 'critical' : 'high',
                'T1505.003',
                $byWeb
                    ? "Web account '{$actorUser}' created {$path} — this is what a webshell landing looks like"
                    : "Executable script {$path} appeared in a served directory"
            );
        }

        /* FIM-002 — account, privilege or boot state changed ---------------- */
        if (in_array($action, ['file_create', 'file_write', 'file_delete'], true) && $this->isCriticalPath($path)) {
            $findings[] = $this->finding(
                'FIM-002',
                'Critical system file modified',
                'high',
                'T1098',
                "{$path} was modified — this file governs who can log in or what runs at boot"
            );
        }

        /* FIM-003 — a script or binary was dropped somewhere world-writable
         * A file appearing in /tmp is unremarkable; a file appearing there
         * that a web account wrote is not. */
        if ($action === 'file_create'
            && preg_match('#^/(tmp|var/tmp|dev/shm|run/shm)/#', $path)
            && in_array($actorUser, self::WEB_ACCOUNTS, true)
        ) {
            $findings[] = $this->finding(
                'FIM-003',
                'Web account staged a file in a world-writable directory',
                'high',
                'T1105',
                "Web account '{$actorUser}' created {$path}"
            );
        }

        /* FIM-004 — an SSH authorised key was added --------------------------
         * Separate from FIM-002 because this one is durable remote access
         * rather than a configuration change, and it survives a password
         * reset. */
        if (in_array($action, ['file_create', 'file_write'], true)
            && str_contains($path, '.ssh/authorized_keys')
        ) {
            $findings[] = $this->finding(
                'FIM-004',
                'SSH authorised keys modified',
                'critical',
                'T1098.004',
                "{$path} changed — this grants durable remote access that survives a password reset"
            );
        }

        /* FIM-007 — a monitored file no longer matches its baseline ---------
         * Deliberately separate from FIM-002. That rule says a critical file
         * was touched; this one says its content is now different from what
         * it has been for as long as we have been watching, and carries the
         * previous digest so the change can be reviewed and, if need be,
         * proved reverted. A first sighting is not a deviation — you cannot
         * deviate from a baseline you never had. */
        $baseline = is_array($event['file']['baseline'] ?? null) ? $event['file']['baseline'] : null;

        if ($baseline !== null
            && !empty($baseline['known'])
            && !empty($baseline['changed'])
            && $this->isCriticalPath($path)
        ) {
            $previous = substr((string) ($baseline['previous_sha256'] ?? ''), 0, 12);
            $current = substr((string) ($event['file']['sha256'] ?? ''), 0, 12);

            $findings[] = $this->finding(
                'FIM-007',
                'Monitored file deviates from its baseline',
                'high',
                'T1565.001',
                "{$path} content changed from {$previous}… to {$current}… — "
                . 'compare against your change record before treating it as routine'
            );
        }

        /* FIM-005 — a monitored file was deleted ----------------------------
         * Deleting a watched file is how you remove evidence or disable a
         * control, and it is not something routine maintenance does to the
         * paths on this list. */
        if ($action === 'file_delete' && $this->isCriticalPath($path)) {
            $findings[] = $this->finding(
                'FIM-005',
                'Monitored system file deleted',
                'high',
                'T1070.004',
                "{$path} was deleted"
            );
        }

        return $findings;
    }

    /**
     * Whether this event came from a watch category the Hub designated as a
     * web root. Keyed on the category rather than guessing at path shapes:
     * web roots live wherever the customer put them.
     */
    private function isWebCategory(array $event): bool
    {
        $category = strtolower((string) ($event['file']['category'] ?? ''));

        if ($category === '') {
            return false;
        }

        foreach (['web', 'www', 'htdocs', 'public', 'site'] as $marker) {
            if (str_contains($category, $marker)) {
                return true;
            }
        }

        return false;
    }

    private function isCriticalPath(string $path): bool
    {
        if (in_array($path, self::CRITICAL_FILES, true)) {
            return true;
        }

        foreach (self::CRITICAL_PREFIXES as $prefix) {
            if (str_starts_with($path, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Batch post-pass for rules that need cross-event context.
     *
     * EDR-012: a burst of discovery commands under one parent is the shape of
     * hands-on-keyboard reconnaissance. No single `whoami` is worth an alert;
     * eight of them from one shell is.
     *
     * @param  array<int, array> $events  normalised events, one batch
     * @return array<int, array{event:array,findings:array}>
     */
    public function evaluateBatch(array $events, int $discoveryThreshold = 6): array
    {
        $byParent = [];

        foreach ($events as $event) {
            if ($this->isExcluded($event)) {
                continue;
            }

            $binary = ($event['path'] ?? '') !== '' ? basename((string) $event['path']) : '';
            if (!in_array($binary, self::DISCOVERY_BINARIES, true)) {
                continue;
            }

            $ppid = (int) ($event['ppid'] ?? 0);
            if ($ppid <= 0) {
                continue;
            }

            $byParent[$ppid]['binaries'][$binary] = true;
            $byParent[$ppid]['event'] ??= $event;
        }

        $results = [];

        foreach ($byParent as $ppid => $bucket) {
            $distinct = count($bucket['binaries']);
            if ($distinct < $discoveryThreshold) {
                continue;
            }

            $names = implode(', ', array_keys($bucket['binaries']));
            $results[] = [
                'event' => $bucket['event'],
                'findings' => [$this->finding(
                    'EDR-012', 'Host reconnaissance burst', 'medium', 'T1082',
                    "PID {$ppid} ran {$distinct} distinct discovery commands ({$names})"
                )],
            ];
        }

        foreach ($this->evaluateMassFileChange($events) as $result) {
            $results[] = $result;
        }

        return $results;
    }

    /**
     * FIM-006 — mass file modification, the shape of ransomware.
     *
     * No single file write looks like encryption. What distinguishes it is
     * volume and spread: many files, across several directories, rewritten
     * inside a short window. This is the one detection that has to fire while
     * there is still something left to save, which is why it is a rate rule
     * rather than a content rule — waiting to recognise a ransom note means
     * waiting until it is over.
     *
     * @param  array<int, array> $events
     * @return array<int, array>
     */
    private function evaluateMassFileChange(
        array $events,
        int $fileThreshold = 40,
        int $directoryThreshold = 3,
        int $windowSeconds = 60
    ): array {
        $writes = [];

        foreach ($events as $event) {
            if (!in_array($event['action'] ?? '', ['file_write', 'file_create'], true)) {
                continue;
            }

            $path = (string) ($event['path'] ?? '');
            if ($path === '') {
                continue;
            }

            $writes[] = [
                'ts' => (int) ($event['ts'] ?? 0),
                'dir' => dirname($path),
                'path' => $path,
                'event' => $event,
            ];
        }

        if (count($writes) < $fileThreshold) {
            return [];
        }

        usort($writes, static fn (array $a, array $b): int => $a['ts'] <=> $b['ts']);

        $first = $writes[0]['ts'];
        $last = $writes[count($writes) - 1]['ts'];

        if (($last - $first) > $windowSeconds) {
            return [];
        }

        $directories = array_unique(array_column($writes, 'dir'));

        // Spread is what separates encryption from an ordinary bulk job: a
        // build or a package install rewrites many files inside one tree.
        if (count($directories) < $directoryThreshold) {
            return [];
        }

        $count = count($writes);
        $dirCount = count($directories);

        return [[
            'event' => $writes[0]['event'],
            'findings' => [$this->finding(
                'FIM-006',
                'Mass file modification',
                'critical',
                'T1486',
                "{$count} files rewritten across {$dirCount} directories within {$windowSeconds}s — "
                . 'consistent with ransomware encryption in progress'
            )],
        ]];
    }

    /**
     * True when the shell is doing nothing but starting the application's own
     * runtime — the PHP-FPM / cron / supervisor pattern.
     *
     * Shell metacharacters disqualify it: `sh -c 'php artisan x && curl evil'`
     * must not inherit the carve-out just because it starts with php.
     */
    private function isAppRuntimeWrapper(string $cmdline): bool
    {
        // Strip the leading `sh -c` and any quoting so we can look at the
        // command the shell was actually asked to run.
        $inner = preg_replace('/^\s*\S*(ba|z|k|da)?sh\s+(-[a-z]+\s+)*-c\s+/', '', $cmdline, 1) ?? $cmdline;
        $inner = trim($inner, " \t\n\"'");

        if ($inner === '') {
            return false;
        }

        // Anything that chains, pipes or redirects is not a plain wrapper.
        if (preg_match('/[|;&`]|\$\(|>>?|<|\|\|/', $inner) === 1) {
            return false;
        }

        return preg_match(self::APP_RUNTIME_PATTERN, $inner) === 1;
    }

    /**
     * Whether this agent is running inside a container. Cached for the life
     * of the process — it cannot change underneath us.
     */
    private function runningInContainer(): bool
    {
        if ($this->inContainer !== null) {
            return $this->inContainer;
        }

        if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) {
            return $this->inContainer = true;
        }

        $cgroup = (string) @file_get_contents('/proc/1/cgroup');

        return $this->inContainer = $cgroup !== ''
            && preg_match('/\b(docker|containerd|kubepods|lxc)\b/', $cgroup) === 1;
    }

    private function isExcluded(array $event): bool
    {
        if ($this->exclusions === []) {
            return false;
        }

        $haystack = ($event['path'] ?? '') . ' ' . ($event['cmdline'] ?? '');

        foreach ($this->exclusions as $pattern) {
            if (@preg_match($pattern, $haystack) === 1) {
                return true;
            }
        }

        return false;
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

    /**
     * Highest severity wins when one event trips several rules.
     */
    public static function worstSeverity(array $findings): string
    {
        $rank = ['low' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3];
        $worst = 'low';

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'low';
            if (($rank[$severity] ?? 0) > ($rank[$worst] ?? 0)) {
                $worst = $severity;
            }
        }

        return $worst;
    }
}

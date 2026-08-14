<?php

namespace App\Services\Detection;

use App\Traits\DetectsPlatform;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * Osquery Endpoint Sensor Engine
 *
 * Manages an agent-owned osqueryd instance used as the EDR process sensor.
 * This is deliberately NOT the packaged `osqueryd` systemd service: customers
 * may already run osquery for inventory/compliance, and hijacking their
 * instance (or their auditd rules) would be hostile. We run our own daemon
 * with our own config, database and log directory.
 *
 * Telemetry source, in order of preference:
 *   1. eBPF  (bpf_process_events)   — kernel >= 5.8 with BTF. No auditd conflict.
 *   2. audit (process_events)        — fallback, only when auditd is NOT active,
 *                                      because osquery must own the audit netlink
 *                                      socket and would otherwise fight auditd.
 *
 * Linux only for now. macOS needs an Endpoint Security entitlement and Windows
 * needs ETW; both are tracked separately and report unsupported here.
 */
class OsqueryEngine
{
    use DetectsPlatform;

    /** Minimum kernel version for the eBPF publisher. */
    private const MIN_BPF_KERNEL = '5.8';

    /**
     * Default file-integrity watch list.
     *
     * Deliberately narrow. inotify places a watch per directory, and a
     * recursive watch on somewhere like /tmp or /var on a busy host costs
     * both kernel memory and a flood of events that buries anything real.
     * These are the paths where a change is nearly always worth a look:
     * account and privilege state, the ways a machine starts things, and the
     * places persistence is installed.
     *
     * Web roots are absent on purpose — they are site-specific and come from
     * the Hub, because guessing wrong means either no coverage or watching a
     * directory with a hundred thousand files in it.
     */
    private const DEFAULT_FILE_PATHS = [
        'accounts' => [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/sudoers',
            '/etc/sudoers.d/%%',
        ],
        'ssh' => [
            '/etc/ssh/%%',
            '/root/.ssh/%%',
        ],
        'scheduling' => [
            '/etc/crontab',
            '/etc/cron.d/%%',
            '/etc/cron.hourly/%%',
            '/etc/cron.daily/%%',
            '/var/spool/cron/%%',
        ],
        'startup' => [
            '/etc/systemd/system/%%',
            '/etc/rc.local',
            '/etc/profile.d/%%',
            '/etc/ld.so.preload',
        ],
    ];

    /**
     * Noise that would otherwise dominate the stream. Each of these is a file
     * the system rewrites constantly for reasons that are never an intrusion.
     */
    private const DEFAULT_FILE_EXCLUDES = [
        '/etc/ssh/ssh_host_%%',
        '/var/spool/cron/atjobs/%%',
    ];

    private string $binaryPath;
    private string $baseDir;
    private string $configPath;
    private string $databasePath;
    private string $logDir;
    private string $pidFile;

    public function __construct()
    {
        $this->binaryPath = $this->detectBinaryPath();
        $this->baseDir = storage_path('app/osquery');
        $this->configPath = $this->baseDir . '/osquery.conf';
        $this->databasePath = $this->baseDir . '/db';
        $this->logDir = $this->detectLogDir();
        $this->pidFile = $this->baseDir . '/osqueryd.pid';
    }

    /* ------------------------------------------------------------------ */
    /* Discovery                                                           */
    /* ------------------------------------------------------------------ */

    private function detectBinaryPath(): string
    {
        foreach ([
            '/opt/osquery/bin/osqueryd',
            '/usr/bin/osqueryd',
            '/usr/local/bin/osqueryd',
        ] as $candidate) {
            if (is_file($candidate) && is_executable($candidate)) {
                return $candidate;
            }
        }

        return '';
    }

    private function detectLogDir(): string
    {
        // Prefer the agent's own /var/log tree so logrotate policy and disk
        // accounting sit next to the rest of the product.
        $preferred = '/var/log/security-one-ids/osquery';
        if (is_dir($preferred) || @mkdir($preferred, 0750, true)) {
            return $preferred;
        }

        return storage_path('app/osquery/log');
    }

    public function isInstalled(): bool
    {
        return $this->binaryPath !== '';
    }

    public function getBinaryPath(): string
    {
        return $this->binaryPath;
    }

    public function getResultsLogPath(): string
    {
        return $this->logDir . '/osqueryd.results.log';
    }

    public function getVersion(): ?string
    {
        if (!$this->isInstalled()) {
            return null;
        }

        try {
            $result = Process::timeout(15)->run(escapeshellarg($this->binaryPath) . ' --version 2>&1');
            if ($result->successful() && preg_match('/version\s+([0-9][0-9.]*)/i', $result->output(), $m)) {
                return $m[1];
            }
        } catch (\Exception $e) {
            Log::debug('[Osquery] Version probe failed: ' . $e->getMessage());
        }

        return null;
    }

    /* ------------------------------------------------------------------ */
    /* Capability detection                                                */
    /* ------------------------------------------------------------------ */

    /**
     * Whether the eBPF publisher can run here: kernel >= 5.8 and a BTF blob
     * for CO-RE. Without BTF osquery's BPF probes will not load.
     */
    public function supportsBpf(): bool
    {
        if ($this->isWindows() || PHP_OS === 'Darwin') {
            return false;
        }

        if (!file_exists('/sys/kernel/btf/vmlinux')) {
            return false;
        }

        $release = trim((string) @file_get_contents('/proc/sys/kernel/osrelease'));
        if ($release === '' || !preg_match('/^(\d+)\.(\d+)/', $release, $m)) {
            return false;
        }

        return version_compare("{$m[1]}.{$m[2]}", self::MIN_BPF_KERNEL, '>=');
    }

    /**
     * auditd owns the audit netlink socket exclusively. If it is running we
     * must not start osquery in audit mode — one of the two will silently
     * lose events, and taking a customer's auditd offline is not our call.
     */
    public function auditdIsActive(): bool
    {
        if ($this->isWindows() || PHP_OS === 'Darwin') {
            return false;
        }

        try {
            $result = Process::timeout(10)->run('systemctl is-active auditd 2>/dev/null');
            if (trim($result->output()) === 'active') {
                return true;
            }
        } catch (\Exception $e) {
            // Fall through to pgrep.
        }

        try {
            $result = Process::timeout(10)->run('pgrep -x auditd 2>/dev/null');
            return $result->successful() && trim($result->output()) !== '';
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Resolve which telemetry backend to use: 'bpf', 'audit', or '' when this
     * host cannot produce process telemetry at all.
     */
    public function resolveBackend(): string
    {
        if ($this->supportsBpf()) {
            return 'bpf';
        }

        if (!$this->isWindows() && PHP_OS !== 'Darwin' && !$this->auditdIsActive()) {
            return 'audit';
        }

        return '';
    }

    public function isSupportedPlatform(): bool
    {
        return !$this->isWindows() && PHP_OS !== 'Darwin';
    }

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                           */
    /* ------------------------------------------------------------------ */

    public function getPid(): ?int
    {
        if (!file_exists($this->pidFile)) {
            return null;
        }

        $pid = (int) trim((string) @file_get_contents($this->pidFile));

        return $pid > 0 ? $pid : null;
    }

    public function isRunning(): bool
    {
        $pid = $this->getPid();
        if ($pid === null) {
            return false;
        }

        if (!file_exists("/proc/{$pid}")) {
            return false;
        }

        // Guard against PID reuse: the pidfile may outlive the daemon and a
        // brand new, unrelated process can land on the same number.
        $cmdline = (string) @file_get_contents("/proc/{$pid}/cmdline");

        return str_contains($cmdline, 'osqueryd');
    }

    /**
     * Write the sensor config. Kept small on purpose: every scheduled query
     * is a recurring cost on the endpoint and a recurring volume on the wire.
     *
     * @param array $options  socket_events   — also collect per-process network events
     *                        interval        — seconds between result flushes
     *                        cpu_limit       — osquery watchdog CPU ceiling (percent)
     *                        memory_limit_mb — osquery watchdog RSS ceiling
     */
    public function writeConfig(array $options = []): bool
    {
        $backend = $this->resolveBackend();
        if ($backend === '') {
            return false;
        }

        if (!is_dir($this->baseDir) && !@mkdir($this->baseDir, 0750, true)) {
            Log::error('[Osquery] Cannot create config directory: ' . $this->baseDir);
            return false;
        }

        $interval = max(5, min(300, (int) ($options['interval'] ?? 15)));
        $wantSockets = (bool) ($options['socket_events'] ?? false);

        $processTable = $backend === 'bpf' ? 'bpf_process_events' : 'process_events';
        $socketTable = $backend === 'bpf' ? 'bpf_socket_events' : 'socket_events';

        $schedule = [
            'process_exec' => [
                'query' => "SELECT * FROM {$processTable};",
                'interval' => $interval,
                'removed' => false,
                'description' => 'Process execution telemetry (EDR)',
            ],
        ];

        if ($wantSockets) {
            // Listening sockets come from a point-in-time table rather than
            // from the socket event stream, because the event stream cannot
            // answer the question. Measured on this host: `local_port` is 0 on
            // 100% of bpf_socket_events rows across all four syscalls —
            // connect, accept, bind and listen — and bind/listen additionally
            // report `local_address` as 0.0.0.0. There is no port in the
            // events to detect a new listener with.
            //
            // `listening_ports` carries a real port and a pid for every
            // listener (88 of 88 on this host), and joining `processes` gives
            // the executable path (88 of 88). Polling and diffing it against
            // a baseline is the only way this detection works here.
            $schedule['listeners'] = [
                'query' => 'SELECT lp.pid, lp.port, lp.protocol, lp.family, lp.address, '
                    . "p.path, p.name FROM listening_ports lp "
                    . 'LEFT JOIN processes p ON lp.pid = p.pid '
                    . 'WHERE lp.port != 0;',
                // Slower than the event stream: a listener is a state, not an
                // event, and re-listing 88 rows every 15 seconds buys nothing.
                'interval' => max(60, $interval * 4),
                'removed' => false,
                'description' => 'Listening sockets with owning process (EDR)',
            ];

            $schedule['process_socket'] = [
                'query' => "SELECT * FROM {$socketTable};",
                // Socket events are an order of magnitude noisier than exec;
                // flush them less often so a chatty host cannot swamp the
                // collector between sync cycles.
                'interval' => $interval * 2,
                'removed' => false,
                'description' => 'Per-process network telemetry (EDR)',
            ];
        }

        // File integrity monitoring rides the same daemon. The inotify
        // publisher is independent of the process backend, so it works
        // alongside eBPF and — unlike the audit-based file table — never
        // contends with a customer's own auditd.
        //
        // The trade is that inotify carries no pid: it can say what changed
        // and produce a hash, but not who did it. Attribution is inferred
        // downstream by correlating with process events, and is marked as
        // inferred rather than presented as fact.
        $wantFiles = (bool) ($options['file_events'] ?? false);
        $filePaths = [];
        $fileExcludes = [];

        if ($wantFiles) {
            $filePaths = self::DEFAULT_FILE_PATHS;

            // Hub-supplied categories, typically the site's web roots.
            foreach ((array) ($options['file_paths'] ?? []) as $category => $paths) {
                if (!is_string($category) || !is_array($paths)) {
                    continue;
                }

                $filePaths[preg_replace('/[^a-z0-9_]/i', '_', $category)] = array_values(
                    array_filter($paths, static fn ($p): bool => is_string($p) && $p !== '')
                );
            }

            $fileExcludes = array_merge(
                self::DEFAULT_FILE_EXCLUDES,
                array_values(array_filter(
                    (array) ($options['file_excludes'] ?? []),
                    static fn ($p): bool => is_string($p) && $p !== ''
                ))
            );

            $schedule['file_changes'] = [
                'query' => 'SELECT * FROM file_events;',
                'interval' => $interval,
                'removed' => false,
                'description' => 'File integrity events (EDR)',
            ];
        }

        $config = [
            'options' => [
                'disable_events' => false,
                'enable_bpf_events' => $backend === 'bpf',
                'disable_audit' => $backend !== 'audit',
                'audit_allow_config' => $backend === 'audit',
                'audit_allow_process_events' => $backend === 'audit',
                'audit_allow_sockets' => $backend === 'audit' && $wantSockets,
                'events_expiry' => 3600,
                'events_max' => 50000,
                'logger_plugin' => 'filesystem',
                'logger_path' => $this->logDir,
                'logger_rotate' => true,
                // The raw sensor log is a credential store we do not control:
                // osquery writes command lines verbatim, so secrets land here
                // before the agent's redaction can strip them on the way into
                // the spool. Keeping it small bounds how long a password that
                // was passed on a command line survives on disk.
                //
                // Sizing it larger would not buy resilience anyway — the
                // collector skips ahead when the backlog exceeds its 8 MB
                // per-cycle budget, so a huge log is read past, not caught up
                // on. 16 MB x 2 leaves roughly a minute of slack on a busy
                // host at a quarter of the previous exposure.
                'logger_rotate_size' => 16777216,   // 16 MB per file
                'logger_rotate_max_files' => 2,     // <=32 MB on disk, then recycled
                'schedule_splay_percent' => 10,
                'utc' => true,
                'disable_distributed' => true,
                'disable_carver' => true,
                // Osquery's own watchdog: if our sensor misbehaves it kills
                // itself rather than degrading the customer's host.
                'watchdog_memory_limit' => max(64, (int) ($options['memory_limit_mb'] ?? 200)),
                'watchdog_utilization_limit' => max(5, (int) ($options['cpu_limit'] ?? 20)),
                'enable_file_events' => $wantFiles,
                // Hashing is what lets a change be compared against a known
                // baseline rather than merely noticed. It costs a read of
                // every changed file, which is why the watch list is narrow.
                'enable_hashing' => $wantFiles,
            ],
            'schedule' => $schedule,
        ];

        if ($wantFiles) {
            $config['file_paths'] = $filePaths;

            if ($fileExcludes !== []) {
                $config['exclude_paths'] = ['exclusions' => $fileExcludes];
            }
        }

        $json = json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            Log::error('[Osquery] Failed to encode config');
            return false;
        }

        if (@file_put_contents($this->configPath, $json) === false) {
            Log::error('[Osquery] Failed to write config: ' . $this->configPath);
            return false;
        }

        @chmod($this->configPath, 0640);

        return true;
    }

    /**
     * Config fingerprint, so the sync layer can detect a settings change from
     * the Hub and restart the daemon instead of leaving it on stale options.
     */
    public function getConfigHash(): string
    {
        return file_exists($this->configPath)
            ? (string) @md5_file($this->configPath)
            : '';
    }

    public function start(array $options = []): array
    {
        if (!$this->isSupportedPlatform()) {
            return ['success' => false, 'error' => 'Endpoint sensor is Linux-only in this release'];
        }

        if (!$this->isInstalled()) {
            return ['success' => false, 'error' => 'osqueryd not installed'];
        }

        if ($this->isRunning()) {
            return ['success' => true, 'message' => 'Already running', 'pid' => $this->getPid()];
        }

        $backend = $this->resolveBackend();
        if ($backend === '') {
            return [
                'success' => false,
                'error' => 'No usable telemetry backend (kernel lacks BTF/eBPF and auditd owns the audit socket)',
            ];
        }

        if (!$this->writeConfig($options)) {
            return ['success' => false, 'error' => 'Failed to write sensor config'];
        }

        // A stale pidfile from a killed daemon blocks startup.
        if (file_exists($this->pidFile) && !$this->isRunning()) {
            @unlink($this->pidFile);
        }

        foreach ([$this->databasePath, $this->logDir] as $dir) {
            if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
                return ['success' => false, 'error' => "Cannot create directory: {$dir}"];
            }
        }

        // --flagfile=/dev/null keeps /etc/osquery/osquery.flags (which belongs
        // to the customer's own deployment, if any) out of our process.
        //
        // setsid + nohup + closed stdin are not belt-and-braces here: osqueryd
        // --daemonize alone still dies with the artisan process that spawned
        // it, so the sensor would come up on every sync cycle and be gone
        // before the next one. A new session detaches it for good.
        $cmd = sprintf(
            'setsid nohup %s --flagfile=/dev/null --config_path=%s --database_path=%s --logger_path=%s --pidfile=%s --daemonize < /dev/null >> %s 2>&1 &',
            escapeshellarg($this->binaryPath),
            escapeshellarg($this->configPath),
            escapeshellarg($this->databasePath),
            escapeshellarg($this->logDir),
            escapeshellarg($this->pidFile),
            escapeshellarg($this->logDir . '/osqueryd.stdout.log')
        );

        try {
            $result = Process::timeout(60)->run($cmd);
        } catch (\Exception $e) {
            return ['success' => false, 'error' => 'Start failed: ' . $e->getMessage()];
        }

        // --daemonize forks; give the child a moment to write its pidfile.
        for ($i = 0; $i < 20; $i++) {
            if ($this->isRunning()) {
                Log::info('[Osquery] Sensor started', ['backend' => $backend, 'pid' => $this->getPid()]);

                return [
                    'success' => true,
                    'pid' => $this->getPid(),
                    'backend' => $backend,
                ];
            }
            usleep(250000);
        }

        return [
            'success' => false,
            'error' => 'osqueryd did not come up',
            'output' => substr($result->output() . $result->errorOutput(), -500),
        ];
    }

    public function stop(): bool
    {
        $pid = $this->getPid();
        if ($pid === null || !$this->isRunning()) {
            @unlink($this->pidFile);
            return true;
        }

        try {
            Process::timeout(15)->run("kill {$pid} 2>/dev/null");

            for ($i = 0; $i < 20; $i++) {
                if (!$this->isRunning()) {
                    @unlink($this->pidFile);
                    return true;
                }
                usleep(250000);
            }

            Process::timeout(15)->run("kill -9 {$pid} 2>/dev/null");
            usleep(500000);
        } catch (\Exception $e) {
            Log::warning('[Osquery] Stop failed: ' . $e->getMessage());
        }

        $stopped = !$this->isRunning();
        if ($stopped) {
            @unlink($this->pidFile);
        }

        return $stopped;
    }

    public function restart(array $options = []): array
    {
        $this->stop();

        return $this->start($options);
    }

    /* ------------------------------------------------------------------ */
    /* Install                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Install osquery from the upstream package repo. Apache-2.0 licensed, so
     * redistributing it inside a commercial agent bundle is permitted — unlike
     * Sysmon, whose Sysinternals EULA forbids redistribution.
     */
    public function install(string $version = '5.15.0'): array
    {
        if (!$this->isSupportedPlatform()) {
            return ['success' => false, 'error' => 'Endpoint sensor is Linux-only in this release'];
        }

        if ($this->isInstalled()) {
            return ['success' => true, 'message' => 'Already installed', 'version' => $this->getVersion()];
        }

        $arch = $this->detectArch();
        if ($arch === '') {
            return ['success' => false, 'error' => 'Unsupported CPU architecture: ' . php_uname('m')];
        }

        $usesDeb = is_file('/usr/bin/dpkg') || is_file('/usr/bin/apt-get');
        $usesRpm = is_file('/usr/bin/rpm') || is_file('/bin/rpm');

        if (!$usesDeb && !$usesRpm) {
            return ['success' => false, 'error' => 'No supported package manager (dpkg/rpm) found'];
        }

        $tmp = sys_get_temp_dir() . '/security-one-osquery';
        if (!is_dir($tmp) && !@mkdir($tmp, 0700, true)) {
            return ['success' => false, 'error' => 'Cannot create temp directory'];
        }

        if ($usesDeb) {
            $url = "https://pkg.osquery.io/deb/osquery_{$version}-1.linux_{$arch}.deb";
            $file = "{$tmp}/osquery.deb";
            $installCmd = 'dpkg -i ' . escapeshellarg($file);
        } else {
            $rpmArch = $arch === 'amd64' ? 'x86_64' : 'aarch64';
            $url = "https://pkg.osquery.io/rpm/osquery-{$version}-1.linux.{$rpmArch}.rpm";
            $file = "{$tmp}/osquery.rpm";
            $installCmd = 'rpm -Uvh --replacepkgs ' . escapeshellarg($file);
        }

        try {
            $dl = Process::timeout(600)->run(
                'curl -fsSL --retry 3 -o ' . escapeshellarg($file) . ' ' . escapeshellarg($url) . ' 2>&1'
            );

            if (!$dl->successful() || !is_file($file) || filesize($file) < 1024 * 1024) {
                @unlink($file);

                return [
                    'success' => false,
                    'error' => 'Download failed: ' . substr($dl->errorOutput() ?: $dl->output(), -300),
                    'url' => $url,
                ];
            }

            $install = Process::timeout(600)->run($installCmd . ' 2>&1');
            @unlink($file);

            // Re-detect; dpkg may have placed the binary somewhere new.
            $this->binaryPath = $this->detectBinaryPath();

            if (!$this->isInstalled()) {
                return [
                    'success' => false,
                    'error' => 'Package installed but osqueryd not found: ' . substr($install->output(), -300),
                ];
            }

            // The distro package registers a systemd unit. We run our own
            // instance, so make sure the packaged one stays out of the way.
            Process::timeout(30)->run('systemctl disable --now osqueryd 2>/dev/null');

            Log::info('[Osquery] Installed', ['version' => $this->getVersion(), 'path' => $this->binaryPath]);

            return ['success' => true, 'version' => $this->getVersion(), 'path' => $this->binaryPath];
        } catch (\Exception $e) {
            @unlink($file);

            return ['success' => false, 'error' => 'Install failed: ' . $e->getMessage()];
        }
    }

    private function detectArch(): string
    {
        return match (php_uname('m')) {
            'x86_64', 'amd64' => 'amd64',
            'aarch64', 'arm64' => 'arm64',
            default => '',
        };
    }

    /* ------------------------------------------------------------------ */
    /* Status                                                              */
    /* ------------------------------------------------------------------ */

    public function getStatus(): array
    {
        $resultsLog = $this->getResultsLogPath();

        return [
            'supported' => $this->isSupportedPlatform(),
            'installed' => $this->isInstalled(),
            'running' => $this->isRunning(),
            'pid' => $this->getPid(),
            'version' => $this->getVersion(),
            'backend' => $this->resolveBackend(),
            'bpf_supported' => $this->supportsBpf(),
            'auditd_active' => $this->auditdIsActive(),
            'binary_path' => $this->binaryPath,
            'config_path' => $this->configPath,
            'config_hash' => $this->getConfigHash(),
            'results_log' => $resultsLog,
            'results_log_size' => file_exists($resultsLog) ? filesize($resultsLog) : 0,
        ];
    }
}

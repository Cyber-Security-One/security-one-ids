<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;

/**
 * Log Discovery Service
 *
 * Auto-discovers web server log files on the system
 */
class LogDiscoveryService
{
    /**
     * Common web server log file locations to scan
     */
    private const LOG_PATHS = [
        // === Linux Nginx ===
        '/var/log/nginx/access.log',
        '/var/log/nginx/*/access.log',
        '/var/log/nginx/*-access.log',
        '/var/log/nginx/error.log',
        '/usr/local/nginx/logs/access.log',

        // === Linux Apache ===
        '/var/log/apache2/access.log',
        '/var/log/apache2/*/access.log',
        '/var/log/apache2/*-access.log',
        '/var/log/apache2/other_vhosts_access.log',
        '/var/log/httpd/access_log',
        '/var/log/httpd/*/access_log',

        // === macOS ===
        '/var/log/apache2/access_log',
        '/var/log/apache2/error_log',
        '/usr/local/var/log/nginx/access.log',
        '/usr/local/var/log/nginx/error.log',
        '/opt/homebrew/var/log/nginx/access.log',
        '/opt/homebrew/var/log/nginx/error.log',
        '/opt/homebrew/var/log/httpd/access_log',
        '/private/var/log/apache2/access_log',
        '/private/var/log/apache2/error_log',

        // === Docker / Container ===
        '/var/log/host-nginx/access.log',
        '/var/log/host-nginx/*/access.log',
        '/var/log/host-nginx/*-access.log',
        '/var/log/host-apache2/access.log',
        '/var/log/host-apache2/*/access.log',
        '/var/log/host-httpd/access_log',
        '/var/log/custom-logs-*/access.log',
        '/var/log/custom-logs-*/*.log',

        // === Common custom paths ===
        '/var/www/*/logs/access.log',
        '/home/*/logs/access.log',
        '/home/*/public_html/logs/access.log',
    ];

    /**
     * System log paths for security monitoring
     */
    private const SYSTEM_LOG_PATHS = [
        // === Linux syslog / auth ===
        '/var/log/syslog',
        '/var/log/messages',
        '/var/log/auth.log',
        '/var/log/secure',
        '/var/log/kern.log',
        '/var/log/ufw.log',
        '/var/log/fail2ban.log',
        '/var/log/firewalld',

        // === macOS system logs ===
        '/var/log/system.log',
        '/var/log/install.log',
        '/private/var/log/system.log',
        '/private/var/log/asl/*.asl',

        // === Application logs ===
        '/var/log/mysql/error.log',
        '/var/log/postgresql/*.log',
        '/var/log/redis/redis-server.log',
        '/var/log/php*.log',
        '/var/log/php-fpm/*.log',
    ];

    /**
     * Log format patterns for different servers
     */
    private const LOG_FORMATS = [
        'nginx_combined' => '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/',
        'apache_combined' => '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/',
        'apache_common' => '/^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^\s]+) ([^"]+)" (\d+) (\d+)/',
    ];

    /**
     * Discover all accessible log files
     */
    public function discoverLogFiles(bool $includeSystemLogs = true): Collection
    {
        $discovered = collect();

        // Scan web server log paths
        foreach (self::LOG_PATHS as $pattern) {
            $files = glob($pattern);
            if ($files) {
                foreach ($files as $file) {
                    if (is_readable($file) && is_file($file)) {
                        $info = $this->getLogInfo($file);
                        if ($info) {
                            $discovered->push($info);
                        }
                    }
                }
            }
        }

        // Scan system log paths
        if ($includeSystemLogs) {
            foreach (self::SYSTEM_LOG_PATHS as $pattern) {
                $files = glob($pattern);
                if ($files) {
                    foreach ($files as $file) {
                        if (is_readable($file) && is_file($file) && filesize($file) > 0) {
                            $discovered->push([
                                'path' => $file,
                                'type' => 'system',
                                'format' => 'syslog',
                                'size' => filesize($file),
                                'modified' => filemtime($file),
                                'readable' => true,
                            ]);
                        }
                    }
                }
            }

            // Dynamic discovery: scan /var/log for any .log files
            $this->scanDirectory('/var/log', $discovered, 2);

            // macOS: also scan /private/var/log
            if (PHP_OS_FAMILY === 'Darwin') {
                $this->scanDirectory('/private/var/log', $discovered, 2);
            }
        }

        // Also check custom paths from config
        $customPaths = config('ids.custom_log_paths', []);
        foreach ($customPaths as $path) {
            if (is_readable($path) && is_file($path)) {
                $info = $this->getLogInfo($path);
                if ($info) {
                    $discovered->push($info);
                }
            }
        }

        // Add custom paths from cache
        foreach ($this->getCustomPaths() as $path) {
            if (is_readable($path) && is_file($path) && !$discovered->contains('path', $path)) {
                $discovered->push([
                    'path' => $path,
                    'type' => 'custom',
                    'format' => 'unknown',
                    'size' => filesize($path),
                    'modified' => filemtime($path),
                    'readable' => true,
                ]);
            }
        }

        return $discovered->unique('path');
    }

    /**
     * Recursively scan a directory for log files
     */
    private function scanDirectory(string $dir, Collection &$discovered, int $maxDepth, int $currentDepth = 0): void
    {
        if ($currentDepth >= $maxDepth || !is_dir($dir) || !is_readable($dir)) {
            return;
        }

        try {
            $entries = @scandir($dir);
            if (!$entries) {
                return;
            }

            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $path = $dir . '/' . $entry;

                if (is_dir($path) && is_readable($path)) {
                    $this->scanDirectory($path, $discovered, $maxDepth, $currentDepth + 1);
                } elseif (is_file($path) && is_readable($path) && filesize($path) > 0) {
                    // Only include .log files or files without extension that look like logs
                    if (str_ends_with($entry, '.log') || str_ends_with($entry, '_log') || $entry === 'syslog' || $entry === 'messages') {
                        if (!$discovered->contains('path', $path)) {
                            $info = $this->getLogInfo($path);
                            if ($info) {
                                $discovered->push($info);
                            } else {
                                // Still add as system log even if format not recognized
                                $discovered->push([
                                    'path' => $path,
                                    'type' => $this->detectServerType($path),
                                    'format' => 'unknown',
                                    'size' => filesize($path),
                                    'modified' => filemtime($path),
                                    'readable' => true,
                                ]);
                            }
                        }
                    }
                }
            }
        } catch (\Exception $e) {
            Log::debug("Failed to scan directory {$dir}: " . $e->getMessage());
        }
    }

    /**
     * Get information about a log file
     */
    private function getLogInfo(string $path): ?array
    {
        $format = $this->detectFormat($path);
        if (!$format) {
            return null;
        }

        $type = $this->detectServerType($path);

        return [
            'path' => $path,
            'type' => $type,
            'format' => $format,
            'size' => filesize($path),
            'modified' => filemtime($path),
            'readable' => is_readable($path),
        ];
    }

    /**
     * Detect the log format by reading sample lines
     */
    private function detectFormat(string $path): ?string
    {
        $handle = @fopen($path, 'r');
        if (!$handle) {
            return null;
        }

        // Read a few sample lines from the end
        $lines = [];
        fseek($handle, max(0, filesize($path) - 4096));
        while (($line = fgets($handle)) !== false) {
            if (trim($line)) {
                $lines[] = trim($line);
            }
        }
        fclose($handle);

        if (empty($lines)) {
            return null;
        }

        // Try to match against known formats
        $sampleLine = end($lines);

        foreach (self::LOG_FORMATS as $name => $pattern) {
            if (preg_match($pattern, $sampleLine)) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Detect server type from path
     */
    private function detectServerType(string $path): string
    {
        if (str_contains($path, 'nginx')) {
            return 'nginx';
        }
        if (str_contains($path, 'apache') || str_contains($path, 'httpd')) {
            return 'apache';
        }
        return 'unknown';
    }

    /**
     * Common cache lock key to prevent concurrent operations overriding each other
     */
    private const CUSTOM_PATHS_LOCK_KEY = 'custom_log_paths_lock';

    /**
     * Add a custom log path to monitor
     *
     * @param string $path
     * @return bool True on success, false if unreadable or lock acquisition failed
     */
    public function addCustomPath(string $path): bool
    {
        if (!is_readable($path)) {
            return false;
        }

        $acquired = false;
        $delayMicroseconds = 10000; // 10ms
        $lock = null;

        try {
            $lock = cache()->lock(self::CUSTOM_PATHS_LOCK_KEY, 10);
            for ($i = 0; $i < 10; $i++) {
                if ($lock->get()) {
                    $acquired = true;
                    break;
                }
                usleep($delayMicroseconds);
                $delayMicroseconds *= 2;
            }
        } catch (\Exception $e) {
            Log::warning("Cache lock failed during addCustomPath: " . $e->getMessage());
        }

        if (!$acquired) {
            Log::warning('addCustomPath lock contention, failing gracefully', ['path' => $path]);
            return false;
        }

        try {
            $cachedPaths = cache()->get('ids::custom_log_paths', []);
            $configPaths = config('ids.custom_log_paths', []);

            $allPaths = array_values(array_unique(array_merge($cachedPaths, $configPaths)));

            if (!in_array($path, $allPaths, true)) {
                $cachedPaths[] = $path;
                cache()->forever('ids::custom_log_paths', array_values(array_unique($cachedPaths)));
            }
        } finally {
            if ($acquired && $lock) {
                $lock->release();
            }
        }

        return true;
    }

    /**
     * Get custom paths from cache
     */
    public function getCustomPaths(): array
    {
        $hasLegacy1 = cache()->has('ids_custom_log_paths');
        $hasLegacy2 = cache()->has('ids.custom_log_paths');

        if ($hasLegacy1 || $hasLegacy2) {
            $acquired = false;
            $delayMicroseconds = 10000;
            $lock = null;

            try {
                $lock = cache()->lock(self::CUSTOM_PATHS_LOCK_KEY, 10);
                for ($i = 0; $i < 10; $i++) {
                    if ($lock->get()) {
                        $acquired = true;
                        break;
                    }
                    usleep($delayMicroseconds);
                    $delayMicroseconds *= 2;
                }
            } catch (\Exception $e) {
                Log::warning("Cache lock failed during migration in getCustomPaths: " . $e->getMessage());
            }

            if ($acquired) {
                try {
                    $hasLegacy1 = cache()->has('ids_custom_log_paths');
                    $hasLegacy2 = cache()->has('ids.custom_log_paths');

                    if ($hasLegacy1 || $hasLegacy2) {
                        $legacyPaths1 = $hasLegacy1 ? cache()->get('ids_custom_log_paths', []) : [];
                        $legacyPaths2 = $hasLegacy2 ? cache()->get('ids.custom_log_paths', []) : [];
                        $currentPaths = cache()->get('ids::custom_log_paths', []);

                        $merged = array_values(array_unique(array_merge($legacyPaths1, $legacyPaths2, $currentPaths)));

                        cache()->forever('ids::custom_log_paths', $merged);

                        if ($hasLegacy1) cache()->forget('ids_custom_log_paths');
                        if ($hasLegacy2) cache()->forget('ids.custom_log_paths');

                        return $merged;
                    }
                } finally {
                    if ($acquired && $lock) {
                        $lock->release();
                    }
                }
            }

            // Fallback: Return merged state if lock acquisition failed but legacies exist
            $legacyPaths1 = $hasLegacy1 ? cache()->get('ids_custom_log_paths', []) : [];
            $legacyPaths2 = $hasLegacy2 ? cache()->get('ids.custom_log_paths', []) : [];
            $currentPaths = cache()->get('ids::custom_log_paths', []);

            return array_values(array_unique(array_merge($legacyPaths1, $legacyPaths2, $currentPaths)));
        }

        return cache()->get('ids::custom_log_paths', []);
    }

    /**
     * Get pattern for a specific format
     */
    public static function getPattern(string $format): ?string
    {
        return self::LOG_FORMATS[$format] ?? self::LOG_FORMATS['nginx_combined'];
    }
}

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
     * Allowed base directories for custom log paths
     */
    private const ALLOWED_BASE_DIRS = [
        '/var/log',
        '/var/www',
        '/usr/local',
        '/opt',
        '/home',
        '/private/var',
    ];

    /**
     * Cached resolved base directories
     */
    private static ?array $resolvedBaseDirs = null;

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
     * Add a custom log path to monitor
     */
    public function addCustomPath(string $path): bool
    {
        $realPath = realpath($path);

        if ($realPath === false || !is_file($realPath) || !is_readable($realPath)) {
            return false;
        }

        // Validate that path does not contain path traversal vectors
        $segments = explode('/', str_replace('\\', '/', $path));
        if (in_array('..', $segments, true)) {
            return false;
        }

        if (!$this->isAllowedPath($realPath)) {
            return false;
        }

        $lock = cache()->lock('ids.custom_log_paths_lock', 5);
        $acquired = false;

        $retriesDeadline = microtime(true) + 5.0;
        $delay = 100000; // 100ms

        while (microtime(true) < $retriesDeadline) {
            if ($lock->get()) {
                $acquired = true;
                break;
            }
            usleep($delay);
            $delay = min($delay * 2, 1000000); // Max 1s
        }

        if (!$acquired) {
            Log::warning("Could not acquire lock to add custom log path (timeout after retries)", ['path' => $path]);
            return false;
        }

        try {
            $cachedPaths = $this->getCustomPaths();

            $normalizedCached = [];
            foreach ($cachedPaths as $cachedPath) {
                $cachedReal = realpath($cachedPath);
                if ($cachedReal !== false) {
                    $normalizedCached[] = $cachedReal;
                }
            }

            if (in_array($realPath, $normalizedCached, true) || in_array($path, $cachedPaths, true)) {
                return true;
            }

            // Store the verified realPath to prevent symlink Time-of-Check to Time-of-Use attacks
            $cachedPaths[] = $realPath;
            $merged = array_values(array_unique($cachedPaths));
            cache()->forever('ids.custom_log_paths', $merged);
        } finally {
            if ($acquired) {
                $lock->release();
            }
        }

        return true;
    }

    private function isAllowedPath(string $realPath): bool
    {
        if (self::$resolvedBaseDirs === null) {
            $allowedDirs = self::ALLOWED_BASE_DIRS;
            $allowedDirs[] = sys_get_temp_dir();

            self::$resolvedBaseDirs = [];
            foreach ($allowedDirs as $dir) {
                $realDir = realpath($dir) ?: $dir;
                self::$resolvedBaseDirs[] = rtrim($realDir, DIRECTORY_SEPARATOR);
            }
        }

        // Ensure case-insensitive comparison on case-insensitive filesystems like Windows/macOS.
        // However, realpath() resolves the casing. But if the configured ALLOWED_BASE_DIRS
        // has incorrect casing, it might not match.
        // Also str_starts_with is case-sensitive. Let's make it more robust.

        $isCaseInsensitive = PHP_OS_FAMILY === 'Windows' || PHP_OS_FAMILY === 'Darwin';

        $checkPath = $isCaseInsensitive ? strtolower($realPath) : $realPath;

        foreach (self::$resolvedBaseDirs as $realDir) {
            $checkDir = $isCaseInsensitive ? strtolower($realDir) : $realDir;

            if ($checkPath === $checkDir || str_starts_with($checkPath, $checkDir . DIRECTORY_SEPARATOR)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get custom paths from cache
     */
    public function getCustomPaths(): array
    {
        // Handle backward compatibility for old cache key
        if (cache()->has('ids_custom_log_paths')) {
            $lock = cache()->lock('ids.custom_log_paths_lock', 5);
            if ($lock->get()) {
                try {
                    // Double check in case it was migrated while waiting for lock
                    if (cache()->has('ids_custom_log_paths')) {
                        $legacyPaths = cache()->get('ids_custom_log_paths', []);

                        if (!is_array($legacyPaths)) {
                            Log::warning('Corrupted legacy custom log paths cache key encountered and discarded.', [
                                'type' => gettype($legacyPaths)
                            ]);
                            $legacyPaths = [];
                        }

                        $currentPaths = cache()->get('ids.custom_log_paths', []);
                        $currentPaths = is_array($currentPaths) ? $currentPaths : [];

                        if (!empty($legacyPaths)) {
                            $mergedPaths = array_values(array_unique(array_merge($currentPaths, $legacyPaths)));
                            cache()->forever('ids.custom_log_paths', $mergedPaths);
                        }

                        cache()->forget('ids_custom_log_paths');
                    }
                } finally {
                    $lock->release();
                }
            }
        }

        $paths = cache()->get('ids.custom_log_paths', []);

        if (!is_array($paths)) {
            Log::warning('Corrupted custom log paths cache key encountered and discarded.', [
                'type' => gettype($paths)
            ]);
            return [];
        }

        return $paths;
    }

    /**
     * Get pattern for a specific format
     */
    public static function getPattern(string $format): ?string
    {
        return self::LOG_FORMATS[$format] ?? self::LOG_FORMATS['nginx_combined'];
    }
}

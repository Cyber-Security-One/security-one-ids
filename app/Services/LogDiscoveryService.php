<?php

namespace App\Services;

use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

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

        $configPaths = config('ids.custom_log_paths', []);

        // We shouldn't redundantly merge and write to cache if not needed.
        // First check if it's already in config.
        if (in_array($path, $configPaths, true) || in_array($realPath, $configPaths, true)) {
            return true;
        }

        $lock = Cache::lock('ids.custom_log_paths_lock', 10);
        $attempts = 0;
        $acquired = false;
        $sleepMicroseconds = 100000; // 100ms

        while ($attempts < 5) {
            if ($lock->get()) {
                $acquired = true;
                break;
            }
            usleep($sleepMicroseconds);
            $sleepMicroseconds *= 2; // exponential backoff
            $attempts++;
        }

        if (!$acquired) {
            Log::warning("Could not acquire lock to add custom log path", ['path' => $path]);
            return false;
        }

        try {
            $cachedPaths = $this->getCustomPaths();

            // If it's already in the cache, we're good.
            if (in_array($path, $cachedPaths, true) || in_array($realPath, $cachedPaths, true)) {
                return true;
            }

            $cachedPaths[] = $realPath;
            // Store in cache for persistence
            Cache::forever('ids.custom_log_paths', $cachedPaths);
        } finally {
            $lock->release();
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

        foreach (self::$resolvedBaseDirs as $realDir) {
            if ($realPath === $realDir || str_starts_with($realPath, $realDir . DIRECTORY_SEPARATOR)) {
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
        if (Cache::has('ids_custom_log_paths')) {
            $legacyPaths = Cache::pull('ids_custom_log_paths', []);

            if (!is_array($legacyPaths)) {
                Log::warning('Corrupted legacy custom log paths cache key encountered and discarded.', [
                    'type' => gettype($legacyPaths)
                ]);
                $legacyPaths = [];
            }

            $currentPaths = Cache::get('ids.custom_log_paths', []);
            $currentPaths = is_array($currentPaths) ? $currentPaths : [];

            if (!empty($legacyPaths)) {
                $mergedPaths = array_values(array_unique(array_merge($currentPaths, $legacyPaths)));
                Cache::forever('ids.custom_log_paths', $mergedPaths);
            }
        }

        $paths = Cache::get('ids.custom_log_paths', []);

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

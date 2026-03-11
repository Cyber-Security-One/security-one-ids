<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;

/**
 * Desktop Log Collector Service
 * 
 * Collects system logs from personal computers (Linux, macOS, Windows)
 * for IDS/IPS analysis including authentication, system events, and network connections.
 */
class DesktopLogCollector
{
    private string $platform;
    private array $logPaths = [];
    
    public function __construct()
    {
        $this->platform = $this->detectPlatform();
        $this->logPaths = $this->getLogPaths();
    }
    
    /**
     * Detect the current operating system
     */
    private function detectPlatform(): string
    {
        if ($this->isWindows()) {
            return 'windows';
        } elseif ($this->isMac()) {
            return 'macos';
        }
        return 'linux';
    }
    
    /**
     * Get log file paths based on platform
     */
    private function getLogPaths(): array
    {
        return match ($this->platform) {
            'linux' => [
                'auth' => [
                    '/var/log/auth.log',           // Debian/Ubuntu
                    '/var/log/secure',             // RHEL/CentOS
                ],
                'syslog' => [
                    '/var/log/syslog',
                    '/var/log/messages',
                ],
                'firewall' => [
                    '/var/log/ufw.log',
                    '/var/log/iptables.log',
                ],
            ],
            'macos' => [
                'auth' => [
                    '/var/log/system.log',
                ],
                'syslog' => [
                    '/var/log/system.log',
                ],
                'firewall' => [
                    '/var/log/appfirewall.log',
                ],
            ],
            'windows' => [
                // Windows uses Event Log API, not files
                'auth' => ['Security'],
                'syslog' => ['System'],
                'firewall' => ['Windows Firewall With Advanced Security'],
            ],
            default => [],
        };
    }
    
    /**
     * Get current platform
     */
    public function getPlatform(): string
    {
        return $this->platform;
    }
    
    /**
     * Collect authentication logs (SSH, sudo, login attempts)
     */
    public function collectAuthLogs(int $lines = 100): array
    {
        $logs = [];
        $rawLogs = []; // For file-based logs that need parsing
        
        // macOS uses unified logging - use the log command
        if ($this->platform === 'macos') {
            Log::debug('Collecting macOS logs via unified logging');
            return $this->collectMacOsLogs(60);
        }
        
        foreach ($this->logPaths['auth'] ?? [] as $path) {
            if ($this->platform === 'windows') {
                Log::debug("Collecting Windows Event Log: {$path}");
                // Windows logs are already parsed arrays
                $windowsLogs = $this->collectWindowsEventLog($path, $lines);
                Log::debug("Windows Event Log returned " . count($windowsLogs) . " entries");
                $logs = array_merge($logs, $windowsLogs);
            } elseif (file_exists($path) && is_readable($path)) {
                Log::debug("Reading log file: {$path}");
                // Linux file logs are strings
                $rawLogs = array_merge($rawLogs, $this->tailFile($path, $lines));
            } else {
                Log::debug("Log file not accessible: {$path}");
            }
        }
        
        // Parse the raw text logs and merge with already parsed logs
        return array_merge($logs, $this->parseAuthLogs($rawLogs));
    }
    
    /**
     * Collect system logs
     */
    public function collectSysLogs(int $lines = 100): array
    {
        $logs = [];
        
        foreach ($this->logPaths['syslog'] ?? [] as $path) {
            if ($this->platform === 'windows') {
                $logs = array_merge($logs, $this->collectWindowsEventLog($path, $lines));
            } elseif (file_exists($path) && is_readable($path)) {
                $logs = array_merge($logs, $this->tailFile($path, $lines));
            }
        }
        
        return $logs;
    }
    
    /**
     * Get active network connections
     */
    public function collectNetworkConnections(): array
    {
        $connections = [];
        
        try {
            if ($this->platform === 'windows') {
                return $this->collectWindowsNetworkConnections();
            }
            
            $output = match ($this->platform) {
                'linux', 'macos' => shell_exec('netstat -tunap 2>/dev/null || ss -tunap 2>/dev/null'),
                default => '',
            };
            
            if ($output) {
                $connections = $this->parseNetstatOutput($output);
            }
        } catch (\Exception $e) {
            Log::warning('Failed to collect network connections: ' . $e->getMessage());
        }
        
        return $connections;
    }

    /**
     * Collect network connections on Windows using PowerShell
     */
    private function collectWindowsNetworkConnections(): array
    {
        $connections = [];
        try {
            // Use Get-NetTCPConnection for reliable structured output
            $psScript = 'Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | ConvertTo-Json -Compress';
            
            // Write script to temp file
            $scriptFile = sys_get_temp_dir() . '\\get_net_' . time() . '.ps1';
            file_put_contents($scriptFile, $psScript);
            
            $psCommand = sprintf(
                'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%s"',
                $scriptFile
            );
            
            $output = [];
            $returnCode = 0;
            exec($psCommand . ' 2>&1', $output, $returnCode);
            @unlink($scriptFile);
            
            $outputStr = implode("\n", $output);
            
            if ($outputStr && strlen(trim($outputStr)) > 2 && $outputStr !== '[]') {
                $entries = json_decode($outputStr, true);
                if (is_array($entries)) {
                    // Handle single entry case
                    if (isset($entries['LocalAddress'])) {
                        $entries = [$entries];
                    }
                    
                    foreach ($entries as $entry) {
                        $connections[] = [
                            'protocol' => 'tcp', // Get-NetTCPConnection implies TCP
                            'local' => ($entry['LocalAddress'] ?? '') . ':' . ($entry['LocalPort'] ?? ''),
                            'remote' => ($entry['RemoteAddress'] ?? '') . ':' . ($entry['RemotePort'] ?? ''),
                            'state' => match($entry['State'] ?? '') {
                                2 => 'Listen', // Numeric enum mapping if needed, but PS usually returns string 'Listen'
                                default => $entry['State'] ?? 'UNKNOWN'
                            },
                            'pid' => $entry['OwningProcess'] ?? null,
                        ];
                    }
                }
            }
        } catch (\Exception $e) {
            Log::warning('Failed to collect Windows network connections: ' . $e->getMessage());
        }
        
        return $connections;
    }
    
    /**
     * Get failed login attempts
     */
    public function getFailedLogins(int $hours = 24): array
    {
        $authLogs = $this->collectAuthLogs(500);
        $failedAttempts = [];
        $cutoffTime = time() - ($hours * 3600);
        
        foreach ($authLogs as $log) {
            if (isset($log['type']) && $log['type'] === 'failed_login') {
                if (isset($log['timestamp']) && strtotime($log['timestamp']) > $cutoffTime) {
                    $failedAttempts[] = $log;
                }
            }
        }
        
        return $failedAttempts;
    }
    
    /**
     * Get successful logins
     */
    public function getSuccessfulLogins(int $hours = 24): array
    {
        $authLogs = $this->collectAuthLogs(500);
        $successfulLogins = [];
        $cutoffTime = time() - ($hours * 3600);
        
        foreach ($authLogs as $log) {
            if (isset($log['type']) && $log['type'] === 'successful_login') {
                if (isset($log['timestamp']) && strtotime($log['timestamp']) > $cutoffTime) {
                    $successfulLogins[] = $log;
                }
            }
        }
        
        return $successfulLogins;
    }
    
    /**
     * Tail a file to get last N lines
     */
    private function tailFile(string $path, int $lines): array
    {
        $result = [];
        
        try {
            $output = shell_exec("tail -n {$lines} " . escapeshellarg($path) . " 2>/dev/null");
            if ($output) {
                $result = array_filter(explode("\n", $output));
            }
        } catch (\Exception $e) {
            Log::warning("Failed to tail file {$path}: " . $e->getMessage());
        }
        
        return $result;
    }
    
    /**
     * Parse authentication log lines
     */
    private function parseAuthLogs(array $lines): array
    {
        $parsed = [];
        
        foreach ($lines as $line) {
            // Ensure $line is a string (Windows Event Log may return arrays)
            if (is_array($line)) {
                $line = json_encode($line);
            }
            if (empty($line) || !is_string($line)) continue;
            
            $entry = [
                'raw' => $line,
                'timestamp' => null,
                'type' => 'unknown',
                'user' => null,
                'ip' => null,
                'service' => null,
            ];
            
            // Extract timestamp (common syslog format)
            if (preg_match('/^(\w+\s+\d+\s+\d+:\d+:\d+)/', $line, $matches)) {
                $entry['timestamp'] = $matches[1] . ' ' . date('Y');
            }
            
            // Detect failed SSH login
            if (preg_match('/Failed password for(?: invalid user)? (\S+) from (\S+)/', $line, $matches)) {
                $entry['type'] = 'failed_login';
                $entry['user'] = $matches[1];
                $entry['ip'] = $matches[2];
                $entry['service'] = 'ssh';
            }
            // Detect successful SSH login
            elseif (preg_match('/Accepted (?:password|publickey) for (\S+) from (\S+)/', $line, $matches)) {
                $entry['type'] = 'successful_login';
                $entry['user'] = $matches[1];
                $entry['ip'] = $matches[2];
                $entry['service'] = 'ssh';
            }
            // Detect sudo attempts
            elseif (preg_match('/sudo:\s+(\S+).*COMMAND=(.*)/', $line, $matches)) {
                $entry['type'] = 'sudo_command';
                $entry['user'] = $matches[1];
                $entry['command'] = $matches[2];
                $entry['service'] = 'sudo';
            }
            // Detect authentication failure
            elseif (preg_match('/authentication failure.*user=(\S+)/', $line, $matches)) {
                $entry['type'] = 'auth_failure';
                $entry['user'] = $matches[1];
            }
            
            if ($entry['type'] !== 'unknown') {
                $parsed[] = $entry;
            }
        }
        
        return $parsed;
    }
    
    /**
     * Parse netstat output
     */
    private function parseNetstatOutput(string $output): array
    {
        $connections = [];
        $lines = explode("\n", $output);
        
        foreach ($lines as $line) {
            // Skip headers and empty lines
            if (empty($line) || preg_match('/^(Proto|Active|tcp|udp)\s/i', $line) === false) {
                continue;
            }
            
            // Parse TCP/UDP connections
            if (preg_match('/^(tcp|udp)\d?\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)?/i', $line, $matches)) {
                $connections[] = [
                    'protocol' => strtolower($matches[1]),
                    'local' => $matches[2],
                    'remote' => $matches[3],
                    'state' => $matches[4] ?? 'UNKNOWN',
                ];
            }
        }
        
        return $connections;
    }
    
    /**
     * Collect Windows Event Log entries using PowerShell (Public for enhanced analysis)
     */
    public function collectWindowsEventLog(string $logName, int $count): array
    {
        $logs = [];
        
        try {
            // Build PowerShell script as a file for more reliable execution
            if ($logName === 'Security') {
                // Get specifically login/failure events to avoid noise from other security events
                // Aggressively replace newlines with spaces to ensure single-line JSON for PHP regex
                $psScript = <<<'PS'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object @{N='TimeCreated';E={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, Id, @{N='Msg';E={$_.Message.Replace("`r", " ").Replace("`n", " ").Substring(0,[Math]::Min(1000,$_.Message.Length))}}
if ($events) { $events | ConvertTo-Json -Compress } else { Write-Output '[]' }
PS;
                $psScript = sprintf($psScript, $count);
            } else {
                $psScript = sprintf(
                    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Get-WinEvent -LogName "%s" -MaxEvents %d -ErrorAction SilentlyContinue | Select-Object @{N=\'TimeCreated\';E={$_.TimeCreated.ToString(\'yyyy-MM-dd HH:mm:ss\')}}, Id, Message | ConvertTo-Json -Compress',
                    $logName,
                    $count
                );
            }
            
            // Write script to temp file
            $scriptFile = sys_get_temp_dir() . '\\get_events_' . time() . '.ps1';
            file_put_contents($scriptFile, $psScript);
            
            Log::debug("PowerShell script file: {$scriptFile}");
            
            // Execute the script file
            $psCommand = sprintf(
                'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%s"',
                $scriptFile
            );
            
            Log::debug("Executing: {$psCommand}");
            
            // Use exec for better output handling on Windows
            $output = [];
            $returnCode = 0;
            exec($psCommand . ' 2>&1', $output, $returnCode);
            
            $outputStr = implode("\n", $output);
            
            Log::debug("PowerShell return code: {$returnCode}");
            
            // Clean up temp files
            @unlink($scriptFile);
            
            if ($outputStr && strlen(trim($outputStr)) > 2 && $outputStr !== '[]') {
                $events = json_decode($outputStr, true);
                
                if (json_last_error() === JSON_ERROR_NONE && is_array($events)) {
                    // Handle single event case
                    if (isset($events['TimeCreated'])) {
                        $events = [$events];
                    }
                    
                    foreach ($events as $event) {
                        $logs[] = $this->parseWindowsEvent($event);
                    }
                }
            }
            
        } catch (\Exception $e) {
            Log::warning("Failed to collect Windows Event Log: " . $e->getMessage());
        }
        
        return $logs;
    }
    
    /**
     * Parse Windows Event into standard format
     */
    private function parseWindowsEvent(array $event): array
    {
        // Handle both 'Message' and 'Msg' field names (PowerShell alias)
        $message = $event['Message'] ?? $event['Msg'] ?? '';
        
        $entry = [
            'raw' => $message,
            'timestamp' => $event['TimeCreated'] ?? null,
            'type' => 'unknown',
            'event_id' => $event['Id'] ?? null,
            'user' => null,
            'ip' => null,
            'service' => 'windows',
        ];
        
        $eventId = $event['Id'] ?? 0;
        
        // Windows Security Event IDs
        // 4624 - Successful login
        // 4625 - Failed login
        // 4634 - Logoff
        // 4648 - Explicit credential logon
        // 4672 - Special privileges assigned
        // 4720 - User account created
        // 4726 - User account deleted
        // 5379 - Credential Manager read
        // 5058 - Key file operation
        // 5061 - Cryptographic operation
        
        switch ($eventId) {
            case 4625:
                $entry['type'] = 'failed_login';
                // More robust regex allowing for whitespace variations
                if (preg_match('/Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                if (preg_match('/Source Network Address:\s+(\S+)/i', $message, $m)) {
                    $entry['ip'] = $m[1];
                }
                break;
                
            case 4624:
                $entry['type'] = 'successful_login';
                // Pattern often appears twice (Target/Subject), we want the Target (second occurrence usually, or explicit New Logon)
                // Using a more specific pattern for New Logon to avoid capturing the machine account
                if (preg_match('/New Logon:.*?Account Name:\s+(\S+)/is', $message, $m)) {
                    $entry['user'] = $m[1];
                } elseif (preg_match('/Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                
                if (preg_match('/Source Network Address:\s+(\S+)/i', $message, $m)) {
                    $entry['ip'] = $m[1];
                }
                break;
                
            case 4634:
                $entry['type'] = 'logoff';
                break;
                
            case 4672:
                $entry['type'] = 'privilege_escalation';
                if (preg_match('/Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                break;
                
            case 4720:
                $entry['type'] = 'user_created';
                if (preg_match('/New Account:\s+Account Name:\s+(\S+)/i', $message, $m)) {
                    $entry['user'] = $m[1];
                }
                break;
                
            case 4726:
                $entry['type'] = 'user_deleted';
                break;
                
            case 5379:
                $entry['type'] = 'credential_read';
                break;
                
            case 5058:
            case 5061:
                $entry['type'] = 'crypto_operation';
                break;
                
            // System events
            case 6005:
                $entry['type'] = 'system_start';
                break;
                
            case 6006:
                $entry['type'] = 'system_shutdown';
                break;
                
            default:
                // For events we don't specifically handle, mark as security_event
                if ($eventId >= 4600 && $eventId <= 5999) {
                    $entry['type'] = 'security_event';
                }
                break;
        }
        
        return $entry;
    }
    
    /**
     * Collect macOS unified logs using log command
     */
    public function collectMacOsLogs(int $minutes = 15): array
    {
        $logs = [];
        
        if ($this->platform !== 'macos') {
            return $logs;
        }
        
        try {
            // macOS authentication/authorization events use specific subsystems
            // Try to find actual login events with targeted predicates
            $predicates = [
                // SSH daemon - captures SSH login attempts
                'process == "sshd"',
                // opendirectoryd handles user authentication
                'subsystem == "com.apple.opendirectoryd"',
                // Authorization and security events  
                'subsystem == "com.apple.authd" OR subsystem == "com.apple.Authorization"',
                // PAM authentication module
                'eventMessage CONTAINS "pam_" OR process == "pam"',
                // Login/authentication process events with specific messages
                'eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "password" OR eventMessage CONTAINS "login" OR eventMessage CONTAINS "Failed"',
                // su and sudo processes (may need root to see these)
                'process == "su" OR process == "sudo"',
            ];
            
            foreach ($predicates as $predicate) {
                // Limit output to 500KB to prevent memory exhaustion (unified log can be hundreds of MB)
                $output = shell_exec("log show --predicate '{$predicate}' --last {$minutes}m --style json 2>/dev/null | head -c 500000");
                
                if ($output && strlen($output) > 10) {
                    $events = @json_decode($output, true);
                    if (is_array($events) && !empty($events)) {
                        Log::debug("macOS unified log matched " . count($events) . " events with predicate: {$predicate}");
                        foreach (array_slice($events, 0, 100) as $event) {
                            $parsed = $this->parseMacOsEvent($event);
                            // Only add if it's a recognized authentication event
                            if ($parsed['type'] !== 'unknown') {
                                $logs[] = $parsed;
                            }
                        }
                        if (!empty($logs)) {
                            break; // Found useful events, stop trying more predicates
                        }
                    }
                }
            }
            
            // Always try to read /var/log/system.log for su/sudo events (may not be in unified log)
            Log::debug("Checking /var/log/system.log for su/sudo events");
            $output = shell_exec("sudo grep -iE '(su:|sudo:|authentication|password|login failure)' /var/log/system.log 2>/dev/null | tail -200");
            if ($output) {
                $lines = array_filter(explode("\n", $output));
                Log::debug("Found " . count($lines) . " lines in system.log");
                foreach ($lines as $line) {
                    $parsed = $this->parseMacOsLogLine($line);
                    if ($parsed['type'] !== 'unknown') {
                        $logs[] = $parsed;
                    }
                }
            }
            
            // Try ASL (Apple System Log) for older macOS
            if (empty($logs) && file_exists('/var/log/asl/')) {
                $output = shell_exec("syslog -k Facility auth -k Level le Warning 2>/dev/null | tail -100");
                if ($output) {
                    $lines = array_filter(explode("\n", $output));
                    foreach ($lines as $line) {
                        $logs[] = $this->parseMacOsLogLine($line);
                    }
                }
            }
            
        } catch (\Exception $e) {
            Log::warning("Failed to collect macOS logs: " . $e->getMessage());
        }
        
        Log::debug("Total macOS authentication logs collected: " . count($logs));
        return $logs;
    }
    
    /**
     * Parse a macOS system log line (text format)
     */
    private function parseMacOsLogLine(string $line): array
    {
        $entry = [
            'raw' => $line,
            'timestamp' => date('Y-m-d H:i:s'),
            'type' => 'unknown',
            'user' => null,
            'ip' => null,
            'service' => 'macos',
        ];
        
        // Extract timestamp if present (macOS syslog format: "Jan  9 12:34:56")
        if (preg_match('/^(\w+\s+\d+\s+\d+:\d+:\d+)/', $line, $m)) {
            $entry['timestamp'] = $m[1] . ' ' . date('Y');
        }
        
        // su failures
        if (preg_match('/su:\s*(BAD SU|FAILED SU|authentication failure)/i', $line)) {
            $entry['type'] = 'failed_login';
            $entry['service'] = 'su';
        }
        // su success
        elseif (preg_match('/su:\s*\S+\s+to\s+(\S+)/i', $line, $m)) {
            $entry['type'] = 'successful_login';
            $entry['user'] = $m[1];
            $entry['service'] = 'su';
        }
        // sudo failures
        elseif (preg_match('/sudo:\s*(\S+).*incorrect password/i', $line, $m)) {
            $entry['type'] = 'failed_login';
            $entry['user'] = $m[1];
            $entry['service'] = 'sudo';
        }
        // Authentication succeeded/failed patterns
        elseif (preg_match('/authentication\s+(succeeded|success|failed|failure)/i', $line, $m)) {
            $entry['type'] = (strtolower($m[1]) === 'succeeded' || strtolower($m[1]) === 'success') 
                ? 'successful_login' : 'failed_login';
        }
        // Login window patterns
        elseif (preg_match('/(login|password)\s+(accepted|rejected|failed|incorrect)/i', $line, $m)) {
            $entry['type'] = (strtolower($m[2]) === 'accepted') ? 'successful_login' : 'failed_login';
        }
        
        // Extract username
        if (preg_match('/user[=:\s]+["\']?(\S+?)["\']?[\s,\]$]/i', $line, $m)) {
            $entry['user'] = trim($m[1], '"\'');
        }
        return $entry;
    }    
    /**
     * Parse macOS unified log event
     */
    private function parseMacOsEvent(array $event): array
    {
        $message = $event['eventMessage'] ?? $event['message'] ?? '';
        
        $entry = [
            'raw' => $message,
            'timestamp' => $event['timestamp'] ?? $event['timeCreate'] ?? date('Y-m-d H:i:s'),
            'type' => 'unknown',
            'user' => null,
            'ip' => null,
            'service' => 'macos',
            'process' => $event['processImagePath'] ?? $event['process'] ?? null,
        ];
        
        // Detect authentication success/failure patterns (case-insensitive)
        if (preg_match('/authentication\s+(succeeded|failed|failure)/i', $message, $m)) {
            $entry['type'] = ($m[1] === 'succeeded') ? 'successful_login' : 'failed_login';
        }
        // Password checking patterns  
        elseif (preg_match('/password\s+(accepted|failed|incorrect|invalid)/i', $message, $m)) {
            $entry['type'] = ($m[1] === 'accepted') ? 'successful_login' : 'failed_login';
        }
        // Login window events
        elseif (preg_match('/(login|logon)\s+(successful|succeeded|failed|failure)/i', $message, $m)) {
            $entry['type'] = ($m[2] === 'successful' || $m[2] === 'succeeded') ? 'successful_login' : 'failed_login';
        }
        // User session events
        elseif (preg_match('/user\s+(\S+)\s+(logged in|logged out|authentication failed)/i', $message, $m)) {
            $entry['user'] = $m[1];
            $entry['type'] = str_contains($m[2], 'failed') ? 'failed_login' : 
                            (str_contains($m[2], 'logged in') ? 'successful_login' : 'logout');
        }
        // Security authorization events
        elseif (preg_match('/Authorization\s+(success|denied|allowed)/i', $message, $m)) {
            $entry['type'] = ($m[1] === 'success' || $m[1] === 'allowed') ? 'successful_login' : 'failed_login';
        }
        // SSH specific patterns
        elseif (preg_match('/sshd.*Invalid user|sshd.*Failed password|Connection closed by authenticating user/i', $message)) {
            $entry['type'] = 'failed_login';
            $entry['service'] = 'ssh';
        }
        elseif (preg_match('/sshd.*Accepted|sshd.*session opened/i', $message)) {
            $entry['type'] = 'successful_login';
            $entry['service'] = 'ssh';
        }
        // PAM failures
        elseif (preg_match('/pam_.*failure|pam_.*error|pam_unix.*authentication failure/i', $message)) {
            $entry['type'] = 'failed_login';
        }
        
        // Detect sudo commands
        if (preg_match('/sudo.*user[=:]\s*(\S+)/i', $message, $m)) {
            $entry['type'] = 'sudo_command';
            $entry['user'] = $m[1];
        }
        
        // Detect SSH connections (extract IP)
        if (preg_match('/sshd.*from\s+(\d+\.\d+\.\d+\.\d+)/i', $message, $m)) {
            $entry['ip'] = $m[1];
            $entry['service'] = 'ssh';
        }
        
        // Extract username if present
        if (!$entry['user'] && preg_match('/user[=:\s]+["\']?(\S+?)["\']?[\s,\]]/i', $message, $m)) {
            $entry['user'] = trim($m[1], '"\'');
        }
        
        return $entry;
    }
    
    /**
     * Get all authentication logs (cross-platform)
     */
    public function getAllAuthLogs(int $lines = 200): array
    {
        return match ($this->platform) {
            'windows' => $this->collectWindowsEventLog('Security', $lines),
            'macos' => $this->collectMacOsLogs(60),
            default => $this->collectAuthLogs($lines),
        };
    }
    
    /**
     * Get summary of system security status
     */
    public function getSecuritySummary(): array
    {
        $failedLogins = $this->getFailedLogins(24);
        $successfulLogins = $this->getSuccessfulLogins(24);
        $connections = $this->collectNetworkConnections();
        
        // Count external connections
        $externalConnections = array_filter($connections, function ($conn) {
            $remote = $conn['remote'] ?? '';
            return !str_starts_with($remote, '127.') && 
                   !str_starts_with($remote, '192.168.') &&
                   !str_starts_with($remote, '10.') &&
                   !str_starts_with($remote, '::1');
        });
        
        return [
            'platform' => $this->platform,
            'failed_logins_24h' => count($failedLogins),
            'successful_logins_24h' => count($successfulLogins),
            'total_connections' => count($connections),
            'external_connections' => count($externalConnections),
            'top_failed_ips' => $this->getTopFailedIps($failedLogins),
            'timestamp' => now()->toIso8601String(),
        ];
    }
    
    /**
     * Get top IPs with failed logins
     */
    private function getTopFailedIps(array $failedLogins): array
    {
        $ipCounts = [];
        
        foreach ($failedLogins as $attempt) {
            $ip = $attempt['ip'] ?? 'unknown';
            $ipCounts[$ip] = ($ipCounts[$ip] ?? 0) + 1;
        }
        
        arsort($ipCounts);
        return array_slice($ipCounts, 0, 5, true);
    }
    
    // ========================================
    // macOS Enhanced Log Collection Methods
    // ========================================
    
    /**
     * Collect macOS system logs (kernel, launchd, system events)
     */
    public function collectMacOsSystemLogs(int $minutes = 60): array
    {
        if ($this->platform !== 'macos') {
            return [];
        }
        
        $logs = [];
        
        try {
            // Use text-based parsing which is proven to work
            // JSON parsing fails due to truncation issues
            $processes = ['launchd', 'WindowServer'];
            
            foreach ($processes as $process) {
                $cmd = "log show --predicate 'process == \"{$process}\"' --last 10m 2>/dev/null | head -100";
                $output = shell_exec($cmd);
                
                if ($output && strlen($output) > 50) {
                    $lines = explode("\n", $output);
                    Log::debug("macOS system log: process '{$process}' returned " . count($lines) . " lines");
                    
                    foreach (array_slice($lines, 1, 50) as $line) { // Skip header
                        if (trim($line) && strlen($line) > 20) {
                            $logs[] = [
                                'raw' => substr($line, 0, 300),
                                'type' => 'system',
                                'category' => 'system',
                                'timestamp' => date('Y-m-d H:i:s'),
                                'process' => $process,
                                'level' => 'info',
                            ];
                        }
                    }
                    if (count($logs) >= 50) break;
                }
            }
            
            Log::debug("macOS system logs total: " . count($logs));
        } catch (\Exception $e) {
            Log::warning('Failed to collect macOS system logs: ' . $e->getMessage());
        }
        
        return array_slice($logs, 0, 100);
    }
    
    /**
     * Collect macOS application logs (crashes, errors)
     */
    public function collectMacOsAppLogs(int $minutes = 60): array
    {
        if ($this->platform !== 'macos') {
            return [];
        }
        
        $logs = [];
        
        try {
            // Application errors, faults, and crashes
            $predicates = [
                'messageType == 17', // Fault level (crashes, serious errors)
                'subsystem == "com.apple.diagnosticd"',
                'process == "ReportCrash"',
                'eventMessage CONTAINS "crash" OR eventMessage CONTAINS "exception"',
            ];
            
            foreach ($predicates as $predicate) {
                $output = shell_exec("log show --predicate '{$predicate}' --last {$minutes}m --style json 2>/dev/null | head -c 300000");
                
                if ($output && strlen($output) > 10) {
                    $events = json_decode($output, true);
                    if (is_array($events)) {
                        foreach (array_slice($events, 0, 30) as $event) {
                            $logs[] = $this->parseGenericMacOsEvent($event, 'application');
                        }
                        if (count($logs) >= 30) break;
                    }
                }
            }
            
            Log::debug("macOS app logs collected: " . count($logs));
        } catch (\Exception $e) {
            Log::warning('Failed to collect macOS app logs: ' . $e->getMessage());
        }
        
        return array_slice($logs, 0, 50);
    }
    
    /**
     * Collect macOS firewall logs (ALF / Application Level Firewall)
     */
    public function collectMacOsFirewallLogs(int $minutes = 60): array
    {
        if ($this->platform !== 'macos') {
            return [];
        }
        
        $logs = [];
        
        try {
            // Network and firewall related processes
            $processes = ['socketfilterfw', 'mDNSResponder', 'configd', 'networkd', 'nfcd', 'WiFiAgent'];
            
            foreach ($processes as $process) {
                $cmd = "log show --predicate 'process == \"{$process}\"' --last {$minutes}m --style json 2>/dev/null | head -c 200000";
                $output = shell_exec($cmd);
                
                if ($output && strlen($output) > 10) {
                    $events = @json_decode($output, true);
                    if (is_array($events) && !empty($events)) {
                        Log::debug("macOS firewall log: process '{$process}' found " . count($events) . " events");
                        foreach (array_slice($events, 0, 20) as $event) {
                            $parsed = $this->parseGenericMacOsEvent($event, 'firewall');
                            // Extract IP from messages if present
                            if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $event['eventMessage'] ?? '', $m)) {
                                $parsed['ip'] = $m[1];
                            }
                            $logs[] = $parsed;
                        }
                        if (count($logs) >= 40) break;
                    }
                }
            }
            
            // Also try appfirewall.log file if exists
            $firewallLog = '/var/log/appfirewall.log';
            if (file_exists($firewallLog) && is_readable($firewallLog)) {
                $fileContent = $this->tailFile($firewallLog, 30);
                foreach ($fileContent as $line) {
                    $logs[] = [
                        'raw' => $line['raw'] ?? (is_string($line) ? $line : ''),
                        'type' => 'firewall',
                        'category' => 'firewall',
                        'timestamp' => date('Y-m-d H:i:s'),
                        'source' => 'appfirewall.log',
                    ];
                }
            }
            
            // If still empty, try general network subsystem
            if (empty($logs)) {
                Log::debug("No firewall process logs found, trying network subsystem");
                $cmd = "log show --predicate 'subsystem CONTAINS \"network\"' --last 10m --style json 2>/dev/null | head -c 200000";
                $output = shell_exec($cmd);
                
                if ($output && strlen($output) > 10) {
                    $events = @json_decode($output, true);
                    if (is_array($events)) {
                        foreach (array_slice($events, 0, 30) as $event) {
                            $logs[] = $this->parseGenericMacOsEvent($event, 'firewall');
                        }
                    }
                }
            }
            
            Log::debug("macOS firewall logs total: " . count($logs));
        } catch (\Exception $e) {
            Log::warning('Failed to collect macOS firewall logs: ' . $e->getMessage());
        }
        
        return array_slice($logs, 0, 50);
    }
    
    /**
     * Collect macOS security audit logs (securityd, keychain, authorization)
     */
    public function collectMacOsSecurityAuditLogs(int $minutes = 60): array
    {
        if ($this->platform !== 'macos') {
            return [];
        }
        
        $logs = [];
        
        try {
            // Security-related subsystems
            $predicates = [
                'subsystem == "com.apple.securityd"',
                'subsystem == "com.apple.security"',
                'subsystem == "com.apple.ManagedClient"',
                'process == "SecurityAgent"',
                'process == "securityd"',
                'eventMessage CONTAINS "keychain" OR eventMessage CONTAINS "certificate" OR eventMessage CONTAINS "codesign"',
            ];
            
            foreach ($predicates as $predicate) {
                $output = shell_exec("log show --predicate '{$predicate}' --last {$minutes}m --style json 2>/dev/null | head -c 300000");
                
                if ($output && strlen($output) > 10) {
                    $events = json_decode($output, true);
                    if (is_array($events)) {
                        foreach (array_slice($events, 0, 30) as $event) {
                            $logs[] = $this->parseGenericMacOsEvent($event, 'security_audit');
                        }
                        if (count($logs) >= 50) break;
                    }
                }
            }
            
            Log::debug("macOS security audit logs collected: " . count($logs));
        } catch (\Exception $e) {
            Log::warning('Failed to collect macOS security audit logs: ' . $e->getMessage());
        }
        
        return array_slice($logs, 0, 50);
    }
    
    /**
     * Parse generic macOS event into standard format
     */
    private function parseGenericMacOsEvent(array $event, string $category): array
    {
        return [
            'raw' => substr($event['eventMessage'] ?? '', 0, 500),
            'type' => $category,
            'category' => $category,
            'timestamp' => $event['timestamp'] ?? date('Y-m-d H:i:s'),
            'process' => $event['processImagePath'] ?? $event['process'] ?? 'unknown',
            'subsystem' => $event['subsystem'] ?? 'unknown',
            'message_type' => $event['messageType'] ?? 'default',
            'level' => match ($event['messageType'] ?? 0) {
                16 => 'error',
                17 => 'fault',
                default => 'info',
            },
        ];
    }
    
    /**
     * Collect all macOS logs (comprehensive collection)
     */
    public function collectAllMacOsLogs(int $minutes = 60): array
    {
        if ($this->platform !== 'macos') {
            return [];
        }
        
        return [
            'auth' => $this->collectMacOsLogs($minutes),
            'system' => $this->collectMacOsSystemLogs($minutes),
            'applications' => $this->collectMacOsAppLogs($minutes),
            'firewall' => $this->collectMacOsFirewallLogs($minutes),
            'security_audit' => $this->collectMacOsSecurityAuditLogs($minutes),
        ];
    }
}

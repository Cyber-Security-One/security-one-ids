import re

content = open('app/Services/WafSyncService.php', 'r').read()

# Using basic string replacement to avoid regex issues
block1 = """<<<<<<< HEAD

                // Sanitize string strictly for log output to prevent CRLF injection
                $safeConsoleUserLog = preg_replace('/[\\r\\n]+/', ' ', $consoleUser);
                file_put_contents($logFile, "[{$timestamp}] Console user: {$safeConsoleUserLog}\\n", FILE_APPEND);

                if ($consoleUser && $consoleUser !== 'root' && $consoleUser !== '_mbsetupuser') {
                    // Escape strictly for shell command evaluation
                    $safeConsoleUser = escapeshellarg($consoleUser);

=======
                $safeConsoleUser = preg_replace('/[\\x00-\\x1F\\x7F]/u', '', str_replace(["\\r", "\\n"], ['\\\\r', '\\\\n'], $consoleUser)) ?? '';
                file_put_contents($logFile, "[{$timestamp}] Console user: {$safeConsoleUser}\\n", FILE_APPEND);

                if ($consoleUser && preg_match('/^[a-zA-Z0-9_.-]+$/', $consoleUser) && $consoleUser !== 'root' && $consoleUser !== '_mbsetupuser') {
>>>>>>> origin/main"""

replacement1 = """                $safeConsoleUserLog = preg_replace('/[\\x00-\\x1F\\x7F]/u', '', str_replace(["\\r", "\\n"], ['\\\\r', '\\\\n'], $consoleUser)) ?? '';
                file_put_contents($logFile, "[{$timestamp}] Console user: {$safeConsoleUserLog}\\n", FILE_APPEND);

                if ($consoleUser && preg_match('/^[a-zA-Z0-9_.-]+$/', $consoleUser) && $consoleUser !== 'root' && $consoleUser !== '_mbsetupuser') {
                    $safeConsoleUser = escapeshellarg($consoleUser);
"""

content = content.replace(block1, replacement1)

block2 = """<<<<<<< HEAD
                    $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                    file_put_contents($logFile, "[{$timestamp}] dscl disable user {$safeConsoleUserLog}: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);

                    if ($returnCode !== 0) {
                        // Method 2: Lock the user's password (they won't be able to login)
                        $output = [];
                        exec("sudo pwpolicy -u {$safeConsoleUser} disableuser 2>&1", $output, $returnCode);
                        $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                        file_put_contents($logFile, "[{$timestamp}] pwpolicy disable user: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);
=======
                    file_put_contents($logFile, "[{$timestamp}] dscl disable user {$safeConsoleUser}: code={$returnCode}, output=" . implode(" ", $output) . "\\n", FILE_APPEND);

                    if ($returnCode !== 0) {
                        // Method 2: Lock the user's password (they won't be able to login)
                        exec("sudo pwpolicy -u {$safeConsoleUser} disableuser 2>&1", $output, $returnCode);
                        file_put_contents($logFile, "[{$timestamp}] pwpolicy disable user: code={$returnCode}\\n", FILE_APPEND);
>>>>>>> origin/main"""

replacement2 = """                    $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                    file_put_contents($logFile, "[{$timestamp}] dscl disable user {$safeConsoleUserLog}: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);

                    if ($returnCode !== 0) {
                        // Method 2: Lock the user's password (they won't be able to login)
                        $output = [];
                        exec("sudo pwpolicy -u {$safeConsoleUser} disableuser 2>&1", $output, $returnCode);
                        $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                        file_put_contents($logFile, "[{$timestamp}] pwpolicy disable user: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);
"""

content = content.replace(block2, replacement2)

block3 = """<<<<<<< HEAD
                        $output = [];
                        exec("sudo dscl . -passwd /Users/{$safeConsoleUser} '*' 2>&1", $output, $returnCode);
                        $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                        file_put_contents($logFile, "[{$timestamp}] dscl set impossible password: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);
=======
                        exec("sudo dscl . -passwd /Users/{$safeConsoleUser} '*' 2>&1", $output, $returnCode);
                        file_put_contents($logFile, "[{$timestamp}] dscl set impossible password: code={$returnCode}\\n", FILE_APPEND);
>>>>>>> origin/main"""

replacement3 = """                        $output = [];
                        exec("sudo dscl . -passwd /Users/{$safeConsoleUser} '*' 2>&1", $output, $returnCode);
                        $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                        file_put_contents($logFile, "[{$timestamp}] dscl set impossible password: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);
"""

content = content.replace(block3, replacement3)

block4 = """<<<<<<< HEAD
                    // Sanitize strictly for log output
                    $safeUserLog = preg_replace('/[\\r\\n]+/', ' ', $user);

                    // Escape strictly for shell command evaluation
                    $safeUser = escapeshellarg($user);

                    // Remove DisabledUser from AuthenticationAuthority
                    $output = [];
                    exec("sudo dscl . -delete /Users/{$safeUser} AuthenticationAuthority 2>&1", $output, $returnCode);
                    $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                    file_put_contents($logFile, "[{$timestamp}] dscl clear auth for {$safeUserLog}: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);

                    // Re-enable with pwpolicy
                    $output = [];
                    exec("sudo pwpolicy -u {$safeUser} enableuser 2>&1", $output, $returnCode);
                    $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                    file_put_contents($logFile, "[{$timestamp}] pwpolicy enable user {$safeUserLog}: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);
=======
                    $safeUser = preg_replace('/[\\x00-\\x1F\\x7F]/u', '', str_replace(["\\r", "\\n"], ['\\\\r', '\\\\n'], $user)) ?? '';

                    // Remove DisabledUser from AuthenticationAuthority
                    exec("sudo dscl . -delete /Users/{$safeUser} AuthenticationAuthority 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] dscl clear auth for {$safeUser}: code={$returnCode}\\n", FILE_APPEND);

                    // Re-enable with pwpolicy
                    exec("sudo pwpolicy -u {$safeUser} enableuser 2>&1", $output, $returnCode);
                    file_put_contents($logFile, "[{$timestamp}] pwpolicy enable user {$safeUser}: code={$returnCode}\\n", FILE_APPEND);
>>>>>>> origin/main"""

replacement4 = """                    $safeUserLog = preg_replace('/[\\x00-\\x1F\\x7F]/u', '', str_replace(["\\r", "\\n"], ['\\\\r', '\\\\n'], $user)) ?? '';
                    $safeUser = escapeshellarg($user);

                    // Remove DisabledUser from AuthenticationAuthority
                    $output = [];
                    exec("sudo dscl . -delete /Users/{$safeUser} AuthenticationAuthority 2>&1", $output, $returnCode);
                    $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                    file_put_contents($logFile, "[{$timestamp}] dscl clear auth for {$safeUserLog}: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);

                    // Re-enable with pwpolicy
                    $output = [];
                    exec("sudo pwpolicy -u {$safeUser} enableuser 2>&1", $output, $returnCode);
                    $safeLogOutput = preg_replace('/[\\r\\n]+/', ' ', implode(" ", $output));
                    file_put_contents($logFile, "[{$timestamp}] pwpolicy enable user {$safeUserLog}: code={$returnCode}, output={$safeLogOutput}\\n", FILE_APPEND);
"""

content = content.replace(block4, replacement4)

open('app/Services/WafSyncService.php', 'w').write(content)

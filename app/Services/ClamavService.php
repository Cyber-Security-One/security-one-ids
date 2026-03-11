<?php

namespace App\Services;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Facades\Http;

class ClamavService
{
    protected bool $isInstalled = false;
    protected ?string $version = null;
    protected ?string $definitionsDate = null;

    public function __construct()
    {
        $this->checkInstallation();
    }

    /**
     * Get HTTP client with SSL configuration for Windows
     */
    protected function getHttpClient(int $timeout = 30): \Illuminate\Http\Client\PendingRequest
    {
        $http = Http::timeout($timeout)
            ->withHeaders([
                'Content-Type' => 'application/json; charset=utf-8',
                'Accept' => 'application/json',
            ]);

        // On Windows, configure SSL certificate path at runtime
        if (PHP_OS_FAMILY === 'Windows') {
            $cacertPath = $this->getCaCertPath();
            if ($cacertPath) {
                $http = $http->withOptions([
                    'verify' => $cacertPath,
                ]);
            } else {
                // No cacert.pem found — disable SSL verification as fallback
                $http = $http->withoutVerifying();
            }
        }

        return $http;
    }

    /**
     * Get CA certificate path for Windows SSL verification
     */
    protected function getCaCertPath(): ?string
    {
        // Check common locations for cacert.pem on Windows
        $possiblePaths = [];

        // Get PHP directory
        $phpBinary = PHP_BINARY;
        if ($phpBinary) {
            $phpDir = dirname($phpBinary);
            $possiblePaths[] = $phpDir . '\\cacert.pem';
            $possiblePaths[] = $phpDir . '\\extras\\ssl\\cacert.pem';
        }

        // Check common PHP installation locations
        $possiblePaths = array_merge($possiblePaths, [
            'C:\\tools\\php85\\cacert.pem',
            'C:\\tools\\php\\cacert.pem',
            'C:\\php\\cacert.pem',
            'C:\\xampp\\php\\extras\\ssl\\cacert.pem',
            'C:\\Program Files\\PHP\\cacert.pem',
            'C:\\ProgramData\\ComposerSetup\\bin\\cacert.pem',
        ]);

        foreach ($possiblePaths as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        // If not found, try to download it
        $downloadPath = sys_get_temp_dir() . '\\cacert.pem';
        if (!file_exists($downloadPath)) {
            try {
                $context = stream_context_create([
                    'ssl' => [
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                    ],
                ]);
                $cacert = @file_get_contents('https://curl.se/ca/cacert.pem', false, $context);
                if ($cacert) {
                    file_put_contents($downloadPath, $cacert);
                    return $downloadPath;
                }
            } catch (\Exception $e) {
                // Ignore
            }
        } elseif (file_exists($downloadPath)) {
            return $downloadPath;
        }

        return null;
    }

    /**
     * Translate Docker container mount paths to actual host paths
     * /mnt/host-www -> /var/www, /mnt/host-tmp -> /tmp, etc.
     */
    public function translateDockerPath(string $path): string
    {
        // Only translate if running in Docker
        if (!file_exists('/.dockerenv')) {
            return $path;
        }

        $translations = [
            '/mnt/host-www' => '/var/www',
            '/mnt/host-home' => '/home',
            '/mnt/host-opt' => '/opt',
            '/mnt/host-tmp' => '/tmp',
        ];

        foreach ($translations as $containerPath => $hostPath) {
            if (str_starts_with($path, $containerPath)) {
                return str_replace($containerPath, $hostPath, $path);
            }
        }

        return $path;
    }

    /**
     * Check if ClamAV is installed
     */
    public function checkInstallation(): bool
    {
        $platform = $this->getPlatform();

        try {
            if ($platform === 'macos') {
                // Check common Homebrew paths for clamscan
                $paths = [
                    '/opt/homebrew/bin/clamscan',
                    '/usr/local/bin/clamscan',
                    '/usr/bin/clamscan',
                ];

                foreach ($paths as $path) {
                    if (file_exists($path)) {
                        $this->isInstalled = true;
                        $this->getVersion();
                        return true;
                    }
                }

                // Also try which command with Homebrew PATH
                $result = Process::run('export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" && which clamscan');
                $this->isInstalled = $result->successful() && !empty(trim($result->output()));
            } elseif ($platform === 'windows') {
                // Check Windows ClamAV paths
                $paths = [
                    'C:\\Program Files\\ClamAV\\clamscan.exe',
                    'C:\\Program Files (x86)\\ClamAV\\clamscan.exe',
                    'C:\\ProgramData\\chocolatey\\bin\\clamscan.exe',
                ];

                foreach ($paths as $path) {
                    if (file_exists($path)) {
                        $this->isInstalled = true;
                        $this->getVersion();
                        return true;
                    }
                }

                // Also try where command on Windows
                $result = Process::run('powershell -Command "Get-Command clamscan -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source"');
                $this->isInstalled = $result->successful() && !empty(trim($result->output()));
            } else {
                $result = Process::run('which clamscan 2>/dev/null || command -v clamscan 2>/dev/null');
                $this->isInstalled = $result->successful() && !empty(trim($result->output()));
            }

            if ($this->isInstalled) {
                $this->getVersion();
            }

            return $this->isInstalled;
        } catch (\Exception $e) {
            Log::error('ClamAV check failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get ClamAV version
     */
    public function getVersion(): ?string
    {
        if ($this->version) {
            return $this->version;
        }

        try {
            // Use full PATH for macOS Homebrew compatibility
            $cmd = $this->getPlatform() === 'macos'
                ? 'export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" && clamscan --version'
                : 'clamscan --version';

            $result = Process::run($cmd);
            if ($result->successful()) {
                $output = trim($result->output());
                // Extract version: "ClamAV 0.103.6/26589/Wed Jul  3 07:32:13 2024"
                if (preg_match('/ClamAV\s+([\d.]+)/', $output, $matches)) {
                    $this->version = $matches[1];
                } else {
                    $this->version = $output;
                }
            }
        } catch (\Exception $e) {
            Log::error('Failed to get ClamAV version: ' . $e->getMessage());
        }

        return $this->version;
    }

    /**
     * Get virus definitions date
     */
    public function getDefinitionsDate(): ?string
    {
        try {
            $result = Process::run('clamscan --version');
            if ($result->successful()) {
                $output = trim($result->output());
                // Extract date from: "ClamAV 0.103.6/26589/Wed Jul  3 07:32:13 2024"
                if (preg_match('/\/(\d+)\/(.+)$/', $output, $matches)) {
                    $this->definitionsDate = $matches[2];
                    return $this->definitionsDate;
                }
            }
        } catch (\Exception $e) {
            Log::error('Failed to get definitions date: ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Install ClamAV (platform-specific)
     */
    public function install(): array
    {
        $platform = $this->getPlatform();

        Log::info('Installing ClamAV on ' . $platform);

        try {
            switch ($platform) {
                case 'macos':
                    return $this->installMacos();
                case 'windows':
                    return $this->installWindows();
                case 'alpine':
                    return $this->installAlpine();
                case 'linux':
                case 'ubuntu':
                case 'debian':
                    return $this->installDebian();
                case 'rhel':
                case 'centos':
                case 'fedora':
                    return $this->installRhel();
                default:
                    return [
                        'success' => false,
                        'message' => "Unsupported platform: {$platform}",
                    ];
            }
        } catch (\Exception $e) {
            Log::error('ClamAV installation failed: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Install on macOS using Homebrew
     */
    protected function installMacos(): array
    {
        // Check if Homebrew is installed
        $brewCheck = Process::run('which brew');
        if (!$brewCheck->successful()) {
            return [
                'success' => false,
                'message' => 'Homebrew not installed. Please install Homebrew first.',
            ];
        }

        // Install ClamAV
        $result = Process::timeout(300)->run('brew install clamav');

        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        // Initialize freshclam configuration
        $this->initializeFreshclam();

        // Update virus definitions
        $this->updateDefinitions();

        $this->isInstalled = true;

        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on macOS',
        ];
    }

    /**
     * Install on Debian/Ubuntu
     *
     * Handles broken third-party PPAs (e.g. Suricata PPA on unsupported
     * Ubuntu releases) by temporarily disabling them before apt-get update.
     */
    protected function installDebian(): array
    {
        // Temporarily disable any broken third-party PPAs that may cause
        // apt-get update to fail (e.g. Suricata PPA on unsupported Ubuntu versions).
        // We rename .list files in sources.list.d so apt ignores them during update.
        $disabledPpas = [];
        $sourcesDir = '/etc/apt/sources.list.d';

        if (is_dir($sourcesDir)) {
            $listFiles = glob("{$sourcesDir}/*.list");
            foreach ($listFiles as $listFile) {
                // Skip the main Ubuntu sources
                $basename = basename($listFile);
                if ($basename === 'ubuntu.list') {
                    continue;
                }

                // Check if this PPA actually works before disabling
                $content = @file_get_contents($listFile);
                if ($content === false) {
                    continue;
                }

                // Temporarily disable all third-party PPAs to avoid update failures
                $disabledPath = $listFile . '.disabled-for-clamav';
                if (@rename($listFile, $disabledPath)) {
                    $disabledPpas[] = ['original' => $listFile, 'disabled' => $disabledPath];
                    Log::info("[ClamAV Install] Temporarily disabled PPA: {$basename}");
                }
            }

            // Also handle .sources files (DEB822 format used by newer Ubuntu)
            $sourcesFiles = glob("{$sourcesDir}/*.sources");
            foreach ($sourcesFiles as $sourcesFile) {
                $basename = basename($sourcesFile);
                // Skip official Ubuntu sources
                if (str_starts_with($basename, 'ubuntu')) {
                    continue;
                }

                $disabledPath = $sourcesFile . '.disabled-for-clamav';
                if (@rename($sourcesFile, $disabledPath)) {
                    $disabledPpas[] = ['original' => $sourcesFile, 'disabled' => $disabledPath];
                    Log::info("[ClamAV Install] Temporarily disabled source: {$basename}");
                }
            }
        }

        try {
            $result = Process::timeout(300)->run('sudo apt-get update && sudo apt-get install -y clamav clamav-daemon');

            if (!$result->successful()) {
                return [
                    'success' => false,
                    'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
                ];
            }

            // Update virus definitions
            Process::run('sudo systemctl stop clamav-freshclam');
            $this->updateDefinitions();
            Process::run('sudo systemctl start clamav-freshclam');

            $this->isInstalled = true;

            return [
                'success' => true,
                'message' => 'ClamAV installed successfully on Debian/Ubuntu',
            ];
        } finally {
            // Always re-enable PPAs, even if installation failed
            foreach ($disabledPpas as $ppa) {
                if (file_exists($ppa['disabled'])) {
                    @rename($ppa['disabled'], $ppa['original']);
                    Log::info("[ClamAV Install] Re-enabled PPA: " . basename($ppa['original']));
                }
            }
        }
    }

    /**
     * Install on Alpine Linux (Docker)
     */
    protected function installAlpine(): array
    {
        // Alpine uses apk package manager
        $result = Process::timeout(300)->run('apk add --no-cache clamav clamav-libunrar');

        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        // Create database directory and update definitions
        Process::run('mkdir -p /var/lib/clamav');
        $this->updateDefinitions();

        $this->isInstalled = true;

        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on Alpine Linux',
        ];
    }

    /**
     * Install on RHEL/CentOS/Fedora
     */
    protected function installRhel(): array
    {
        // Try dnf first, fallback to yum
        $dnfCheck = Process::run('which dnf');
        $pm = $dnfCheck->successful() ? 'dnf' : 'yum';

        $result = Process::timeout(300)->run("sudo {$pm} install -y clamav clamav-update clamd");

        if (!$result->successful()) {
            return [
                'success' => false,
                'message' => 'Failed to install ClamAV: ' . $result->errorOutput(),
            ];
        }

        $this->updateDefinitions();
        $this->isInstalled = true;

        return [
            'success' => true,
            'message' => 'ClamAV installed successfully on RHEL/CentOS',
        ];
    }

    /**
     * Install on Windows using winget or chocolatey
     */
    protected function installWindows(): array
    {
        Log::info('Installing ClamAV on Windows');

        // First, check if ClamAV is already installed
        $checkPaths = [
            'C:\\Program Files\\ClamAV\\clamscan.exe',
            'C:\\Program Files (x86)\\ClamAV\\clamscan.exe',
            'C:\\ProgramData\\chocolatey\\bin\\clamscan.exe',
        ];

        foreach ($checkPaths as $checkPath) {
            if (file_exists($checkPath)) {
                $this->isInstalled = true;
                return [
                    'success' => true,
                    'message' => 'ClamAV is already installed on Windows',
                ];
            }
        }

        // Try winget first (Windows 10/11)
        $wingetCheck = Process::run('powershell -Command "Get-Command winget -ErrorAction SilentlyContinue"');
        if ($wingetCheck->successful() && !empty(trim($wingetCheck->output()))) {
            Log::info('Installing ClamAV via winget');
            $result = Process::timeout(600)->run('powershell -Command "winget install -e --id CLAMAV.ClamAV --accept-package-agreements --accept-source-agreements"');

            if ($result->successful()) {
                $this->isInstalled = true;
                $this->initializeFreshclamWindows();
                return [
                    'success' => true,
                    'message' => 'ClamAV installed successfully via winget',
                ];
            }
            Log::warning('winget installation failed, trying chocolatey: ' . $result->errorOutput());
        }

        // Try chocolatey
        $chocoPath = 'C:\\ProgramData\\chocolatey\\bin\\choco.exe';
        $hasChocolatey = file_exists($chocoPath);

        // Also check via command if path check fails
        if (!$hasChocolatey) {
            $chocoCheck = Process::run('powershell -Command "Get-Command choco -ErrorAction SilentlyContinue"');
            $hasChocolatey = $chocoCheck->successful() && !empty(trim($chocoCheck->output()));
        }

        // If chocolatey not installed, install it first
        if (!$hasChocolatey) {
            Log::info('Chocolatey not found, installing...');
            $installResult = $this->installChocolatey();

            if (!$installResult['success']) {
                return $installResult;
            }
            // After installation, chocolatey should be at this path
            $chocoPath = 'C:\\ProgramData\\chocolatey\\bin\\choco.exe';
            $hasChocolatey = file_exists($chocoPath);
        }

        // Now install ClamAV via chocolatey using full path
        if ($hasChocolatey) {
            Log::info('Installing ClamAV via chocolatey', ['choco_path' => $chocoPath]);

            // Use full path to choco.exe since PATH may not be updated in current process
            $chocoCmd = file_exists($chocoPath) 
                ? "& '{$chocoPath}' install clamav -y"
                : 'choco install clamav -y';

            $result = Process::timeout(600)->run("powershell -Command \"{$chocoCmd}\"");

            if ($result->successful()) {
                $this->isInstalled = true;
                $this->initializeFreshclamWindows();
                return [
                    'success' => true,
                    'message' => 'ClamAV installed successfully via chocolatey',
                ];
            }
            Log::warning('chocolatey ClamAV installation failed: ' . $result->errorOutput());
        }

        // Final fallback - provide manual installation guidance
        return [
            'success' => false,
            'message' => 'Unable to install ClamAV automatically. Please download ClamAV manually from https://www.clamav.net/downloads',
        ];
    }

    /**
     * Install Chocolatey package manager on Windows
     */
    protected function installChocolatey(): array
    {
        Log::info('Installing Chocolatey package manager...');

        try {
            // The official chocolatey installation command
            $installCmd = 'powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; ' .
                '[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; ' .
                "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))\"";

            $result = Process::timeout(300)->run($installCmd);

            if ($result->successful()) {
                Log::info('Chocolatey installed successfully');

                // Refresh environment to pick up choco
                Process::run('powershell -Command "refreshenv"');

                return [
                    'success' => true,
                    'message' => 'Chocolatey installed successfully',
                ];
            }

            Log::error('Chocolatey installation failed: ' . $result->errorOutput());
            return [
                'success' => false,
                'message' => 'Failed to install Chocolatey: ' . $result->errorOutput(),
            ];
        } catch (\Exception $e) {
            Log::error('Chocolatey installation exception: ' . $e->getMessage());
            return [
                'success' => false,
                'message' => 'Chocolatey installation failed: ' . $e->getMessage(),
            ];
        }
    }

    /**
     * Initialize freshclam configuration on Windows
     */
    protected function initializeFreshclamWindows(): void
    {
        Log::info('Initializing freshclam on Windows...');

        // Find ClamAV installation directory (different for Chocolatey vs MSI)
        $possiblePaths = [
            'C:\\Program Files\\ClamAV',
        ];

        // Check Chocolatey versioned paths
        $chocoGlob = glob('C:\\ProgramData\\chocolatey\\lib\\clamav\\tools\\clamav-*');
        if (!empty($chocoGlob)) {
            foreach ($chocoGlob as $p) {
                if (is_dir($p)) {
                    $possiblePaths[] = $p;
                }
            }
        }

        $clamavDir = null;
        $freshclamPath = null;

        foreach ($possiblePaths as $path) {
            if (is_dir($path) && file_exists("{$path}\\freshclam.exe")) {
                $clamavDir = $path;
                $freshclamPath = "{$path}\\freshclam.exe";
                break;
            }
        }

        if (!$clamavDir) {
            Log::warning('Could not find ClamAV installation directory');
            return;
        }

        Log::info('Found ClamAV directory', ['path' => $clamavDir]);

        $confPath = "{$clamavDir}\\freshclam.conf";
        $samplePath = "{$clamavDir}\\freshclam.conf.sample";

        // Create or fix config file
        if (!file_exists($confPath)) {
            if (file_exists($samplePath)) {
                copy($samplePath, $confPath);
                Log::info('Copied freshclam.conf from sample');
            } else {
                // Create minimal config
                $dbDir = "{$clamavDir}\\database";
                if (!is_dir($dbDir)) {
                    @mkdir($dbDir, 0755, true);
                }

                $config = "DatabaseMirror database.clamav.net\nDatabaseDirectory {$dbDir}\n";
                file_put_contents($confPath, $config);
                Log::info('Created minimal freshclam.conf');
            }
        }

        // Comment out Example line
        if (file_exists($confPath)) {
            $content = file_get_contents($confPath);
            if (preg_match('/^Example\s*$/m', $content)) {
                $content = preg_replace('/^Example\s*$/m', '#Example', $content);
                file_put_contents($confPath, $content);
            }
        }

        // Run freshclam with explicit config
        Log::info('Downloading initial virus definitions...');
        $result = Process::timeout(600)->run("powershell -Command \"& '{$freshclamPath}' --config-file='{$confPath}'\"");
        if ($result->successful()) {
            Log::info('Initial virus definitions downloaded');
        } else {
            Log::warning('freshclam failed', ['error' => $result->errorOutput()]);
        }
    }

    /**
     * Initialize freshclam configuration
     */
    protected function initializeFreshclam(): void
    {
        $platform = $this->getPlatform();

        if ($platform === 'macos') {
            // Create freshclam.conf from sample if not exists
            $confPath = '/opt/homebrew/etc/clamav/freshclam.conf';
            $samplePath = '/opt/homebrew/etc/clamav/freshclam.conf.sample';

            if (!file_exists($confPath) && file_exists($samplePath)) {
                Process::run("cp {$samplePath} {$confPath}");
                // Comment out Example line
                Process::run("sed -i '' 's/^Example/#Example/' {$confPath}");
            }
        }
    }

    /**
     * Update virus definitions
     */
    public function updateDefinitions(): array
    {
        Log::info('Updating ClamAV virus definitions');

        try {
            $platform = $this->getPlatform();

            if ($platform === 'windows') {
                // Windows: find freshclam and its config file
                $possibleDirs = [
                    'C:\\Program Files\\ClamAV',
                ];

                // Check Chocolatey versioned paths
                $chocoGlob = glob('C:\\ProgramData\\chocolatey\\lib\\clamav\\tools\\clamav-*');
                if (!empty($chocoGlob)) {
                    foreach ($chocoGlob as $p) {
                        if (is_dir($p)) {
                            $possibleDirs[] = $p;
                        }
                    }
                }

                $clamavDir = null;
                $freshclamPath = null;

                foreach ($possibleDirs as $dir) {
                    if (is_dir($dir) && file_exists("{$dir}\\freshclam.exe")) {
                        $clamavDir = $dir;
                        $freshclamPath = "{$dir}\\freshclam.exe";
                        break;
                    }
                }

                // Fallback to bin path
                if (!$freshclamPath && file_exists('C:\\ProgramData\\chocolatey\\bin\\freshclam.exe')) {
                    $freshclamPath = 'C:\\ProgramData\\chocolatey\\bin\\freshclam.exe';
                    // Try to find the actual directory for config
                    if (!empty($chocoGlob)) {
                        $clamavDir = $chocoGlob[0];
                    }
                }

                if (!$freshclamPath) {
                    return [
                        'success' => false,
                        'message' => 'freshclam.exe not found on Windows',
                    ];
                }

                Log::info('Found freshclam', ['path' => $freshclamPath, 'dir' => $clamavDir]);

                // Ensure config file exists
                $confPath = $clamavDir ? "{$clamavDir}\\freshclam.conf" : null;

                if ($clamavDir && !file_exists($confPath)) {
                    $samplePath = "{$clamavDir}\\freshclam.conf.sample";
                    if (file_exists($samplePath)) {
                        copy($samplePath, $confPath);
                        // Comment out Example line
                        $content = file_get_contents($confPath);
                        $content = preg_replace('/^Example\s*$/m', '#Example', $content);
                        file_put_contents($confPath, $content);
                        Log::info('Created freshclam.conf from sample');
                    } else {
                        // Create minimal config
                        $dbDir = "{$clamavDir}\\database";
                        if (!is_dir($dbDir)) {
                            @mkdir($dbDir, 0755, true);
                        }
                        $config = "DatabaseMirror database.clamav.net\r\nDatabaseDirectory {$dbDir}\r\n";
                        file_put_contents($confPath, $config);
                        Log::info('Created minimal freshclam.conf');
                    }
                }

                // Run freshclam with explicit config if available
                if ($confPath && file_exists($confPath)) {
                    $result = Process::timeout(600)->run("powershell -Command \"& '{$freshclamPath}' --config-file='{$confPath}'\"");
                } else {
                    $result = Process::timeout(600)->run("powershell -Command \"& '{$freshclamPath}'\"");
                }
            } elseif ($platform === 'macos') {
                // macOS: Fix permissions and run freshclam

                $freshclamPath = '/opt/homebrew/bin/freshclam';
                if (!file_exists($freshclamPath)) {
                    $freshclamPath = '/usr/local/bin/freshclam';
                }

                if (!file_exists($freshclamPath)) {
                    return [
                        'success' => false,
                        'message' => 'freshclam not found. Please install ClamAV: brew install clamav',
                    ];
                }

                // Fix permissions on ClamAV database directory first
                $clamavDir = '/opt/homebrew/var/lib/clamav';
                if (!is_dir($clamavDir)) {
                    $clamavDir = '/usr/local/var/lib/clamav';
                }

                if (is_dir($clamavDir)) {
                    // Make directory writable by current process (running as root via launchd)
                    Log::info('Fixing ClamAV directory permissions', ['dir' => $clamavDir]);
                    Process::run("chmod -R 777 {$clamavDir}");
                } else {
                    // Create directory if it doesn't exist
                    @mkdir($clamavDir, 0777, true);
                }

                Log::info('Running freshclam', ['path' => $freshclamPath]);
                $result = Process::timeout(600)->run($freshclamPath);

                if (!$result->successful()) {
                    $errorOutput = $result->errorOutput() ?: $result->output();
                    Log::warning('freshclam failed', ['error' => $errorOutput]);
                }
            } else {
                // Use freshclam without sudo in Docker, with sudo on native Linux
                $cmd = file_exists('/.dockerenv') ? 'freshclam' : 'sudo freshclam';
                $result = Process::timeout(600)->run($cmd);
            }

            if ($result->successful()) {
                // Refresh definitions date after update
                $this->definitionsDate = null;  // Clear cache
                $newDefDate = $this->getDefinitionsDate();

                Log::info('ClamAV definitions updated', ['new_date' => $newDefDate]);

                return [
                    'success' => true,
                    'message' => 'Virus definitions updated successfully',
                    'definitions_date' => $newDefDate,
                ];
            }

            return [
                'success' => false,
                'message' => 'Failed to update definitions: ' . $result->errorOutput(),
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Scan a directory
     */
    public function scan(string $path = '/'): array
    {
        if (!$this->isInstalled) {
            return [
                'success' => false,
                'status' => 'not_installed',
                'message' => 'ClamAV is not installed',
            ];
        }

        Log::info('Starting ClamAV scan on: ' . $path);

        try {
            $platform = $this->getPlatform();
            $output = '';
            $returnCode = 0;

            if ($platform === 'windows') {
                // Windows: find clamscan.exe and run with PowerShell
                $clamscanPaths = [
                    'C:\\Program Files\\ClamAV\\clamscan.exe',
                    'C:\\Program Files (x86)\\ClamAV\\clamscan.exe',
                    'C:\\ProgramData\\chocolatey\\bin\\clamscan.exe',
                ];

                $clamscanPath = null;
                foreach ($clamscanPaths as $exePath) {
                    if (file_exists($exePath)) {
                        $clamscanPath = $exePath;
                        break;
                    }
                }

                if (!$clamscanPath) {
                    return [
                        'success' => false,
                        'status' => 'not_installed',
                        'message' => 'clamscan.exe not found on Windows',
                    ];
                }

                // Windows path escaping
                $escapedPath = str_replace('/', '\\', $path);
                $scanCmd = "powershell -Command \"& '{$clamscanPath}' -r '{$escapedPath}' 2>&1\"";

                Log::info('Executing Windows clamscan command', ['command' => $scanCmd]);
                exec($scanCmd, $outputLines, $returnCode);
                $output = implode("\n", $outputLines);
            } else {
                // Unix: Build command with proper PATH for macOS Homebrew
                $pathPrefix = $platform === 'macos' 
                    ? 'export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" && '
                    : '';

                // Run clamscan with recursive option and get summary
                $scanCmd = "{$pathPrefix}clamscan -r {$path} 2>&1";

                Log::info('Executing clamscan command', ['command' => $scanCmd]);
                exec($scanCmd, $outputLines, $returnCode);
                $output = implode("\n", $outputLines);
            }

            Log::info('Clamscan execution completed', [
                'return_code' => $returnCode,
                'output_length' => strlen($output),
                'output_preview' => substr($output, -500), // Last 500 chars (includes summary)
            ]);

            // clamscan returns 0 for clean, 1 for infected found, 2 for error
            if ($returnCode > 1) {
                Log::warning('ClamAV scan command returned error', [
                    'exit_code' => $returnCode,
                    'error_output' => substr($output, 0, 500),
                ]);
            }
            $infected = [];
            $scannedFiles = 0;
            $infectedCount = 0;
            $scanErrors = 0;
            $okCount = 0;

            // Parse output for infected files
            $lines = explode("\n", trim($output));
            foreach ($lines as $line) {
                if (str_contains($line, ' FOUND')) {
                    $infected[] = trim(str_replace(' FOUND', '', $line));
                }
                // Count OK lines as fallback for scanned files
                if (str_ends_with(trim($line), ': OK') || str_ends_with(trim($line), 'OK')) {
                    $okCount++;
                }
                // Look for scan summary in output (handles multiple formats)
                if (preg_match('/Scanned files:\s*(\d+)/i', $line, $matches)) {
                    $scannedFiles = (int) $matches[1];
                }
                if (preg_match('/Scanned\s+(?:files|directories):\s*(\d+)/i', $line, $matches)) {
                    $scannedFiles = max($scannedFiles, (int) $matches[1]);
                }
                if (preg_match('/Infected files:\s*(\d+)/i', $line, $matches)) {
                    $infectedCount = (int) $matches[1];
                }
                // Parse Total errors count
                if (preg_match('/Total errors:\s*(\d+)/i', $line, $matches)) {
                    $scanErrors = (int) $matches[1];
                }
            }

            // Fallback: if summary parsing found 0 but we counted files with OK/FOUND
            if ($scannedFiles === 0 && ($okCount > 0 || count($infected) > 0)) {
                $scannedFiles = $okCount + count($infected);
                Log::info('ClamAV: using line-count fallback for scanned_files', [
                    'ok_count' => $okCount,
                    'found_count' => count($infected),
                ]);
            }

            Log::info('ClamAV scan completed', [
                'path' => $path,
                'scanned_files' => $scannedFiles,
                'infected_files' => max(count($infected), $infectedCount),
                'scan_errors' => $scanErrors,
            ]);

            // Translate Docker container paths to host paths for display
            $translatedThreats = array_map(
                fn($threat) => $this->translateDockerPath($threat),
                $infected
            );

            return [
                'success' => true,
                'status' => count($infected) > 0 ? 'warning' : 'healthy',
                'scanned_files' => $scannedFiles,
                'infected_files' => max(count($infected), $infectedCount),
                'scan_errors' => $scanErrors,
                'threats' => $translatedThreats,
            ];
        } catch (\Exception $e) {
            Log::error('ClamAV scan failed: ' . $e->getMessage());
            return [
                'success' => false,
                'status' => 'error',
                'message' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get current status
     */
    public function getStatus(): array
    {
        return [
            'installed' => $this->isInstalled,
            'version' => $this->getVersion(),
            'definitions_date' => $this->getDefinitionsDate(),
            'status' => $this->isInstalled ? 'healthy' : 'not_installed',
        ];
    }

    /**
     * Report status to WAF Hub
     */
    public function reportToHub(array $scanResult = []): bool
    {
        try {
            $wafUrl = rtrim(config('ids.waf_url') ?? env('WAF_URL', ''), '/');

            // Use the same token resolution as WafSyncService:
            // 1. Cached token from registration (most reliable)
            // 2. .env AGENT_TOKEN
            // 3. Direct .env file read as last resort
            $token = cache()->get('waf_agent_token');

            if (empty($token)) {
                $token = env('AGENT_TOKEN', '');
            }

            // Also try reading .env file directly if env() doesn't work
            if (empty($token)) {
                $envPath = base_path('.env');
                if (file_exists($envPath)) {
                    $envContent = file_get_contents($envPath);
                    if (preg_match('/^AGENT_TOKEN=(.*)$/m', $envContent, $matches)) {
                        $token = trim($matches[1], '"\'');
                    }
                }
            }

            Log::info('ClamAV reportToHub: attempting to report status', [
                'waf_url' => $wafUrl,
                'has_token' => !empty($token),
            ]);

            if (empty($wafUrl) || empty($token)) {
                Log::warning('Cannot report ClamAV status: WAF not configured', [
                    'waf_url_empty' => empty($wafUrl),
                    'token_empty' => empty($token),
                ]);
                return false;
            }

            $status = $this->getStatus();

            $payload = [
                'version' => $status['version'],
                'definitions_date' => $this->parseDefinitionsDate($status['definitions_date']),
                'status' => $scanResult['status'] ?? $status['status'],
                'scan_progress' => $scanResult['scan_progress'] ?? null,
                'error_message' => $scanResult['message'] ?? null,
            ];

            // Only include scan results if they have actual data (not heartbeat defaults)
            // This prevents resetting existing counts in WAF Hub
            if (isset($scanResult['last_scan']) || 
                (isset($scanResult['scanned_files']) && $scanResult['scanned_files'] > 0) ||
                (isset($scanResult['infected_files']) && $scanResult['infected_files'] > 0)) {
                $payload['last_scan'] = $scanResult['last_scan'] ?? now()->toDateTimeString();
                $payload['infected_files'] = $scanResult['infected_files'] ?? 0;
                $payload['scanned_files'] = $scanResult['scanned_files'] ?? 0;
                $payload['threats'] = $scanResult['threats'] ?? [];
            }

            // ALWAYS send real scan_status - detect if clamscan is running
            // This replaces the old skip_scan_status logic which was unreliable
            if (isset($scanResult['scan_status'])) {
                // Explicit status from RunScan - use it
                $payload['scan_status'] = $scanResult['scan_status'];
            } else {
                // Heartbeat - detect actual status and directory from clamscan process
                $scanProgress = $this->getScanProgress();
                $isScanning = $scanProgress !== null;
                $payload['scan_status'] = $isScanning ? 'scanning' : 'idle';

                // Use actual scan progress from ps command (shows current directory)
                if ($isScanning && empty($payload['scan_progress'])) {
                    $payload['scan_progress'] = $scanProgress;
                }
            }

            // Log full payload for debugging
            Log::info('ClamAV reportToHub: sending payload', [
                'scanned_files' => $payload['scanned_files'] ?? null,
                'infected_files' => $payload['infected_files'] ?? null,
                'last_scan' => $payload['last_scan'] ?? null,
                'scan_status' => $payload['scan_status'] ?? null,
                'scan_progress' => $payload['scan_progress'] ?? null,
            ]);

            $response = $this->getHttpClient(30)
                ->withToken($token)
                ->post("{$wafUrl}/api/ids/agents/clamav-status", $payload);

            if ($response->successful()) {
                Log::info('ClamAV status reported successfully', [
                    'scanned_files' => $payload['scanned_files'] ?? 'NOT_IN_PAYLOAD',
                    'infected_files' => $payload['infected_files'] ?? 'NOT_IN_PAYLOAD',
                    'last_scan' => $payload['last_scan'] ?? 'NOT_IN_PAYLOAD',
                ]);
                return true;
            }

            $errBody = substr($response->body(), 0, 500);
            Log::error('ClamAV reportToHub failed', [
                'status' => $response->status(),
                'body' => $errBody,
                'scanned_files' => $payload['scanned_files'] ?? 'NOT_IN_PAYLOAD',
            ]);
            // Report failure as agent event so it shows in hub
            try {
                app(\App\Services\WafSyncService::class)->reportAgentEvent(
                    '系統日誌',
                    "ClamAV reportToHub failed: HTTP {$response->status()} — {$errBody}"
                );
            } catch (\Exception $ignore) {
            }
            return false;
        } catch (\Exception $e) {
            Log::error('Failed to report ClamAV status: ' . $e->getMessage());
            // Report exception as agent event
            try {
                app(\App\Services\WafSyncService::class)->reportAgentEvent(
                    '系統日誌',
                    "ClamAV reportToHub exception: {$e->getMessage()}"
                );
            } catch (\Exception $ignore) {
            }
            return false;
        }
    }

    /**
     * Parse definitions date string to date format
     */
    protected function parseDefinitionsDate(?string $dateStr): ?string
    {
        if (!$dateStr) {
            return null;
        }

        try {
            $date = new \DateTime($dateStr);
            return $date->format('Y-m-d');
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Detect platform
     */
    protected function getPlatform(): string
    {
        if (stripos(PHP_OS, 'Darwin') !== false) {
            return 'macos';
        }

        // Windows detection
        if (stripos(PHP_OS, 'WIN') === 0 || stripos(PHP_OS_FAMILY, 'Windows') !== false) {
            return 'windows';
        }

        if (stripos(PHP_OS, 'Linux') !== false) {
            // Detect Linux distribution
            // Check Alpine first (Docker containers typically use Alpine)
            if (file_exists('/etc/alpine-release')) {
                return 'alpine';
            }
            if (file_exists('/etc/debian_version')) {
                return 'debian';
            }
            if (file_exists('/etc/redhat-release')) {
                return 'rhel';
            }
            return 'linux';
        }

        return 'unknown';
    }

    /**
     * Check if ClamAV is installed
     */
    public function isInstalled(): bool
    {
        return $this->isInstalled;
    }

    /**
     * Check if a clamscan process is currently running
     * This is used to detect real-time scan status
     */
    public function isScanRunning(): bool
    {
        return $this->getScanProgress() !== null;
    }

    /**
     * Get current scan progress by checking clamscan process
     * Returns the directory being scanned, or null if not scanning
     */
    public function getScanProgress(): ?string
    {
        try {
            // First check if there's a cached progress from RunScan
            $cacheFile = storage_path('app/scan_progress.txt');
            if (file_exists($cacheFile)) {
                $cachedTime = filemtime($cacheFile);
                // Use cache if it's less than 5 minutes old (300 seconds)
                if (time() - $cachedTime < 300) {
                    $progress = trim(file_get_contents($cacheFile));
                    if (!empty($progress)) {
                        return $progress;
                    }
                }
            }

            // Fallback to checking ps for clamscan process
            if (PHP_OS_FAMILY === 'Windows') {
                // Windows: Use PowerShell to check for clamscan process
                $result = Process::run('powershell -Command "Get-Process clamscan -ErrorAction SilentlyContinue | Select-Object -First 1 | Format-List Id,ProcessName"');
            } elseif (PHP_OS_FAMILY === 'Darwin') {
                $result = Process::run('ps aux | grep -v grep | grep "clamscan -r"');
            } else {
                $result = Process::run('ps aux | grep -v grep | grep "clamscan"');
            }

            if ($result->successful() && !empty(trim($result->output()))) {
                $output = trim($result->output());
                $currentPath = null;

                // Windows: Get-Process doesn't show command line, so we rely on cache file
                // Just detecting the process is running is enough
                if (PHP_OS_FAMILY === 'Windows') {
                    // Process is running, use cache file for progress
                    if (file_exists($cacheFile)) {
                        $progress = trim(file_get_contents($cacheFile));
                        if (!empty($progress)) {
                            return $progress;
                        }
                    }
                    // Process running but no cache - still indicate scanning
                    return "掃描中...";
                }

                // Unix: Parse command line to extract directory
                if (preg_match('/clamscan\s+(?:-\w+\s+)*-r\s+(\S+)/', $output, $matches)) {
                    $currentPath = $matches[1];
                } elseif (preg_match('/clamscan\s+(?:-\w+\s+)*(\S+)/', $output, $matches)) {
                    $currentPath = $matches[1];
                }

                if ($currentPath) {
                    $displayPath = $this->translateDockerPath($currentPath);

                    // Try to get index from scan paths cache
                    $pathsFile = storage_path('app/scan_paths.json');
                    if (file_exists($pathsFile)) {
                        $pathsData = json_decode(file_get_contents($pathsFile), true);
                        $scanPaths = $pathsData['paths'] ?? [];
                        $total = count($scanPaths);

                        // Find current path index
                        $index = array_search($currentPath, $scanPaths);
                        if ($index !== false) {
                            $index++; // Convert to 1-based index
                            return "掃描中: {$displayPath} ({$index}/{$total})";
                        }
                    }

                    return "掃描中: " . $displayPath;
                }

                return "掃描中...";
            }

            // No scan running - clean up cache files
            if (file_exists($cacheFile)) {
                @unlink($cacheFile);
            }

            return null;
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Save scan progress to cache file for getScanProgress to read
     */
    public function saveScanProgress(string $progress): void
    {
        $cacheFile = storage_path('app/scan_progress.txt');
        file_put_contents($cacheFile, $progress);
    }

    /**
     * Clear scan progress cache
     */
    public function clearScanProgress(): void
    {
        $cacheFile = storage_path('app/scan_progress.txt');
        if (file_exists($cacheFile)) {
            @unlink($cacheFile);
        }

        // Also clear scan paths cache
        $pathsFile = storage_path('app/scan_paths.json');
        if (file_exists($pathsFile)) {
            @unlink($pathsFile);
        }
    }
}

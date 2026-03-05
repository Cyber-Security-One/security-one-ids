# Security One IDS Agent - Windows Installation Script
# Run as Administrator in PowerShell:
# iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/vito1317/security-one-ids/main/install/install-windows.ps1'))

param(
    [string]$WafHubUrl = $env:WAF_HUB_URL,
    [string]$InstallToken = $env:INSTALL_TOKEN,
    [string]$AgentToken = $env:AGENT_TOKEN,
    [string]$AgentName = $(if ($env:AGENT_NAME) { $env:AGENT_NAME } else { $env:COMPUTERNAME })
)

$ErrorActionPreference = "Stop"

Write-Host "
╔═══════════════════════════════════════════════════╗
║     Security One IDS Agent - Windows Installer    ║
╚═══════════════════════════════════════════════════╝
" -ForegroundColor Cyan

# Check if running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "❌ Please run this script as Administrator" -ForegroundColor Red
    exit 1
}

# Configuration
$InstallDir = "$env:ProgramFiles\SecurityOneIDS"
$DataDir = "$env:ProgramData\SecurityOneIDS"
$ServiceName = "SecurityOneIDS"

Write-Host "📁 Installation Directory: $InstallDir" -ForegroundColor Yellow
Write-Host "📁 Data Directory: $DataDir" -ForegroundColor Yellow

# Check prerequisites
Write-Host "`n🔍 Checking prerequisites..." -ForegroundColor Cyan

# Check PHP
$phpPath = Get-Command php -ErrorAction SilentlyContinue
if (-not $phpPath) {
    Write-Host "❌ PHP not found. Installing PHP..." -ForegroundColor Yellow
    
    # Download and install PHP using Chocolatey or manual download
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install php -y
    } else {
        Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        choco install php -y
    }
    
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

Write-Host "✅ PHP is installed" -ForegroundColor Green

# Enable required PHP extensions
Write-Host "🔧 Enabling required PHP extensions..." -ForegroundColor Cyan

# First, check for "Module already loaded" warnings and auto-fix
Write-Host "🔍 Checking for duplicate extension warnings..." -ForegroundColor Yellow
$phpWarnings = @()
try {
    # Capture PHP warnings - these indicate duplicate extensions
    $tempErrFile = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath "php" -ArgumentList "-m" -RedirectStandardError $tempErrFile -RedirectStandardOutput "$tempErrFile.out" -Wait -NoNewWindow -PassThru
    if (Test-Path $tempErrFile) {
        $phpWarnings = Get-Content $tempErrFile | Where-Object { $_ -match "Module .+ is already loaded" }
        Remove-Item $tempErrFile -Force -ErrorAction SilentlyContinue
        Remove-Item "$tempErrFile.out" -Force -ErrorAction SilentlyContinue
    }
} catch {
    # Ignore errors
}

if ($phpWarnings.Count -gt 0) {
    Write-Host "  ⚠️ Found $($phpWarnings.Count) duplicate extension warning(s)" -ForegroundColor Yellow
    foreach ($warn in $phpWarnings) {
        Write-Host "    → $warn" -ForegroundColor Gray
    }
    
    # Auto-fix: Find php.ini and comment out duplicate extensions
    Write-Host "  🔧 Auto-fixing php.ini..." -ForegroundColor Cyan
    $phpDir = Split-Path (Get-Command php).Source -Parent
    $iniPath = "$phpDir\php.ini"
    
    if (Test-Path $iniPath) {
        $iniContent = Get-Content $iniPath -Raw
        $modified = $false
        
        foreach ($warn in $phpWarnings) {
            if ($warn -match 'Module "(.+)" is already loaded') {
                $extName = $matches[1]
                # Comment out the extension line
                if ($iniContent -match "(?m)^(\s*)extension\s*=\s*$extName") {
                    $iniContent = $iniContent -replace "(?m)^(\s*)extension(\s*=\s*$extName)", "`$1;extension`$2"
                    Write-Host "    ✅ Commented out duplicate: extension=$extName" -ForegroundColor Green
                    $modified = $true
                }
            }
        }
        
        if ($modified) {
            Set-Content $iniPath $iniContent -Force
            Write-Host "  ✅ php.ini fixed - duplicate extensions disabled" -ForegroundColor Green
        }
    }
}

# Get list of already loaded (compiled-in) extensions to avoid duplicate loading
Write-Host "Detecting already loaded extensions..." -ForegroundColor Yellow
$loadedExtensions = @()
try {
    # Use temp file to avoid PowerShell stderr issues
    $tempOutFile = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath "php" -ArgumentList "-m" -RedirectStandardOutput $tempOutFile -RedirectStandardError "$tempOutFile.err" -Wait -NoNewWindow -PassThru
    if (Test-Path $tempOutFile) {
        $phpModulesOutput = Get-Content $tempOutFile
        $loadedExtensions = $phpModulesOutput | Where-Object { $_ -and $_.Trim() -ne "" -and $_ -notmatch "^\[" } | ForEach-Object { $_.Trim().ToLower() }
        Remove-Item $tempOutFile -Force -ErrorAction SilentlyContinue
        Remove-Item "$tempOutFile.err" -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  Found $($loadedExtensions.Count) loaded extensions" -ForegroundColor Gray
} catch {
    Write-Host "  ⚠️ Could not detect loaded extensions, will check php.ini only" -ForegroundColor Yellow
}

# Find php.ini location (using temp file to avoid stderr issues)
$phpIniPath = $null
try {
    $tempFile = [System.IO.Path]::GetTempFileName()
    $process = Start-Process -FilePath "php" -ArgumentList "-i" -RedirectStandardOutput $tempFile -RedirectStandardError "$tempFile.err" -Wait -NoNewWindow -PassThru
    if (Test-Path $tempFile) {
        $phpInfo = Get-Content $tempFile -Raw
        if ($phpInfo -match "Loaded Configuration File\s*=>\s*(.+)") {
            $phpIniPath = $matches[1].Trim()
            if ($phpIniPath -eq "(none)") { $phpIniPath = $null }
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        Remove-Item "$tempFile.err" -Force -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "  ⚠️ Could not run php -i: $_" -ForegroundColor Yellow
}

if (-not $phpIniPath) {
    # Try to find php.ini in common locations
    $phpDir = Split-Path (Get-Command php).Source -Parent
    $possiblePaths = @(
        "$phpDir\php.ini",
        "$phpDir\php.ini-development",
        "$phpDir\php.ini-production",
        "C:\php\php.ini",
        "C:\tools\php\php.ini",
        "C:\xampp\php\php.ini",
        "C:\xampp-new\php\php.ini"
    )
    
    foreach ($p in $possiblePaths) {
        if (Test-Path $p) {
            $phpIniPath = $p
            break
        }
    }
    
    # If still no php.ini, copy from sample
    if (-not $phpIniPath -or -not (Test-Path $phpIniPath)) {
        $sampleIni = Get-ChildItem -Path $phpDir -Filter "php.ini-*" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($sampleIni) {
            Copy-Item $sampleIni.FullName "$phpDir\php.ini"
            $phpIniPath = "$phpDir\php.ini"
            Write-Host "Created php.ini from sample" -ForegroundColor Yellow
        }
    }
}

if ($phpIniPath -and (Test-Path $phpIniPath)) {
    Write-Host "Found php.ini: $phpIniPath" -ForegroundColor Yellow
    
    # Extensions to enable (Windows uses php_xxx format for DLLs)
    # Map: short_name => windows_dll_name
    $extensionMap = @{
        "fileinfo" = "php_fileinfo"
        "curl" = "php_curl"
        "mbstring" = "php_mbstring"
        "openssl" = "php_openssl"
        "pdo_sqlite" = "php_pdo_sqlite"
        "sqlite3" = "php_sqlite3"
    }
    
    $content = Get-Content $phpIniPath -Raw
    $modified = $false
    $phpDir = Split-Path $phpIniPath -Parent
    
    foreach ($ext in $extensionMap.Keys) {
        $winExt = $extensionMap[$ext]
        
        # First check if extension is already loaded (compiled-in)
        if ($loadedExtensions -contains $ext.ToLower()) {
            Write-Host "  ✓ Extension already loaded (built-in): $ext" -ForegroundColor Gray
            continue
        }
        
        # Check both short and Windows DLL name patterns
        $patterns = @(
            "extension\s*=\s*$ext",
            "extension\s*=\s*$winExt",
            "extension\s*=\s*${winExt}\.dll"
        )
        
        $isEnabled = $false
        $isCommented = $false
        
        foreach ($pat in $patterns) {
            if ($content -match "(?m)^\s*$pat") {
                $isEnabled = $true
                break
            }
            if ($content -match "(?m)^\s*;\s*$pat") {
                $isCommented = $true
            }
        }
        
        if ($isEnabled) {
            Write-Host "  ✓ Extension already enabled: $ext" -ForegroundColor Gray
        } elseif ($isCommented) {
            # Uncomment the extension
            $content = $content -replace "(?m)^(\s*);(\s*extension\s*=\s*(?:$ext|$winExt|${winExt}\.dll))", "`$1`$2"
            $modified = $true
            Write-Host "  ✅ Enabled extension: $ext" -ForegroundColor Green
        } else {
            # Check if DLL exists before adding
            $dllPath = "$phpDir\ext\${winExt}.dll"
            if (Test-Path $dllPath) {
                $content = $content + "`nextension=$winExt"
                $modified = $true
                Write-Host "  ✅ Added extension: $ext (${winExt}.dll found)" -ForegroundColor Green
            } else {
                Write-Host "  ⚠️ Extension DLL not found: $dllPath" -ForegroundColor Yellow
            }
        }
    }
    
    # Download and configure CA certificates for SSL
    Write-Host "`n🔐 Configuring SSL certificates..." -ForegroundColor Cyan
    $phpDir = Split-Path $phpIniPath -Parent
    $cacertPath = "$phpDir\cacert.pem"
    
    if (-not (Test-Path $cacertPath)) {
        Write-Host "Downloading CA certificates bundle..." -ForegroundColor Yellow
        try {
            # Download Mozilla's CA certificate bundle
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri "https://curl.se/ca/cacert.pem" -OutFile $cacertPath -UseBasicParsing
            Write-Host "  ✅ Downloaded cacert.pem" -ForegroundColor Green
        } catch {
            Write-Host "  ⚠️ Could not download CA certificates: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ✓ CA certificates already exist" -ForegroundColor Gray
    }
    
    # Configure php.ini to use the CA bundle
    if (Test-Path $cacertPath) {
        $cacertPathEscaped = $cacertPath -replace '\\', '\\\\'
        
        # Check if curl.cainfo is already set
        if ($content -match "curl\.cainfo\s*=") {
            # Update existing setting
            $content = $content -replace "curl\.cainfo\s*=.*", "curl.cainfo = `"$cacertPath`""
            $modified = $true
        } elseif ($content -notmatch "curl\.cainfo") {
            # Add new setting
            $content = $content + "`n[curl]`ncurl.cainfo = `"$cacertPath`""
            $modified = $true
        }
        
        # Also set openssl.cafile
        if ($content -match "openssl\.cafile\s*=") {
            $content = $content -replace "openssl\.cafile\s*=.*", "openssl.cafile = `"$cacertPath`""
            $modified = $true
        } elseif ($content -notmatch "openssl\.cafile") {
            $content = $content + "`n[openssl]`nopenssl.cafile = `"$cacertPath`""
            $modified = $true
        }
        
        Write-Host "  ✅ Configured SSL certificates in php.ini" -ForegroundColor Green
    }
    
    if ($modified) {
        Set-Content $phpIniPath $content -Force
        Write-Host "✅ PHP configuration updated" -ForegroundColor Green
    }
} else {
    Write-Host "⚠️ Could not find php.ini - extensions may need manual configuration" -ForegroundColor Yellow
}

# Create directories
Write-Host "`n📂 Creating directories..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path "$DataDir\logs" -Force | Out-Null
New-Item -ItemType Directory -Path "$DataDir\storage" -Force | Out-Null

# Download IDS Agent via git clone (required for updates)
Write-Host "`n📥 Downloading Security One IDS Agent via Git...`n" -ForegroundColor Cyan

# Check if git is installed
$gitPath = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitPath) {
    Write-Host "Installing Git..." -ForegroundColor Yellow
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        & choco install git -y
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        & winget install -e --id Git.Git --accept-package-agreements --accept-source-agreements
    } else {
        # Install chocolatey first, then git
        Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        & 'C:\ProgramData\chocolatey\bin\choco.exe' install git -y
    }
    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}
Write-Host "✅ Git is installed" -ForegroundColor Green

# Clone or update repository
$RepoUrl = "https://github.com/Cyber-Security-One/security-one-ids.git"

if (Test-Path "$InstallDir\.git") {
    Write-Host "📂 Existing git repository found, updating..." -ForegroundColor Yellow
    Set-Location $InstallDir
    & git fetch origin
    & git reset --hard origin/main
} else {
# Remove existing directory if it's not a git repo
    if (Test-Path $InstallDir) {
        # Stop any running scheduled tasks first
        Write-Host "🛑 Stopping existing services..." -ForegroundColor Yellow
        Stop-ScheduledTask -TaskName "SecurityOneIDS-Scan" -ErrorAction SilentlyContinue
        Stop-ScheduledTask -TaskName "SecurityOneIDS-Sync" -ErrorAction SilentlyContinue
        
        # Wait a moment for processes to terminate
        Start-Sleep -Seconds 2
        
        # Kill ALL PHP processes (more aggressive)
        Write-Host "🔪 Terminating PHP processes..." -ForegroundColor Yellow
        Get-Process -Name php -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Get-Process -Name php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        
        # Wait for file handles to be released
        Start-Sleep -Seconds 3
        
        # Backup .env if exists
        $envBackup = $null
        if (Test-Path "$InstallDir\.env") {
            $envBackup = Get-Content "$InstallDir\.env" -Raw
        }
        
        # Try to remove directory with multiple attempts
        $maxAttempts = 3
        $attempt = 1
        while ($attempt -le $maxAttempts) {
            try {
                Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction Stop
                break
            } catch {
                Write-Host "⚠️ Attempt $attempt/$maxAttempts - Could not remove directory: $($_.Exception.Message)" -ForegroundColor Yellow
                if ($attempt -eq $maxAttempts) {
                    Write-Host "❌ Failed to remove directory. Please close any applications using files in $InstallDir and try again." -ForegroundColor Red
                    exit 1
                }
                $attempt++
                Start-Sleep -Seconds 5
            }
        }
    }
    
    # Clone the repository
    & git clone $RepoUrl $InstallDir
    
    # Restore .env if it was backed up
    if ($envBackup) {
        $envBackup | Out-File -FilePath "$InstallDir\.env" -Encoding UTF8
    }
}

Write-Host "✅ IDS Agent downloaded via Git" -ForegroundColor Green

# Install Composer dependencies
Write-Host "`n📦 Installing dependencies..." -ForegroundColor Cyan
Set-Location $InstallDir

# Check if composer is available
$composerPath = Get-Command composer -ErrorAction SilentlyContinue
if (-not $composerPath) {
    Write-Host "Installing Composer..." -ForegroundColor Yellow
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        choco install composer -y
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    }
}

# Run composer with ignore-platform-reqs to bypass missing extensions like ext-fileinfo
Write-Host "Running composer install (this may take a moment)..." -ForegroundColor Yellow

# Remove old composer.lock as it may have dependencies requiring missing extensions
if (Test-Path "$InstallDir\composer.lock") {
    Remove-Item "$InstallDir\composer.lock" -Force
    Write-Host "Removed old composer.lock" -ForegroundColor Yellow
}

# Verify PHP has fileinfo enabled now
Write-Host "Verifying PHP extensions..." -ForegroundColor Yellow
$phpExtensions = @()
try {
    $phpModulesOutput = & php -m 2>&1
    $phpExtensions = $phpModulesOutput | Where-Object { $_ -is [string] -and $_ -notmatch "^PHP Warning" -and $_.Trim() -ne "" -and $_ -notmatch "^\[" } | ForEach-Object { $_.Trim() }
} catch {
    # Ignore errors
}
if ($phpExtensions -contains 'fileinfo') {
    Write-Host "✅ PHP fileinfo extension is enabled" -ForegroundColor Green
} else {
    Write-Host "⚠️ PHP fileinfo extension not detected" -ForegroundColor Yellow
}

# Run composer update using Start-Process to avoid PowerShell stderr issues
Write-Host "Running composer update..." -ForegroundColor Yellow

# Suppress all errors from composer (it writes progress to stderr)
$ErrorActionPreference = 'SilentlyContinue'

# Find composer.phar or use composer command
$composerPhar = "C:\ProgramData\ComposerSetup\bin\composer.phar"
if (-not (Test-Path $composerPhar)) {
    $composerPhar = "C:\Program Files (x86)\ComposerSetup\bin\composer.phar"
}

if (Test-Path $composerPhar) {
    Write-Host "Using composer.phar directly..." -ForegroundColor Yellow
    $process = Start-Process -FilePath "php" -ArgumentList "$composerPhar update --no-dev --optimize-autoloader --no-interaction --ignore-platform-reqs" -WorkingDirectory $InstallDir -Wait -NoNewWindow -PassThru
} else {
    Write-Host "Using composer command..." -ForegroundColor Yellow
    $process = Start-Process -FilePath "composer" -ArgumentList "update --no-dev --optimize-autoloader --no-interaction --ignore-platform-reqs" -WorkingDirectory $InstallDir -Wait -NoNewWindow -PassThru
}

$ErrorActionPreference = 'Continue'

if ($process.ExitCode -eq 0) {
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "⚠️ First attempt had issues (exit code: $($process.ExitCode)), trying install..." -ForegroundColor Yellow
    $ErrorActionPreference = 'SilentlyContinue'
    $process2 = Start-Process -FilePath "composer" -ArgumentList "install --no-dev --no-interaction --ignore-platform-reqs" -WorkingDirectory $InstallDir -Wait -NoNewWindow -PassThru
    $ErrorActionPreference = 'Continue'
    
    if ($process2.ExitCode -eq 0) {
        Write-Host "✅ Dependencies installed (fallback)" -ForegroundColor Green
    } else {
        Write-Host "⚠️ Composer had warnings but may have succeeded. Continuing..." -ForegroundColor Yellow
    }
}

# Configure environment
Write-Host "`n⚙️ Configuring IDS Agent..." -ForegroundColor Cyan

# Check for existing configuration
$ExistingEnvPath = "$InstallDir\.env"
if ((Test-Path $ExistingEnvPath) -and (-not $WafHubUrl) -and (-not $AgentToken)) {
    Write-Host "📋 Found existing configuration, loading previous settings..." -ForegroundColor Yellow
    
    $EnvFileContent = Get-Content $ExistingEnvPath
    
    # Parse existing values
    foreach ($line in $EnvFileContent) {
        if ($line -match '^WAF_URL="(.+)"') {
            $ExistingWafUrl = $matches[1]
        }
        if ($line -match '^INSTALL_TOKEN="(.+)"') {
            $ExistingInstallToken = $matches[1]
        }
        if ($line -match '^AGENT_TOKEN="(.+)"') {
            $ExistingToken = $matches[1]
        }
        if ($line -match '^AGENT_NAME="(.+)"') {
            $ExistingName = $matches[1]
        }
    }
    
    # Use existing values if found
    if ($ExistingWafUrl) {
        $WafHubUrl = $ExistingWafUrl
        Write-Host "  WAF Hub URL: $WafHubUrl" -ForegroundColor Green
    }
    
    if ($ExistingInstallToken) {
        $InstallToken = $ExistingInstallToken
        Write-Host "  Install Token: (using existing token)" -ForegroundColor Green
    }
    
    if ($ExistingToken) {
        $AgentToken = $ExistingToken
        Write-Host "  Agent Token: (using existing token)" -ForegroundColor Green
    }
    
    if ($ExistingName) {
        $AgentName = $ExistingName
        Write-Host "  Agent Name: $AgentName" -ForegroundColor Green
    }
    
    Write-Host "✅ Using existing configuration" -ForegroundColor Green
}

# Get configuration if still not provided
if (-not $WafHubUrl) {
    $WafHubUrl = Read-Host "Enter WAF Hub URL (e.g., https://waf.example.com)"
}
if (-not $AgentToken) {
    $AgentToken = Read-Host "Enter Agent Token"
}

$EnvContent = @"
APP_NAME="Security One IDS"
APP_ENV=production
APP_DEBUG=false

WAF_URL="$WafHubUrl"
INSTALL_TOKEN="$InstallToken"
AGENT_TOKEN="$AgentToken"
AGENT_NAME="$AgentName"

OLLAMA_URL=https://ollama.futron-life.com
OLLAMA_MODEL=sentinel-security
AI_DETECTION_ENABLED=true
AI_TIMEOUT=30

LOG_CHANNEL=daily
LOG_LEVEL=info
"@

# Write .env file with UTF8 encoding WITHOUT BOM (important for Laravel)
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText("$InstallDir\.env", $EnvContent, $Utf8NoBom)
Write-Host "✅ Configuration saved (UTF8 no BOM)" -ForegroundColor Green

# Create SQLite database and run migrations
Write-Host "`n🗄️  Setting up database...`n" -ForegroundColor Cyan

# Create all required directories
$RequiredDirs = @(
    "$InstallDir\database",
    "$InstallDir\storage\logs",
    "$InstallDir\storage\framework\sessions",
    "$InstallDir\storage\framework\views",
    "$InstallDir\storage\framework\cache",
    "$InstallDir\bootstrap\cache"
)

foreach ($dir in $RequiredDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# Create database file
$DbPath = "$InstallDir\database\database.sqlite"
if (-not (Test-Path $DbPath)) {
    New-Item -ItemType File -Path $DbPath -Force | Out-Null
}

# Set permissions (allow full control for SYSTEM and Administrators)
Write-Host "🔐 Setting permissions..." -ForegroundColor Cyan
$Acl = Get-Acl $InstallDir
$Permission = "NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
$Acl.SetAccessRule($AccessRule)
Set-Acl $InstallDir $Acl

# Set storage directory permissions
$StorageDirs = @("$InstallDir\storage", "$InstallDir\database", "$InstallDir\bootstrap\cache", "$DataDir\logs")
foreach ($dir in $StorageDirs) {
    if (Test-Path $dir) {
        $Acl = Get-Acl $dir
        $Permission = "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow"
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
        $Acl.SetAccessRule($AccessRule)
        Set-Acl $dir $Acl
    }
}
Write-Host "✅ Permissions set" -ForegroundColor Green

# Run migrations
Set-Location $InstallDir
& php artisan migrate --force 2>$null
& php artisan package:discover --ansi 2>$null
Write-Host "✅ Database ready" -ForegroundColor Green

# Create Windows Service
Write-Host "`n🔧 Creating Windows Services..." -ForegroundColor Cyan

# Create scan service script with watchdog (runs every 5 minutes)
$ScanServiceScript = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$InstallDir'

# Watchdog Configuration
`$maxConsecutiveFailures = 5
`$consecutiveFailures = 0
`$watchdogLog = '$DataDir\logs\watchdog.log'
`$scanLog = '$DataDir\logs\scan.log'

# Find PHP path
`$phpPath = 'php'
`$possiblePhpPaths = @(
    'C:\php\php.exe',
    'C:\tools\php\php.exe',
    'C:\Program Files\PHP\php.exe',
    'C:\xampp\php\php.exe',
    'C:\xampp-new\php\php.exe',
    (Get-Command php -ErrorAction SilentlyContinue).Source
)
foreach (`$p in `$possiblePhpPaths) {
    if (`$p -and (Test-Path `$p -ErrorAction SilentlyContinue)) {
        `$phpPath = `$p
        break
    }
}

function Write-WatchdogLog {
    param([string]`$Message, [string]`$Level = 'INFO')
    `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path `$watchdogLog -Value "[`$timestamp] [SCAN] [`$Level] `$Message" -ErrorAction SilentlyContinue
}

Write-WatchdogLog "=== Scan Watchdog Starting ===" 'INFO'

while (`$true) {
    try {
        `$startTime = Get-Date
        `$job = Start-Job -ScriptBlock {
            param(`$php, `$dir)
            Set-Location `$dir
            & `$php artisan desktop:scan --full 2>&1
        } -ArgumentList `$phpPath, '$InstallDir'
        
        # Wait up to 10 minutes for scan completion
        `$completed = Wait-Job `$job -Timeout 600
        `$duration = [int](New-TimeSpan -Start `$startTime).TotalSeconds
        
        if (`$completed) {
            `$output = Receive-Job `$job | Out-String
            `$consecutiveFailures = 0
            Add-Content -Path `$scanLog -Value "[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Scan completed in `${duration}s"
            if (`$output.Trim()) {
                Add-Content -Path `$scanLog -Value `$output.Trim()
            }
        } else {
            Stop-Job `$job -ErrorAction SilentlyContinue
            `$consecutiveFailures++
            Write-WatchdogLog "TIMEOUT after `${duration}s (attempt `$consecutiveFailures/`$maxConsecutiveFailures)" 'WARN'
        }
        Remove-Job `$job -Force -ErrorAction SilentlyContinue
        
    } catch {
        `$consecutiveFailures++
        Write-WatchdogLog "CRASH: `$_ (attempt `$consecutiveFailures/`$maxConsecutiveFailures)" 'ERROR'
    }
    
    if (`$consecutiveFailures -ge `$maxConsecutiveFailures) {
        Write-WatchdogLog "Max failures reached. Cleaning up and restarting..." 'CRITICAL'
        `$consecutiveFailures = 0
        Get-Process -Name php, php-cgi -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 60
    }
    
    # Wait 5 minutes before next scan
    Start-Sleep -Seconds 300
}
"@

$ScanServiceScript | Out-File -FilePath "$InstallDir\run-scan-service.ps1" -Encoding UTF8

# Create sync service script - SIMPLIFIED VERSION for reliability
$SyncServiceScript = @'
$ErrorActionPreference = 'Continue'

# Configuration
$InstallDir = 'INSTALL_DIR_PLACEHOLDER'
$LogDir = 'DATA_DIR_PLACEHOLDER\logs'
$LogFile = "$LogDir\watchdog.log"
$MaxFailures = 10
$FailCount = 0

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Find PHP path
$PhpPath = 'php'
$PossiblePaths = @(
    'C:\php\php.exe',
    'C:\tools\php\php.exe',
    'C:\Program Files\PHP\php.exe',
    'C:\xampp\php\php.exe',
    'C:\xampp-new\php\php.exe'
)
foreach ($p in $PossiblePaths) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        $PhpPath = $p
        break
    }
}

function Log {
    param([string]$Msg, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Msg"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    
    # Rotate if > 5MB
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile -EA SilentlyContinue).Length -gt 5MB)) {
        Move-Item $LogFile "$LogFile.old" -Force -EA SilentlyContinue
    }
}

Log "=== Sync Watchdog v3.0 Starting ===" 'INFO'
Log "Install Dir: $InstallDir" 'INFO'
Log "PHP Path: $PhpPath" 'INFO'

# Main loop - run waf:sync with dynamic heartbeat interval from Hub config
while ($true) {
    try {
        Set-Location $InstallDir
        
        # Read heartbeat interval from waf_config.json (set by Hub)
        $SleepInterval = 60
        $ConfigFile = "$InstallDir\storage\app\waf_config.json"
        if (Test-Path $ConfigFile -ErrorAction SilentlyContinue) {
            try {
                $Config = Get-Content $ConfigFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($Config.heartbeat_interval -and $Config.heartbeat_interval -ge 5 -and $Config.heartbeat_interval -le 300) {
                    $SleepInterval = [int]$Config.heartbeat_interval
                }
            } catch { }
        }
        
        # Run sync command with timeout (2 min max)
        $proc = Start-Process -FilePath $PhpPath -ArgumentList 'artisan','waf:sync' -WorkingDirectory $InstallDir -NoNewWindow -PassThru -Wait:$false
        $exited = $proc.WaitForExit(120000)  # 2 min timeout
        
        if (-not $exited) {
            Log "waf:sync timeout - killing process" 'WARN'
            $proc.Kill()
            $FailCount++
        } elseif ($proc.ExitCode -ne 0) {
            Log "waf:sync failed with code $($proc.ExitCode)" 'ERROR'
            $FailCount++
        } else {
            Log "waf:sync completed (interval: ${SleepInterval}s)" 'INFO'
            $FailCount = 0
        }
        
        # Full reset after too many failures
        if ($FailCount -ge $MaxFailures) {
            Log "Too many failures ($FailCount), performing full reset..." 'WARN'
            
            # Clear Laravel cache
            & $PhpPath artisan cache:clear 2>&1 | Out-Null
            & $PhpPath artisan config:clear 2>&1 | Out-Null
            
            $FailCount = 0
            Log "Reset complete, waiting 60s..." 'INFO'
            Start-Sleep -Seconds 60
        }
        
    } catch {
        Log "Exception: $($_.Exception.Message)" 'ERROR'
        $FailCount++
    }
    
    # Wait before next sync (dynamic interval from Hub)
    Start-Sleep -Seconds $SleepInterval
}
'@

# Replace placeholders
$SyncServiceScript = $SyncServiceScript -replace 'INSTALL_DIR_PLACEHOLDER', $InstallDir
$SyncServiceScript = $SyncServiceScript -replace 'DATA_DIR_PLACEHOLDER', $DataDir

$SyncServiceScript | Out-File -FilePath "$InstallDir\run-sync-service.ps1" -Encoding UTF8

# Register scan scheduled task (for desktop:scan)
$ScanTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\run-scan-service.ps1`""
$ScanTaskTrigger = New-ScheduledTaskTrigger -AtStartup
$ScanTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$ScanTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Hours 0)

Register-ScheduledTask -TaskName "$ServiceName-Scan" -Action $ScanTaskAction -Trigger $ScanTaskTrigger -Principal $ScanTaskPrincipal -Settings $ScanTaskSettings -Force | Out-Null
Write-Host "✅ Scan Service created ($ServiceName-Scan)" -ForegroundColor Green

# Register sync scheduled task with BOTH startup and repetition triggers
$SyncTaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstallDir\run-sync-service.ps1`""

# Create two triggers: AtStartup + Every minute repetition as backup
$SyncTaskTrigger1 = New-ScheduledTaskTrigger -AtStartup
$SyncTaskTrigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 9999)

$SyncTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Settings: No execution time limit, restart on failure, run even if already running
$SyncTaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Hours 0) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName "$ServiceName-Sync" -Action $SyncTaskAction -Trigger @($SyncTaskTrigger1, $SyncTaskTrigger2) -Principal $SyncTaskPrincipal -Settings $SyncTaskSettings -Force | Out-Null
Write-Host "✅ Sync Service created ($ServiceName-Sync) with auto-restart" -ForegroundColor Green

# Suricata IDS/IPS Installation (always install for IDS/IPS functionality)
Write-Host "`n🛡️  Installing Suricata IDS/IPS..." -ForegroundColor Cyan

$InstallSuricata = if ($env:INSTALL_SURICATA) { $env:INSTALL_SURICATA } else { "yes" }

if ($InstallSuricata -eq "yes") {
    Write-Host "`n🛡️  Installing Suricata IDS/IPS..." -ForegroundColor Cyan
    
    $suricataInstalled = $false
    
    # Method 1: Try Chocolatey
    if (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "Installing Suricata via Chocolatey..." -ForegroundColor Yellow
        $ErrorActionPreference = 'SilentlyContinue'
        $proc = Start-Process -FilePath "choco" -ArgumentList "install suricata -y" -Wait -NoNewWindow -PassThru
        $ErrorActionPreference = 'Continue'
        
        if ($proc.ExitCode -eq 0) {
            $suricataInstalled = $true
            Write-Host "✅ Suricata installed via Chocolatey" -ForegroundColor Green
        }
    }

    # Method 2: Try winget
    if (-not $suricataInstalled -and (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Installing Suricata via winget..." -ForegroundColor Yellow
        $ErrorActionPreference = 'SilentlyContinue'
        $proc = Start-Process -FilePath "winget" -ArgumentList "install -e --id OISF.Suricata --accept-package-agreements --accept-source-agreements" -Wait -NoNewWindow -PassThru
        $ErrorActionPreference = 'Continue'
        
        if ($proc.ExitCode -eq 0) {
            $suricataInstalled = $true
            Write-Host "✅ Suricata installed via winget" -ForegroundColor Green
        }
    }
    
    # Method 3: Download MSI from OISF
    if (-not $suricataInstalled) {
        Write-Host "Downloading Suricata from OISF..." -ForegroundColor Yellow
        $suricataUrl = "https://www.openinfosecfoundation.org/download/windows/Suricata-latest-1-64bit.msi"
        $suricataMsi = "$env:TEMP\Suricata-latest.msi"
        
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $suricataUrl -OutFile $suricataMsi -UseBasicParsing -ErrorAction SilentlyContinue
            
            if (Test-Path $suricataMsi) {
                Write-Host "Installing Suricata MSI..." -ForegroundColor Yellow
                $proc = Start-Process -FilePath "msiexec" -ArgumentList "/i `"$suricataMsi`" /qn" -Wait -NoNewWindow -PassThru
                if ($proc.ExitCode -eq 0) {
                    $suricataInstalled = $true
                    Write-Host "✅ Suricata installed from MSI" -ForegroundColor Green
                }
                Remove-Item $suricataMsi -Force -ErrorAction SilentlyContinue
            }
        } catch {
            Write-Host "⚠️  Could not download Suricata: $_" -ForegroundColor Yellow
        }
    }
    
    if ($suricataInstalled) {
        # Create directories
        New-Item -ItemType Directory -Path "C:\Suricata\log" -Force -ErrorAction SilentlyContinue | Out-Null
        New-Item -ItemType Directory -Path "C:\Suricata\rules" -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Refresh PATH
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        # Verify
        $suricataCmd = Get-Command suricata -ErrorAction SilentlyContinue
        if ($suricataCmd) {
            Write-Host "✅ Suricata is ready" -ForegroundColor Green
        } else {
            Write-Host "⚠️  Suricata installed but not in PATH. You may need to restart your terminal." -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠️  Suricata installation skipped (can be installed later via Dashboard)" -ForegroundColor Yellow
    }
}

# Start services
Write-Host "`n🚀 Starting IDS Agent..." -ForegroundColor Cyan
Start-ScheduledTask -TaskName "$ServiceName-Scan" -ErrorAction SilentlyContinue
Start-ScheduledTask -TaskName "$ServiceName-Sync" -ErrorAction SilentlyContinue

# Register with WAF Hub
Write-Host "`n📡 Registering with WAF Hub..." -ForegroundColor Cyan
Set-Location $InstallDir
& php artisan waf:sync --register

# Run initial scan
Write-Host "`n🔍 Running initial security scan..." -ForegroundColor Cyan
& php artisan desktop:scan

Write-Host "`n
╔═══════════════════════════════════════════════════╗
║      ✅ Installation Complete!                     ║
╠═══════════════════════════════════════════════════╣
║  Install Path: $InstallDir
║  Data Path:    $DataDir
║  Services:     $ServiceName-Scan (Scheduled Task)
║                $ServiceName-Sync (Heartbeat)
║                                                   
║  Commands:                                        
║    Manual Scan:  php artisan desktop:scan        
║    Full Scan:    php artisan desktop:scan --full 
║    Manual Sync:  php artisan waf:sync
║    Check Status: Get-ScheduledTask $ServiceName*
║                                                   
╚═══════════════════════════════════════════════════╝
" -ForegroundColor Green

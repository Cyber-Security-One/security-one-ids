<#
.SYNOPSIS
    Provision the Security One EDR endpoint sensor on Windows.

.DESCRIPTION
    Installs osquery, writes the agent's own osqueryd configuration, and
    registers it as a Windows service.

    Deliberately not the osquery package's own service. A customer may already
    run osquery for inventory or compliance, and taking over their daemon —
    its config, its database, its schedule — would be hostile. This runs a
    second osqueryd with its own everything, exactly as the Linux and macOS
    installers do.

    The script is idempotent: run it again to repair or upgrade.

.NOTES
    Must run elevated. ETW's kernel process provider cannot be subscribed to
    from a non-administrator context, so a sensor installed without elevation
    would start cleanly and report nothing.
#>

[CmdletBinding()]
param(
    # Where the agent itself lives. Defaults to the parent of this script,
    # because install.ps1 ships inside the checkout — resolving it rather than
    # hardcoding a path is what keeps the service pointed at the same config
    # file the agent rewrites.
    [string] $InstallDir = (Split-Path -Parent $PSScriptRoot),
    [string] $DataDir    = 'C:\ProgramData\SecurityOne',
    [switch] $Uninstall,
    [switch] $StatusOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'SecurityOneSensor'

# Absolute, not bare. A bare `sc` in PowerShell resolves to Set-Content
# before it ever reaches sc.exe, and a bare `sc.exe` depends on a PATH that
# a service or a constrained shell may not have. The same shape blinded
# this product's IDS for 2.26 days on Linux: a bare iptables call that
# exited 127 under the watchdog's PATH, with the error swallowed by a
# 2>/dev/null on the existence check.
$ScExe = Join-Path $env:SystemRoot 'System32\sc.exe'
$MinOsquery  = [version]'5.5.0'

function Write-Step   { param($m) Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok     { param($m) Write-Host "    $m" -ForegroundColor Green }
function Write-Warn   { param($m) Write-Host "    $m" -ForegroundColor Yellow }
function Write-Fail   { param($m) Write-Host "    $m" -ForegroundColor Red }

function Assert-Elevated {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Fail 'This must run as Administrator.'
        Write-Host '    ETW cannot subscribe to the kernel process provider otherwise, and the'
        Write-Host '    sensor would install, start, and silently collect nothing.'
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

function Find-Osqueryd {
    # Read the program directories from the environment rather than assuming
    # C:. A machine whose system drive is D: would otherwise be told osquery
    # is missing while it sat there installed.
    $roots = @($env:ProgramFiles, ${env:ProgramW6432}, ${env:ProgramFiles(x86)}) |
             Where-Object { $_ } | Select-Object -Unique

    foreach ($root in $roots) {
        foreach ($rel in @('osquery\osqueryd\osqueryd.exe', 'osquery\osqueryd.exe')) {
            $candidate = Join-Path $root $rel
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }

    return $null
}

function Get-OsqueryVersion {
    param([string] $Exe)

    try {
        $raw = & $Exe --version 2>&1 | Out-String
        if ($raw -match 'version\s+([0-9][0-9.]*)') { return [version]$Matches[1] }
    } catch {
        # A version we cannot read is not a version that is too old. Say so
        # rather than refusing to install over a string.
    }

    return $null
}

# ---------------------------------------------------------------------------
# Install osquery
# ---------------------------------------------------------------------------

function Install-Osquery {
    $exe = Find-Osqueryd

    if ($exe) {
        $version = Get-OsqueryVersion $exe

        if ($null -eq $version) {
            Write-Warn "osquery present at $exe, version unreadable — continuing"
            return $exe
        }

        if ($version -ge $MinOsquery) {
            Write-Ok "osquery $version already installed"
            return $exe
        }

        Write-Warn "osquery $version is older than $MinOsquery; process_etw_events does not exist there"
        Write-Warn 'Upgrade it and run this again:  winget upgrade osquery.osquery'
        exit 1
    }

    Write-Step 'Installing osquery'

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        # --silent so it does not sit on a UAC-adjacent prompt inside a
        # provisioning run that nobody is watching.
        & winget install --id osquery.osquery --silent --accept-package-agreements --accept-source-agreements
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        & choco install osquery -y
    } else {
        Write-Fail 'Neither winget nor choco is available.'
        Write-Host  '    Install osquery 5.5 or later from https://osquery.io/downloads and re-run.'
        exit 1
    }

    $exe = Find-Osqueryd

    if (-not $exe) {
        Write-Fail 'osquery installed but osqueryd.exe was not found afterwards.'
        exit 1
    }

    Write-Ok "osquery installed at $exe"
    return $exe
}

# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

function Install-Service {
    param([string] $Exe, [string] $ConfigPath, [string] $DbPath, [string] $LogPath, [string] $FlagFile)

    Write-Step "Registering the $ServiceName service"

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if ($existing) {
        if ($existing.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force
            # Wait rather than assume: sc.exe delete on a service that is
            # still stopping leaves it marked for deletion and the create
            # below fails with a message that does not say why.
            $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }

        & $ScExe delete $ServiceName | Out-Null
        Start-Sleep -Seconds 2
    }

    # No --pidfile and no --daemonize. Both are POSIX-only flags in osquery,
    # and OsqueryEngine::isRunning() knows it — on Windows it asks the service
    # control manager rather than reading a file that nothing would ever
    # write. Passing them here would be rejected by osqueryd at startup.
    #
    # --flagfile points at a file we own rather than being omitted. Omitting
    # it lets osqueryd pick up whatever the MSI left in its own install
    # directory, which is exactly the customer-owned configuration this agent
    # refuses to inherit everywhere else. Its contents are the three ETW flags
    # and nothing more — see where it is written.
    $binPath = '"{0}" --flagfile="{1}" --config_path="{2}" --database_path="{3}" --logger_path="{4}"' -f `
        $Exe, $FlagFile, $ConfigPath, $DbPath, $LogPath

    # LocalSystem explicitly. It is the default, but ETW's kernel process
    # provider will not subscribe under anything less, and a service that
    # silently ran as something else would start, report healthy, and collect
    # nothing.
    & $ScExe create $ServiceName binPath= $binPath start= auto obj= LocalSystem DisplayName= 'Security One Endpoint Sensor' | Out-Null
    & $ScExe description $ServiceName 'Collects process telemetry for the Security One EDR agent.' | Out-Null

    # Restart on failure rather than leaving the host blind after one crash.
    & $ScExe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

    Start-Service -Name $ServiceName
    Write-Ok "$ServiceName started"
}

function Uninstall-All {
    Write-Step "Removing $ServiceName"

    $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $existing) {
        Write-Warn 'Service is not installed'
        return
    }

    if ($existing.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }

    & $ScExe delete $ServiceName | Out-Null
    Write-Ok 'Service removed'
    Write-Warn "Data left in place at $DataDir — delete it by hand if you mean to"
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

function Show-Status {
    $exe = Find-Osqueryd

    Write-Step 'Endpoint sensor'

    if (-not $exe) {
        Write-Fail 'osquery       not installed'
    } else {
        $version = Get-OsqueryVersion $exe
        $shown = if ($null -eq $version) { 'unreadable' } else { "$version" }
        Write-Ok  "osquery       $shown"
        Write-Host "    path          $exe"

        if ($null -ne $version -and $version -lt $MinOsquery) {
            Write-Fail "              older than $MinOsquery — process_etw_events is absent"
        }
    }

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

    if (-not $svc) {
        Write-Fail "service       $ServiceName not installed"
    } elseif ($svc.Status -eq 'Running') {
        Write-Ok  "service       running"
    } else {
        Write-Fail "service       $($svc.Status)"
    }

    # The results log is the evidence that the publisher actually attached.
    # A running service with an empty log is the failure mode worth catching:
    # everything reports healthy and no telemetry exists.
    $results = Join-Path $DataDir 'osquery\osqueryd.results.log'

    if (Test-Path -LiteralPath $results) {
        $size = (Get-Item -LiteralPath $results).Length
        $age  = [int]((Get-Date) - (Get-Item -LiteralPath $results).LastWriteTime).TotalSeconds

        if ($size -eq 0) {
            Write-Fail "telemetry     results log is empty — the ETW publisher is not producing rows"
        } else {
            Write-Ok "telemetry     $([math]::Round($size / 1KB)) KB, last written ${age}s ago"
        }
    } else {
        Write-Warn 'telemetry     no results log yet'
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if ($StatusOnly) {
    Show-Status
    exit 0
}

Assert-Elevated

if ($Uninstall) {
    Uninstall-All
    exit 0
}

Write-Host ''
Write-Host '  Security One — Windows endpoint sensor' -ForegroundColor White
Write-Host ''

$osqueryd = Install-Osquery

Write-Step 'Preparing directories'

# These four paths are not a choice. They must match what OsqueryEngine
# computes, or the two halves work perfectly against different files:
#
#   config, db  ->  storage/app/osquery/    (storage_path in the engine)
#   logs        ->  C:\ProgramData\SecurityOne\osquery  (detectLogDir)
#
# Get the config path wrong and the agent rewrites a file the service never
# reads — so every option the Hub pushes is applied, saved, and ignored, while
# the sensor runs forever on the floor config written below. Get the log path
# wrong and the collector tails a results log nothing writes to, which reads
# as a host that produces no telemetry.
$agentOsquery = Join-Path $InstallDir 'storage\app\osquery'
$configPath   = Join-Path $agentOsquery 'osquery.conf'
$dbPath       = Join-Path $agentOsquery 'db'

$osqueryData = Join-Path $DataDir 'osquery'
$flagFile    = Join-Path $osqueryData 'osquery.flags'

if (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'artisan'))) {
    Write-Fail "No agent found at $InstallDir (expected an 'artisan' file there)."
    Write-Host  '    Pass -InstallDir with the path to the checkout.'
    exit 1
}

foreach ($dir in @($DataDir, $osqueryData, $agentOsquery, $dbPath)) {
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
}

# The three ETW flags live here as well as in the config, and the redundancy
# is deliberate.
#
# Publisher enablement is read when osqueryd initialises its event subsystem,
# which happens before the scheduled config is fully applied — so a flag that
# exists only in the config can arrive too late to turn a publisher on. In the
# flagfile it is present at process start, unconditionally.
#
# All three are required together. The publisher without the subscriber starts
# cleanly, logs nothing wrong, and emits no rows: a sensor that is running,
# reporting healthy, and blind. OsqueryEngine::writeConfig() sets the same
# three, so the Hub cannot push a config that drops one.
#
# Nothing else goes in here. An otherwise-empty file is what stops osqueryd
# picking up whatever the MSI left in its own install directory.
@(
    '--enable_process_etw_events=true'
    '--enable_windows_events_publisher=true'
    '--enable_windows_events_subscriber=true'
) | Set-Content -LiteralPath $flagFile -Encoding ASCII

# The sensor log holds command lines verbatim, which means it holds any
# credential that was ever passed as an argument. Administrators and SYSTEM
# only — the same reasoning as the 0750 on the Unix side.
Write-Step 'Restricting access to the sensor data'

$acl = Get-Acl -LiteralPath $DataDir
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }

foreach ($who in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
    ))
}

Set-Acl -LiteralPath $DataDir -AclObject $acl
Write-Ok 'SYSTEM and Administrators only'

Write-Step 'Writing the sensor configuration'

# Written here only as a floor, so the service has something valid to start
# with on a host that has never synced. The agent rewrites it from the Hub's
# options on the next cycle — see OsqueryEngine::writeConfig(), which is the
# single place the schedule is defined for all three platforms.
$config = [ordered]@{
    options = [ordered]@{
        disable_events                    = $false
        enable_process_etw_events         = $true
        enable_windows_events_publisher   = $true
        enable_windows_events_subscriber  = $true
        events_expiry                     = 3600
        events_max                        = 50000
        logger_plugin                     = 'filesystem'
        logger_path                       = $osqueryData
        logger_rotate                     = $true
        logger_rotate_size                = 16777216
        logger_rotate_max_files           = 2
        schedule_splay_percent            = 10
        utc                               = $true
        disable_distributed               = $true
        disable_carver                    = $true
        watchdog_memory_limit             = 200
        watchdog_utilization_limit        = 20
    }
    schedule = [ordered]@{
        process_exec = [ordered]@{
            query       = 'SELECT * FROM process_etw_events;'
            interval    = 15
            removed     = $false
            description = 'Process execution telemetry (EDR)'
        }
    }
}

$config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8
Write-Ok $configPath

Install-Service -Exe $osqueryd -ConfigPath $configPath -DbPath $dbPath -LogPath $osqueryData -FlagFile $flagFile

Write-Host ''
Show-Status
Write-Host ''
Write-Host '  Next:' -ForegroundColor White
Write-Host "    php artisan ids:sync-edr --status     expect backend: etw"
Write-Host "    php artisan ids:status                the whole agent in one view"
Write-Host ''
Write-Host '  If the service runs but telemetry stays empty, the publisher did not attach.' -ForegroundColor Yellow
Write-Host '  That is the one failure here that looks exactly like success.' -ForegroundColor Yellow
Write-Host ''

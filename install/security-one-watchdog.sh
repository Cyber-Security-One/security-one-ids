#!/bin/bash
# Security One IDS - Multi-Threaded Watchdog Wrapper
# Runs 3 independent background loops: heartbeat, sync, scan
# Version 3.0 - True multi-threaded with independent process loops

INSTALL_DIR="/opt/security-one-ids"
LOG_DIR="/var/log/security-one-ids"
WATCHDOG_LOG="$LOG_DIR/watchdog.log"
PID_FILE="$INSTALL_DIR/storage/ids.pid"
CRASH_COUNT_FILE="$INSTALL_DIR/storage/crash_count"
MAX_CRASHES_BEFORE_RESET=5
SCAN_INTERVAL=300  # Security scan interval (5 min)
DEFAULT_HEARTBEAT_INTERVAL=60
CONFIG_FILE="$INSTALL_DIR/storage/app/waf_config.json"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Find PHP binary (check common locations)
find_php() {
    for path in /opt/homebrew/bin/php /usr/local/bin/php /usr/bin/php /usr/local/php/bin/php; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

PHP_BIN=$(find_php)
if [ -z "$PHP_BIN" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [FATAL] PHP not found!" >> "$WATCHDOG_LOG"
    exit 1
fi

# Logging function
log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): [$level] $message" >> "$WATCHDOG_LOG"
    
    # Keep log size manageable (rotate at 10MB)
    if [ -f "$WATCHDOG_LOG" ] && [ $(stat -f%z "$WATCHDOG_LOG" 2>/dev/null || stat -c%s "$WATCHDOG_LOG" 2>/dev/null) -gt 10485760 ]; then
        mv "$WATCHDOG_LOG" "$WATCHDOG_LOG.old"
        log_message "INFO" "Log rotated"
    fi
}

# Run artisan command with timeout and error handling
run_artisan() {
    local command="$1"
    local timeout_seconds="${2:-120}"
    local exit_code=0
    
    cd "$INSTALL_DIR" || return 1
    
    # Run with timeout (if available)
    if command -v timeout &> /dev/null; then
        timeout "$timeout_seconds" "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    elif command -v gtimeout &> /dev/null; then
        gtimeout "$timeout_seconds" "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    else
        "$PHP_BIN" "$INSTALL_DIR/artisan" $command >> "$LOG_DIR/output.log" 2>&1
        exit_code=$?
    fi
    
    return $exit_code
}

# Read heartbeat interval from Hub config
get_heartbeat_interval() {
    local interval=$DEFAULT_HEARTBEAT_INTERVAL
    if [ -f "$CONFIG_FILE" ]; then
        local hi=$(grep -o '"heartbeat_interval"[[:space:]]*:[[:space:]]*[0-9]*' "$CONFIG_FILE" 2>/dev/null | grep -o '[0-9]*$')
        if [ -n "$hi" ] && [ "$hi" -ge 5 ] && [ "$hi" -le 300 ]; then
            interval=$hi
        fi
    fi
    echo "$interval"
}

# Auto-install Suricata on Linux if not found
ensure_suricata_installed() {
    # Only run on Linux
    if [[ "$OSTYPE" == "darwin"* ]]; then
        return 0
    fi

    # Check if Suricata is already installed
    if command -v suricata &>/dev/null; then
        local ver=$(suricata -V 2>&1 | grep -oP '(\d+\.\d+[\d.]*)' | head -1 || echo "unknown")
        log_message "INFO" "Suricata already installed: $ver"
        return 0
    fi

    # Check common paths
    for p in /usr/bin/suricata /usr/local/bin/suricata /usr/sbin/suricata; do
        if [ -x "$p" ]; then
            log_message "INFO" "Suricata found at $p"
            return 0
        fi
    done

    log_message "INFO" "Suricata not found, auto-installing..."
    local MARKER="$INSTALL_DIR/storage/suricata_install_attempted"

    # Prevent repeated install attempts
    if [ -f "$MARKER" ]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$MARKER" 2>/dev/null || echo 0) ))
        if [ "$age" -lt 86400 ]; then
            log_message "WARNING" "Suricata install was attempted less than 24h ago, skipping"
            return 1
        fi
    fi
    touch "$MARKER"

    # Detect package manager and install
    if command -v apt-get &>/dev/null; then
        log_message "INFO" "Installing Suricata (apt)..."
        apt-get update -qq 2>/dev/null
        if command -v add-apt-repository &>/dev/null; then
            add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
            apt-get update -qq 2>/dev/null
        fi
        apt-get install -y suricata suricata-update 2>/dev/null || \
        apt-get install -y suricata 2>/dev/null
    elif command -v yum &>/dev/null; then
        log_message "INFO" "Installing Suricata (yum)..."
        yum install -y epel-release 2>/dev/null || true
        yum install -y suricata 2>/dev/null
    elif command -v dnf &>/dev/null; then
        log_message "INFO" "Installing Suricata (dnf)..."
        dnf install -y epel-release 2>/dev/null || true
        dnf install -y suricata 2>/dev/null
    else
        log_message "ERROR" "No supported package manager found (apt/yum/dnf)"
        return 1
    fi

    # Verify installation
    if command -v suricata &>/dev/null; then
        mkdir -p /var/log/suricata /etc/suricata/rules 2>/dev/null
        chmod 755 /var/log/suricata /etc/suricata /etc/suricata/rules

        # Update rules
        if command -v suricata-update &>/dev/null; then
            suricata-update 2>/dev/null || true
        fi

        local installed_ver=$(suricata -V 2>&1 | grep -oP '(\d+\.\d+[\d.]*)' | head -1 || echo "unknown")
        log_message "INFO" "Suricata installed successfully: v${installed_ver}"
        return 0
    else
        log_message "ERROR" "Failed to install Suricata"
        return 1
    fi
}


# Start the endpoint sensor if it is installed but not running.
#
# Installing osqueryd and running it are two different things, and nothing did
# the second one — not the installer, not this watchdog. A fresh install left
# the sensor installed, supported, and permanently down, while the status
# command politely told the operator to run the start command by hand. Suricata
# already gets looked after above; the sensor that produces the process
# telemetry deserves it at least as much.
#
# Checked once per watchdog start rather than on a loop: the daemon carries
# KeepAlive, so boot is the moment that actually matters.
ensure_edr_running() {
    local status
    status=$("$PHP_BIN" "$INSTALL_DIR/artisan" ids:sync-edr --status 2>/dev/null) || return 0

    if echo "$status" | grep -qE '^[[:space:]]*running[[:space:]]+yes'; then
        log_message "INFO" "[EDR] Endpoint sensor already running"
        return 0
    fi

    if ! echo "$status" | grep -qE '^[[:space:]]*installed[[:space:]]+yes'; then
        log_message "INFO" "[EDR] Endpoint sensor not installed; nothing to start"
        return 0
    fi

    log_message "INFO" "[EDR] Installed but not running - starting it"
    if run_artisan "ids:sync-edr --start" 120; then
        log_message "INFO" "[EDR] Endpoint sensor started"
    else
        log_message "WARNING" "[EDR] Endpoint sensor failed to start"
    fi
}

# Auto-install Suricata if not present
ensure_suricata_installed

# Start the endpoint sensor if it is installed but idle
ensure_edr_running


# Cleanup all child processes on exit
CHILD_PIDS=()
cleanup() {
    log_message "INFO" "Watchdog shutting down, stopping all child processes..."
    for pid in "${CHILD_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    rm -f "$PID_FILE"
    log_message "INFO" "Watchdog stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGHUP

# Write PID file
echo $$ > "$PID_FILE"

log_message "INFO" "=== Security One IDS Multi-Threaded Watchdog v3.0 ==="
log_message "INFO" "PHP: $PHP_BIN"
log_message "INFO" "Install Dir: $INSTALL_DIR"



# ============================================================
# Thread 1: HEARTBEAT (independent, high-frequency)
# Never blocked by sync or scan operations
# ============================================================
heartbeat_loop() {
    log_message "INFO" "[Thread:Heartbeat] Started"
    local failures=0
    
    while true; do
        if run_artisan "waf:heartbeat" 60; then
            log_message "INFO" "[Thread:Heartbeat] OK"
            failures=0
        else
            failures=$((failures + 1))
            log_message "WARNING" "[Thread:Heartbeat] Failed (consecutive: $failures)"
            
            if [ $failures -ge 5 ]; then
                log_message "ERROR" "[Thread:Heartbeat] Too many failures, waiting 60s"
                sleep 60
                failures=0
                continue
            fi
        fi
        
        local interval=$(get_heartbeat_interval)
        sleep "$interval"
    done
}

# ============================================================
# Thread 2: SYNC (rule sync, Suricata management, maintenance)
# Uses Process::pool internally for sub-parallelism
# ============================================================
sync_loop() {
    log_message "INFO" "[Thread:Sync] Started"
    local crash_count=0
    
    while true; do
        if run_artisan "waf:sync" 600; then
            log_message "INFO" "[Thread:Sync] Completed"
            crash_count=0
        else
            exit_code=$?
            crash_count=$((crash_count + 1))
            log_message "ERROR" "[Thread:Sync] Failed (exit: $exit_code, crashes: $crash_count)"
            
            if [ $crash_count -ge $MAX_CRASHES_BEFORE_RESET ]; then
                log_message "CRITICAL" "[Thread:Sync] Max crashes reached, cooling down 5min"
                crash_count=0
                rm -f "$INSTALL_DIR/storage/framework/cache/data/*" 2>/dev/null
                sleep 300
                continue
            fi
            
            # Backoff on specific errors
            if [ $exit_code -eq 137 ] || [ $exit_code -eq 139 ]; then
                sleep 60
            else
                sleep 10
            fi
        fi
        
        # Sync runs less frequently than heartbeat
        local interval=$(get_heartbeat_interval)
        local sync_wait=$((interval * 3))
        [ $sync_wait -lt 60 ] && sync_wait=60
        [ $sync_wait -gt 600 ] && sync_wait=600
        sleep "$sync_wait"
    done
}

# ============================================================
# Thread 3: SCAN (desktop security scan + AI analysis)
# Runs every SCAN_INTERVAL, completely independent
# ============================================================
scan_loop() {
    log_message "INFO" "[Thread:Scan] Started (interval: ${SCAN_INTERVAL}s)"
    
    while true; do
        log_message "INFO" "[Thread:Scan] Starting security scan..."
        if run_artisan "desktop:scan --full" 600; then
            log_message "INFO" "[Thread:Scan] Completed"
        else
            log_message "WARNING" "[Thread:Scan] Failed"
        fi
        
        sleep $SCAN_INTERVAL
    done
}

# ============================================================
# Thread 4 (macOS only): PF enforcement
# Tail Suricata drop events into pf ids_block table every 15s.
# ============================================================
pf_enforce_loop() {
    [[ "$OSTYPE" != "darwin"* ]] && { log_message "INFO" "[Thread:PfEnforce] non-macOS, skipping"; return 0; }
    log_message "INFO" "[Thread:PfEnforce] Started (interval: 15s)"
    while true; do
        run_artisan "ids:pf-enforce" 30
        sleep 15
    done
}

# ============================================================
# Launch all 3 threads as background processes
# ============================================================
log_message "INFO" "Launching 3 independent threads..."

heartbeat_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → Heartbeat thread: PID $!"

sync_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → Sync thread: PID $!"

scan_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → Scan thread: PID $!"

pf_enforce_loop &
CHILD_PIDS+=($!)
log_message "INFO" "  → PfEnforce thread: PID $!"

log_message "INFO" "All threads launched. Monitoring..."

# Main watchdog: monitor child processes, restart if they die
while true; do
    for i in "${!CHILD_PIDS[@]}"; do
        pid=${CHILD_PIDS[$i]}
        labels=("Heartbeat" "Sync" "Scan" "PfEnforce")
        label=${labels[$i]:-"Unknown"}
        
        if ! kill -0 "$pid" 2>/dev/null; then
            log_message "CRITICAL" "[Thread:$label] Process $pid died! Restarting..."
            
            case $i in
                0) heartbeat_loop & ;;
                1) sync_loop & ;;
                2) scan_loop & ;;
                3) pf_enforce_loop & ;;
            esac
            CHILD_PIDS[$i]=$!
            log_message "INFO" "[Thread:$label] Restarted as PID ${CHILD_PIDS[$i]}"
        fi
    done
    
    sleep 30
done

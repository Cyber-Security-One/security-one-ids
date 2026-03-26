#!/bin/bash
# Security One IDS Agent - macOS/Linux Installation Script
# One-line install:
# curl -fsSL https://raw.githubusercontent.com/vito1317/security-one-ids/main/install/install.sh | \
#   sudo WAF_HUB_URL="https://your-waf.example.com" \
#   INSTALL_TOKEN="your-install-token" \
#   AGENT_TOKEN="your-token" \
#   AGENT_NAME="your-agent-name" \
#   bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}
╔═══════════════════════════════════════════════════╗
║   Security One IDS Agent - macOS/Linux Installer  ║
╚═══════════════════════════════════════════════════╝
${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root (sudo)${NC}"
    exit 1
fi

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ -f /etc/debian_version ]]; then
    OS="debian"
elif [[ -f /etc/redhat-release ]]; then
    OS="redhat"
else
    OS="linux"
fi

echo -e "${YELLOW}🖥️  Detected OS: $OS${NC}"

# Configuration
INSTALL_DIR="/opt/security-one-ids"
DATA_DIR="/var/lib/security-one-ids"
LOG_DIR="/var/log/security-one-ids"
SERVICE_NAME="security-one-ids"

# Get configuration from user or environment
WAF_HUB_URL="${WAF_HUB_URL:-}"
INSTALL_TOKEN="${INSTALL_TOKEN:-}"
AGENT_TOKEN="${AGENT_TOKEN:-}"
AGENT_NAME="${AGENT_NAME:-$(hostname)}"

# Fallback: if env vars are empty, try reading from parent process environment
# This handles sudo stripping env vars (both Linux and macOS)
if [ -z "$WAF_HUB_URL" ]; then
    # Method 1: Linux /proc filesystem
    if [ -f "/proc/$PPID/environ" ] 2>/dev/null; then
        WAF_HUB_URL=$(tr '\0' '\n' < /proc/$PPID/environ 2>/dev/null | grep '^WAF_HUB_URL=' | cut -d'=' -f2- || true)
        INSTALL_TOKEN=$(tr '\0' '\n' < /proc/$PPID/environ 2>/dev/null | grep '^INSTALL_TOKEN=' | cut -d'=' -f2- || true)
        AGENT_TOKEN=$(tr '\0' '\n' < /proc/$PPID/environ 2>/dev/null | grep '^AGENT_TOKEN=' | cut -d'=' -f2- || true)
        _PARENT_AGENT_NAME=$(tr '\0' '\n' < /proc/$PPID/environ 2>/dev/null | grep '^AGENT_NAME=' | cut -d'=' -f2- || true)
        if [ -n "$_PARENT_AGENT_NAME" ]; then
            AGENT_NAME="$_PARENT_AGENT_NAME"
        fi
    fi

    # Method 2: macOS - parse SUDO_COMMAND which preserves the full command line
    # When user runs: WAF_HUB_URL=x sudo bash -c "script", SUDO_COMMAND contains the bash invocation
    # But env vars set BEFORE sudo are visible in the parent process tree
    if [ -z "$WAF_HUB_URL" ] && [[ "$OSTYPE" == "darwin"* ]]; then
        # Try ps eww on parent and grandparent processes
        for _PID in $PPID $(ps -o ppid= -p $PPID 2>/dev/null | tr -d ' ') $(ps -o ppid= -p $(ps -o ppid= -p $PPID 2>/dev/null | tr -d ' ') 2>/dev/null | tr -d ' '); do
            [ -z "$_PID" ] || [ "$_PID" = "1" ] && continue
            _PENV=$(ps eww -o command= -p "$_PID" 2>/dev/null || true)
            if [ -n "$_PENV" ]; then
                # Strip quotes from captured values
                _TRY_WAF=$(echo "$_PENV" | tr ' ' '\n' | grep '^WAF_HUB_URL=' | head -1 | cut -d'=' -f2- | sed "s/[\"']//g" || true)
                if [ -n "$_TRY_WAF" ]; then
                    WAF_HUB_URL="$_TRY_WAF"
                    INSTALL_TOKEN=$(echo "$_PENV" | tr ' ' '\n' | grep '^INSTALL_TOKEN=' | head -1 | cut -d'=' -f2- | sed "s/[\"']//g" || true)
                    AGENT_TOKEN=$(echo "$_PENV" | tr ' ' '\n' | grep '^AGENT_TOKEN=' | head -1 | cut -d'=' -f2- | sed "s/[\"']//g" || true)
                    _PARENT_AGENT_NAME=$(echo "$_PENV" | tr ' ' '\n' | grep '^AGENT_NAME=' | head -1 | cut -d'=' -f2- | sed "s/[\"']//g" || true)
                    if [ -n "$_PARENT_AGENT_NAME" ]; then
                        AGENT_NAME="$_PARENT_AGENT_NAME"
                    fi
                    break
                fi
            fi
        done
    fi
fi

echo -e "${YELLOW}📁 Installation Directory: $INSTALL_DIR${NC}"
echo -e "${YELLOW}📁 Data Directory: $DATA_DIR${NC}"

# Install prerequisites
echo -e "\n${CYAN}🔍 Installing prerequisites...${NC}"

install_php() {
    case $OS in
        macos)
            if ! command -v brew &> /dev/null; then
                echo -e "${YELLOW}Installing Homebrew...${NC}"
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew install php composer
            ;;
        debian)
            apt-get update
            apt-get install -y php php-cli php-curl php-json php-mbstring php-xml php-sqlite3 php-zip composer git
            # Stop and disable Apache2 (installed as PHP dependency) to avoid port 80 conflict with Docker/WAF
            systemctl stop apache2 2>/dev/null || true
            systemctl disable apache2 2>/dev/null || true
            ;;
        redhat)
            yum install -y epel-release
            yum install -y php php-cli php-curl php-json php-mbstring php-xml php-pdo php-sqlite3 composer git
            ;;
        *)
            echo -e "${RED}Unsupported OS. Please install PHP 8.0+ manually.${NC}"
            exit 1
            ;;
    esac
}

# Check PHP
if ! command -v php &> /dev/null; then
    echo -e "${YELLOW}PHP not found. Installing...${NC}"
    install_php
fi

PHP_VERSION=$(php -r "echo PHP_VERSION;")
echo -e "${GREEN}✅ PHP $PHP_VERSION installed${NC}"

if ! command -v composer &> /dev/null; then
    echo -e "${YELLOW}Installing Composer...${NC}"
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
fi
echo -e "${GREEN}✅ Composer installed${NC}"

# ClamAV Installation Function
install_clamav() {
    echo -e "\n${CYAN}🛡️  Installing ClamAV Antivirus...${NC}"
    
    if [ "$OS" = "macos" ]; then
        # macOS - use Homebrew
        if command -v brew &> /dev/null; then
            # Run brew as the original user (not root)
            ORIGINAL_USER="${SUDO_USER:-$USER}"
            echo -e "${YELLOW}Installing ClamAV via Homebrew as $ORIGINAL_USER...${NC}"
            sudo -u "$ORIGINAL_USER" brew install clamav 2>/dev/null || brew install clamav
            
            # Configure freshclam
            CLAMAV_CONF_DIR="/opt/homebrew/etc/clamav"
            if [ ! -d "$CLAMAV_CONF_DIR" ]; then
                CLAMAV_CONF_DIR="/usr/local/etc/clamav"
            fi
            
            if [ -f "$CLAMAV_CONF_DIR/freshclam.conf.sample" ] && [ ! -f "$CLAMAV_CONF_DIR/freshclam.conf" ]; then
                cp "$CLAMAV_CONF_DIR/freshclam.conf.sample" "$CLAMAV_CONF_DIR/freshclam.conf"
                sed -i '' 's/^Example/#Example/' "$CLAMAV_CONF_DIR/freshclam.conf" 2>/dev/null || true
            fi
            
            # Fix ClamAV database directory permissions for freshclam
            echo -e "${YELLOW}Setting up ClamAV database directory permissions...${NC}"
            ORIGINAL_USER="${SUDO_USER:-$USER}"
            
            # Check both possible locations
            CLAMAV_DB_DIR="/opt/homebrew/var/lib/clamav"
            if [ ! -d "$CLAMAV_DB_DIR" ]; then
                CLAMAV_DB_DIR="/usr/local/var/lib/clamav"
            fi
            
            # Create directory if it doesn't exist
            mkdir -p "$CLAMAV_DB_DIR"
            
            # Set proper ownership (user:admin for macOS)
            chown -R "$ORIGINAL_USER:admin" "$CLAMAV_DB_DIR"
            chmod -R 755 "$CLAMAV_DB_DIR"
            
            echo -e "${GREEN}✅ ClamAV database directory permissions set for user: $ORIGINAL_USER${NC}"
            
        else
            echo -e "${RED}Homebrew not found. Please install Homebrew first or install ClamAV manually.${NC}"
            return 1
        fi
    elif [ "$OS" = "debian" ]; then
        apt-get update -qq
        apt-get install -y clamav clamav-daemon
        systemctl stop clamav-freshclam 2>/dev/null || true
    elif [ "$OS" = "redhat" ]; then
        if command -v dnf &> /dev/null; then
            dnf install -y clamav clamav-update clamd
        else
            yum install -y clamav clamav-update clamd
        fi
    else
        echo -e "${YELLOW}Please install ClamAV manually for your distribution.${NC}"
        return 1
    fi
    
    # Update virus definitions
    echo -e "${CYAN}📥 Updating virus definitions...${NC}"
    if [ "$OS" = "macos" ]; then
        # Run freshclam as the original user on macOS
        ORIGINAL_USER="${SUDO_USER:-$USER}"
        echo -e "${YELLOW}Running freshclam as $ORIGINAL_USER...${NC}"
        
        # Use sudo -u to run as regular user (not root)
        if sudo -u "$ORIGINAL_USER" freshclam 2>&1; then
            echo -e "${GREEN}✅ Virus definitions updated successfully${NC}"
        else
            echo -e "${YELLOW}⚠️  freshclam had issues, will retry later${NC}"
        fi
    else
        freshclam 2>/dev/null || true
    fi
    
    echo -e "${GREEN}✅ ClamAV installed${NC}"
    return 0
}

# Ask about ClamAV installation
INSTALL_CLAMAV="${INSTALL_CLAMAV:-}"
if [ -z "$INSTALL_CLAMAV" ]; then
    echo -e "\n${YELLOW}🛡️  Install ClamAV Antivirus? (Optional add-on)${NC}"
    echo -e "   ClamAV can scan your system for malware and viruses."
    read -p "   Install ClamAV? [y/N]: " CLAMAV_CHOICE
    if [[ "$CLAMAV_CHOICE" =~ ^[Yy]$ ]]; then
        INSTALL_CLAMAV="yes"
    fi
fi

if [ "$INSTALL_CLAMAV" = "yes" ]; then
    install_clamav || echo -e "${YELLOW}⚠️  ClamAV installation skipped${NC}"
fi

# Suricata IDS/IPS Installation Function
install_suricata() {
    echo -e "\n${CYAN}🛡️  Installing Suricata IDS/IPS...${NC}"
    
    if [ "$OS" = "macos" ]; then
        # macOS - use Homebrew
        if command -v brew &> /dev/null; then
            ORIGINAL_USER="${SUDO_USER:-$USER}"
            echo -e "${YELLOW}Installing Suricata via Homebrew as $ORIGINAL_USER...${NC}"
            sudo -u "$ORIGINAL_USER" brew install suricata 2>/dev/null || brew install suricata
        else
            echo -e "${RED}Homebrew not found. Please install Homebrew first or install Suricata manually.${NC}"
            return 1
        fi
    elif [ "$OS" = "debian" ]; then
        apt-get update -qq
        # Check if Suricata is already installed
        if command -v suricata &>/dev/null; then
            EXISTING_VER=$(suricata -V 2>&1 | grep -oE '[0-9]+\.[0-9][0-9.]*' | head -1 || echo "")
            if [ -n "$EXISTING_VER" ]; then
                echo -e "${GREEN}✅ Suricata ($EXISTING_VER) already installed${NC}"
                return 0
            fi
        fi
        
        echo -e "${YELLOW}Installing Suricata via package manager...${NC}"
        
        # Try to add OISF PPA for latest version (Ubuntu/Debian)
        if command -v add-apt-repository &>/dev/null; then
            add-apt-repository -y ppa:oisf/suricata-stable 2>/dev/null || true
            apt-get update -qq 2>/dev/null
        fi
        
        apt-get install -y suricata suricata-update 2>/dev/null || \
        apt-get install -y suricata 2>/dev/null
        
        if ! command -v suricata &>/dev/null; then
            echo -e "${RED}Failed to install Suricata via package manager${NC}"
            return 1
        fi
        
        echo -e "${GREEN}✅ Suricata installed via package manager${NC}"
    elif [ "$OS" = "redhat" ]; then
        if command -v dnf &> /dev/null; then
            dnf install -y epel-release 2>/dev/null
            dnf install -y suricata 2>/dev/null
        else
            yum install -y epel-release 2>/dev/null
            yum install -y suricata 2>/dev/null
        fi
    else
        echo -e "${YELLOW}Please install Suricata manually for your distribution.${NC}"
        return 1
    fi
    
    # Create directories
    mkdir -p /var/log/suricata /etc/suricata/rules 2>/dev/null
    chmod 755 /var/log/suricata /etc/suricata /etc/suricata/rules
    
    # Update Suricata rules using suricata-update
    echo -e "${CYAN}📥 Updating Suricata rules...${NC}"
    if command -v suricata-update &>/dev/null; then
        suricata-update 2>/dev/null || true
        echo -e "${GREEN}✅ Suricata rules updated${NC}"
    else
        echo -e "${YELLOW}⚠️  suricata-update not found, rules will be synced from Hub${NC}"
    fi
    
    # Verify installation
    if command -v suricata &> /dev/null; then
        SURI_VER=$(suricata -V 2>&1 | grep -oE '[0-9]+\.[0-9][0-9.]*' | head -1 || echo "unknown")
        echo -e "${GREEN}✅ Suricata $SURI_VER installed${NC}"
    else
        echo -e "${YELLOW}⚠️  Suricata binary not found in PATH after install${NC}"
    fi
    
    # Generate default Suricata config if missing
    if command -v suricata &> /dev/null; then
        CONFIG_FOUND=false
        for cfg in /etc/suricata/suricata.yaml /usr/local/etc/suricata/suricata.yaml /opt/homebrew/etc/suricata/suricata.yaml; do
            if [ -f "$cfg" ]; then
                CONFIG_FOUND=true
                break
            fi
        done
        
        if [ "$CONFIG_FOUND" = false ]; then
            echo -e "${YELLOW}Generating default Suricata config...${NC}"
            mkdir -p /etc/suricata/rules
            
            cat > /etc/suricata/suricata.yaml << 'SURICATAYAML'
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

default-log-dir: /var/log/suricata/

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            packet: yes
            metadata: yes
        - stats:
            totals: yes
            threads: no

af-packet:
  - interface: default

default-rule-path: /etc/suricata/rules
rule-files:
  - "*.rules"
SURICATAYAML
            
            # Create local.rules if not exists
            if [ ! -f /etc/suricata/rules/local.rules ]; then
                echo '# Security One IDS - Local Rules' > /etc/suricata/rules/local.rules
            fi
            echo -e "${GREEN}✅ Default Suricata config generated${NC}"
        fi
    fi
    
    return 0
}

# Always install Suricata (required for IDS/IPS functionality)
INSTALL_SURICATA="${INSTALL_SURICATA:-yes}"

if [ "$INSTALL_SURICATA" = "yes" ]; then
    install_suricata || echo -e "${YELLOW}⚠️  Suricata installation skipped${NC}"
fi

# Create directories
echo -e "\n${CYAN}📂 Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# Check for existing configuration BEFORE downloading or deleting files
EXISTING_ENV="$INSTALL_DIR/.env"
if [ -f "$EXISTING_ENV" ] && [ -z "$WAF_HUB_URL" ] && [ -z "$AGENT_TOKEN" ]; then
    echo -e "${YELLOW}📋 Found existing configuration, loading previous settings...${NC}"
    
    # Read existing values from .env file
    EXISTING_WAF_URL=$(grep "^WAF_URL=" "$EXISTING_ENV" | tr -d '\r' | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    EXISTING_TOKEN=$(grep "^AGENT_TOKEN=" "$EXISTING_ENV" | tr -d '\r' | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    EXISTING_NAME=$(grep "^AGENT_NAME=" "$EXISTING_ENV" | tr -d '\r' | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    
    # Use existing values if found
    if [ -n "$EXISTING_WAF_URL" ]; then
        WAF_HUB_URL="$EXISTING_WAF_URL"
        echo -e "  WAF Hub URL: ${GREEN}$WAF_HUB_URL${NC}"
    fi
    
    if [ -n "$EXISTING_TOKEN" ]; then
        AGENT_TOKEN="$EXISTING_TOKEN"
        echo -e "  Agent Token: ${GREEN}(using existing token)${NC}"
    fi
    
    if [ -n "$EXISTING_NAME" ]; then
        AGENT_NAME="$EXISTING_NAME"
        echo -e "  Agent Name: ${GREEN}$AGENT_NAME${NC}"
    fi
    
    echo -e "${GREEN}✅ Using existing configuration${NC}"
fi

# Download IDS Agent using git clone (allows git pull for updates)
echo -e "\n${CYAN}📥 Downloading Security One IDS Agent...${NC}"

# Check if git is available
if command -v git &> /dev/null; then
    # Backup existing .env if exists
    if [ -f "$INSTALL_DIR/.env" ]; then
        cp "$INSTALL_DIR/.env" /tmp/security-one-ids-env-backup
    fi
    
    # Remove old installation but keep data
    rm -rf "$INSTALL_DIR/.git" "$INSTALL_DIR/app" "$INSTALL_DIR/config" "$INSTALL_DIR/routes" "$INSTALL_DIR/resources" 2>/dev/null
    
    # Clone or update repository
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git pull origin main
    else
        git clone --depth 1 https://github.com/Cyber-Security-One/security-one-ids.git /tmp/security-one-ids-clone
        cp -r /tmp/security-one-ids-clone/* "$INSTALL_DIR/"
        cp -r /tmp/security-one-ids-clone/.git "$INSTALL_DIR/"
        rm -rf /tmp/security-one-ids-clone
    fi
    
    # Restore .env if was backed up
    if [ -f /tmp/security-one-ids-env-backup ]; then
        cp /tmp/security-one-ids-env-backup "$INSTALL_DIR/.env"
        rm /tmp/security-one-ids-env-backup
    fi
    
    echo -e "${GREEN}✅ IDS Agent downloaded via Git (supports updates)${NC}"
else
    # Fallback to zip download if git is not available
    echo -e "${YELLOW}Git not found, using zip download (git pull won't work)${NC}"
    cd /tmp
    rm -rf security-one-ids-main security-one-ids.zip
    curl -fsSL -o security-one-ids.zip https://github.com/vito1317/security-one-ids/archive/refs/heads/main.zip
    unzip -q security-one-ids.zip
    cp -r security-one-ids-main/* "$INSTALL_DIR/"
    rm -rf security-one-ids-main security-one-ids.zip
    echo -e "${GREEN}✅ IDS Agent downloaded${NC}"
fi

# Install Composer dependencies (skip scripts to avoid .env loading issues)
echo -e "\n${CYAN}📦 Installing dependencies...${NC}"
cd "$INSTALL_DIR"

# Remove any existing .env to prevent parsing errors during composer install
rm -f "$INSTALL_DIR/.env"

# Use --no-scripts to prevent artisan package:discover from running before .env is created
export COMPOSER_ALLOW_SUPERUSER=1
composer install --no-dev --optimize-autoloader --no-interaction --no-scripts 2>/dev/null || composer install --no-dev --no-interaction --no-scripts

# Configure environment
echo -e "\n${CYAN}⚙️  Configuring IDS Agent...${NC}"



# Prompt for configuration if still not set
if [ -z "$WAF_HUB_URL" ]; then
    read -p "Enter WAF Hub URL (e.g., https://waf.example.com): " WAF_HUB_URL
fi

if [ -z "$AGENT_TOKEN" ]; then
    read -p "Enter Agent Token: " AGENT_TOKEN
fi

# Strip any stray quotes from values before writing .env
WAF_HUB_URL=$(echo "$WAF_HUB_URL" | sed "s/[\"']//g")
INSTALL_TOKEN=$(echo "$INSTALL_TOKEN" | sed "s/[\"']//g")
AGENT_TOKEN=$(echo "$AGENT_TOKEN" | sed "s/[\"']//g")
AGENT_NAME=$(echo "$AGENT_NAME" | sed "s/[\"']//g")

cat > "$INSTALL_DIR/.env" << EOF
APP_NAME=SecurityOneIDS
APP_ENV=production
APP_DEBUG=false

WAF_URL=${WAF_HUB_URL}
INSTALL_TOKEN=${INSTALL_TOKEN}
AGENT_TOKEN=${AGENT_TOKEN}
AGENT_NAME=${AGENT_NAME}

OLLAMA_URL=https://ollama.futron-life.com
OLLAMA_MODEL=sentinel-security
AI_DETECTION_ENABLED=true
AI_TIMEOUT=30

LOG_CHANNEL=daily
LOG_LEVEL=info
EOF

echo -e "${GREEN}✅ Configuration saved${NC}"

# Create SQLite database and run migrations
echo -e "\n${CYAN}🗄️  Setting up database...${NC}"
touch "$INSTALL_DIR/database/database.sqlite"
cd "$INSTALL_DIR"
php artisan migrate --force 2>/dev/null || echo -e "${YELLOW}⚠️  Migration skipped (may already exist)${NC}"
php artisan package:discover --ansi 2>/dev/null || true

# Set permissions (macOS uses 'wheel' group, Linux uses 'root')
echo -e "${CYAN}🔐 Setting permissions...${NC}"

# Get the actual user (not root when running with sudo)
ACTUAL_USER="${SUDO_USER:-$USER}"

if [ "$OS" = "macos" ]; then
    # On macOS, make the actual user own the writable directories
    # This prevents "readonly database" errors when running as the user
    chown -R root:wheel "$INSTALL_DIR"
    
    # Make writable directories owned by the actual user
    chown -R "$ACTUAL_USER" "$INSTALL_DIR/storage"
    chown -R "$ACTUAL_USER" "$INSTALL_DIR/database"  
    chown -R "$ACTUAL_USER" "$INSTALL_DIR/bootstrap/cache"
    chown -R "$ACTUAL_USER" "$LOG_DIR"
else
    chown -R root:root "$INSTALL_DIR"
fi
chmod -R 755 "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/.env"

# Ensure writable directories have proper permissions
chmod -R 777 "$INSTALL_DIR/storage"
chmod -R 777 "$INSTALL_DIR/bootstrap/cache"
chmod -R 777 "$INSTALL_DIR/database"
chmod 666 "$INSTALL_DIR/database/database.sqlite"

# Also set log directory permissions
chmod -R 777 "$LOG_DIR"
echo -e "${GREEN}✅ Permissions set${NC}"

# Create systemd service (Linux) or launchd plist (macOS)
echo -e "\n${CYAN}🔧 Creating system service...${NC}"

if [ "$OS" = "macos" ]; then
    # macOS launchd - detect PHP path
    PHP_PATH=$(which php 2>/dev/null || echo "/usr/local/bin/php")
    if [ ! -f "$PHP_PATH" ]; then
        PHP_PATH="/opt/homebrew/bin/php"
    fi
    if [ ! -f "$PHP_PATH" ]; then
        PHP_PATH="/usr/bin/php"
    fi
    
    # Create both scan and sync plist files
    cat > /Library/LaunchDaemons/com.securityone.ids.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securityone.ids</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PHP_PATH</string>
        <string>$INSTALL_DIR/artisan</string>
        <string>desktop:scan</string>
        <string>--full</string>
        <string>--report</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>StartInterval</key>
    <integer>300</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/output.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
EOF
    
    # Create heartbeat sync plist (daemon mode - reads interval from Hub config)
    cat > /Library/LaunchDaemons/com.securityone.ids.sync.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securityone.ids.sync</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PHP_PATH</string>
        <string>$INSTALL_DIR/artisan</string>
        <string>waf:heartbeat</string>
        <string>--daemon</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/sync.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/sync-error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>/var/root</string>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
EOF
    
    # Unload any existing daemons first (ignore errors)
    launchctl bootout system/com.securityone.ids 2>/dev/null || launchctl unload /Library/LaunchDaemons/com.securityone.ids.plist 2>/dev/null || true
    launchctl bootout system/com.securityone.ids.sync 2>/dev/null || launchctl unload /Library/LaunchDaemons/com.securityone.ids.sync.plist 2>/dev/null || true

    # Load daemons - use bootstrap (modern macOS) with load as fallback
    launchctl bootstrap system /Library/LaunchDaemons/com.securityone.ids.plist 2>/dev/null || \
        launchctl load /Library/LaunchDaemons/com.securityone.ids.plist 2>/dev/null || true
    launchctl bootstrap system /Library/LaunchDaemons/com.securityone.ids.sync.plist 2>/dev/null || \
        launchctl load /Library/LaunchDaemons/com.securityone.ids.sync.plist 2>/dev/null || true
    echo -e "${GREEN}✅ macOS LaunchDaemons created (scan + sync)${NC}"
    
else
    # Linux systemd - Enhanced with watchdog support
    
    # Copy watchdog script to install directory
    cp "$INSTALL_DIR/install/security-one-watchdog.sh" "$INSTALL_DIR/security-one-watchdog.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/security-one-watchdog.sh"
    
    # Main watchdog service (replaces schedule:work with enhanced wrapper)
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Security One IDS Agent Watchdog
After=network.target
StartLimitIntervalSec=600
StartLimitBurst=10

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash $INSTALL_DIR/security-one-watchdog.sh
Restart=always
RestartSec=10
WatchdogSec=300
MemoryLimit=512M
TimeoutStopSec=30

# Environment
Environment=HOME=/root
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=multi-user.target
EOF

    # Create timer for periodic scans (backup if watchdog fails)
    cat > /etc/systemd/system/$SERVICE_NAME-scan.timer << EOF
[Unit]
Description=Security One IDS Periodic Scan (Backup)

[Timer]
OnBootSec=5min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF

    cat > /etc/systemd/system/$SERVICE_NAME-scan.service << EOF
[Unit]
Description=Security One IDS Scan

[Service]
Type=oneshot
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/php $INSTALL_DIR/artisan desktop:scan --full
TimeoutStartSec=300
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    systemctl enable $SERVICE_NAME-scan.timer
    systemctl restart $SERVICE_NAME 2>/dev/null || systemctl start $SERVICE_NAME
    systemctl start $SERVICE_NAME-scan.timer
    
    echo -e "${GREEN}✅ Systemd service created with auto-recovery watchdog${NC}"
fi

# Register with WAF Hub
echo -e "\n${CYAN}📡 Registering with WAF Hub...${NC}"
cd "$INSTALL_DIR"
php artisan waf:sync --register || echo -e "${YELLOW}⚠️  Registration will retry on next scan${NC}"

# Run initial scan with full AI analysis
echo -e "\n${CYAN}🔍 Running initial security scan...${NC}"
php artisan desktop:scan --full --report

# Create convenience commands
echo -e "\n${CYAN}🔧 Creating convenience commands...${NC}"

cat > /usr/local/bin/ids-scan << 'EOF'
#!/bin/bash
cd /opt/security-one-ids && php artisan desktop:scan "$@"
EOF
chmod +x /usr/local/bin/ids-scan

cat > /usr/local/bin/ids-status << 'EOF'
#!/bin/bash
if [[ "$OSTYPE" == "darwin"* ]]; then
    launchctl list | grep securityone
else
    systemctl status security-one-ids
fi
EOF
chmod +x /usr/local/bin/ids-status

echo -e "${GREEN}
╔═══════════════════════════════════════════════════╗
║      ✅ Installation Complete!                     ║
╠═══════════════════════════════════════════════════╣
║  Install Path: $INSTALL_DIR
║  Log Path:     $LOG_DIR
║  
║  Commands:
║    ids-scan         Quick security scan
║    ids-scan --full  Full AI analysis
║    ids-status       Check service status
║
║  Manual Commands:
║    cd $INSTALL_DIR
║    php artisan desktop:scan
║    php artisan desktop:scan --full --report
║
╚═══════════════════════════════════════════════════╝
${NC}"

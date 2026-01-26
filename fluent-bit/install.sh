#!/bin/bash
# Fluent Bit Installation Script for Linux and macOS
# Run with sudo

set -e

CONFIG_PATH="/etc/fluent-bit"
SERVICE_NAME="fluent-bit"

echo "Installing Fluent Bit..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

if [[ "$OS" == "linux" ]]; then
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION_ID=$VERSION_ID
    else
        echo "Cannot detect Linux distribution"
        exit 1
    fi

    echo "Detected distribution: $DISTRO"

    case "$DISTRO" in
        ubuntu|debian)
            echo "Installing Fluent Bit on Debian or Ubuntu..."

            curl -fsSL https://packages.fluentbit.io/fluentbit.key \
                | gpg --dearmor \
                | tee /usr/share/keyrings/fluentbit-keyring.gpg > /dev/null

            CODENAME=$(lsb_release -cs 2>/dev/null || echo "")

            case "$CODENAME" in
                jammy|focal|noble|bullseye|bookworm)
                    ;;
                plucky)
                    echo "Ubuntu plucky detected. Fluent Bit repo unavailable. Using noble."
                    CODENAME="noble"
                    ;;
                *)
                    echo "Unknown codename $CODENAME. Defaulting to jammy."
                    CODENAME="jammy"
                    ;;
            esac

            echo "Using codename: $CODENAME"

            echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/$DISTRO/$CODENAME $CODENAME main" \
                | tee /etc/apt/sources.list.d/fluent-bit.list

            apt-get update
            apt-get install -y fluent-bit
            ;;
        centos|rhel|fedora|rocky|almalinux)
            echo "Installing Fluent Bit on RHEL based system..."

            cat > /etc/yum.repos.d/fluent-bit.repo << 'EOF'
[fluent-bit]
name=Fluent Bit
baseurl=https://packages.fluentbit.io/centos/$releasever/$basearch/
gpgcheck=1
gpgkey=https://packages.fluentbit.io/fluentbit.key
enabled=1
EOF

            yum install -y fluent-bit
            ;;
        *)
            echo "Unsupported Linux distribution: $DISTRO"
            exit 1
            ;;
    esac

elif [[ "$OS" == "macos" ]]; then
    echo "Installing Fluent Bit on macOS..."

    if ! command -v brew >/dev/null 2>&1; then
        echo "Homebrew not found. Install Homebrew first."
        exit 1
    fi

    brew install fluent-bit
fi

echo "Creating directories..."
mkdir -p "$CONFIG_PATH"
mkdir -p /var/log/fluent-bit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -f "$SCRIPT_DIR/fluent-bit.conf" ]; then
    echo "Copying configuration files..."
    cp "$SCRIPT_DIR/fluent-bit.conf" "$CONFIG_PATH/"
    [ -f "$SCRIPT_DIR/parsers.conf" ] && cp "$SCRIPT_DIR/parsers.conf" "$CONFIG_PATH/"
fi

if [[ "$OS" == "linux" ]]; then
    chown -R fluent-bit:fluent-bit /var/log/fluent-bit 2>/dev/null || true

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"

    echo "Fluent Bit service started"
    echo "Status: sudo systemctl status $SERVICE_NAME"
fi

echo "Fluent Bit installation completed"
echo "Config path: $CONFIG_PATH/fluent-bit.conf"

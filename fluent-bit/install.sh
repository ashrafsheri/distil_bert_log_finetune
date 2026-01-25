#!/bin/bash
# Fluent Bit Installation Script for Linux/Mac
# Run with sudo

set -e

# Configuration
CONFIG_PATH="/etc/fluent-bit"
SERVICE_NAME="fluent-bit"

echo "Installing Fluent Bit for Linux..."

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
    # Detect Linux distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION_ID=$VERSION_ID
    else
        echo "Cannot detect Linux distribution"
        exit 1
    fi
    
    echo "Detected distribution: $DISTRO"
    
    # Install Fluent Bit using official repositories
    case $DISTRO in
        ubuntu|debian)
            echo "Installing Fluent Bit on Debian/Ubuntu..."
            
            # Add GPG key
            curl https://packages.fluentbit.io/fluentbit.key | gpg --dearmor > /usr/share/keyrings/fluentbit-keyring.gpg
            
            # Detect codename for Ubuntu/Debian
            CODENAME=$(lsb_release -cs 2>/dev/null || echo "")
            if [ -z "$CODENAME" ]; then
                # Fallback for common versions
                case $VERSION_ID in
                    22.04) CODENAME="jammy" ;;
                    20.04) CODENAME="focal" ;;
                    24.04) CODENAME="noble" ;;
                    11) CODENAME="bullseye" ;;
                    12) CODENAME="bookworm" ;;
                    *) CODENAME="jammy" ;;
                esac
            fi
            
            echo "Using codename: $CODENAME"
            
            # Add repository
            echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/$DISTRO/$CODENAME $CODENAME main" | tee /etc/apt/sources.list.d/fluent-bit.list
            
            # Update and install
            apt-get update
            apt-get install -y fluent-bit
            ;;
            
        centos|rhel|fedora|rocky|almalinux)
            echo "Installing Fluent Bit on RHEL-based system..."
            
            # Add repository
            cat > /etc/yum.repos.d/fluent-bit.repo << 'EOF'
[fluent-bit]
name = Fluent Bit
baseurl = https://packages.fluentbit.io/centos/$releasever/$basearch/
gpgcheck=1
gpgkey=https://packages.fluentbit.io/fluentbit.key
enabled=1
EOF
            
            # Install
            yum install -y fluent-bit
            ;;
            
        *)
            echo "Unsupported distribution: $DISTRO"
            echo "Please install Fluent Bit manually from https://docs.fluentbit.io/manual/installation/linux"
            exit 1
            ;;
    esac
    
elif [[ "$OS" == "macos" ]]; then
    echo "Installing Fluent Bit on macOS..."
    
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed. Please install Homebrew first:"
        echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
        exit 1
    fi
    
    # Install via Homebrew
    brew install fluent-bit
fi

# Create directories
echo "Creating configuration directories..."
mkdir -p "$CONFIG_PATH"
mkdir -p "/var/log/fluent-bit"

# Create directories
echo "Creating configuration directories..."
mkdir -p "$CONFIG_PATH"
mkdir -p "/var/log/fluent-bit"

# Copy configuration files if they exist in current directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/fluent-bit.conf" ]; then
    echo "Installing custom configuration..."
    cp "$SCRIPT_DIR/fluent-bit.conf" "$CONFIG_PATH/"
    cp "$SCRIPT_DIR/parsers.conf" "$CONFIG_PATH/" 2>/dev/null || true
fi

# Set permissions
if [[ "$OS" == "linux" ]]; then
    chown -R fluent-bit:fluent-bit "/var/log/fluent-bit" 2>/dev/null || true
    
    # Enable and start service
    echo "Enabling and starting Fluent Bit service..."
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    
    echo "Service started successfully"
    echo ""
    echo "To manage the service:"
    echo "  Start:   sudo systemctl start $SERVICE_NAME"
    echo "  Stop:    sudo systemctl stop $SERVICE_NAME"
    echo "  Restart: sudo systemctl restart $SERVICE_NAME"
    echo "  Status:  sudo systemctl status $SERVICE_NAME"
    echo "  Logs:    sudo journalctl -u $SERVICE_NAME -f"
fi

echo ""
echo "Fluent Bit installation completed!"
echo "Configuration: $CONFIG_PATH/fluent-bit.conf"
echo ""
echo "Edit the configuration file and restart the service to apply changes."

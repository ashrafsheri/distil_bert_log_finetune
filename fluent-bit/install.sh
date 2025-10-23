#!/bin/bash
# Fluent Bit Installation Script for Linux/Mac
# Run with sudo

set -e

# Configuration
INSTALL_PATH="/opt/fluent-bit"
SERVICE_USER="fluent-bit"
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

# Create user if it doesn't exist
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "Creating user: $SERVICE_USER"
    useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
fi

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_PATH"
mkdir -p "$CONFIG_PATH"
mkdir -p "/var/log/fluent-bit"

# Download Fluent Bit
echo "Downloading Fluent Bit..."
cd /tmp

if [[ "$OS" == "linux" ]]; then
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    FLUENT_BIT_URL="https://github.com/fluent/fluent-bit/releases/latest/download/fluent-bit-2.2.0-linux-${ARCH}.tar.gz"
elif [[ "$OS" == "macos" ]]; then
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        arm64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    FLUENT_BIT_URL="https://github.com/fluent/fluent-bit/releases/latest/download/fluent-bit-2.2.0-darwin-${ARCH}.tar.gz"
fi

wget -O fluent-bit.tar.gz "$FLUENT_BIT_URL"

# Extract Fluent Bit
echo "Extracting Fluent Bit..."
tar -xzf fluent-bit.tar.gz
cp -r fluent-bit-*/bin "$INSTALL_PATH/"
cp -r fluent-bit-*/lib "$INSTALL_PATH/"

# Copy configuration files
echo "Installing configuration..."
cp fluent-bit.conf "$CONFIG_PATH/"
cp parsers.conf "$CONFIG_PATH/"

# Set permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_PATH"
chown -R "$SERVICE_USER:$SERVICE_USER" "$CONFIG_PATH"
chown -R "$SERVICE_USER:$SERVICE_USER" "/var/log/fluent-bit"

# Create systemd service (Linux only)
if [[ "$OS" == "linux" ]]; then
    echo "Creating systemd service..."
    cat > /etc/systemd/system/fluent-bit.service << EOF
[Unit]
Description=Fluent Bit Log Shipper
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
ExecStart=$INSTALL_PATH/bin/fluent-bit -c $CONFIG_PATH/fluent-bit.conf
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Enable and start service
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"
    
    echo "Service started successfully"
    echo "To manage the service:"
    echo "  Start:   sudo systemctl start $SERVICE_NAME"
    echo "  Stop:    sudo systemctl stop $SERVICE_NAME"
    echo "  Status:  sudo systemctl status $SERVICE_NAME"
    echo "  Logs:    sudo journalctl -u $SERVICE_NAME -f"
fi

# Cleanup
rm -rf fluent-bit.tar.gz fluent-bit-*

echo "Fluent Bit installation completed!"
echo "Installation Path: $INSTALL_PATH"
echo "Configuration: $CONFIG_PATH/fluent-bit.conf"

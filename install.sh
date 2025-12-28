#!/bin/bash
set -e

# NannyAgent Installer Script
# Description: Installs NannyAgent Linux diagnostic tool with eBPF capabilities and systemd support
INSTALL_DIR="/usr/sbin"
CONFIG_DIR="/etc/nannyagent"
DATA_DIR="/var/lib/nannyagent"
BINARY_NAME="nannyagent"
LOCKFILE="${DATA_DIR}/.nannyagent.lock"
SYSTEMD_SERVICE="nannyagent.service"
SYSTEMD_DIR="/etc/systemd/system"

# GitHub repository for releases
GITHUB_REPO="${GITHUB_REPO:-harshavmb/nannyagent}"
INSTALL_FROM_SOURCE="${INSTALL_FROM_SOURCE:-false}"
# Auto-detect latest version if not specified
INSTALL_VERSION="${INSTALL_VERSION:-latest}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This installer must be run as root"
        log_info "Please run: sudo bash install.sh"
        exit 1
    fi
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    log_info "Detected OS: $OS"
    log_info "Detected Architecture: $ARCH"

    # Check if OS is Linux
    if [ "$OS" != "linux" ]; then
        log_error "Unsupported operating system: $OS"
        log_error "This installer only supports Linux"
        exit 2
    fi

    # Check if architecture is supported (amd64 or arm64)
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            log_error "Only amd64 (x86_64) and arm64 (aarch64) are supported"
            exit 3
            ;;
    esac

    # Check if running in container/LXC
    if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
        log_error "Container environment detected (Docker)"
        log_error "NannyAgent does not support running inside containers or LXC"
        exit 4
    fi

    if [ -f /proc/1/environ ] && grep -q "container=lxc" /proc/1/environ 2>/dev/null; then
        log_error "LXC environment detected"
        log_error "NannyAgent does not support running inside containers or LXC"
        exit 4
    fi
}

# Check kernel version (5.x or higher)
check_kernel_version() {
    log_info "Checking kernel version..."
    
    KERNEL_VERSION=$(uname -r)
    KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
    
    log_info "Kernel version: $KERNEL_VERSION"
    
    if [ "$KERNEL_MAJOR" -lt 5 ]; then
        log_error "Kernel version $KERNEL_VERSION is not supported"
        log_error "NannyAgent requires Linux kernel 5.x or higher"
        log_error "Current kernel: $KERNEL_VERSION (major version: $KERNEL_MAJOR)"
        exit 5
    fi
    
    log_success "Kernel version $KERNEL_VERSION is supported"
}

# Check if another instance is already installed
check_existing_installation() {
    log_info "Checking for existing installation..."
    
    # Check if binary already exists
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        CURRENT_VERSION=$("$INSTALL_DIR/$BINARY_NAME" --version 2>/dev/null | grep -oP 'version \K[0-9.]+' || echo "unknown")
        log_warning "Binary $INSTALL_DIR/$BINARY_NAME already exists (version: $CURRENT_VERSION)"
        log_warning "It will be replaced with the new version"
    fi
    
    # Check if data directory exists with registered agent
    if [ -f "$DATA_DIR/token.json" ]; then
        log_info "Detected existing agent registration (token found)"
        log_info "Agent registration will be preserved during upgrade"
    fi
    
    log_success "Installation check complete"
}

# Install required dependencies (eBPF tools)
install_dependencies() {
    log_info "Installing eBPF dependencies..."
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        log_info "Detected Debian/Ubuntu system"
        
        # Update package list
        log_info "Updating package list..."
        apt-get update -qq || {
            log_error "Failed to update package list"
            exit 7
        }
        
        # Install bpftrace, and unzip
        log_info "Installing bpftrace, and unzip..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftrace unzip 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }
        
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        log_info "Detected Fedora/RHEL 8+ system"
        
        log_info "Installing bpftrace, and unzip..."
        dnf install -y -q bpftrace unzip 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }
        
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        log_info "Detected CentOS/RHEL 7 system"
        
        log_info "Installing bpftrace and unzip..."
        yum install -y -q bpftrace unzip 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }

    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
        log_info "Detected Arch Linux system"
        
        log_info "Installing bpftrace, and unzip..."
        pacman -Sy --noconfirm bpftrace unzip 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }

    elif command -v zypper &> /dev/null; then
        PKG_MANAGER="zypper"
        log_info "Detected openSUSE/SLE system"
        
        log_info "Installing bpftrace, and unzip..."
        zypper install -y bpftrace unzip 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }
        
    else
        log_error "Unsupported package manager"
        log_error "Please install 'unzip' and 'bpftrace' manually"
        exit 7
    fi
    
    # Verify installations
    if ! command -v bpftrace &> /dev/null; then
        log_error "bpftrace installation failed or not in PATH"
        exit 7
    fi    
}

# Download pre-built binary from GitHub releases
download_binary() {
    log_info "Downloading pre-built NannyAgent binary for $ARCH..."
    
    # Determine version to install
    if [ "$INSTALL_VERSION" = "latest" ]; then
        log_info "Fetching latest release version from GitHub..."
        if command -v curl &> /dev/null; then
            LATEST_VERSION=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        elif command -v wget &> /dev/null; then
            LATEST_VERSION=$(wget -qO- "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        else
            log_error "Neither curl nor wget found. Cannot fetch latest version."
            log_error "Please install curl or wget"
            exit 8
        fi
        
        if [ -z "$LATEST_VERSION" ]; then
            log_error "Failed to fetch latest version from GitHub"
            log_error "Please check your internet connection or try building from source"
            log_error "To build from source: export INSTALL_FROM_SOURCE=true"
            exit 8
        fi
        
        VERSION="$LATEST_VERSION"
        log_info "Latest version: v$VERSION"
    else
        VERSION="$INSTALL_VERSION"
        log_info "Installing version: v$VERSION"
    fi
    
    # Download URLs from GitHub releases (goreleaser format)
    ARCHIVE_NAME="nannyagent_${VERSION}_linux_${ARCH}.tar.gz"
    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/${ARCHIVE_NAME}"
    CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}/checksums.txt"
    
    log_info "Download URL: $DOWNLOAD_URL"
    
    # Download archive using curl or wget
    if command -v curl &> /dev/null; then
        curl -fsSL "$DOWNLOAD_URL" -o "$ARCHIVE_NAME" || {
            log_error "Failed to download binary from $DOWNLOAD_URL"
            log_error "Please check your internet connection or try building from source"
            log_error "To build from source: export INSTALL_FROM_SOURCE=true"
            exit 8
        }
        curl -fsSL "$CHECKSUM_URL" -o "checksums.txt" || {
            log_warning "Failed to download checksums file"
        }
    elif command -v wget &> /dev/null; then
        wget -q "$DOWNLOAD_URL" -O "$ARCHIVE_NAME" || {
            log_error "Failed to download binary from $DOWNLOAD_URL"
            log_error "Please check your internet connection or try building from source"
            log_error "To build from source: export INSTALL_FROM_SOURCE=true"
            exit 8
        }
        wget -q "$CHECKSUM_URL" -O "checksums.txt" || {
            log_warning "Failed to download checksums file"
        }
    else
        log_error "Neither curl nor wget found. Cannot download binary."
        log_error "Please install curl or wget"
        exit 8
    fi
    
    # Verify checksum if available
    if [ -f "checksums.txt" ]; then
        log_info "Verifying checksum..."
        if command -v sha256sum &> /dev/null; then
            grep "$ARCHIVE_NAME" checksums.txt | sha256sum -c - || {
                log_error "Checksum verification failed!"
                log_error "Downloaded file may be corrupted or tampered with"
                rm -f "$ARCHIVE_NAME" checksums.txt
                exit 8
            }
            log_success "Checksum verified successfully"
            rm -f checksums.txt
        else
            log_warning "sha256sum not found, skipping checksum verification"
        fi
    fi
    
    # Extract binary from tar.gz
    if command -v tar &> /dev/null; then
        tar -xzf "$ARCHIVE_NAME" "$BINARY_NAME" || {
            log_error "Failed to extract binary from archive"
            exit 8
        }
        rm "$ARCHIVE_NAME"
    else
        log_error "tar not found. Please install tar package"
        exit 8
    fi
    
    # Make binary executable
    chmod +x "$BINARY_NAME"
    
    # Test the binary
    if ./"$BINARY_NAME" --version &>/dev/null; then
        log_success "Binary downloaded and tested successfully for $ARCH (version: v$VERSION)"
    else
        log_error "Binary download succeeded but execution test failed"
        exit 8
    fi
}

# Check Go installation
check_go() {
    log_info "Checking for Go installation..."
    
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        log_error "Please install Go 1.23 or higher from https://golang.org/dl/"
        exit 9
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $GO_VERSION"
    log_success "Go is installed"
}

# Build the binary
build_binary() {
    log_info "Building NannyAgent binary for $ARCH architecture..."
    
    # Check if go.mod exists
    if [ ! -f "go.mod" ]; then
        log_error "go.mod not found. Are you in the correct directory?"
        exit 9
    fi
    
    # Read version from VERSION file
    if [ -f "VERSION" ]; then
        BUILD_VERSION=$(cat VERSION)
    else
        BUILD_VERSION="dev"
    fi
    log_info "Building version: $BUILD_VERSION"
    
    # Get Go dependencies
    log_info "Downloading Go dependencies..."
    go mod download || {
        log_error "Failed to download Go dependencies"
        exit 9
    }
    
    # Build the binary for the current architecture
    log_info "Compiling binary for $ARCH..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -a -installsuffix cgo \
        -ldflags "-w -s -X main.Version=$BUILD_VERSION" \
        -o "$BINARY_NAME" . || {
        log_error "Failed to build binary for $ARCH"
        exit 9
    }
    
    # Verify binary was created
    if [ ! -f "$BINARY_NAME" ]; then
        log_error "Binary not found after build"
        exit 9
    fi
    
    # Verify binary is executable
    chmod +x "$BINARY_NAME"
    
    # Test the binary
    if ./"$BINARY_NAME" --version &>/dev/null; then
        log_success "Binary built and tested successfully for $ARCH (version: $BUILD_VERSION)"
    else
        log_error "Binary build succeeded but execution test failed"
        exit 9
    fi
}

# Check connectivity to NannyAPI
check_connectivity() {
    log_info "Checking connectivity to NannyAPI..."
    
    # Check env var first
    API_URL="${NANNYAPI_URL}"
    
    # If not set, try to grep from config.yaml if it exists
    if [ -z "$API_URL" ] && [ -f "$CONFIG_DIR/config.yaml" ]; then
        API_URL=$(grep "nannyapi_url:" "$CONFIG_DIR/config.yaml" | awk '{print $2}' | tr -d '"')
    fi
    
    # Default if nothing found
    if [ -z "$API_URL" ]; then
        API_URL="http://localhost:8090"
    fi
    
    log_info "Testing connection to $API_URL..."
    
    # Try to reach the endpoint
    if command -v curl &> /dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$API_URL/api/health" || echo "000")
        
        if [ "$HTTP_CODE" = "000" ]; then
            log_warning "Cannot connect to $API_URL"
            log_warning "Network connectivity issue detected or server is down"
        elif [ "$HTTP_CODE" = "200" ]; then
            log_success "Successfully connected to NannyAPI"
        else
            log_warning "Received HTTP $HTTP_CODE from $API_URL"
        fi
    else
        log_warning "curl not found, skipping connectivity check"
    fi
}

# Create necessary directories
create_directories() {
    log_info "Creating directories..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR" || {
        log_error "Failed to create config directory: $CONFIG_DIR"
        exit 10
    }
    
    # Create data directory with restricted permissions
    mkdir -p "$DATA_DIR" || {
        log_error "Failed to create data directory: $DATA_DIR"
        exit 10
    }
    chmod 700 "$DATA_DIR"
    
    log_success "Directories created successfully"
}

# Install the binary
install_binary() {
    log_info "Installing binary to $INSTALL_DIR..."
    
    # Copy binary
    cp "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME" || {
        log_error "Failed to copy binary to $INSTALL_DIR"
        exit 11
    }
    
    # Set permissions
    chmod 755 "$INSTALL_DIR/$BINARY_NAME"
    
    # Create config.yaml if it doesn't exist
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        log_info "Creating default configuration at $CONFIG_DIR/config.yaml..."
        cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# NannyAgent Configuration File
# Location: /etc/nannyagent/config.yaml

# NannyAPI Endpoint (required)
# Default: http://localhost:8090
nannyapi_url: "http://localhost:8090"

# Portal URL for device authorization (optional)
# Default: https://nannyai.dev
portal_url: "https://nannyai.dev"

# Token storage path (optional)
# Default: /var/lib/nannyagent/token.json
token_path: "/var/lib/nannyagent/token.json"

# Metrics collection interval in seconds (optional)
# Default: 30 for node, 300 for proxmox
metrics_interval: 30
proxmox_interval: 300

# Debug mode (optional)
# Default: false
debug: false
EOF
        chmod 600 "$CONFIG_DIR/config.yaml"
        log_success "Created default config.yaml"
    else
        log_info "Configuration file already exists at $CONFIG_DIR/config.yaml"
    fi
    
    # Create lock file
    touch "$LOCKFILE"
    echo "Installed at $(date)" > "$LOCKFILE"
    
    log_success "Binary installed successfully"
}

# Install systemd service
install_systemd_service() {
    log_info "Installing systemd service..."
    
    # Check if systemd is available
    if ! command -v systemctl &> /dev/null; then
        log_warning "systemctl not found. Skipping systemd service installation."
        log_warning "You can run nannyagent manually: sudo $INSTALL_DIR/$BINARY_NAME"
        return
    fi
    
    # Create systemd service file
    cat > "$SYSTEMD_DIR/$SYSTEMD_SERVICE" << 'EOF'
[Unit]
Description=NannyAgent - AI-Powered Linux Diagnostic Agent
Documentation=https://nannyai.dev/documentation
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/nannyagent --daemon
Restart=always
RestartSec=10s

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nannyagent

# Working Directory
WorkingDirectory=/var/lib/nannyagent

# Run as root (required for eBPF)
User=root
Group=root

# Security hardening
PrivateTmp=true
## need a thorough review on this, anything else other than this fails as
## as patching literally touches every filesystem, cannot be strict/full
ProtectSystem=false
ReadWritePaths=/var/lib/nannyagent
NoNewPrivileges=false
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON

[Install]
WantedBy=multi-user.target
EOF
    
    chmod 644 "$SYSTEMD_DIR/$SYSTEMD_SERVICE"
    
    # Reload systemd daemon
    systemctl daemon-reload || {
        log_error "Failed to reload systemd daemon"
        exit 12
    }
    
    log_success "Systemd service installed successfully"
    log_info "To enable and start the service:"
    log_info "  sudo systemctl enable --now $SYSTEMD_SERVICE"
}

# Display post-installation information
post_install_info() {
    echo ""
    log_success "NannyAgent v$VERSION installed successfully!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Configuration: $CONFIG_DIR/config.yaml"
    echo "  Data Directory: $DATA_DIR"
    echo "  Binary Location: $INSTALL_DIR/$BINARY_NAME"
    echo "  Service: $SYSTEMD_DIR/$SYSTEMD_SERVICE"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Configure your NannyAPI URL in $CONFIG_DIR/config.yaml"
    echo "     Default: http://localhost:8090"
    echo ""
    echo "  2. Register the agent with NannyAI:"
    echo "     sudo nannyagent --register"
    echo ""
    echo "  3. Enable and start the systemd service:"
    echo "     sudo systemctl enable --now nannyagent"
    echo ""
    echo "  4. Check agent status:"
    echo "     nannyagent --status"
    echo "     sudo systemctl status nannyagent"
    echo ""
    echo "  5. Run a one-off diagnosis:"
    echo "     sudo nannyagent --diagnose \"postgresql is having troubles\""
    echo ""
    echo "  6. View logs:"
    echo "     sudo journalctl -u nannyagent -f"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  NannyAgent Installer v$VERSION"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    check_root
    detect_platform
    check_kernel_version
    check_existing_installation
    install_dependencies
    create_directories
    
    # Download pre-built binary or build from source
    if [ "$INSTALL_FROM_SOURCE" = "true" ] || [ -f "go.mod" ]; then
        log_info "Building from source..."
        check_go
        build_binary
    else
        log_info "Downloading pre-built binary..."
        download_binary
    fi
    
    check_connectivity
    install_binary
    install_systemd_service
    post_install_info
}

# Run main installation
main

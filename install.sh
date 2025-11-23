#!/bin/bash
set -e

# NannyAgent Installer Script
# Version: 0.0.1
# Description: Installs NannyAgent Linux diagnostic tool with eBPF capabilities

VERSION="0.0.1"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nannyagent"
DATA_DIR="/var/lib/nannyagent"
BINARY_NAME="nannyagent"
LOCKFILE="${DATA_DIR}/.nannyagent.lock"

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
    
    # Check if lock file exists
    if [ -f "$LOCKFILE" ]; then
        log_error "An installation lock file exists at $LOCKFILE"
        log_error "Another instance of NannyAgent may already be installed or running"
        log_error "If you're sure no other instance exists, remove the lock file:"
        log_error "  sudo rm $LOCKFILE"
        exit 6
    fi
    
    # Check if data directory exists and has files
    if [ -d "$DATA_DIR" ]; then
        FILE_COUNT=$(find "$DATA_DIR" -type f 2>/dev/null | wc -l)
        if [ "$FILE_COUNT" -gt 0 ]; then
            log_error "Data directory $DATA_DIR already exists with $FILE_COUNT files"
            log_error "Another instance of NannyAgent may already be installed"
            log_error "To reinstall, please remove the data directory first:"
            log_error "  sudo rm -rf $DATA_DIR"
            exit 6
        fi
    fi
    
    # Check if binary already exists
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        log_warning "Binary $INSTALL_DIR/$BINARY_NAME already exists"
        log_warning "It will be replaced with the new version"
    fi
    
    log_success "No conflicting installation found"
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
        
        # Install bpfcc-tools and bpftrace
        log_info "Installing bpfcc-tools and bpftrace..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpfcc-tools bpftrace linux-headers-$(uname -r) 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }
        
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        log_info "Detected Fedora/RHEL 8+ system"
        
        log_info "Installing bcc-tools and bpftrace..."
        dnf install -y -q bcc-tools bpftrace kernel-devel 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }
        
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        log_info "Detected CentOS/RHEL 7 system"
        
        log_info "Installing bcc-tools and bpftrace..."
        yum install -y -q bcc-tools bpftrace kernel-devel 2>&1 || {
            log_error "Failed to install eBPF tools"
            exit 7
        }
        
    else
        log_error "Unsupported package manager"
        log_error "Please install 'bpfcc-tools' and 'bpftrace' manually"
        exit 7
    fi
    
    # Verify installations
    if ! command -v bpftrace &> /dev/null; then
        log_error "bpftrace installation failed or not in PATH"
        exit 7
    fi
    
    # Check for BCC tools (RedHat systems may have them in /usr/share/bcc/tools/)
    if [ -d "/usr/share/bcc/tools" ]; then
        log_info "BCC tools found at /usr/share/bcc/tools/"
        # Add to PATH if not already there
        if [[ ":$PATH:" != *":/usr/share/bcc/tools:"* ]]; then
            export PATH="/usr/share/bcc/tools:$PATH"
            log_info "Added /usr/share/bcc/tools to PATH"
        fi
    fi
    
    log_success "eBPF tools installed successfully"
}

# Check Go installation
check_go() {
    log_info "Checking for Go installation..."
    
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        log_error "Please install Go 1.23 or higher from https://golang.org/dl/"
        exit 8
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
    
    # Get Go dependencies
    log_info "Downloading Go dependencies..."
    go mod download || {
        log_error "Failed to download Go dependencies"
        exit 9
    }
    
    # Build the binary for the current architecture
    log_info "Compiling binary for $ARCH..."
    CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -a -installsuffix cgo \
        -ldflags "-w -s -X main.Version=$VERSION" \
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
        log_success "Binary built and tested successfully for $ARCH"
    else
        log_error "Binary build succeeded but execution test failed"
        exit 9
    fi
}

# Check connectivity to Supabase
check_connectivity() {
    log_info "Checking connectivity to Supabase..."
    
    # Load SUPABASE_PROJECT_URL from .env if it exists
    if [ -f ".env" ]; then
        source .env 2>/dev/null || true
    fi
    
    if [ -z "$SUPABASE_PROJECT_URL" ]; then
        log_warning "SUPABASE_PROJECT_URL not set in .env file"
        log_warning "The agent may not work without proper configuration"
        log_warning "Please configure $CONFIG_DIR/config.env after installation"
        return
    fi
    
    log_info "Testing connection to $SUPABASE_PROJECT_URL..."
    
    # Try to reach the Supabase endpoint
    if command -v curl &> /dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$SUPABASE_PROJECT_URL" || echo "000")
        
        if [ "$HTTP_CODE" = "000" ]; then
            log_warning "Cannot connect to $SUPABASE_PROJECT_URL"
            log_warning "Network connectivity issue detected"
            log_warning "The agent will not work without connectivity to Supabase"
            log_warning "Please check your network configuration and firewall settings"
        elif [ "$HTTP_CODE" = "404" ] || [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
            log_success "Successfully connected to Supabase (HTTP $HTTP_CODE)"
        else
            log_warning "Received HTTP $HTTP_CODE from $SUPABASE_PROJECT_URL"
            log_warning "The agent may not work correctly"
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
    
    # Copy .env to config if it exists
    if [ -f ".env" ]; then
        log_info "Copying configuration to $CONFIG_DIR..."
        cp .env "$CONFIG_DIR/config.env"
        chmod 600 "$CONFIG_DIR/config.env"
    fi
    
    # Create lock file
    touch "$LOCKFILE"
    echo "Installed at $(date)" > "$LOCKFILE"
    
    log_success "Binary installed successfully"
}

# Display post-installation information
post_install_info() {
    echo ""
    log_success "NannyAgent v$VERSION installed successfully!"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  Configuration: $CONFIG_DIR/config.env"
    echo "  Data Directory: $DATA_DIR"
    echo "  Binary Location: $INSTALL_DIR/$BINARY_NAME"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Next steps:"
    echo ""
    echo "  1. Configure your Supabase URL in $CONFIG_DIR/config.env"
    echo "  2. Run the agent: sudo $BINARY_NAME"
    echo "  3. Check version: $BINARY_NAME --version"
    echo "  4. Get help: $BINARY_NAME --help"
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
    check_go
    build_binary
    check_connectivity
    create_directories
    install_binary
    post_install_info
}

# Run main installation
main

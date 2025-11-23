# NannyAgent Installation Guide

## Quick Install

### One-Line Install (Recommended)

After uploading `install.sh` to your website:

```bash
curl -fsSL https://your-domain.com/install.sh | sudo bash
```

Or with wget:

```bash
wget -qO- https://your-domain.com/install.sh | sudo bash
```

### Two-Step Install (More Secure)

Download and inspect the installer first:

```bash
# Download the installer
curl -fsSL https://your-domain.com/install.sh -o install.sh

# Inspect the script (recommended!)
less install.sh

# Make it executable
chmod +x install.sh

# Run the installer
sudo ./install.sh
```

## Installation from GitHub

If you're hosting on GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/yourusername/nannyagent/main/install.sh | sudo bash
```

## System Requirements

Before installing, ensure your system meets these requirements:

### Operating System
- ✅ Linux (any distribution)
- ❌ Windows (not supported)
- ❌ macOS (not supported)
- ❌ Containers/Docker (not supported)
- ❌ LXC (not supported)

### Architecture
- ✅ amd64 (x86_64)
- ✅ arm64 (aarch64)
- ❌ i386/i686 (32-bit not supported)
- ❌ Other architectures (not supported)

### Kernel Version
- ✅ Linux kernel 5.x or higher
- ❌ Linux kernel 4.x or lower (not supported)

Check your kernel version:
```bash
uname -r
# Should show 5.x.x or higher
```

### Privileges
- Must have root/sudo access
- Will create system directories:
  - `/usr/local/bin/nannyagent` (binary)
  - `/etc/nannyagent` (configuration)
  - `/var/lib/nannyagent` (data directory)

### Network
- Connectivity to Supabase backend required
- HTTPS access to your Supabase project URL
- No proxy support at this time

## What the Installer Does

The installer performs these steps automatically:

1. ✅ **System Checks**
   - Verifies root privileges
   - Detects OS and architecture
   - Checks kernel version (5.x+)
   - Detects container environments
   - Checks for existing installations

2. ✅ **Dependency Installation**
   - Installs `bpftrace` (eBPF tracing tool)
   - Installs `bpfcc-tools` (BCC toolkit)
   - Installs kernel headers if needed
   - Uses your system's package manager (apt/dnf/yum)

3. ✅ **Build & Install**
   - Verifies Go installation (required for building)
   - Compiles the nannyagent binary
   - Tests connectivity to Supabase
   - Installs binary to `/usr/local/bin`

4. ✅ **Configuration**
   - Creates `/etc/nannyagent/config.env`
   - Creates `/var/lib/nannyagent` data directory
   - Sets proper permissions (secure)
   - Creates installation lock file

## Installation Exit Codes

The installer exits with specific codes for different scenarios:

| Exit Code | Meaning | Resolution |
|-----------|---------|------------|
| 0 | Success | Installation completed |
| 1 | Not root | Run with `sudo` |
| 2 | Unsupported OS | Use Linux |
| 3 | Unsupported architecture | Use amd64 or arm64 |
| 4 | Container detected | Install on bare metal or VM |
| 5 | Kernel too old | Upgrade to kernel 5.x+ |
| 6 | Existing installation | Remove `/var/lib/nannyagent` first |
| 7 | eBPF tools failed | Check package manager and repos |
| 8 | Go not installed | Install Go from golang.org |
| 9 | Build failed | Check Go installation and dependencies |
| 10 | Directory creation failed | Check permissions |
| 11 | Binary installation failed | Check disk space and permissions |

## Post-Installation

After successful installation:

### 1. Configure Supabase URL

Edit the configuration file:
```bash
sudo nano /etc/nannyagent/config.env
```

Set your Supabase project URL:
```bash
SUPABASE_PROJECT_URL=https://your-project.supabase.co
TOKEN_PATH=/var/lib/nannyagent/token.json
DEBUG=false
```

### 2. Test the Installation

Check version (no sudo needed):
```bash
nannyagent --version
```

Show help (no sudo needed):
```bash
nannyagent --help
```

### 3. Run the Agent

Start the agent (requires sudo):
```bash
sudo nannyagent
```

On first run, you'll see authentication instructions:
```
Visit: https://your-app.com/device-auth
Enter code: ABCD-1234
```

## Uninstallation

To remove NannyAgent:

```bash
# Remove binary
sudo rm /usr/local/bin/nannyagent

# Remove configuration
sudo rm -rf /etc/nannyagent

# Remove data directory (includes authentication tokens)
sudo rm -rf /var/lib/nannyagent
```

## Troubleshooting

### "Kernel version X.X is not supported"

Your kernel is too old. Check current version:
```bash
uname -r
```

Options:
1. Upgrade your kernel to 5.x or higher
2. Use a different system with a newer kernel
3. Check your distribution's documentation for kernel upgrades

### "Another instance may already be installed"

The installer detected an existing installation. Options:

**Option 1:** Remove the existing installation
```bash
sudo rm -rf /var/lib/nannyagent
```

**Option 2:** Check if it's actually running
```bash
ps aux | grep nannyagent
```

If running, stop it first, then remove the data directory.

### "Cannot connect to Supabase"

This is a warning, not an error. The installation will complete, but the agent won't work without connectivity.

Check:
1. Is SUPABASE_PROJECT_URL set correctly?
   ```bash
   cat /etc/nannyagent/config.env
   ```

2. Can you reach the URL?
   ```bash
   curl -I https://your-project.supabase.co
   ```

3. Check firewall rules:
   ```bash
   sudo iptables -L -n | grep -i drop
   ```

### "Go is not installed"

The installer requires Go to build the binary. Install Go:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install golang-go
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install golang
```

Or download from: https://golang.org/dl/

### "eBPF tools installation failed"

Check your package repositories:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install bpfcc-tools bpftrace
```

**RHEL/Fedora:**
```bash
sudo dnf install bcc-tools bpftrace
```

## Security Considerations

### Permissions

The installer creates directories with restricted permissions:
- `/etc/nannyagent` - 755 (readable by all, writable by root)
- `/etc/nannyagent/config.env` - 600 (only root can read/write)
- `/var/lib/nannyagent` - 700 (only root can access)

### Authentication Tokens

Authentication tokens are stored securely in:
```
/var/lib/nannyagent/token.json
```

Only root can access this file (permissions: 600).

### Network Communication

All communication with Supabase uses HTTPS (TLS encrypted).

## Manual Installation (Alternative)

If you prefer manual installation:

```bash
# 1. Clone repository
git clone https://github.com/harshavmb/nannyagent.git
cd nannyagent

# 2. Install eBPF tools (Ubuntu/Debian)
sudo apt update
sudo apt install bpfcc-tools bpftrace linux-headers-$(uname -r)

# 3. Build binary
go mod tidy
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o nannyagent .

# 4. Install
sudo cp nannyagent /usr/local/bin/
sudo chmod 755 /usr/local/bin/nannyagent

# 5. Create directories
sudo mkdir -p /etc/nannyagent
sudo mkdir -p /var/lib/nannyagent
sudo chmod 700 /var/lib/nannyagent

# 6. Create configuration
sudo cat > /etc/nannyagent/config.env <<EOF
SUPABASE_PROJECT_URL=https://your-project.supabase.co
TOKEN_PATH=/var/lib/nannyagent/token.json
DEBUG=false
EOF

sudo chmod 600 /etc/nannyagent/config.env
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/harshavmb/nannyagent/issues
- Documentation: https://github.com/harshavmb/nannyagent/docs

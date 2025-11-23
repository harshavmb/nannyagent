# NannyAgent - Linux Diagnostic Agent

A Go-based AI agent that diagnoses Linux system issues using eBPF-powered deep monitoring and TensorZero AI integration.

## Features

- 🤖 **AI-Powered Diagnostics** - Intelligent issue analysis and resolution planning
- 🔍 **eBPF Deep Monitoring** - Real-time kernel-level tracing for network, processes, files, and security events
- 🛡️ **Safe Command Execution** - Validates and executes diagnostic commands with timeouts
- 📊 **Automatic System Information Gathering** - Comprehensive OS, kernel, CPU, memory, and network metrics
- 🔄 **WebSocket Integration** - Real-time communication with backend investigation system
- 🔐 **OAuth Device Flow Authentication** - Secure agent registration and authentication
- ✅ **Comprehensive Integration Tests** - Realistic Linux problem scenarios

## Requirements

- **Operating System**: Linux only (no containers/LXC support)
- **Architecture**: amd64 (x86_64) or arm64 (aarch64)
- **Kernel Version**: Linux kernel 5.x or higher
- **Privileges**: Root/sudo access required for eBPF functionality
- **Dependencies**: bpftrace and bpfcc-tools (automatically installed by installer)
- **Network**: Connectivity to Supabase backend

## Quick Installation

### One-Line Install (Recommended)

```bash
# Download and run the installer
curl -fsSL https://your-domain.com/install.sh | sudo bash
```

Or download first, then install:

```bash
# Download the installer
wget https://your-domain.com/install.sh

# Make it executable
chmod +x install.sh

# Run the installer
sudo ./install.sh
```

### Manual Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/harshavmb/nannyagent.git
   cd nannyagent
   ```

2. Run the installer script:
   ```bash
   sudo ./install.sh
   ```

The installer will:
- ✅ Verify system requirements (OS, architecture, kernel version)
- ✅ Check for existing installations
- ✅ Install eBPF tools (bpftrace, bpfcc-tools)
- ✅ Build the nannyagent binary
- ✅ Test connectivity to Supabase
- ✅ Install to `/usr/local/bin/nannyagent`
- ✅ Create configuration in `/etc/nannyagent/config.env`
- ✅ Create secure data directory `/var/lib/nannyagent`

## Configuration

After installation, configure your Supabase URL:

```bash
# Edit the configuration file
sudo nano /etc/nannyagent/config.env
```

Required configuration:

```bash
# Supabase Configuration
SUPABASE_PROJECT_URL=https://your-project.supabase.co

# Portal URL for device authorization (default: https://nannyai.dev)
# NANNYAI_PORTAL_URL=https://nannyai.dev

# Optional Configuration
# TOKEN_PATH=/var/lib/nannyagent/token.json  # Default path
DEBUG=false
```

**Configuration Notes:**
- `SUPABASE_PROJECT_URL`: Required - Your Supabase project URL
- `NANNYAI_PORTAL_URL`: Optional - Portal URL for device auth (defaults to https://nannyai.dev)
- `TOKEN_PATH`: Optional - Token storage path (defaults to /var/lib/nannyagent/token.json)
- `DEBUG`: Optional - Enable debug logging (true/false)

## Command-Line Options

```bash
# Show version (no sudo required)
nannyagent --version
nannyagent -v

# Show help (no sudo required)
nannyagent --help
nannyagent -h

# Run the agent (requires sudo)
sudo nannyagent
```

## Usage

1. **First-time Setup** - Authenticate the agent:
   ```bash
   sudo nannyagent
   ```
   
   The agent will display a verification URL and code. Visit the URL and enter the code to authorize the agent.

2. **Interactive Diagnostics** - After authentication, enter system issues:
   ```
   > On /var filesystem I cannot create any file but df -h shows 30% free space available.
   ```

3. **The agent will**:
   - Gather comprehensive system information automatically
   - Send the issue to AI for analysis via TensorZero
   - Execute diagnostic commands safely
   - Run eBPF traces for deep kernel-level monitoring
   - Provide AI-generated root cause analysis and resolution plan

4. **Exit the agent**:
   ```
   > quit
   ```
   or
   ```
   > exit
   ```

## How It Works

1. **User Input**: Submit a description of the system issue you're experiencing
2. **System Info Gathering**: Agent automatically collects comprehensive system information and eBPF capabilities
3. **AI Analysis**: Sends the issue description + system info to NannyAPI for analysis
4. **Diagnostic Phase**: AI returns structured commands and eBPF monitoring requests for investigation
5. **Command Execution**: Agent safely executes diagnostic commands and runs eBPF traces in parallel
6. **eBPF Monitoring**: Real-time system tracing (network, processes, files, syscalls) provides deep insights
7. **Iterative Analysis**: Command results and eBPF trace data are sent back to AI for further analysis
8. **Resolution**: AI provides root cause analysis and step-by-step resolution plan based on comprehensive data

## Testing & Integration Tests

The agent includes comprehensive integration tests that simulate realistic Linux problems:

### Available Test Scenarios:
1. **Disk Space Issues** - Inode exhaustion scenarios
2. **Memory Problems** - OOM killer and memory pressure
3. **Network Issues** - DNS resolution problems
4. **Performance Issues** - High load averages and I/O bottlenecks
5. **Web Server Problems** - Permission and configuration issues
6. **Hardware/Boot Issues** - Kernel module and device problems
7. **Database Performance** - Slow queries and I/O contention
8. **Service Failures** - Startup and configuration problems

### Run Integration Tests:
```bash
# Run unit tests
make test

# Run integration tests
./tests/test_ebpf_integration.sh
```

## Installation Exit Codes

The installer uses specific exit codes for different failure scenarios:

| Exit Code | Description |
|-----------|-------------|
| 0 | Success |
| 1 | Not running as root |
| 2 | Unsupported operating system (non-Linux) |
| 3 | Unsupported architecture (not amd64/arm64) |
| 4 | Container/LXC environment detected |
| 5 | Kernel version < 5.x |
| 6 | Existing installation detected |
| 7 | eBPF tools installation failed |
| 8 | Go not installed |
| 9 | Binary build failed |
| 10 | Directory creation failed |
| 11 | Binary installation failed |

## Troubleshooting

### Installation Issues

**Error: "Kernel version X.X is not supported"**
- NannyAgent requires Linux kernel 5.x or higher
- Upgrade your kernel or use a different system

**Error: "Another instance may already be installed"**
- Check if `/var/lib/nannyagent` exists
- Remove it if you're sure: `sudo rm -rf /var/lib/nannyagent`
- Then retry installation

**Warning: "Cannot connect to Supabase"**
- Check your network connectivity
- Verify firewall settings allow HTTPS connections
- Ensure SUPABASE_PROJECT_URL is correctly configured in `/etc/nannyagent/config.env`

### Runtime Issues

**Error: "This program must be run as root"**
- eBPF requires root privileges
- Always run with: `sudo nannyagent`

**Error: "Cannot determine kernel version"**
- Ensure `uname` command is available
- Check system integrity

## Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/harshavmb/nannyagent.git
cd nannyagent

# Install Go dependencies
go mod tidy

# Build binary
make build

# Run locally (requires sudo)
sudo ./nannyagent
```

### Running Tests

```bash
# Run unit tests
make test

# Test eBPF capabilities
./tests/test_ebpf_integration.sh
```

## Safety

## eBPF Monitoring Capabilities

The agent includes advanced eBPF (Extended Berkeley Packet Filter) monitoring for deep system investigation:

- **System Call Tracing**: Monitor process behavior through syscall analysis
- **Network Activity**: Track network connections, data flow, and protocol usage  
- **Process Monitoring**: Real-time process creation, execution, and lifecycle tracking
- **File System Events**: Monitor file access, creation, deletion, and permission changes
- **Performance Analysis**: CPU, memory, and I/O performance profiling
- **Security Events**: Detect privilege escalation and suspicious activities

The AI automatically requests appropriate eBPF monitoring based on the issue type, providing unprecedented visibility into system behavior during problem diagnosis.

For detailed eBPF documentation, see [EBPF_README.md](EBPF_README.md).

## Safety

- All commands are validated before execution to prevent dangerous operations
- Read-only diagnostic commands are prioritized
- No commands that modify system state (rm, mv, etc.) are executed
- Commands have timeouts to prevent hanging
- Secure execution environment with proper error handling
- eBPF monitoring is read-only and time-limited for safety

## API Integration

The agent uses the `github.com/sashabaranov/go-openai` SDK to communicate with NannyAPI's OpenAI-compatible API endpoint. This provides:

- Robust HTTP client with retries and timeouts
- Structured request/response handling
- Automatic JSON marshaling/unmarshaling
- Error handling and validation

## Example Session

```
Linux Diagnostic Agent Started
Enter a system issue description (or 'quit' to exit):
> Cannot create files in /var but df shows space available

Diagnosing issue: Cannot create files in /var but df shows space available
Gathering system information...

AI Response:
{
  "response_type": "diagnostic",
  "reasoning": "The 'No space left on device' error despite available disk space suggests inode exhaustion...",
  "commands": [
    {"id": "check_inodes", "command": "df -i /var", "description": "Check inode usage..."}
  ]
}

Executing command 'check_inodes': df -i /var
Output:
Filesystem      Inodes   IUsed   IFree IUse% Mounted on
/dev/sda1      1000000  999999       1  100% /var

=== DIAGNOSIS COMPLETE ===
Root Cause: The /var filesystem has exhausted all available inodes
Resolution Plan: 1. Find and remove unnecessary files...
Confidence: High
```

Note: The AI receives comprehensive system information including:
- Hostname, OS version, kernel version
- CPU cores, memory, system uptime
- Network interfaces and private IPs
- Current load average and disk usage

## Available Make Commands

- `make build` - Build the application
- `make run` - Build and run the application  
- `make clean` - Clean build artifacts
- `make test` - Run unit tests
- `make install` - Install dependencies
- `make build-prod` - Build for production
- `make install-system` - Install system-wide (requires sudo)
- `make fmt` - Format code
- `make help` - Show available commands

## Testing Commands

- `./test-examples.sh` - Show interactive test scenarios
- `./integration-tests.sh` - Run automated integration tests
- `./discover-functions.sh` - Find available NannyAPI functions
- `./install.sh` - Installation script for Linux VMs

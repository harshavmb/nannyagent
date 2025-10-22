# Linux Diagnostic Agent

A Go-based AI agent that diagnoses Linux system issues using the NannyAPI gateway with OpenAI-compatible SDK.

## Features

- Interactive command-line interface for submitting system issues
- **Automatic system information gathering** - Includes OS, kernel, CPU, memory, network info
- **eBPF-powered deep system monitoring** - Advanced tracing for network, processes, files, and security events
- Integrates with NannyAPI using OpenAI-compatible Go SDK
- Executes diagnostic commands safely and collects output
- Provides step-by-step resolution plans
- **Comprehensive integration tests** with realistic Linux problem scenarios

## Setup

1. Clone this repository
2. Copy `.env.example` to `.env` and configure your NannyAPI endpoint:
   ```bash
   cp .env.example .env
   ```
3. Install dependencies:
   ```bash
   go mod tidy
   ```
4. Build and run:
   ```bash
   make build
   ./nanny-agent
   ```

## Configuration

The agent can be configured using environment variables:

- `NANNYAPI_ENDPOINT`: The NannyAPI endpoint (default: `http://tensorzero.netcup.internal:3000/openai/v1`)
- `NANNYAPI_MODEL`: The model identifier (default: `nannyapi::function_name::diagnose_and_heal`)

## Installation on Linux VM

### Direct Installation

1. **Install Go** (if not already installed):
   ```bash
   # For Ubuntu/Debian
   sudo apt update
   sudo apt install golang-go

   # For RHEL/CentOS/Fedora
   sudo dnf install golang
   # or
   sudo yum install golang
   ```

2. **Clone and build the agent**:
   ```bash
   git clone <your-repo-url>
   cd nannyagentv2
   go mod tidy
   make build
   ```

3. **Install as system service** (optional):
   ```bash
   sudo cp nanny-agent /usr/local/bin/
   sudo chmod +x /usr/local/bin/nanny-agent
   ```

4. **Set environment variables**:
   ```bash
   export NANNYAPI_ENDPOINT="http://your-nannyapi-endpoint:3000/openai/v1"
   export NANNYAPI_MODEL="your-model-identifier"
   ```

## Usage

1. Start the agent:
   ```bash
   ./nanny-agent
   ```

2. Enter a system issue description when prompted:
   ```
   > On /var filesystem I cannot create any file but df -h shows 30% free space available.
   ```

3. The agent will:
   - Send the issue to the AI via NannyAPI using OpenAI SDK
   - Execute diagnostic commands as suggested by the AI
   - Provide command outputs back to the AI
   - Display the final diagnosis and resolution plan

4. Type `quit` or `exit` to stop the agent

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
# Interactive test scenarios
./test-examples.sh

# Automated integration tests
./integration-tests.sh

# Function discovery (find valid NannyAPI functions)
./discover-functions.sh
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

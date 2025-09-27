# Linux Diagnostic Agent

A Go-based AI agent that diagnoses Linux system issues using the NannyAPI gateway with OpenAI-compatible SDK.

## Features

- Interactive command-line interface for submitting system issues
- **Automatic system information gathering** - Includes OS, kernel, CPU, memory, network info
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

- `NANNYAPI_ENDPOINT`: The NannyAPI endpoint (default: `http://nannyapi.local:3000/openai/v1`)
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

1. **System Information Gathering**: Agent automatically collects system details (OS, kernel, CPU, memory, network, etc.)
2. **Initial Issue**: User describes a Linux system problem
3. **Enhanced Prompt**: AI receives both the issue description and comprehensive system information
4. **Diagnostic Phase**: AI responds with diagnostic commands to run
5. **Command Execution**: Agent safely executes read-only commands
6. **Iterative Analysis**: AI analyzes command outputs and may request more commands
7. **Resolution Phase**: AI provides root cause analysis and step-by-step resolution plan

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

- Only read-only commands are executed automatically
- Commands that modify the system (rm, mv, dd, redirection) are blocked by validation
- The resolution plan is provided for manual execution by the operator
- All commands have execution timeouts to prevent hanging

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

# NannyAgent

NannyAgent is a Linux diagnostic tool that interfaces with the NannyAI API to provide intelligent system diagnostics and troubleshooting. The agent collects system metrics and interacts with the API to diagnose system issues.

## Features

- System metrics collection (CPU, memory, disk, network)
- Interactive diagnostic sessions
- Offline mode support for basic diagnostics
- Automatic agent registration and metadata management
- Real-time command execution and analysis
- Persistent agent state management

## Installation

1. Clone the repository:
```bash
git clone https://github.com/harshavmb/nannyagent.git
cd nannyagent
```

2. Build the agent:
```bash
go build -o nannyagent ./cmd/main.go
```

## Configuration

The agent can be configured using command-line flags or environment variables:

### Environment Variables

- `NANNY_API_KEY`: Your NannyAI API key (required for online mode)

### Command Line Flags

- `--api-url`: NannyAI API URL (default: https://api.nannyai.dev)
- `--api-key`: NannyAI API key
- `--prompt`: Initial diagnostic prompt
- `--offline`: Run in offline mode

## Usage

### Online Mode

1. Set your API key:
```bash
export NANNY_API_KEY="your-api-key"
```

2. Run the agent:
```bash
./nannyagent
```

### Offline Mode

Run the agent in offline mode for basic diagnostics without API connectivity:
```bash
./nannyagent --offline
```

### Interactive Commands

Once running, the following commands are available:

- `help`: Show available commands and examples
- `status`: Show agent and system status
- `exit`: Exit the program

For diagnostics, simply type your query, for example:
- "Check system health"
- "Investigate high CPU usage"
- "Check disk space"
- "Memory usage analysis"

## System Requirements

- Linux-based operating system
- Go 1.22 or later

## Development

### Running Tests

```bash
go test ./...
```

### Project Structure

```
nannyagent/
├── cmd/
│   └── main.go           # Main application entry
├── pkg/
│   ├── agent/
│   │   ├── agent.go      # Core agent functionality
│   │   └── agent_test.go # Agent tests
│   └── api/
│       └── nanny.go      # API client implementation
├── go.mod               # Go module definition
└── README.md           # This file
```

## Offline Diagnostics

When running in offline mode or when API connectivity is lost, the agent provides basic diagnostic capabilities including:

- CPU usage monitoring
- Memory usage analysis
- Disk space checking
- Network statistics
- Basic system information

## Security

The agent:
- Only executes commands received from the authenticated API endpoint
- Stores sensitive data (API key, metadata) in the user's home directory
- Validates all API responses and command outputs

## License

GNU General Public License v3.0

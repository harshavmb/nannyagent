# nannyagent

nannyagent is a Linux-based agent that interacts with the Gemini API (gemini-1.5-flash) over REST. The agent allows users to query system information such as health status, filesystem usage, disk usage, memory usage, and process details by sending requests to the Gemini API.

## Project Structure

```
nannyagent
├── cmd
│   └── main.go         # Entry point of the application
├── pkg
│   ├── api
│   │   └── gemini.go   # Functions for interacting with the Gemini API
│   ├── agent
│   │   └── agent.go     # Agent struct and command execution methods
├── go.mod               # Module definition and dependencies
└── README.md            # Project documentation
```

## Setup Instructions

1. Clone the repository:
   ```
   git clone https://github.com/harshavmb/nannyagent.git
   cd nannyagent
   ```

2. Initialize the Go module:
   ```
   go mod tidy
   ```

3. Build the application:
   ```
   go build -o nannyagent ./cmd/main.go
   ```

## Usage

To run the agent, execute the following command:
```
./nannyagent
```

Once running, you can input queries such as:
- "Check my system health"
- "Filesystem usage"
- "Disk usage"
- "Memory"
- "Processes details"

The agent will send the input to the Gemini API, fetch the necessary commands, execute them, and return the output to the user.

## Functionality

- **System Health Check**: Queries the health status of the system.
- **Filesystem Usage**: Retrieves information about filesystem usage.
- **Disk Usage**: Provides details on disk usage statistics.
- **Memory Usage**: Displays current memory usage.
- **Process Details**: Lists active processes and their details.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue for any enhancements or bug fixes.
# eBPF Integration for Linux Diagnostic Agent

The Linux Diagnostic Agent now includes comprehensive eBPF (Extended Berkeley Packet Filter) capabilities for advanced system monitoring and investigation during diagnostic sessions.

## eBPF Capabilities

### Available Monitoring Types

1. **System Call Tracing** (`syscall_trace`)
   - Monitors all system calls made by processes
   - Useful for debugging process behavior and API usage
   - Can filter by process ID or name

2. **Network Activity Tracing** (`network_trace`)
   - Tracks TCP/UDP send/receive operations
   - Monitors network connections and data flow
   - Identifies network-related bottlenecks

3. **Process Monitoring** (`process_trace`)
   - Tracks process creation, execution, and termination
   - Monitors process lifecycle events
   - Useful for debugging startup issues

4. **File System Monitoring** (`file_trace`)
   - Monitors file open, create, delete operations
   - Tracks file access patterns
   - Can filter by specific paths

5. **Performance Monitoring** (`performance`)
   - Collects CPU, memory, and I/O metrics
   - Provides detailed performance profiling
   - Uses perf integration when available

6. **Security Event Monitoring** (`security_event`)
   - Detects privilege escalation attempts
   - Monitors security-relevant system calls
   - Tracks suspicious activities

## How eBPF Integration Works

### AI-Driven eBPF Selection

The AI agent can automatically request eBPF monitoring by including specific fields in its diagnostic response:

```json
{
  "response_type": "diagnostic",
  "reasoning": "Need to trace network activity to diagnose connection timeout issues",
  "commands": [
    {"id": "basic_net", "command": "ss -tulpn", "description": "Current network connections"},
    {"id": "net_config", "command": "ip route show", "description": "Network configuration"}
  ],
  "ebpf_capabilities": ["network_trace", "syscall_trace"],
  "ebpf_duration_seconds": 15,
  "ebpf_filters": {
    "comm": "nginx",
    "path": "/etc"
  }
}
```

### eBPF Trace Execution

1. eBPF traces run in parallel with regular diagnostic commands
2. Multiple eBPF capabilities can be activated simultaneously  
3. Traces collect structured JSON events in real-time
4. Results are automatically parsed and included in the diagnostic data

### Event Data Structure

eBPF events follow a consistent structure:

```json
{
  "timestamp": 1634567890000000000,
  "event_type": "syscall_enter",
  "process_id": 1234,
  "process_name": "nginx",
  "user_id": 1000,
  "data": {
    "syscall": "openat",
    "filename": "/etc/nginx/nginx.conf"
  }
}
```

## Installation and Setup

### Prerequisites

The agent automatically detects available eBPF tools and capabilities. For full functionality, install:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install bpftrace linux-tools-generic linux-tools-$(uname -r)
sudo apt install bcc-tools python3-bcc  # Optional, for additional tools
```

**RHEL/CentOS/Fedora:**
```bash
sudo dnf install bpftrace perf bcc-tools python3-bcc
```

**openSUSE:**
```bash
sudo zypper install bpftrace perf
```

### Automated Setup

Use the included helper script:

```bash
# Check current eBPF capabilities
./ebpf_helper.sh check

# Install eBPF tools (requires root)
sudo ./ebpf_helper.sh install

# Create monitoring scripts
./ebpf_helper.sh setup

# Test eBPF functionality
sudo ./ebpf_helper.sh test
```

## Usage Examples

### Network Issue Diagnosis

When describing network problems, the AI may automatically request network tracing:

```
User: "Web server is experiencing intermittent connection timeouts"

AI Response: Includes network_trace and syscall_trace capabilities
eBPF Output: Real-time network send/receive events, connection attempts, and related system calls
```

### Performance Issue Investigation

For performance problems, the AI can request comprehensive monitoring:

```
User: "System is running slowly, high CPU usage"

AI Response: Includes process_trace, performance, and syscall_trace
eBPF Output: Process execution patterns, performance metrics, and system call analysis
```

### Security Incident Analysis

For security concerns, specialized monitoring is available:

```
User: "Suspicious activity detected, possible privilege escalation"

AI Response: Includes security_event, process_trace, and file_trace
eBPF Output: Security-relevant events, process behavior, and file access patterns
```

## Filtering Options

eBPF traces can be filtered for focused monitoring:

- **Process ID**: `{"pid": "1234"}` - Monitor specific process
- **Process Name**: `{"comm": "nginx"}` - Monitor processes by name  
- **File Path**: `{"path": "/etc"}` - Monitor specific path (file tracing)

## Integration with Existing Workflow

eBPF monitoring integrates seamlessly with the existing diagnostic workflow:

1. **Automatic Detection**: Agent detects available eBPF capabilities at startup
2. **AI Decision Making**: AI decides when eBPF monitoring would be helpful
3. **Parallel Execution**: eBPF traces run alongside regular diagnostic commands
4. **Structured Results**: eBPF data is included in command results for AI analysis
5. **Contextual Analysis**: AI correlates eBPF events with other diagnostic data

## Troubleshooting

### Common Issues

**Permission Errors:**
- Most eBPF operations require root privileges
- Run the agent with `sudo` for full eBPF functionality

**Tool Not Available:**
- Use `./ebpf_helper.sh check` to verify available tools
- Install missing tools with `./ebpf_helper.sh install`

**Kernel Compatibility:**
- eBPF requires Linux kernel 4.4+ (5.0+ recommended)
- Some features may require newer kernel versions

**Debugging eBPF Issues:**
```bash
# Check kernel eBPF support
sudo ./ebpf_helper.sh check

# Test basic eBPF functionality  
sudo bpftrace -e 'BEGIN { print("eBPF works!"); exit(); }'

# Verify debugfs mount (required for ftrace)
sudo mount -t debugfs none /sys/kernel/debug
```

## Security Considerations

- eBPF monitoring provides deep system visibility
- Traces may contain sensitive information (file paths, process arguments)
- Traces are stored temporarily in `/tmp/nannyagent/ebpf/`
- Old traces are automatically cleaned up after 1 hour
- Consider the security implications of detailed system monitoring

## Performance Impact

- eBPF monitoring has minimal performance overhead
- Traces are time-limited (typically 10-30 seconds)
- Event collection is optimized for efficiency
- Heavy tracing may impact system performance on resource-constrained systems

## Contributing

To add new eBPF capabilities:

1. Extend the `EBPFCapability` enum in `ebpf_manager.go`
2. Add detection logic in `detectCapabilities()`
3. Implement trace command generation in `buildXXXTraceCommand()`
4. Update capability descriptions in `FormatSystemInfoWithEBPFForPrompt()`

The eBPF integration is designed to be extensible and can accommodate additional monitoring capabilities as needed.

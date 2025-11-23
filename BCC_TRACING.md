# BCC-Style eBPF Tracing Implementation

## Overview

This implementation adds powerful BCC-style (Berkeley Packet Filter Compiler) tracing capabilities to the diagnostic agent, similar to the `trace.py` tool from the iovisor BCC project. Instead of just filtering events, this system actually counts and traces real system calls with detailed argument parsing.

## Key Features

### 1. Real System Call Tracing
- **Actual event counting**: Unlike the previous implementation that just simulated events, this captures real system calls
- **Argument extraction**: Extracts function arguments (arg1, arg2, etc.) and return values
- **Multiple probe types**: Supports kprobes, kretprobes, tracepoints, and uprobes
- **Filtering capabilities**: Filter by process name, PID, UID, argument values

### 2. BCC-Style Syntax
Supports familiar BCC trace.py syntax patterns:
```bash
# Simple syscall tracing
"sys_open"                    # Trace open syscalls
"sys_read (arg3 > 1024)"      # Trace reads >1024 bytes
"r::sys_open"                 # Return probe on open

# With format strings
"sys_write \"wrote %d bytes\", arg3"
"sys_open \"opening %s\", arg2@user"
```

### 3. Comprehensive Event Data
Each trace captures:
```json
{
  "timestamp": 1234567890,
  "pid": 1234,
  "tid": 1234,
  "process_name": "nginx",
  "function": "__x64_sys_openat",
  "message": "opening file: /var/log/access.log",
  "raw_args": {
    "arg1": "3",
    "arg2": "/var/log/access.log",
    "arg3": "577"
  }
}
```

## Architecture

### Core Components

1. **BCCTraceManager** (`ebpf_trace_manager.go`)
   - Main orchestrator for BCC-style tracing
   - Generates bpftrace scripts dynamically
   - Manages trace sessions and event collection

2. **TraceSpec** - Trace specification format
   ```go
   type TraceSpec struct {
       ProbeType    string            // "p", "r", "t", "u"
       Target       string            // Function/syscall to trace
       Format       string            // Output format string
       Arguments    []string          // Arguments to extract
       Filter       string            // Filter conditions
       Duration     int               // Trace duration in seconds
       ProcessName  string            // Process filter
       PID          int               // Process ID filter
       UID          int               // User ID filter
   }
   ```

3. **EventScanner** (`ebpf_event_parser.go`)
   - Parses bpftrace output in real-time
   - Converts raw trace data to structured events
   - Handles argument extraction and enrichment

4. **TraceSpecBuilder** - Fluent API for building specs
   ```go
   spec := NewTraceSpecBuilder().
       Kprobe("__x64_sys_write").
       Format("write %d bytes to fd %d", "arg3", "arg1").
       Filter("arg1 == 1").
       Duration(30).
       Build()
   ```

## Usage Examples

### 1. Basic System Call Tracing

```go
// Trace file open operations
spec := TraceSpec{
    ProbeType: "p",
    Target:    "__x64_sys_openat",
    Format:    "opening file: %s",
    Arguments: []string{"arg2@user"},
    Duration:  30,
}

traceID, err := manager.StartTrace(spec)
```

### 2. Filtered Tracing

```go
// Trace only large reads
spec := TraceSpec{
    ProbeType: "p",
    Target:    "__x64_sys_read",
    Format:    "read %d bytes from fd %d",
    Arguments: []string{"arg3", "arg1"},
    Filter:    "arg3 > 1024",
    Duration:  30,
}
```

### 3. Process-Specific Tracing

```go
// Trace only nginx processes
spec := TraceSpec{
    ProbeType:   "p",
    Target:      "__x64_sys_write",
    ProcessName: "nginx",
    Duration:    60,
}
```

### 4. Return Value Tracing

```go
// Trace return values from file operations
spec := TraceSpec{
    ProbeType: "r",
    Target:    "__x64_sys_openat",
    Format:    "open returned: %d",
    Arguments: []string{"retval"},
    Duration:  30,
}
```

## Integration with Agent

### API Request Format
The remote API can send trace specifications in the `ebpf_programs` field:

```json
{
  "commands": [
    {"id": "cmd1", "command": "ps aux"}
  ],
  "ebpf_programs": [
    {
      "name": "file_monitoring",
      "type": "kprobe", 
      "target": "sys_open",
      "duration": 30,
      "filters": {"process": "nginx"},
      "description": "Monitor file access by nginx"
    }
  ]
}
```

### Agent Response Format
The agent returns detailed trace results:

```json
{
  "name": "__x64_sys_openat",
  "type": "bcc_trace",
  "target": "__x64_sys_openat", 
  "duration": 30,
  "status": "completed",
  "success": true,
  "event_count": 45,
  "events": [
    {
      "timestamp": 1234567890,
      "pid": 1234,
      "process_name": "nginx",
      "function": "__x64_sys_openat",
      "message": "opening file: /var/log/access.log",
      "raw_args": {"arg1": "3", "arg2": "/var/log/access.log"}
    }
  ],
  "statistics": {
    "total_events": 45,
    "events_per_second": 1.5,
    "top_processes": [
      {"process_name": "nginx", "event_count": 30},
      {"process_name": "apache", "event_count": 15}
    ]
  }
}
```

## Test Specifications

The implementation includes test specifications for unit testing:

- **test_sys_open**: File open operations
- **test_sys_read**: Read operations with filters
- **test_sys_write**: Write operations  
- **test_process_creation**: Process execution
- **test_kretprobe**: Return value tracing
- **test_with_filter**: Filtered tracing

## Running Tests

```bash
# Run all BCC tracing tests
go test -v -run TestBCCTracing

# Test trace manager capabilities
go test -v -run TestTraceManagerCapabilities

# Test syscall suggestions
go test -v -run TestSyscallSuggestions

# Run all tests
go test -v
```

## Requirements

### System Requirements
- **Linux kernel 4.4+** with eBPF support
- **bpftrace** installed (`apt install bpftrace`)
- **Root privileges** for actual tracing

### Checking Capabilities
The trace manager automatically detects capabilities:

```bash
$ go test -run TestTraceManagerCapabilities
🔧 Trace Manager Capabilities:
   ✅ kernel_ebpf: Available
   ✅ bpftrace: Available  
   ❌ root_access: Not Available
   ❌ debugfs_access: Not Available
```

## Advanced Features

### 1. Syscall Suggestions
The system can suggest appropriate syscalls based on issue descriptions:

```go
suggestions := SuggestSyscallTargets("file not found error")
// Returns: ["test_sys_open", "test_sys_read", "test_sys_write", "test_sys_unlink"]
```

### 2. BCC-Style Parsing
Parse BCC trace.py style specifications:

```go
parser := NewTraceSpecParser()
spec, err := parser.ParseFromBCCStyle("sys_write (arg1 == 1) \"stdout: %d bytes\", arg3")
```

### 3. Event Filtering and Aggregation
Post-processing capabilities for trace events:

```go
filter := &TraceEventFilter{
    ProcessNames: []string{"nginx", "apache"},
    MinTimestamp: startTime,
}
filteredEvents := filter.ApplyFilter(events)

aggregator := NewTraceEventAggregator(events)
topProcesses := aggregator.GetTopProcesses(5)
eventRate := aggregator.GetEventRate()
```

## Performance Considerations

- **Short durations**: Test specs use 5-second durations for quick testing
- **Efficient parsing**: Event scanner processes bpftrace output in real-time
- **Memory management**: Events are processed and aggregated efficiently
- **Timeout handling**: Automatic cleanup of hanging trace sessions

## Security Considerations

- **Root privileges required**: eBPF tracing requires root access
- **Resource limits**: Maximum trace duration of 10 minutes
- **Process isolation**: Each trace runs in its own context
- **Automatic cleanup**: Traces are automatically stopped and cleaned up

## Future Enhancements

1. **USDT probe support**: Add support for user-space tracing
2. **BTF integration**: Use BPF Type Format for better type information  
3. **Flame graph generation**: Generate performance flame graphs
4. **Custom eBPF programs**: Allow uploading custom eBPF bytecode
5. **Distributed tracing**: Correlation across multiple hosts

This implementation provides a solid foundation for advanced system introspection and debugging, bringing the power of BCC-style tracing to the diagnostic agent.
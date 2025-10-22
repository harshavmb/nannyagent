# eBPF Integration Summary for TensorZero

## 🎯 Overview
Your Linux diagnostic agent now has advanced eBPF monitoring capabilities integrated with the Cilium eBPF Go library. This enables real-time kernel-level monitoring alongside traditional system commands for unprecedented diagnostic precision.

## 🔄 Key Changes from Previous System Prompt

### Before (Traditional Commands Only):
```json
{
  "response_type": "diagnostic",
  "reasoning": "Need to check network connections",
  "commands": [
    {"id": "net_check", "command": "netstat -tulpn", "description": "Check connections"}
  ]
}
```

### After (eBPF-Enhanced):
```json
{
  "response_type": "diagnostic", 
  "reasoning": "Network timeout issues require monitoring TCP connections and system calls to identify bottlenecks",
  "commands": [
    {"id": "net_status", "command": "ss -tulpn", "description": "Current network connections"}
  ],
  "ebpf_programs": [
    {
      "name": "tcp_connect_monitor",
      "type": "kprobe",
      "target": "tcp_connect", 
      "duration": 15,
      "description": "Monitor TCP connection attempts in real-time"
    }
  ]
}
```

## 🔧 TensorZero Configuration Steps

### 1. Update System Prompt
Replace your current system prompt with the content from `TENSORZERO_SYSTEM_PROMPT.md`. Key additions:

- **eBPF program request format** in diagnostic responses
- **Comprehensive eBPF guidelines** for different issue types  
- **Enhanced resolution format** with `ebpf_evidence` field
- **Specific tracepoint/kprobe recommendations** per issue category

### 2. Response Format Changes

#### Diagnostic Phase (Enhanced):
```json
{
  "response_type": "diagnostic",
  "reasoning": "Analysis explanation...",
  "commands": [...],
  "ebpf_programs": [
    {
      "name": "program_name",
      "type": "tracepoint|kprobe|kretprobe", 
      "target": "kernel_function_or_tracepoint",
      "duration": 10-30,
      "filters": {"comm": "process_name", "pid": 1234},
      "description": "Why this monitoring is needed"
    }
  ]
}
```

#### Resolution Phase (Enhanced):
```json
{
  "response_type": "resolution",
  "root_cause": "Definitive root cause statement",
  "resolution_plan": "Step-by-step fix plan", 
  "confidence": "High|Medium|Low",
  "ebpf_evidence": "Summary of eBPF findings that led to diagnosis"
}
```

### 3. eBPF Program Categories (AI Guidelines)

The system prompt now includes specific eBPF program recommendations:

| Issue Type | Recommended eBPF Programs |
|------------|---------------------------|
| **Network** | `syscalls/sys_enter_connect`, `kprobe:tcp_connect`, `kprobe:tcp_sendmsg` |
| **Process** | `syscalls/sys_enter_execve`, `sched/sched_process_exit`, `kprobe:do_fork` |
| **File I/O** | `syscalls/sys_enter_openat`, `kprobe:vfs_read`, `kprobe:vfs_write` |
| **Performance** | `syscalls/sys_enter_*`, `kprobe:schedule`, `irq/irq_handler_entry` |
| **Memory** | `kprobe:__alloc_pages_nodemask`, `kmem/kmalloc` |

## 🔍 Data Flow

### 1. AI Request → Agent
```json
{
  "ebpf_programs": [
    {"name": "tcp_monitor", "type": "kprobe", "target": "tcp_connect", "duration": 15}
  ]
}
```

### 2. Agent → eBPF Manager  
```go
programID, err := ebpfManager.StartEBPFProgram(ebpfRequest)
```

### 3. eBPF Results → AI
```json
{
  "ebpf_results": {
    "tcp_monitor_1695902400": {
      "program_name": "tcp_monitor", 
      "event_count": 42,
      "events": [
        {
          "timestamp": 1695902400000000000,
          "process_id": 1234,
          "process_name": "curl",
          "event_type": "tcp_connect", 
          "data": {"destination": "192.168.1.1:443"}
        }
      ],
      "summary": "Captured 42 TCP connection attempts over 15 seconds"
    }
  }
}
```

## ✅ Validation Checklist

Before deploying to TensorZero:

- [ ] **System Prompt Updated**: Copy complete content from `TENSORZERO_SYSTEM_PROMPT.md`
- [ ] **JSON Format Validated**: Ensure AI model can generate structured eBPF requests
- [ ] **Agent Endpoint**: Verify `NANNYAPI_MODEL` environment variable points to your TensorZero function
- [ ] **Test Scenarios**: Prepare test cases for network, process, file, and performance issues
- [ ] **Root Privileges**: Ensure production agent runs with sufficient privileges for eBPF

## 🚀 Example Diagnostic Flow

### User Issue: "Application randomly fails to connect to database"

### AI Response:
```json
{
  "response_type": "diagnostic",
  "reasoning": "Database connection failures could be due to network issues, DNS resolution, or connection pool exhaustion. Need to monitor both system-level network activity and application behavior.",
  "commands": [
    {"id": "db_connections", "command": "ss -tlnp | grep :5432", "description": "Check PostgreSQL connections"},
    {"id": "dns_check", "command": "nslookup db.example.com", "description": "Verify DNS resolution"}
  ],
  "ebpf_programs": [
    {
      "name": "tcp_connect_db",
      "type": "kprobe", 
      "target": "tcp_connect",
      "duration": 20,
      "filters": {"comm": "myapp"},
      "description": "Monitor TCP connection attempts from application"
    },
    {
      "name": "dns_queries",
      "type": "tracepoint",
      "target": "syscalls/sys_enter_connect", 
      "duration": 20,
      "description": "Monitor network system calls for DNS resolution"
    }
  ]
}
```

### Agent Execution:
1. Runs `ss` and `nslookup` commands
2. Starts eBPF programs to monitor TCP connections and DNS queries  
3. Collects real-time kernel events for 20 seconds
4. Returns combined traditional + eBPF results to AI

### AI Analysis:
```json
{
  "response_type": "resolution",
  "root_cause": "Application is experiencing DNS resolution timeouts. eBPF traces show successful TCP connections to IP addresses but failed connections when using hostname.",
  "resolution_plan": "1. Configure application to use IP address directly\n2. Fix DNS timeout: echo 'nameserver 8.8.8.8' >> /etc/resolv.conf\n3. Test connectivity: dig db.example.com",
  "confidence": "High",
  "ebpf_evidence": "eBPF tcp_connect traces show 15 successful connections to 10.0.1.50:5432 but 8 failed connection attempts during DNS lookups. DNS query monitoring revealed 3-5 second delays in resolution."
}
```

This integration provides your diagnostic agent with professional-grade system monitoring capabilities that were previously only available in dedicated observability tools!

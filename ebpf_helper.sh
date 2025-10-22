#!/bin/bash

# eBPF Helper Scripts for NannyAgent
# This script contains various eBPF programs and helpers for system monitoring

# Check if running as root (required for most eBPF operations)
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Warning: Many eBPF operations require root privileges"
        echo "Consider running with sudo for full functionality"
    fi
}

# Install eBPF tools if not present
install_ebpf_tools() {
    echo "Installing eBPF tools..."
    
    # Detect package manager and install appropriate packages
    if command -v apt-get >/dev/null 2>&1; then
        # Ubuntu/Debian
        echo "Detected Ubuntu/Debian system"
        apt-get update
        apt-get install -y bpftrace linux-tools-generic linux-tools-$(uname -r) || true
        apt-get install -y bcc-tools python3-bcc || true
    elif command -v yum >/dev/null 2>&1; then
        # RHEL/CentOS 7
        echo "Detected RHEL/CentOS system"
        yum install -y bpftrace perf || true
    elif command -v dnf >/dev/null 2>&1; then
        # RHEL/CentOS 8+/Fedora
        echo "Detected Fedora/RHEL 8+ system"
        dnf install -y bpftrace perf bcc-tools python3-bcc || true
    elif command -v zypper >/dev/null 2>&1; then
        # openSUSE
        echo "Detected openSUSE system"
        zypper install -y bpftrace perf || true
    else
        echo "Unknown package manager. Please install eBPF tools manually:"
        echo "- bpftrace"
        echo "- perf (linux-tools)"
        echo "- BCC tools (optional)"
    fi
}

# Check eBPF capabilities of the current system
check_ebpf_capabilities() {
    echo "Checking eBPF capabilities..."
    
    # Check kernel version
    kernel_version=$(uname -r)
    echo "Kernel version: $kernel_version"
    
    # Check if eBPF is enabled in kernel
    if [ -f /proc/config.gz ]; then
        if zcat /proc/config.gz | grep -q "CONFIG_BPF=y"; then
            echo "✓ eBPF support enabled in kernel"
        else
            echo "✗ eBPF support not found in kernel config"
        fi
    elif [ -f "/boot/config-$(uname -r)" ]; then
        if grep -q "CONFIG_BPF=y" "/boot/config-$(uname -r)"; then
            echo "✓ eBPF support enabled in kernel"
        else
            echo "✗ eBPF support not found in kernel config"
        fi
    else
        echo "? Unable to check kernel eBPF config"
    fi
    
    # Check available tools
    echo ""
    echo "Available eBPF tools:"
    
    tools=("bpftrace" "perf" "execsnoop" "opensnoop" "tcpconnect" "biotop")
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo "✓ $tool"
        else
            echo "✗ $tool"
        fi
    done
    
    # Check debugfs mount
    if mount | grep -q debugfs; then
        echo "✓ debugfs mounted"
    else
        echo "✗ debugfs not mounted (required for ftrace)"
        echo "  To mount: sudo mount -t debugfs none /sys/kernel/debug"
    fi
    
    # Check if we can load eBPF programs
    echo ""
    echo "Testing eBPF program loading..."
    if bpftrace -e 'BEGIN { print("eBPF test successful"); exit(); }' >/dev/null 2>&1; then
        echo "✓ eBPF program loading works"
    else
        echo "✗ eBPF program loading failed (may need root privileges)"
    fi
}

# Create simple syscall monitoring script
create_syscall_monitor() {
    cat > /tmp/nannyagent_syscall_monitor.bt << 'EOF'
#!/usr/bin/env bpftrace

BEGIN {
    printf("Monitoring syscalls... Press Ctrl-C to stop\n");
    printf("[\n");
}

tracepoint:syscalls:sys_enter_* {
    printf("{\"timestamp\":%llu,\"event_type\":\"syscall_enter\",\"process_id\":%d,\"process_name\":\"%s\",\"syscall\":\"%s\",\"user_id\":%d},\n",
        nsecs, pid, comm, probe, uid);
}

END {
    printf("]\n");
}
EOF

    chmod +x /tmp/nannyagent_syscall_monitor.bt
    echo "Syscall monitor created: /tmp/nannyagent_syscall_monitor.bt"
}

# Create network activity monitor
create_network_monitor() {
    cat > /tmp/nannyagent_network_monitor.bt << 'EOF'
#!/usr/bin/env bpftrace

BEGIN {
    printf("Monitoring network activity... Press Ctrl-C to stop\n");
    printf("[\n");
}

kprobe:tcp_sendmsg,
kprobe:tcp_recvmsg,
kprobe:udp_sendmsg,
kprobe:udp_recvmsg {
    $action = (probe =~ /send/ ? "send" : "recv");
    $protocol = (probe =~ /tcp/ ? "tcp" : "udp");
    printf("{\"timestamp\":%llu,\"event_type\":\"network_%s\",\"protocol\":\"%s\",\"process_id\":%d,\"process_name\":\"%s\"},\n",
        nsecs, $action, $protocol, pid, comm);
}

END {
    printf("]\n");
}
EOF

    chmod +x /tmp/nannyagent_network_monitor.bt
    echo "Network monitor created: /tmp/nannyagent_network_monitor.bt"
}

# Create file access monitor
create_file_monitor() {
    cat > /tmp/nannyagent_file_monitor.bt << 'EOF'
#!/usr/bin/env bpftrace

BEGIN {
    printf("Monitoring file access... Press Ctrl-C to stop\n");
    printf("[\n");
}

tracepoint:syscalls:sys_enter_openat {
    printf("{\"timestamp\":%llu,\"event_type\":\"file_open\",\"process_id\":%d,\"process_name\":\"%s\",\"filename\":\"%s\",\"flags\":%d},\n",
        nsecs, pid, comm, str(args->pathname), args->flags);
}

tracepoint:syscalls:sys_enter_unlinkat {
    printf("{\"timestamp\":%llu,\"event_type\":\"file_delete\",\"process_id\":%d,\"process_name\":\"%s\",\"filename\":\"%s\"},\n",
        nsecs, pid, comm, str(args->pathname));
}

END {
    printf("]\n");
}
EOF

    chmod +x /tmp/nannyagent_file_monitor.bt
    echo "File monitor created: /tmp/nannyagent_file_monitor.bt"
}

# Create process monitor
create_process_monitor() {
    cat > /tmp/nannyagent_process_monitor.bt << 'EOF'
#!/usr/bin/env bpftrace

BEGIN {
    printf("Monitoring process activity... Press Ctrl-C to stop\n");
    printf("[\n");
}

tracepoint:syscalls:sys_enter_execve {
    printf("{\"timestamp\":%llu,\"event_type\":\"process_exec\",\"process_id\":%d,\"process_name\":\"%s\",\"filename\":\"%s\"},\n",
        nsecs, pid, comm, str(args->filename));
}

tracepoint:sched:sched_process_exit {
    printf("{\"timestamp\":%llu,\"event_type\":\"process_exit\",\"process_id\":%d,\"process_name\":\"%s\",\"exit_code\":%d},\n",
        nsecs, args->pid, args->comm, args->code);
}

END {
    printf("]\n");
}
EOF

    chmod +x /tmp/nannyagent_process_monitor.bt
    echo "Process monitor created: /tmp/nannyagent_process_monitor.bt"
}

# Performance monitoring setup
setup_performance_monitoring() {
    echo "Setting up performance monitoring..."
    
    # Create performance monitoring script
    cat > /tmp/nannyagent_perf_monitor.sh << 'EOF'
#!/bin/bash

DURATION=${1:-10}
OUTPUT_FILE=${2:-/tmp/nannyagent_perf_output.json}

echo "Running performance monitoring for $DURATION seconds..."
echo "[" > "$OUTPUT_FILE"

# Sample system performance every second
for i in $(seq 1 $DURATION); do
    timestamp=$(date +%s)000000000
    cpu_percent=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    memory_percent=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    
    echo "{\"timestamp\":$timestamp,\"event_type\":\"performance_sample\",\"cpu_percent\":\"$cpu_percent\",\"memory_percent\":\"$memory_percent\",\"load_avg\":\"$load_avg\"}," >> "$OUTPUT_FILE"
    
    [ $i -lt $DURATION ] && sleep 1
done

echo "]" >> "$OUTPUT_FILE"
echo "Performance data saved to $OUTPUT_FILE"
EOF

    chmod +x /tmp/nannyagent_perf_monitor.sh
    echo "Performance monitor created: /tmp/nannyagent_perf_monitor.sh"
}

# Main function
main() {
    check_root
    
    case "${1:-help}" in
        "install")
            install_ebpf_tools
            ;;
        "check")
            check_ebpf_capabilities
            ;;
        "setup")
            echo "Setting up eBPF monitoring scripts..."
            create_syscall_monitor
            create_network_monitor
            create_file_monitor
            create_process_monitor
            setup_performance_monitoring
            echo "All eBPF monitoring scripts created in /tmp/"
            ;;
        "test")
            echo "Testing eBPF functionality..."
            check_ebpf_capabilities
            if command -v bpftrace >/dev/null 2>&1; then
                echo "Running quick eBPF test..."
                timeout 5s bpftrace -e 'BEGIN { print("eBPF is working!"); } tracepoint:syscalls:sys_enter_openat { @[comm] = count(); } END { print(@); clear(@); }'
            fi
            ;;
        "help"|*)
            echo "eBPF Helper Script for NannyAgent"
            echo ""
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  install  - Install eBPF tools on the system"
            echo "  check    - Check eBPF capabilities"
            echo "  setup    - Create eBPF monitoring scripts"
            echo "  test     - Test eBPF functionality"
            echo "  help     - Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 check          # Check what eBPF tools are available"
            echo "  $0 install        # Install eBPF tools (requires root)"
            echo "  $0 setup          # Create monitoring scripts"
            echo "  $0 test           # Test eBPF functionality"
            ;;
    esac
}

# Run main function with all arguments
main "$@"

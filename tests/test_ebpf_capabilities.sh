#!/bin/bash

# eBPF Capability Test Script for NannyAgent
# This script demonstrates and tests the eBPF integration

set -e

echo "🔍 NannyAgent eBPF Capability Test"
echo "=================================="
echo ""

AGENT_PATH="./nannyagent-ebpf"
HELPER_PATH="./ebpf_helper.sh"

# Check if agent binary exists
if [ ! -f "$AGENT_PATH" ]; then
    echo "Building NannyAgent with eBPF capabilities..."
    go build -o nannyagent-ebpf .
fi

echo "1. Checking eBPF system capabilities..."
echo "--------------------------------------"
$HELPER_PATH check
echo ""

echo "2. Setting up eBPF monitoring scripts..."
echo "---------------------------------------"
$HELPER_PATH setup
echo ""

echo "3. Testing eBPF functionality..."
echo "------------------------------"

# Test if bpftrace is available and working
if command -v bpftrace >/dev/null 2>&1; then
    echo "✓ Testing bpftrace functionality..."
    if timeout 3s bpftrace -e 'BEGIN { print("eBPF test successful"); exit(); }' >/dev/null 2>&1; then
        echo "✓ bpftrace working correctly"
    else
        echo "⚠ bpftrace available but may need root privileges"
    fi
else
    echo "ℹ bpftrace not available (install with: sudo apt install bpftrace)"
fi

# Test perf availability
if command -v perf >/dev/null 2>&1; then
    echo "✓ perf tools available"
else
    echo "ℹ perf tools not available (install with: sudo apt install linux-tools-generic)"
fi

echo ""
echo "4. Example eBPF monitoring scenarios..."
echo "------------------------------------"

echo ""
echo "Scenario 1: Network Issue"
echo "Problem: 'Web server experiencing intermittent connection timeouts'"
echo "Expected eBPF: network_trace, syscall_trace"
echo ""

echo "Scenario 2: Performance Issue"  
echo "Problem: 'System running slowly with high CPU usage'"
echo "Expected eBPF: process_trace, performance, syscall_trace"
echo ""

echo "Scenario 3: File System Issue"
echo "Problem: 'Application cannot access configuration files'"
echo "Expected eBPF: file_trace, security_event"
echo ""

echo "Scenario 4: Security Issue"
echo "Problem: 'Suspicious activity detected, possible privilege escalation'"
echo "Expected eBPF: security_event, process_trace, syscall_trace"
echo ""

echo "5. Interactive Test Mode"
echo "----------------------"
read -p "Would you like to test the eBPF-enhanced agent interactively? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Starting NannyAgent with eBPF capabilities..."
    echo "Try describing one of the scenarios above to see eBPF in action!"
    echo ""
    echo "Example inputs:"
    echo "- 'Network connection timeouts'"
    echo "- 'High CPU usage and slow performance'"  
    echo "- 'File permission errors'"
    echo "- 'Suspicious process behavior'"
    echo ""
    echo "Note: For full eBPF functionality, run with 'sudo $AGENT_PATH'"
    echo ""
    
    $AGENT_PATH
fi

echo ""
echo "6. eBPF Files Created"
echo "-------------------"
echo "Monitor scripts created in /tmp/:"
ls -la /tmp/nannyagent_*monitor* 2>/dev/null || echo "No monitor scripts found"
echo ""

echo "eBPF data directory: /tmp/nannyagent/ebpf/"
ls -la /tmp/nannyagent/ebpf/ 2>/dev/null || echo "No eBPF data files found"
echo ""

echo "✅ eBPF capability test complete!"
echo ""
echo "Next Steps:"
echo "----------"
echo "1. For full functionality: sudo $AGENT_PATH"
echo "2. Install eBPF tools: sudo $HELPER_PATH install"
echo "3. Read documentation: cat EBPF_README.md"
echo "4. Test specific monitoring: $HELPER_PATH test"

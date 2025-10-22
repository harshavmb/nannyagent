#!/bin/bash

# Direct eBPF test to verify functionality
echo "Testing eBPF Cilium Manager directly..."

# Test if bpftrace works
echo "Checking bpftrace availability..."
if ! command -v bpftrace &> /dev/null; then
    echo "❌ bpftrace not found - installing..."
    sudo apt update && sudo apt install -y bpftrace
fi

echo "✅ bpftrace available"

# Test a simple UDP probe
echo "Testing UDP probe for 10 seconds..."
timeout 10s sudo bpftrace -e '
BEGIN {
    printf("Starting UDP monitoring...\n");
}

kprobe:udp_sendmsg {
    printf("UDP_SEND|%d|%s|%d|%s\n", nsecs, probe, pid, comm);
}

kprobe:udp_recvmsg {
    printf("UDP_RECV|%d|%s|%d|%s\n", nsecs, probe, pid, comm);
}

END {
    printf("UDP monitoring completed\n");
}'

echo "✅ Direct bpftrace test completed"

# Test if there's any network activity
echo "Generating some network activity..."
ping -c 3 8.8.8.8 &
nslookup google.com &
wait

echo "✅ Network activity generated"
echo "Now testing our Go eBPF implementation..."

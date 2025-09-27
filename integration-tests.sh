#!/bin/bash

# Linux Diagnostic Agent - Integration Tests
# This script creates realistic Linux problem scenarios for testing

set -e

AGENT_BINARY="./nanny-agent"
TEST_DIR="/tmp/nanny-agent-tests"
TEST_LOG="$TEST_DIR/integration_test.log"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Ensure test directory exists
mkdir -p "$TEST_DIR"

echo -e "${BLUE}🧪 Linux Diagnostic Agent - Integration Tests${NC}"
echo "================================================="
echo ""

# Check if agent binary exists
if [[ ! -f "$AGENT_BINARY" ]]; then
    echo -e "${RED}❌ Agent binary not found at $AGENT_BINARY${NC}"
    echo "Please run: make build"
    exit 1
fi

# Function to run a test scenario
run_test() {
    local test_name="$1"
    local scenario="$2"
    local expected_keywords="$3"
    
    echo -e "${YELLOW}📋 Test: $test_name${NC}"
    echo "Scenario: $scenario"
    echo ""
    
    # Run the agent with the scenario
    echo "$scenario" | timeout 120s "$AGENT_BINARY" > "$TEST_LOG" 2>&1 || true
    
    # Check if any expected keywords are found in the output
    local found_keywords=0
    IFS=',' read -ra KEYWORDS <<< "$expected_keywords"
    for keyword in "${KEYWORDS[@]}"; do
        keyword=$(echo "$keyword" | xargs) # trim whitespace
        if grep -qi "$keyword" "$TEST_LOG"; then
            echo -e "${GREEN}  ✅ Found expected keyword: $keyword${NC}"
            ((found_keywords++))
        else
            echo -e "${RED}  ❌ Missing keyword: $keyword${NC}"
        fi
    done
    
    # Show summary
    if [[ $found_keywords -gt 0 ]]; then
        echo -e "${GREEN}  ✅ Test PASSED ($found_keywords keywords found)${NC}"
    else
        echo -e "${RED}  ❌ Test FAILED (no expected keywords found)${NC}"
    fi
    
    echo ""
    echo "Full output saved to: $TEST_LOG"
    echo "----------------------------------------"
    echo ""
}

# Test Scenario 1: Disk Space Issues (Inode Exhaustion)
run_test "Disk Space - Inode Exhaustion" \
    "I cannot create new files in /home directory even though df -h shows plenty of space available. Getting 'No space left on device' error when trying to touch new files." \
    "inode,df -i,filesystem,inodes,exhausted"

# Test Scenario 2: Memory Issues
run_test "Memory Issues - OOM Killer" \
    "My applications keep getting killed randomly and I see 'killed' messages in logs. The system becomes unresponsive for a few seconds before recovering. This happens especially when running memory-intensive tasks." \
    "memory,oom,killed,dmesg,free,swap"

# Test Scenario 3: Network Connectivity Issues
run_test "Network Connectivity - DNS Resolution" \
    "I can ping IP addresses directly (like 8.8.8.8) but cannot resolve domain names. Web browsing fails with DNS resolution errors, but ping 8.8.8.8 works fine." \
    "dns,resolv.conf,nslookup,nameserver,dig"

# Test Scenario 4: Service/Process Issues
run_test "Service Issues - High Load" \
    "System load average is consistently above 10.0 even when CPU usage appears normal. Applications are responding slowly and I notice high wait times. The server feels sluggish overall." \
    "load,average,cpu,iostat,vmstat,processes"

# Test Scenario 5: File System Issues
run_test "Filesystem Issues - Permission Problems" \
    "Web server returns 403 Forbidden errors for all pages. Files exist and seem readable, but nginx logs show permission denied errors. SELinux is disabled and file permissions look correct." \
    "permission,403,nginx,chmod,chown,selinux"

# Test Scenario 6: Boot/System Issues
run_test "Boot Issues - Kernel Module" \
    "System boots but some hardware devices are not working. Network interface shows as down, USB devices are not recognized, and dmesg shows module loading failures." \
    "module,lsmod,dmesg,hardware,interface,usb"

# Test Scenario 7: Performance Issues
run_test "Performance Issues - I/O Bottleneck" \
    "Database queries are extremely slow, taking 30+ seconds for simple SELECT statements. Disk activity LED is constantly on and system feels unresponsive during database operations." \
    "iostat,iotop,disk,database,slow,performance"

echo -e "${BLUE}🏁 Integration Tests Complete${NC}"
echo ""
echo "Check individual test logs in: $TEST_DIR"
echo ""
echo -e "${YELLOW}💡 Tips:${NC}"
echo "- Tests use realistic scenarios that could occur on production systems"
echo "- Each test expects the AI to suggest relevant diagnostic commands"
echo "- Review the full logs to see the complete diagnostic conversation"
echo "- Tests timeout after 120 seconds to prevent hanging"
echo "- Make sure NANNYAPI_ENDPOINT and NANNYAPI_MODEL are set correctly"

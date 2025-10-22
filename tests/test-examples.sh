#!/bin/bash

# Linux Diagnostic Agent - Test Scenarios
# Realistic Linux problems for testing the diagnostic agent

echo "🔧 Linux Diagnostic Agent - Test Scenarios"
echo "==========================================="
echo ""

echo "📚 Available test scenarios (copy-paste into the agent):"
echo ""

echo "1. 💾 DISK SPACE ISSUES (Inode Exhaustion):"
echo "────────────────────────────────────────────"
echo "I cannot create new files in /home directory even though df -h shows plenty of space available. Getting 'No space left on device' error when trying to touch new files."
echo ""

echo "2. 🧠 MEMORY ISSUES (OOM Killer):"
echo "─────────────────────────────────"
echo "My applications keep getting killed randomly and I see 'killed' messages in logs. The system becomes unresponsive for a few seconds before recovering. This happens especially when running memory-intensive tasks."
echo ""

echo "3. 🌐 NETWORK CONNECTIVITY (DNS Resolution):"
echo "─────────────────────────────────────────────"
echo "I can ping IP addresses directly (like 8.8.8.8) but cannot resolve domain names. Web browsing fails with DNS resolution errors, but ping 8.8.8.8 works fine."
echo ""

echo "4. ⚡ PERFORMANCE ISSUES (High Load):"
echo "───────────────────────────────────"
echo "System load average is consistently above 10.0 even when CPU usage appears normal. Applications are responding slowly and I notice high wait times. The server feels sluggish overall."
echo ""

echo "5. 🚫 WEB SERVER ISSUES (Permission Problems):"
echo "──────────────────────────────────────────────"
echo "Web server returns 403 Forbidden errors for all pages. Files exist and seem readable, but nginx logs show permission denied errors. SELinux is disabled and file permissions look correct."
echo ""

echo "6. 🖥️  HARDWARE/BOOT ISSUES (Kernel Module):"
echo "─────────────────────────────────────────────"
echo "System boots but some hardware devices are not working. Network interface shows as down, USB devices are not recognized, and dmesg shows module loading failures."
echo ""

echo "7. 🐌 DATABASE PERFORMANCE (I/O Bottleneck):"
echo "─────────────────────────────────────────────"
echo "Database queries are extremely slow, taking 30+ seconds for simple SELECT statements. Disk activity LED is constantly on and system feels unresponsive during database operations."
echo ""

echo "8. 🔥 HIGH CPU USAGE (Process Analysis):"
echo "────────────────────────────────────────"
echo "System is running slow and CPU usage is constantly at 100%. Top shows high CPU usage but I can't identify which specific process or thread is causing the issue."
echo ""

echo "9. 📁 FILE SYSTEM CORRUPTION:"
echo "────────────────────────────"
echo "Getting 'Input/output error' when accessing certain files and directories. Some files appear corrupted and applications crash when trying to read specific data files."
echo ""

echo "10. 🔌 SERVICE STARTUP FAILURES:"
echo "───────────────────────────────"
echo "Critical services fail to start after system reboot. Systemctl shows services in failed state but error messages are unclear. System appears to boot normally otherwise."
echo ""

echo "🚀 Quick Start:"
echo "──────────────"
echo "1. Run: ./nanny-agent"
echo "2. Copy-paste any scenario above when prompted"
echo "3. Watch the AI diagnose the problem step by step"
echo ""

echo "🧪 Automated Testing:"
echo "────────────────────"
echo "Run integration tests: ./integration-tests.sh"
echo "This will test all scenarios automatically"
echo ""

echo "💡 Pro Tips:"
echo "───────────"
echo "- Each scenario is based on real-world Linux issues"
echo "- The AI will gather system info automatically"
echo "- Diagnostic commands are executed safely (read-only)"
echo "- You'll get a detailed resolution plan at the end"
echo "- Set NANNYAPI_ENDPOINT and NANNYAPI_MODEL before running"

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// checkRootPrivileges ensures the program is running as root
func checkRootPrivileges() {
	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "❌ ERROR: This program must be run as root for eBPF functionality.\n")
		fmt.Fprintf(os.Stderr, "Please run with: sudo %s\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Reason: eBPF programs require root privileges to:\n")
		fmt.Fprintf(os.Stderr, "  - Load programs into the kernel\n")
		fmt.Fprintf(os.Stderr, "  - Attach to kernel functions and tracepoints\n")
		fmt.Fprintf(os.Stderr, "  - Access kernel memory maps\n")
		os.Exit(1)
	}
}

// checkKernelVersionCompatibility ensures kernel version is 4.4 or higher
func checkKernelVersionCompatibility() {
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ ERROR: Cannot determine kernel version: %v\n", err)
		os.Exit(1)
	}

	kernelVersion := strings.TrimSpace(string(output))

	// Parse version (e.g., "5.15.0-56-generic" -> major=5, minor=15)
	parts := strings.Split(kernelVersion, ".")
	if len(parts) < 2 {
		fmt.Fprintf(os.Stderr, "❌ ERROR: Cannot parse kernel version: %s\n", kernelVersion)
		os.Exit(1)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ ERROR: Cannot parse major kernel version: %s\n", parts[0])
		os.Exit(1)
	}

	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ ERROR: Cannot parse minor kernel version: %s\n", parts[1])
		os.Exit(1)
	}

	// Check if kernel is 4.4 or higher
	if major < 4 || (major == 4 && minor < 4) {
		fmt.Fprintf(os.Stderr, "❌ ERROR: Kernel version %s is too old for eBPF.\n", kernelVersion)
		fmt.Fprintf(os.Stderr, "Required: Linux kernel 4.4 or higher\n")
		fmt.Fprintf(os.Stderr, "Current: %s\n", kernelVersion)
		fmt.Fprintf(os.Stderr, "Reason: eBPF requires kernel features introduced in 4.4+:\n")
		fmt.Fprintf(os.Stderr, "  - BPF system call support\n")
		fmt.Fprintf(os.Stderr, "  - eBPF program types (kprobe, tracepoint)\n")
		fmt.Fprintf(os.Stderr, "  - BPF maps and helper functions\n")
		os.Exit(1)
	}

	fmt.Printf("✅ Kernel version %s is compatible with eBPF\n", kernelVersion)
}

// checkEBPFSupport validates eBPF subsystem availability
func checkEBPFSupport() {
	// Check if /sys/kernel/debug/tracing exists (debugfs mounted)
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "⚠️  WARNING: debugfs not mounted. Some eBPF features may not work.\n")
		fmt.Fprintf(os.Stderr, "To fix: sudo mount -t debugfs debugfs /sys/kernel/debug\n")
	}

	// Check if we can access BPF syscall
	fd, _, errno := syscall.Syscall(321, 0, 0, 0) // BPF syscall number on x86_64
	if errno != 0 && errno != syscall.EINVAL {
		fmt.Fprintf(os.Stderr, "❌ ERROR: BPF syscall not available (errno: %v)\n", errno)
		fmt.Fprintf(os.Stderr, "This may indicate:\n")
		fmt.Fprintf(os.Stderr, "  - Kernel compiled without BPF support\n")
		fmt.Fprintf(os.Stderr, "  - BPF syscall disabled in kernel config\n")
		os.Exit(1)
	}
	if fd > 0 {
		syscall.Close(int(fd))
	}

	fmt.Printf("✅ eBPF syscall is available\n")
}

func main() {
	fmt.Println("🔍 Linux eBPF-Enhanced Diagnostic Agent")
	fmt.Println("=======================================")

	// Perform system compatibility checks
	fmt.Println("Performing system compatibility checks...")

	checkRootPrivileges()
	checkKernelVersionCompatibility()
	checkEBPFSupport()

	fmt.Println("✅ All system checks passed")
	fmt.Println("")

	// Initialize the agent
	agent := NewLinuxDiagnosticAgent()

	// Start the interactive session
	fmt.Println("Linux Diagnostic Agent Started")
	fmt.Println("Enter a system issue description (or 'quit' to exit):")

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		if input == "quit" || input == "exit" {
			break
		}

		if input == "" {
			continue
		}

		// Process the issue with eBPF capabilities
		if err := agent.DiagnoseWithEBPF(input); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Goodbye!")
}

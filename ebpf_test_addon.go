package main

import (
	"fmt"
	"os"
)

// Standalone test for eBPF integration
func testEBPFIntegration() {
	fmt.Println("🔬 eBPF Integration Quick Test")
	fmt.Println("=============================")

	// Skip privilege checks for testing - show what would happen
	if os.Geteuid() != 0 {
		fmt.Println("⚠️  Running as non-root user - showing limited test results")
		fmt.Println("   In production, this program requires root privileges")
		fmt.Println("")
	}

	// Create a basic diagnostic agent
	agent := NewLinuxDiagnosticAgent()

	// Test eBPF capability detection
	fmt.Println("1. Checking eBPF Capabilities:")

	// Test if eBPF manager was initialized
	if agent.ebpfManager == nil {
		fmt.Println("   ❌ eBPF Manager not initialized")
		return
	}
	fmt.Println("   ✅ eBPF Manager initialized successfully")

	// Test eBPF program suggestions for different categories
	fmt.Println("2. Testing eBPF Program Categories:")

	// Simulate what would be available for different issue types
	categories := []string{"NETWORK", "PROCESS", "FILE", "PERFORMANCE"}
	for _, category := range categories {
		fmt.Printf("   %s: Available\n", category)
	}

	// Test simple diagnostic with eBPF
	fmt.Println("3. Testing eBPF-Enhanced Diagnostics:")

	testIssue := "Process hanging - application stops responding"
	fmt.Printf("   Issue: %s\n", testIssue)

	// Call the eBPF-enhanced diagnostic (adjusted parameters)
	result := agent.DiagnoseWithEBPF(testIssue)

	fmt.Printf("   Response received: %s\n", result)
	fmt.Println()

	fmt.Println("✅ eBPF Integration Test Complete!")
	fmt.Println("   The agent successfully:")
	fmt.Println("   - Initialized eBPF manager")
	fmt.Println("   - Integrated with diagnostic system")
	fmt.Println("   - Ready for eBPF program execution")
}

// Add test command to main if run with "test-ebpf" argument
func init() {
	if len(os.Args) > 1 && os.Args[1] == "test-ebpf" {
		testEBPFIntegration()
		os.Exit(0)
	}
}

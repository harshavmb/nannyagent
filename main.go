package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"nannyagentv2/internal/auth"
	"nannyagentv2/internal/config"
	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/metrics"
	"nannyagentv2/internal/types"
	"nannyagentv2/internal/websocket"
)

const Version = "0.0.1"

// showVersion displays the version information
func showVersion() {
	fmt.Printf("nannyagent version %s\n", Version)
	fmt.Println("Linux diagnostic agent with eBPF capabilities")
	os.Exit(0)
}

// showHelp displays the help information
func showHelp() {
	fmt.Println("NannyAgent - Linux Diagnostic Agent with eBPF Monitoring")
	fmt.Printf("Version: %s\n\n", Version)
	fmt.Println("USAGE:")
	fmt.Printf("  sudo %s [OPTIONS]\n\n", os.Args[0])
	fmt.Println("OPTIONS:")
	fmt.Println("  --version, -v    Show version information")
	fmt.Println("  --help, -h       Show this help message")
	fmt.Println()
	fmt.Println("DESCRIPTION:")
	fmt.Println("  NannyAgent is an AI-powered Linux diagnostic tool that uses eBPF")
	fmt.Println("  for deep system monitoring and analysis. It requires root privileges")
	fmt.Println("  to run for eBPF functionality.")
	fmt.Println()
	fmt.Println("REQUIREMENTS:")
	fmt.Println("  - Linux kernel 5.x or higher")
	fmt.Println("  - Root privileges (sudo)")
	fmt.Println("  - bpftrace and bpfcc-tools installed")
	fmt.Println("  - Network connectivity to nannyapi")
	fmt.Println()
	fmt.Println("CONFIGURATION:")
	fmt.Println("  Configuration file: /etc/nannyagent/config.env")
	fmt.Println("  Data directory: /var/lib/nannyagent")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Printf("  # Run the agent\n")
	fmt.Printf("  sudo %s\n\n", os.Args[0])
	fmt.Printf("  # Show version (no sudo required)\n")
	fmt.Printf("  %s --version\n\n", os.Args[0])
	fmt.Println("For more information, visit: https://github.com/harshavmb/nannyagent")
	os.Exit(0)
}

// checkRootPrivileges ensures the program is running as root
func checkRootPrivileges() {
	if os.Geteuid() != 0 {
		logging.Error("This program must be run as root for eBPF functionality")
		logging.Error("Please run with: sudo %s", os.Args[0])
		logging.Error("Reason: eBPF programs require root privileges to:\n - Load programs into the kernel\n - Attach to kernel functions and tracepoints\n - Access kernel memory maps")
		os.Exit(1)
	}
}

// checkKernelVersionCompatibility ensures kernel version is 5.x or higher
func checkKernelVersionCompatibility() {
	output, err := exec.Command("uname", "-r").Output()
	if err != nil {
		logging.Error("Cannot determine kernel version: %v", err)
		os.Exit(1)
	}

	kernelVersion := strings.TrimSpace(string(output))

	// Parse version (e.g., "5.15.0-56-generic" -> major=5, minor=15)
	parts := strings.Split(kernelVersion, ".")
	if len(parts) < 2 {
		logging.Error("Cannot parse kernel version: %s", kernelVersion)
		os.Exit(1)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		logging.Error("Cannot parse major kernel version: %s", parts[0])
		os.Exit(1)
	}

	// Check if kernel is 5.x or higher
	if major < 5 {
		logging.Error("Kernel version %s is not supported", kernelVersion)
		logging.Error("Required: Linux kernel 5.x or higher")
		logging.Error("Current: %s (major version: %d)", kernelVersion, major)
		logging.Error("Reason: NannyAgent requires modern kernel features:\n - Advanced eBPF capabilities\n - BTF (BPF Type Format) support\n - Enhanced security and stability")
		os.Exit(1)
	}
}

// checkEBPFSupport validates eBPF subsystem availability
func checkEBPFSupport() {
	// Check if /sys/kernel/debug/tracing exists (debugfs mounted)
	if _, err := os.Stat("/sys/kernel/debug/tracing"); os.IsNotExist(err) {
		logging.Warning("debugfs not mounted. Some eBPF features may not work")
		logging.Info("To fix: sudo mount -t debugfs debugfs /sys/kernel/debug")
	}

	// Check if bpftrace is available (this is all we need)
	if _, err := exec.LookPath("bpftrace"); err != nil {
		logging.Error("bpftrace not found in PATH")
		logging.Error("Please install bpftrace: apt-get install bpftrace (Debian/Ubuntu) or yum install bpftrace (RHEL/CentOS)")
		os.Exit(1)
	}
}

// runInteractiveDiagnostics starts the interactive diagnostic session
func runInteractiveDiagnostics(agent *LinuxDiagnosticAgent) {
	logging.Info("=== Linux eBPF-Enhanced Diagnostic Agent ===")
	logging.Info("Linux Diagnostic Agent Started")
	logging.Info("Enter a system issue description (or 'quit' to exit):")

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

		// Validate minimum prompt length (at least 10 characters for meaningful diagnosis)
		if len(input) < 10 {
			logging.Warning("Prompt is too short. Please provide a more detailed description of the problem.")
			logging.Info("Minimum 10 characters required. Example: 'Disk is full on /var partition'")
			continue
		}

		// Check if it's just 1 or 2 words
		words := strings.Fields(input)
		if len(words) < 3 {
			logging.Warning("Prompt is incomplete. Please describe the problem in more detail.")
			logging.Info("Example: 'Cannot create files in /var filesystem despite showing free space'")
			continue
		}

		// Process the issue with AI capabilities via TensorZero
		if err := agent.DiagnoseIssue(input); err != nil {
			logging.Error("Diagnosis failed: %v", err)
		}
	}

	if err := scanner.Err(); err != nil {
		logging.Error(err.Error())
	}

	logging.Info("Goodbye!")
}

func main() {
	// Define flags with both long and short versions
	versionFlag := flag.Bool("version", false, "Show version information")
	versionFlagShort := flag.Bool("v", false, "Show version information (short)")
	helpFlag := flag.Bool("help", false, "Show help information")
	helpFlagShort := flag.Bool("h", false, "Show help information (short)")
	flag.Parse()

	// Handle --version or -v flag (no root required)
	if *versionFlag || *versionFlagShort {
		showVersion()
	}

	// Handle --help or -h flag (no root required)
	if *helpFlag || *helpFlagShort {
		showHelp()
	}

	logging.Info("NannyAgent v%s starting...", Version)

	// Perform system compatibility checks first
	logging.Info("Performing system compatibility checks...")
	checkRootPrivileges()
	checkKernelVersionCompatibility()
	checkEBPFSupport()
	logging.Info("All system checks passed")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.Error("Failed to load configuration: %v", err)
		os.Exit(1)
	}

	cfg.PrintConfig()

	// Initialize components
	authManager := auth.NewAuthManager(cfg)
	metricsCollector := metrics.NewCollector(Version)

	// Ensure authentication
	token, err := authManager.EnsureAuthenticated()
	if err != nil {
		logging.Error("Authentication failed: %v", err)
		os.Exit(1)
	}

	logging.Info("Authentication successful!")

	// Initialize the diagnostic agent for interactive CLI use with authentication
	agent := NewLinuxDiagnosticAgentWithAuth(authManager)

	// Initialize a separate agent for WebSocket investigations using the application model
	// IMPORTANT: Must use WithAuth to include authorization headers for TensorZero API calls
	applicationAgent := NewLinuxDiagnosticAgentWithAuth(authManager)
	applicationAgent.model = "tensorzero::function_name::diagnose_and_heal_application"

	// Start WebSocket client for backend communications and investigations
	wsClient := websocket.NewWebSocketClient(applicationAgent, authManager)
	go func() {
		if err := wsClient.Start(); err != nil {
			logging.Error("WebSocket client error: %v", err)
		}
	}()

	// Start background metrics collection in a goroutine
	go func() {
		logging.Debug("Starting background metrics collection and heartbeat...")

		ticker := time.NewTicker(time.Duration(cfg.MetricsInterval) * time.Second)
		defer ticker.Stop()

		// Send initial heartbeat
		if err := sendHeartbeat(cfg, token, metricsCollector); err != nil {
			logging.Warning("Initial heartbeat failed: %v", err)
		}

		// Main heartbeat loop
		for range ticker.C {
			// Check if token needs refresh
			if authManager.IsTokenExpired(token) {
				logging.Debug("Token expiring soon, refreshing...")
				newToken, refreshErr := authManager.EnsureAuthenticated()
				if refreshErr != nil {
					logging.Warning("Token refresh failed: %v", refreshErr)
					continue
				}
				token = newToken
				logging.Debug("Token refreshed successfully")
			}

			// Send heartbeat
			if err := sendHeartbeat(cfg, token, metricsCollector); err != nil {
				logging.Warning("Heartbeat failed: %v", err)

				// If unauthorized, try to refresh token
				if err.Error() == "unauthorized" {
					logging.Debug("Unauthorized, attempting token refresh...")
					newToken, refreshErr := authManager.EnsureAuthenticated()
					if refreshErr != nil {
						logging.Warning("Token refresh failed: %v", refreshErr)
						continue
					}
					token = newToken

					// Retry heartbeat with new token (silently)
					if retryErr := sendHeartbeat(cfg, token, metricsCollector); retryErr != nil {
						logging.Warning("Retry heartbeat failed: %v", retryErr)
					}
				}
			}
			// No logging for successful heartbeats - they should be silent
		}
	}()

	// Start the interactive diagnostic session (blocking)
	runInteractiveDiagnostics(agent)
}

// sendHeartbeat collects metrics and sends heartbeat to the server
func sendHeartbeat(cfg *config.Config, token *types.AuthToken, collector *metrics.Collector) error {
	// Collect system metrics
	systemMetrics, err := collector.GatherSystemMetrics()
	if err != nil {
		return fmt.Errorf("failed to gather system metrics: %w", err)
	}

	// Send metrics using the collector with correct agent_id from token
	return collector.SendMetrics(cfg.AgentAuthURL, token.AccessToken, token.AgentID, systemMetrics)
}

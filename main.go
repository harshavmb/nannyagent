package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

const (
	// DataDir is the hardcoded path for agent data (not configurable)
	DataDir = "/var/lib/nannyagent"
)

var Version = "dev" // Will be set by build ldflags (e.g., -ldflags "-X main.Version=1.0.0")

// showVersion displays the version information (stdout only, no syslog)
func showVersion() {
	fmt.Printf("nannyagent version %s\n", Version)
	fmt.Println("Linux diagnostic agent with eBPF capabilities")
	os.Exit(0)
}

// showHelp displays the help information (stdout only, no syslog)
func showHelp() {
	fmt.Println("NannyAgent - AI-Powered Linux Diagnostic Agent")
	fmt.Printf("Version: %s\n\n", Version)
	fmt.Println("USAGE:")
	fmt.Printf("  %s [COMMAND]\n\n", os.Args[0])
	fmt.Println("COMMANDS:")
	fmt.Println("  --register           Register agent with NannyAI")
	fmt.Println("  --status             Show agent status")
	fmt.Println("  --diagnose <issue>   Run one-off diagnosis")
	fmt.Println("  --daemon             Run as daemon (systemd)")
	fmt.Println("  --version            Show version")
	fmt.Println("  --help               Show this help")
	fmt.Println()
	fmt.Println("EXAMPLES:")
	fmt.Println("  sudo nannyagent --register")
	fmt.Println("  nannyagent --status")
	fmt.Println("  sudo nannyagent --diagnose \"postgresql is slow\"")
	fmt.Println("  sudo nannyagent    # Interactive mode")
	fmt.Println()
	fmt.Printf("Documentation: https://nannyai.dev/documentation\n")
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

// validateDiagnosisPrompt validates that a diagnosis prompt is meaningful
func validateDiagnosisPrompt(prompt string) error {
	prompt = strings.TrimSpace(prompt)

	// Check minimum length (at least 10 characters)
	if len(prompt) < 10 {
		return fmt.Errorf("prompt is too short (minimum 10 characters required)")
	}

	// Check it has at least 3 words for meaningful context
	words := strings.Fields(prompt)
	if len(words) < 3 {
		return fmt.Errorf("prompt is incomplete (minimum 3 words required for meaningful diagnosis)")
	}

	return nil
}

// testAPIConnectivity tests if we can reach the API endpoint by sending a heartbeat
func testAPIConnectivity(cfg *config.Config, accessToken string, agentID string) error {
	// Test by sending actual heartbeat to agent-auth-api
	metricsCollector := metrics.NewCollector(Version)
	systemMetrics, err := metricsCollector.GatherSystemMetrics()
	if err != nil {
		return fmt.Errorf("failed to gather metrics: %w", err)
	}

	err = metricsCollector.SendMetrics(cfg.AgentAuthURL, accessToken, agentID, systemMetrics)
	if err != nil {
		return fmt.Errorf("heartbeat failed: %w", err)
	}

	return nil
}

// checkExistingAgentInstance verifies if an agent is already registered on this machine
func checkExistingAgentInstance() error {
	tokenPath := filepath.Join(DataDir, "token.json")

	// Check if token file exists
	if _, err := os.Stat(tokenPath); err == nil {
		return fmt.Errorf("agent already registered on this machine (token found at %s)", tokenPath)
	}

	return nil
}

// runRegisterCommand handles agent registration
func runRegisterCommand() {
	logging.Info("Starting NannyAgent registration")

	// Check if agent is already registered on this machine
	if err := checkExistingAgentInstance(); err != nil {
		logging.Error("Cannot register: %v", err)
		logging.Error("Only one agent instance is allowed per machine")
		logging.Error("To re-register, remove the existing token:")
		logging.Error("  sudo rm -rf %s", DataDir)
		os.Exit(1)
	}

	// Load configuration (use defaults if not available)
	cfg, err := config.LoadConfig()
	if err != nil {
		logging.Warning("Could not load configuration, using defaults: %v", err)
		cfg = &config.DefaultConfig
		cfg.SupabaseProjectURL = "https://api.nannyai.dev"
		cfg.DeviceAuthURL = fmt.Sprintf("%s/functions/v1/device-auth", cfg.SupabaseProjectURL)
		cfg.AgentAuthURL = fmt.Sprintf("%s/functions/v1/agent-auth-api", cfg.SupabaseProjectURL)
	}

	// Ensure token path uses hardcoded DataDir
	cfg.TokenPath = filepath.Join(DataDir, "token.json")

	// Initialize auth manager
	authManager := auth.NewAuthManager(cfg)

	// Run device flow
	logging.Info("Initiating device authorization flow...")
	token, err := authManager.EnsureAuthenticated()
	if err != nil {
		logging.Error("Registration failed: %v", err)
		os.Exit(1)
	}

	logging.Info("✓ Registration successful!")
	logging.Info("✓ Agent ID: %s", token.AgentID)
	logging.Info("✓ Token saved to: %s", cfg.TokenPath)
	logging.Info("")
	logging.Info("Next steps:")
	logging.Info("  1. Enable and start the service: sudo systemctl enable --now nannyagent")
	logging.Info("  2. Check status: nannyagent --status")
	logging.Info("  3. View logs: sudo journalctl -u nannyagent -f")
	os.Exit(0)
}

// runStatusCommand shows agent connectivity and status (stdout only)
func runStatusCommand() {
	// Disable syslog for status command - everything goes to stdout only
	logging.DisableSyslogOnly()

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Println("✗ Configuration: Not found")
		os.Exit(1)
	}

	fmt.Printf("✓ API Endpoint: %s\n", cfg.SupabaseProjectURL)

	// Check if token exists
	if _, err := os.Stat(cfg.TokenPath); os.IsNotExist(err) {
		fmt.Println("✗ Not registered")
		fmt.Println("\nRegister with: sudo nannyagent --register")
		os.Exit(1)
	}

	// Load and refresh token if needed
	authManager := auth.NewAuthManager(cfg)
	token, err := authManager.EnsureAuthenticated()
	if err != nil {
		fmt.Println("✗ Authentication failed")
		os.Exit(1)
	}

	// Get Agent ID from cache file or JWT
	agentID, err := authManager.GetCurrentAgentID()
	if err != nil {
		fmt.Println("✗ Failed to get Agent ID")
		os.Exit(1)
	}

	fmt.Printf("✓ Agent ID: %s\n", agentID)

	// Test connectivity by sending a heartbeat to agent-auth-api
	metricsCollector := metrics.NewCollector(Version)
	systemMetrics, err := metricsCollector.GatherSystemMetrics()
	if err != nil {
		fmt.Println("✗ Failed to gather metrics")
		os.Exit(1)
	}

	err = metricsCollector.SendMetrics(cfg.AgentAuthURL, token.AccessToken, agentID, systemMetrics)
	if err != nil {
		fmt.Printf("✗ API error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ API connectivity OK")

	// Check systemd service status
	if _, err := exec.LookPath("systemctl"); err == nil {
		cmd := exec.Command("systemctl", "is-active", "nannyagent")
		output, _ := cmd.Output()
		status := strings.TrimSpace(string(output))

		if status == "active" {
			fmt.Println("✓ Service running")
		} else {
			fmt.Printf("✗ Service %s\n", status)
		}
	}

	os.Exit(0)
}

// runInteractiveDiagnostics starts the interactive diagnostic session
func runInteractiveDiagnostics(agent *LinuxDiagnosticAgent) {
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
	// Define flags (all with -- prefix for uniformity)
	versionFlag := flag.Bool("version", false, "Show version information")
	helpFlag := flag.Bool("help", false, "Show help information")
	registerFlag := flag.Bool("register", false, "Register agent with NannyAI backend")
	statusFlag := flag.Bool("status", false, "Show agent status and connectivity")
	diagnoseFlag := flag.String("diagnose", "", "Run one-off diagnosis (e.g., --diagnose \"postgresql is slow\")")
	daemonFlag := flag.Bool("daemon", false, "Run as daemon (systemd mode)")
	flag.Parse()

	// Also check for commands without -- prefix (for backward compatibility)
	// But log a warning to use -- prefix
	if flag.NArg() > 0 {
		cmd := flag.Arg(0)
		switch cmd {
		case "register":
			logging.Warning("Please use: nannyagent --register (with -- prefix)")
			*registerFlag = true
		case "status":
			logging.Warning("Please use: nannyagent --status (with -- prefix)")
			*statusFlag = true
		case "diagnose":
			logging.Warning("Please use: nannyagent --diagnose (with -- prefix)")
			if flag.NArg() > 1 {
				*diagnoseFlag = flag.Arg(1)
			} else {
				*diagnoseFlag = ""
			}
		case "daemon":
			logging.Warning("Please use: nannyagent --daemon (with -- prefix)")
			*daemonFlag = true
		}
	}

	// Whitelist: commands that don't require root or auth
	// Handle --version flag (no root required)
	if *versionFlag {
		showVersion()
	}

	// Handle --help flag (no root required)
	if *helpFlag {
		showHelp()
	}

	// Handle --status flag (no root or auth required) - EXIT IMMEDIATELY
	if *statusFlag {
		runStatusCommand()
		return
	}

	// Handle --register flag (requires root, no auth needed) - EXIT IMMEDIATELY
	if *registerFlag {
		checkRootPrivileges()
		runRegisterCommand()
		return
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

	// Get Agent ID
	agentID, err := authManager.GetCurrentAgentID()
	if err != nil {
		logging.Error("Failed to get Agent ID: %v", err)
		os.Exit(1)
	}

	// Test API connectivity with authenticated token
	logging.Info("Testing connectivity to NannyAI API...")
	if err := testAPIConnectivity(cfg, token.AccessToken, agentID); err != nil {
		logging.Error("Cannot connect to NannyAI API: %v", err)
		logging.Error("Endpoint: %s", cfg.AgentAuthURL)
		logging.Error("Please check:")
		logging.Error("  1. Network connectivity")
		logging.Error("  2. Firewall settings")
		logging.Error("  3. API endpoint in /etc/nannyagent/config.yaml")
		os.Exit(1)
	}
	logging.Info("✓ API connectivity OK")

	logging.Info("Authentication successful!")

	// Initialize the diagnostic agent for interactive CLI use with authentication
	agent := NewLinuxDiagnosticAgentWithAuth(authManager)

	// Handle --diagnose flag (one-off diagnosis)
	if *diagnoseFlag != "" {
		logging.Info("Running one-off diagnosis...")

		// Validate the diagnosis prompt
		if err := validateDiagnosisPrompt(*diagnoseFlag); err != nil {
			logging.Error("%v", err)
			logging.Info("Example: sudo nannyagent --diagnose \"postgresql is slow and using high CPU\"")
			os.Exit(1)
		}

		if err := agent.DiagnoseIssue(*diagnoseFlag); err != nil {
			logging.Error("Diagnosis failed: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Initialize a separate agent for WebSocket investigations using the application model
	// IMPORTANT: Must use WithAuth to include authorization headers for TensorZero API calls
	applicationAgent := NewLinuxDiagnosticAgentWithAuth(authManager)
	applicationAgent.SetModel("tensorzero::function_name::diagnose_and_heal_application")

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

	// Check if running in daemon mode
	if *daemonFlag {
		// Switch to syslog-only logging first to avoid duplicates
		logging.EnableSyslogOnly()

		logging.Info("Running in daemon mode (no interactive session)")
		logging.Info("Logs will be sent to syslog. View with: journalctl -u nannyagent -f")

		// Block forever, let background goroutines handle everything
		select {}
	}

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

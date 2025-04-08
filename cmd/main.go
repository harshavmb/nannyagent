package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/harshavmb/nannyagent/pkg/agent"
)

var (
	apiURL  string
	apiKey  string
	prompt  string
	offline bool
	version = "1.0.0"
)

func init() {
	flag.StringVar(&apiURL, "api-url", "https://api.nannyai.dev", "NannyAI API URL")
	flag.StringVar(&apiKey, "api-key", "", "NannyAI API Key")
	flag.StringVar(&prompt, "prompt", "", "Initial diagnostic prompt")
	flag.BoolVar(&offline, "offline", false, "Run in offline mode")
	flag.Parse()

	// Check if API key is provided via environment variable
	if apiKey == "" {
		apiKey = os.Getenv("NANNY_API_KEY")
	}
}

func main() {
	if !offline && apiKey == "" {
		log.Fatal("API key must be provided either via -api-key flag or NANNY_API_KEY environment variable")
	}

	a := agent.NewAgent()
	if err := a.Initialize(apiURL, apiKey); err != nil {
		log.Printf("Warning: Agent initialization failed: %v\n", err)
		if !offline {
			log.Fatal("Cannot continue in online mode due to initialization failure")
		}
	}

	// Print agent information
	fmt.Printf("NannyAgent v%s\n", version)
	fmt.Printf("Mode: %s\n", map[bool]string{true: "Offline", false: "Online"}[offline || a.Offline])

	// If prompt was provided via command line, handle it and exit
	if prompt != "" {
		if err := a.StartDiagnostic(prompt); err != nil {
			log.Fatalf("Diagnostic failed: %v", err)
		}
		return
	}

	// Interactive mode
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("\nEnter your diagnostic queries (type 'exit' to quit, 'help' for commands):")

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		switch strings.ToLower(input) {
		case "exit":
			fmt.Println("Goodbye!")
			return
		case "help":
			printHelp()
		case "status":
			printStatus(a)
		default:
			if err := a.StartDiagnostic(input); err != nil {
				log.Printf("Diagnostic failed: %v\n", err)
			}
		}
	}
}

func printHelp() {
	fmt.Println("\nAvailable commands:")
	fmt.Println("  help    - Show this help message")
	fmt.Println("  status  - Show agent status")
	fmt.Println("  exit    - Exit the program")
	fmt.Println("\nFor diagnostics, simply type your query, for example:")
	fmt.Println("  - Check system health")
	fmt.Println("  - Investigate high CPU usage")
	fmt.Println("  - Check disk space")
	fmt.Println("  - Memory usage analysis")
	fmt.Println()
}

func printStatus(a *agent.Agent) {
	fmt.Printf("\nAgent Status:\n")
	fmt.Printf("Agent ID: %s\n", map[bool]string{true: "Not registered (offline mode)", false: a.ID}[a.Offline])
	fmt.Printf("API URL: %s\n", a.APIURL)
	fmt.Printf("Mode: %s\n", map[bool]string{true: "Offline", false: "Online"}[a.Offline])

	if metadata := a.MetaData; metadata != nil {
		fmt.Println("\nSystem Information:")
		fmt.Printf("Hostname: %v\n", metadata["hostname"])
		fmt.Printf("Platform: %v %v\n", metadata["platform"], metadata["platform_family"])
		fmt.Printf("Kernel: %v\n", metadata["kernel_version"])
		fmt.Printf("CPU: %v (%v cores)\n", metadata["cpu_model"], metadata["cpu_cores"])
	}
	fmt.Println()
}

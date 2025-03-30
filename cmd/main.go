package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/harshavmb/nannyagent/pkg/agent"
)

func main() {
	apiURLFlag := flag.String("api-url", "https://api.nannyai.dev", "API URL")
	flag.Parse()

	apiKey := os.Getenv("NANNY_API_KEY")
	if apiKey == "" {
		log.Fatalf("NANNY_API_KEY environment variable not set")
		return
	}

	a := agent.NewAgent()

	// Initialize the agent
	if err := a.Initialize(*apiURLFlag, apiKey); err != nil {
		log.Fatalf("Error initializing agent: %v", err)
	}

	hostInfo, err := a.CollectHostInfo()
	if err != nil {
		log.Fatalf("Error collecting host info: %v", err)
		return
	}

	userInfo, err := a.GetUserInfo()
	if err != nil {
		log.Fatalf("Error getting user info: %v", err)
		return
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Welcome %s to the NannyAgent.\nYour Host information:%v\n", userInfo["name"], fmt.Sprintf("%+v", hostInfo))
	fmt.Println("Type your command: Type 'exit' to quit")

	// Channel to signal when to stop the status checker
	stopChan := make(chan struct{})

	// Start the status checker in the background
	go func() {
		for {
			select {
			case <-stopChan:
				return
			default:
				if !checkAPIStatus(a) {
					fmt.Println("API is unavailable after 3 retries. Exiting...")
					close(stopChan)
					os.Exit(1)
				}
				time.Sleep(10 * time.Second) // Adjust the interval as needed
			}
		}
	}()

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Error reading input: %v", err)
		}

		input = input[:len(input)-1] // Remove newline character
		if input == "exit" {
			fmt.Println("Exiting...")
			close(stopChan)
			break
		}

		// Start chat with the input prompt
		err = a.StartChat(input)
		if err != nil {
			log.Fatalf("Error starting chat: %v", err)
		}

	}
}

func checkAPIStatus(a *agent.Agent) bool {
	retries := 3
	for i := 0; i < retries; i++ {
		_, err := a.GetStatus()
		if err == nil {
			return true
		}
		log.Printf("Error getting status from API (attempt %d/%d): %v", i+1, retries, err)
		time.Sleep(10 * time.Second) // Adjust the retry interval as needed
	}
	return false
}

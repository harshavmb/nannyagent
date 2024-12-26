package main

import (
	"bufio"
	"fmt"
	"log"
	"os"

	"github.com/harshavmb/nannyagent/pkg/agent"
)

func main() {
	a := agent.NewAgent()

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Welcome to the Go Agent. Type your command:")

	for {
		fmt.Print("> ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("Error reading input: %v", err)
		}

		input = input[:len(input)-1] // Remove newline character
		if input == "exit" {
			fmt.Println("Exiting...")
			break
		}

		response, err := a.SendToGeminiAPI(input)
		if err != nil {
			log.Printf("Error communicating with Gemini API: %v", err)
			continue
		}

		log.Println("Response from Gemini API:", response)

		commands, err := a.ParseCommands(response)
		if err != nil {
			log.Printf("Error parsing commands: %v", err)
			continue
		}

		log.Printf("Commands to execute: %v", commands)
		output, err := a.ExecuteCommands(commands)
		if err != nil {
			log.Printf("Error executing commands: %v", err)
			return
		}

		fmt.Println(output)
	}
}

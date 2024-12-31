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

		//response, err := a.SendToGeminiAPI(input)
		commands, err := a.GetGenerativeAIResponse(input)
		if err != nil {
			log.Printf("Error communicating with Gemini API: %v", err)
			continue
		}

		log.Println("Response from Gemini API:", commands)

		// sometimes the response from the API is non array, so we need to handle that
		if len(commands) < 1 || commands == nil {
			log.Fatalf("No valid commands received from Gemini API")
			return
		}

		output, err := a.ExecuteCommands(commands)
		if err != nil {
			log.Printf("Error executing commands: %v", err)
			continue
		}

		log.Println("Command output:", output)

		finalResponse, err := a.FinalGenerativeAIResponse(input, output)
		if err != nil {
			log.Printf("Error communicating with Gemini API: %v", err)
			continue
		}
		log.Println("Final Response from Gemini API:", finalResponse)
	}
}

package agent

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/harshavmb/nannyagent/pkg/api"
)

// Agent struct
type Agent struct{}

func NewAgent() *Agent {
	return &Agent{}
}

func (a *Agent) ExecuteCommands(commands []string) (string, error) {
	var output []string
	var lastPID string

	for _, command := range commands {

		// Replace <PID> with the lastPID if present
		if strings.Contains(command, "<PID>") {
			if lastPID == "" {
				output = append(output, fmt.Sprintf("no PID available for command: %s", command))
				continue
			}
			command = strings.ReplaceAll(command, "<PID>", lastPID)
		}

		// Start the command
		out, err := exec.Command("sh", "-c", command).Output()
		if err != nil {
			log.Println("Error executing command %: ", err)
			continue
		}

		outputStr := string(out)
		output = append(output, outputStr)

		// Extract PID from the output if needed
		if strings.Contains(command, "ps aux") {
			re := regexp.MustCompile(`\s+(\d+)\s+`)
			match := re.FindStringSubmatch(outputStr)
			if len(match) > 1 {
				lastPID = match[1]
			}
		}
	}

	return strings.Join(output, "\n"), nil
}

func (a *Agent) GetGenerativeAIResponse(input string) ([]string, error) {
	geminiClient, err := api.NewGeminiClient()
	if err != nil {
		return nil, err
	}
	defer geminiClient.Close()

	response, err := geminiClient.GetGenerativeAIResponse(input)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (a *Agent) FinalGenerativeAIResponse(input, output string) (string, error) {
	geminiClient, err := api.NewGeminiClient()
	if err != nil {
		return "", err
	}
	defer geminiClient.Close()

	response, err := geminiClient.FinalGenerativeAIResponse(input, output)
	if err != nil {
		return "", err
	}

	return response, nil
}

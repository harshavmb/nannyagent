package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// Agent struct
type Agent struct{}

func NewAgent() *Agent {
	return &Agent{}
}

func (a *Agent) ExecuteCommand(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (a *Agent) CheckSystemHealth() (string, error) {
	command := "echo 'System Health: OK'"
	return a.ExecuteCommand(command)
}

func (a *Agent) GetFilesystemUsage() (string, error) {
	command := "df -h"
	return a.ExecuteCommand(command)
}

func (a *Agent) GetDiskUsage() (string, error) {
	command := "du -sh /*"
	return a.ExecuteCommand(command)
}

func (a *Agent) GetMemoryUsage() (string, error) {
	command := "free -h"
	return a.ExecuteCommand(command)
}

func (a *Agent) GetProcessDetails() (string, error) {
	command := "ps aux"
	return a.ExecuteCommand(command)
}

func ParseResponse(response string) []string {
	return strings.Split(response, "\n")
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

	ctx := context.Background()

	// Access your API key as an environment variable
	genaiClient, err := genai.NewClient(context.Background(), option.WithAPIKey(os.Getenv("GEMINI_API_TOKEN")))
	if err != nil {
		return nil, fmt.Errorf("failed to create Generative AI client: %v", err)
	}
	defer genaiClient.Close()

	model := genaiClient.GenerativeModel("gemini-1.5-flash")

	// Ask the model to respond with JSON.
	model.ResponseMIMEType = "application/json"

	// Specify the schema.
	model.ResponseSchema = &genai.Schema{
		Type:  genai.TypeArray,
		Items: &genai.Schema{Type: genai.TypeString},
	}
	resp, err := model.GenerateContent(ctx, genai.Text(fmt.Sprintf("Run a list investigative Linux commands to diagnose %s on a server. If binaries are from sysstat, collect metrics for 5 seconds every 1 sec interval", input)))
	if err != nil {
		return nil, fmt.Errorf("failed to create Generative AI client: %v", err)
	}

	var recipes []string

	for _, part := range resp.Candidates[0].Content.Parts {
		if txt, ok := part.(genai.Text); ok {
			if err := json.Unmarshal([]byte(txt), &recipes); err != nil {
				log.Fatal(err)
			}

		}
	}
	return recipes, nil
}

func (a *Agent) FinalGenerativeAIResponse(input, output string) (string, error) {

	ctx := context.Background()

	// Access your API key as an environment variable
	genaiClient, err := genai.NewClient(context.Background(), option.WithAPIKey(os.Getenv("GEMINI_API_TOKEN")))
	if err != nil {
		return "", fmt.Errorf("failed to create Generative AI client: %v", err)
	}
	defer genaiClient.Close()

	model := genaiClient.GenerativeModel("gemini-1.5-flash")

	// Ask the model to respond with JSON.
	model.ResponseMIMEType = "application/json"

	resp, err := model.GenerateContent(ctx, genai.Text(fmt.Sprintf("For given input commands %s. Output from the server %s.", input, output)))
	if err != nil {
		return "", fmt.Errorf("failed to create Generative AI client: %v", err)
	}

	var response string

	for _, part := range resp.Candidates[0].Content.Parts {
		if txt, ok := part.(genai.Text); ok {
			response += string(txt)
		}
	}
	return response, nil
}

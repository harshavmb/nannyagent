package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Agent struct
type Agent struct{}

func NewAgent() *Agent {
	return &Agent{}
}

type GeminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// Command struct
type Command struct {
	Command string `json:"command"`
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

// ParseCommands parses the response from the Gemini API and extracts the commands
func (a *Agent) ParseCommands(response string) ([]Command, error) {
	var geminiResponse GeminiResponse
	err := json.Unmarshal([]byte(response), &geminiResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Gemini response JSON: %v", err)
	}

	var commands []Command
	for _, candidate := range geminiResponse.Candidates {
		for _, part := range candidate.Content.Parts {
			// Extract the JSON string containing the commands
			var commandWrapper struct {
				Commands []Command `json:"commands"`
			}
			err := json.Unmarshal([]byte(part.Text), &commandWrapper)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal command JSON: %v", err)
			}
			commands = append(commands, commandWrapper.Commands...)
		}
	}
	return commands, nil
}

// ExecuteCommands executes the given commands and returns the combined output
func (a *Agent) ExecuteCommands(commands []Command) (string, error) {
	var output []string
	var lastPID string

	for _, cmd := range commands {
		command := cmd.Command

		// Replace <PID> with the lastPID if present
		if strings.Contains(command, "<PID>") {
			if lastPID == "" {
				return "", fmt.Errorf("no PID available for command: %s", command)
			}
			command = strings.ReplaceAll(command, "<PID>", lastPID)
		}

		out, err := exec.Command("sh", "-c", command).Output()
		if err != nil {
			return "", fmt.Errorf("failed to execute command '%s': %v", command, err)
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

// SendToGeminiAPI sends the input string to the Gemini API and returns the response
func (a *Agent) SendToGeminiAPI(input string) (string, error) {
	token := os.Getenv("GEMINI_API_TOKEN")
	if token == "" {
		return "", fmt.Errorf("GEMINI_API_TOKEN environment variable not set")
	}

	url := "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=" + token // Replace with the actual Gemini API endpoint
	jsonStr := []byte(fmt.Sprintf(`{
  "contents": [{
    "parts":[{"text": " Please provide a list of investigative Linux commands to diagnose %s on a server. The commands should be in the following JSON format:\n\n{ \"commands\": [ {\"command\": \"<command1>\"}, {\"command\": \"<command2>\"}, {\"command\": \"<command3>\"} ] }"}]
    }]
   }`, input))

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

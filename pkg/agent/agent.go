package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/harshavmb/nannyagent/pkg/api"
	"golang.org/x/sys/unix"
)

// State machine design pattern
type AgentState int

const (
	WaitingForPrompt AgentState = iota
	WaitingForCommands
	ExecutingCommands
	WaitingForDiagnosis
)

// Agent struct
type Agent struct {
	ID      string
	APIURL  string
	APIKey  string
	ChatID  string
	History []map[string]string
	State   AgentState
}

func NewAgent() *Agent {
	return &Agent{}
}

func (a *Agent) metadataToString() (string, error) {
	metadata, err := a.CollectMetadata()
	if err != nil {
		return "", err
	}

	// Convert metadata map to JSON string
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata to JSON: %v", err)
	}

	return string(metadataJSON), nil
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

func (a *Agent) GetStatus() (string, error) {
	nannyClient, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return "", err
	}
	defer nannyClient.Close()

	status, err := nannyClient.CheckStatus()
	if err != nil {
		return "", err
	}

	return status, nil
}

func (a *Agent) CollectHostInfo() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %v", err)
	}

	ip, err := getLocalIP()
	if err != nil {
		return "", fmt.Errorf("failed to get IP address: %v", err)
	}

	// Get kernel version
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "", fmt.Errorf("error getting kernel version: %v", err)
	}

	// Get OS version
	osVersion := string(uname.Version[:])

	info := fmt.Sprintf("Hostname: %s\nIP Address: %s\nKernel Version: %s\nOS Version: %s\n", strings.TrimSpace(string(hostname)), ip, strings.TrimSpace(string(uname.Release[:])), osVersion)
	return info, nil
}

func getLocalIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("no IP address found")
}

func (a *Agent) GetUserInfo() (string, error) {
	nannyClient, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return "", err
	}
	defer nannyClient.Close()

	resp, err := nannyClient.DoRequest("/api/user-auth-token", "GET", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get user auth token from server: %s", resp.Status)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]string
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	return result["name"], nil
}

func (a *Agent) CollectMetadata() (map[string]string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("failed to get hostname: %v", err)
	}

	ip, err := getLocalIP()
	if err != nil {
		return nil, fmt.Errorf("failed to get IP address: %v", err)
	}

	// Get kernel version
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return nil, fmt.Errorf("error getting kernel version: %v", err)
	}

	// Get OS version
	osVersion := string(uname.Version[:])

	metadata := map[string]string{
		"hostname":       strings.TrimSpace(hostname),
		"ip_address":     ip,
		"kernel_version": strings.TrimSpace(string(uname.Release[:])),
		"os_version":     osVersion,
	}

	return metadata, nil
}

func (a *Agent) SaveMetadata(metadata map[string]string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	nannyDir := filepath.Join(homeDir, ".nannyagent")
	if err := os.MkdirAll(nannyDir, 0755); err != nil {
		return fmt.Errorf("failed to create .nannyagent directory: %v", err)
	}

	metadataFile := filepath.Join(nannyDir, "metadata.json")
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	if err := os.WriteFile(metadataFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %v", err)
	}

	return nil
}

func (a *Agent) LoadMetadata() (map[string]string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %v", err)
	}

	metadataFile := filepath.Join(homeDir, ".nannyagent", "metadata.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %v", err)
	}

	return metadata, nil
}

func (a *Agent) RegisterAgent() error {
	metadata, err := a.CollectMetadata()
	if err != nil {
		return err
	}

	nannyClient, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return err
	}
	defer nannyClient.Close()

	resp, err := nannyClient.RegisterAgent(metadata)
	if err != nil {
		return err
	}

	id, ok := resp["id"]
	if !ok {
		return fmt.Errorf("no ID returned from server")
	}

	a.ID = id
	metadata["id"] = a.ID

	if err := a.SaveMetadata(metadata); err != nil {
		return err
	}
	return nil
}

func (a *Agent) Initialize(apiURL, apiKey string) error {
	a.APIURL = apiURL
	a.APIKey = apiKey

	metadata, err := a.LoadMetadata()
	if err != nil {
		if os.IsNotExist(err) {
			if err := a.RegisterAgent(); err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		a.ID = metadata["id"]
	}

	// Load and display chat history
	if err := a.LoadAndDisplayChatHistory(); err != nil {
		return err
	}

	return nil
}

func (a *Agent) LoadAndDisplayChatHistory() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	nannyDir := filepath.Join(homeDir, ".nannyagent")
	files, err := os.ReadDir(nannyDir)
	if err != nil {
		return fmt.Errorf("failed to read .nannyagent directory: %v", err)
	}

	var chatFiles []string
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "chat_") {
			chatFiles = append(chatFiles, file.Name())
		}
	}

	if len(chatFiles) == 0 {
		fmt.Println("No chat history found.")
		return nil
	}

	fmt.Println("Chat History:")
	for _, chatFile := range chatFiles {
		_, err := os.ReadFile(filepath.Join(nannyDir, chatFile))
		if err != nil {
			return fmt.Errorf("failed to read chat file %s: %v", chatFile, err)
		}

		// var history []map[string]string
		// if err := json.Unmarshal(data, &history); err != nil {
		// 	return fmt.Errorf("failed to unmarshal chat history: %v", err)
		// }

		// if len(history) > 0 {
		// 	fmt.Printf("Chat ID: %s, Title: %s\n", chatFile, history[0]["prompt"])
		// }

		// // Fetch chat history from the API
		// if err := a.FetchChatHistory(chatFile); err != nil {
		// 	return err
		// }
	}

	return nil
}

func (a *Agent) StartChat(prompt string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	nannyDir := filepath.Join(homeDir, ".nannyagent")
	if err := os.MkdirAll(nannyDir, 0755); err != nil {
		return fmt.Errorf("failed to create .nannyagent directory: %v", err)
	}

	nannyClient, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return err
	}
	defer nannyClient.Close()

	var promptType = "text"
	var commandsToExecute []string
	var commandOutput string

	// If ChatID is empty, create a new chat
	if a.ChatID == "" {
		metadataString, err := a.metadataToString()
		if err != nil {
			return err
		}

		initialPrompt := fmt.Sprintf("Agent metadata: %s.", metadataString)

		history := []map[string]string{
			{"prompt": initialPrompt, "response": "", "type": promptType},
		}

		payload := map[string]interface{}{
			"agent_id": a.ID,
			"history":  history,
		}

		resp, err := nannyClient.StartChat(payload)
		if err != nil {
			return err
		}

		chatID, ok := resp["id"]
		if !ok {
			return fmt.Errorf("no chat id returned from server")
		}

		chatFile := filepath.Join(nannyDir, fmt.Sprintf("chat_%s.json", chatID))
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal chat: %v", err)
		}

		if err := os.WriteFile(chatFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write chat file: %v", err)
		}

		a.ChatID = chatID
		a.History = history
		a.State = WaitingForCommands // Transition to waiting for commands
	}

	// Handle subsequent prompts based on the agent's state
	switch a.State {
	case WaitingForCommands:
		promptType = "commands"
		payload := map[string]string{
			"prompt": prompt,
			"type":   promptType,
		}

		resp, err := nannyClient.AddPromptResponse(a.ChatID, payload)
		if err != nil {
			return err
		}
		history := resp["history"].([]interface{})

		// Type assert to map[string]interface{}
		lastHistory, ok := history[len(history)-1].(map[string]interface{})
		if !ok {
			return fmt.Errorf("failed to assert history type")
		}

		// Convert map[string]interface{} to map[string]string
		stringMap := make(map[string]string)
		for k, v := range lastHistory {
			stringMap[k] = fmt.Sprint(v) // Convert interface{} to string
		}
		a.History = append(a.History, stringMap)

		// Extract commands from the response
		commandsStr, ok := lastHistory["response"].(string)
		if ok {
			commandsToExecute = strings.Split(commandsStr, "\n")
			a.State = ExecutingCommands // Transition to executing commands
		} else {
			return fmt.Errorf("commands not found in response")
		}

		// Execute commands immediately
		commandOutput, err = a.ExecuteCommands(commandsToExecute)
		if err != nil {
			fmt.Printf("Error executing commands: %v\n", err)
		}

		fmt.Printf("Command output: %s\n", commandOutput)

		// Send command output to API
		//a.ShareOutput(commandOutput)
		prompt = commandOutput
		a.State = WaitingForDiagnosis // Transition to waiting for diagnosis

		return nil

	case ExecutingCommands:
		// This state should not be directly entered by user prompt
		return fmt.Errorf("invalid state: ExecutingCommands")

	case WaitingForDiagnosis:
		promptType = "text"
		payload := map[string]string{
			"prompt": prompt,
			"type":   promptType,
		}

		resp, err := nannyClient.AddPromptResponse(a.ChatID, payload)
		if err != nil {
			return err
		}

		history, ok := resp["history"].([]interface{})
		if !ok {
			return fmt.Errorf("invalid history format")
		}

		lastHistory, ok := history[len(history)-1].(map[string]interface{})
		if !ok {
			return fmt.Errorf("failed to assert history type")
		}

		// Convert map[string]interface{} to map[string]string
		stringMap := make(map[string]string)
		for k, v := range lastHistory {
			stringMap[k] = fmt.Sprint(v) // Convert interface{} to string
		}

		a.History = append(a.History, stringMap)
		a.State = WaitingForPrompt // Transition back to waiting for prompt

		return nil

	case WaitingForPrompt:
		// Handle user prompt
		promptType = "text"
		payload := map[string]string{
			"prompt": prompt,
			"type":   promptType,
		}

		resp, err := nannyClient.AddPromptResponse(a.ChatID, payload)
		if err != nil {
			return err
		}

		history, ok := resp["history"].([]interface{})
		if !ok {
			return fmt.Errorf("invalid history format")
		}

		lastHistory, ok := history[len(history)-1].(map[string]interface{})
		if !ok {
			return fmt.Errorf("failed to assert history type")
		}

		// Convert map[string]interface{} to map[string]string
		stringMap := make(map[string]string)
		for k, v := range lastHistory {
			stringMap[k] = fmt.Sprint(v) // Convert interface{} to string
		}

		a.History = append(a.History, stringMap)
		a.State = WaitingForCommands // Transition to waiting for commands

		return nil

	default:
		return fmt.Errorf("invalid agent state")
	}

}

func (a *Agent) FetchChatHistory(chatID string) error {
	nannyClient, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return err
	}
	defer nannyClient.Close()

	result, err := nannyClient.GetChat(chatID)
	if err != nil {
		return err
	}

	history, ok := result["history"].([]interface{})
	if !ok {
		return fmt.Errorf("invalid chat history format")
	}

	fmt.Printf("Chat ID: %s, History: %v\n", chatID, history)
	return nil
}

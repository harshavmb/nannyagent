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
	"regexp"
	"strings"

	"github.com/harshavmb/nannyagent/pkg/api"
	"golang.org/x/sys/unix"
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

func (a *Agent) GetStatus() (string, error) {
	nannyClient, err := api.NewNannyClient()
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
	nannyClient, err := api.NewNannyClient()
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

// func (a *Agent) GetGenerativeAIResponse(input string) ([]string, error) {
// 	geminiClient, err := api.NewGeminiClient()
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer geminiClient.Close()

// 	response, err := geminiClient.GetGenerativeAIResponse(input)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return response, nil
// }

// func (a *Agent) FinalGenerativeAIResponse(input, output string) (string, error) {
// 	geminiClient, err := api.NewGeminiClient()
// 	if err != nil {
// 		return "", err
// 	}
// 	defer geminiClient.Close()

// 	response, err := geminiClient.FinalGenerativeAIResponse(input, output)
// 	if err != nil {
// 		return "", err
// 	}

// 	return response, nil
// }

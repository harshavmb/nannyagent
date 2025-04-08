package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/harshavmb/nannyagent/pkg/api"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

type Agent struct {
	ID       string
	APIURL   string
	APIKey   string
	MetaData map[string]interface{}
	Offline  bool
}

func NewAgent() *Agent {
	return &Agent{
		MetaData: make(map[string]interface{}),
		Offline:  false,
	}
}

func (a *Agent) Initialize(apiURL, apiKey string) error {
	a.APIURL = apiURL
	a.APIKey = apiKey

	// Collect system information
	if err := a.collectSystemInfo(); err != nil {
		return fmt.Errorf("failed to collect system info: %v", err)
	}

	// Try to register with API
	if err := a.RegisterWithAPI(); err != nil {
		fmt.Printf("Warning: Failed to register with API: %v\n", err)
		fmt.Println("Running in offline mode. Limited functionality will be available.")
		a.Offline = true
		return nil
	}

	return nil
}

func (a *Agent) collectSystemInfo() error {
	// Get host info
	hostInfo, err := host.Info()
	if err != nil {
		return fmt.Errorf("failed to get host info: %v", err)
	}

	// Get CPU info
	cpuInfo, err := cpu.Info()
	if err != nil {
		return fmt.Errorf("failed to get CPU info: %v", err)
	}

	// Get memory info
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return fmt.Errorf("failed to get memory info: %v", err)
	}

	// Get disk info
	partitions, err := disk.Partitions(true)
	if err != nil {
		return fmt.Errorf("failed to get disk partitions: %v", err)
	}

	diskInfo := make([]map[string]interface{}, 0)
	for _, partition := range partitions {
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			continue
		}
		diskInfo = append(diskInfo, map[string]interface{}{
			"device":     partition.Device,
			"mountpoint": partition.Mountpoint,
			"fstype":     partition.Fstype,
			"total":      usage.Total,
			"used":       usage.Used,
			"free":       usage.Free,
		})
	}

	a.MetaData = map[string]interface{}{
		"hostname":        hostInfo.Hostname,
		"platform":        hostInfo.Platform,
		"platform_family": hostInfo.PlatformFamily,
		"kernel_version":  hostInfo.KernelVersion,
		"os_version":      hostInfo.PlatformVersion,
		"cpu_model":       cpuInfo[0].ModelName,
		"cpu_cores":       cpuInfo[0].Cores,
		"memory_total":    memInfo.Total,
		"memory_free":     memInfo.Free,
		"disk_info":       diskInfo,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
	}

	return nil
}

func (a *Agent) RegisterWithAPI() error {
	if a.APIURL == "" || a.APIKey == "" {
		return fmt.Errorf("API URL and Key must be set")
	}

	client, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return err
	}

	resp, err := client.RegisterAgent(a.MetaData)
	if err != nil {
		return err
	}

	if id, ok := resp["id"].(string); ok {
		a.ID = id
		return nil
	}

	return fmt.Errorf("no agent ID received from registration")
}

func (a *Agent) ExecuteCommand(cmd string) (string, error) {
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %v", err)
	}
	return string(output), nil
}

func (a *Agent) StartDiagnostic(prompt string) error {
	if a.Offline {
		return a.handleOfflineDiagnostic(prompt)
	}

	client, err := api.NewNannyClient(a.APIURL, a.APIKey)
	if err != nil {
		return err
	}

	// Start diagnostic session
	payload := map[string]interface{}{
		"agent_id": a.ID,
		"prompt":   prompt,
		"metadata": a.MetaData,
	}

	resp, err := client.StartDiagnostic(payload)
	if err != nil {
		return err
	}

	diagnosticID, ok := resp["id"].(string)
	if !ok {
		return fmt.Errorf("invalid diagnostic ID received")
	}

	// Process commands and continue diagnostic
	for {
		commands, ok := resp["commands"].([]interface{})
		if !ok || len(commands) == 0 {
			break
		}

		// Execute commands and collect output
		var outputs []string
		for _, cmd := range commands {
			if cmdStr, ok := cmd.(string); ok {
				output, err := a.ExecuteCommand(cmdStr)
				if err != nil {
					outputs = append(outputs, fmt.Sprintf("Error: %v", err))
				} else {
					outputs = append(outputs, output)
				}
			}
		}

		// Continue diagnostic with command outputs
		payload = map[string]interface{}{
			"output": strings.Join(outputs, "\n"),
		}

		resp, err = client.ContinueDiagnostic(diagnosticID, payload)
		if err != nil {
			return err
		}

		// Check if we have a diagnosis
		if diagnosis, ok := resp["diagnosis"].(string); ok {
			fmt.Printf("\nDiagnosis:\n%s\n", diagnosis)
			break
		}
	}

	return nil
}

func (a *Agent) handleOfflineDiagnostic(prompt string) error {
	fmt.Println("Running in offline mode. Here are some basic diagnostic commands you can try:")

	basicCommands := map[string][]string{
		"CPU Usage": {"top -bn1 | head -n 5", "mpstat 1 1"},
		"Memory":    {"free -h", "vmstat 1 1"},
		"Disk":      {"df -h", "iostat -x 1 1"},
		"Network":   {"netstat -i", "ss -s"},
		"System":    {"uname -a", "uptime"},
	}

	fmt.Println("\nAvailable diagnostic categories:")
	for category := range basicCommands {
		fmt.Printf("- %s\n", category)
	}

	fmt.Println("\nExecuting basic system checks...")
	for category, commands := range basicCommands {
		fmt.Printf("\n=== %s ===\n", category)
		for _, cmd := range commands {
			output, err := a.ExecuteCommand(cmd)
			if err != nil {
				fmt.Printf("Error running '%s': %v\n", cmd, err)
				continue
			}
			fmt.Printf("\n$ %s\n%s\n", cmd, output)
		}
	}

	return nil
}

func (a *Agent) SaveMetadata() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	nannyDir := filepath.Join(homeDir, ".nannyagent")
	if err := os.MkdirAll(nannyDir, 0755); err != nil {
		return fmt.Errorf("failed to create .nannyagent directory: %v", err)
	}

	metadataFile := filepath.Join(nannyDir, "metadata.json")
	data, err := json.Marshal(a.MetaData)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %v", err)
	}

	if err := os.WriteFile(metadataFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write metadata file: %v", err)
	}

	return nil
}

func (a *Agent) LoadMetadata() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %v", err)
	}

	metadataFile := filepath.Join(homeDir, ".nannyagent", "metadata.json")
	data, err := os.ReadFile(metadataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No existing metadata is not an error
		}
		return err
	}

	return json.Unmarshal(data, &a.MetaData)
}

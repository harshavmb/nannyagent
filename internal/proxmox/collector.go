package proxmox

import (
	"encoding/json"
	"fmt"
	"os/exec"

	"nannyagent/internal/logging"
)

// CommandExecutor defines an interface for executing commands
type CommandExecutor interface {
	Execute(command string, args ...string) ([]byte, error)
}

// RealCommandExecutor implements CommandExecutor using os/exec
type RealCommandExecutor struct{}

func (e *RealCommandExecutor) Execute(command string, args ...string) ([]byte, error) {
	cmd := exec.Command(command, args...)
	return cmd.Output()
}

// Collector handles Proxmox data collection
type Collector struct {
	executor CommandExecutor
}

func NewCollector(executor CommandExecutor) *Collector {
	return &Collector{
		executor: executor,
	}
}

// IsProxmoxInstalled checks if Proxmox VE is installed
func (c *Collector) IsProxmoxInstalled() bool {
	_, err := c.executor.Execute("/usr/bin/pveversion", "--verbose")
	return err == nil
}

// IsPartOfCluster checks if the node is part of a cluster
func (c *Collector) IsPartOfCluster() bool {
	_, err := c.executor.Execute("pvecm", "status")
	return err == nil
}

// GetClusterStatus executes `pvesh get /cluster/status --output-format json`
func (c *Collector) GetClusterStatus() ([]map[string]interface{}, error) {
	output, err := c.executor.Execute("pvesh", "get", "/cluster/status", "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster status: %w", err)
	}

	var status []map[string]interface{}
	if err := json.Unmarshal(output, &status); err != nil {
		return nil, fmt.Errorf("failed to parse cluster status: %w", err)
	}
	return status, nil
}

// GetClusterResources executes `pvesh get /cluster/resources --output-format json`
func (c *Collector) GetClusterResources() ([]map[string]interface{}, error) {
	output, err := c.executor.Execute("pvesh", "get", "/cluster/resources", "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster resources: %w", err)
	}

	var resources []map[string]interface{}
	if err := json.Unmarshal(output, &resources); err != nil {
		return nil, fmt.Errorf("failed to parse cluster resources: %w", err)
	}
	return resources, nil
}

// GetNodeConfig executes `pvesh get /nodes/{node}/status --output-format json`
func (c *Collector) GetNodeConfig(node string) (map[string]interface{}, error) {
	output, err := c.executor.Execute("pvesh", "get", fmt.Sprintf("/nodes/%s/status", node), "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to get node config for %s: %w", node, err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(output, &config); err != nil {
		return nil, fmt.Errorf("failed to parse node config: %w", err)
	}
	return config, nil
}

// GetLXCConfig executes `pvesh get /nodes/{node}/lxc/{vmid}/config --output-format json`
func (c *Collector) GetLXCConfig(node string, vmid int) (map[string]interface{}, error) {
	output, err := c.executor.Execute("pvesh", "get", fmt.Sprintf("/nodes/%s/lxc/%d/config", node, vmid), "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to get lxc config for %d: %w", vmid, err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(output, &config); err != nil {
		return nil, fmt.Errorf("failed to parse lxc config: %w", err)
	}
	return config, nil
}

// GetQemuConfig executes `pvesh get /nodes/{node}/qemu/{vmid}/config --output-format json`
func (c *Collector) GetQemuConfig(node string, vmid int) (map[string]interface{}, error) {
	output, err := c.executor.Execute("pvesh", "get", fmt.Sprintf("/nodes/%s/qemu/%d/config", node, vmid), "--output-format", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to get qemu config for %d: %w", vmid, err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(output, &config); err != nil {
		return nil, fmt.Errorf("failed to parse qemu config: %w", err)
	}
	return config, nil
}

// CollectClusterInfo collects cluster information
func (c *Collector) CollectClusterInfo() (*ProxmoxCluster, error) {
	status, err := c.GetClusterStatus()
	if err != nil {
		return nil, err
	}

	for _, item := range status {
		if item["type"] == "cluster" {
			return &ProxmoxCluster{
				ClusterName: getString(item, "name"),
				Nodes:       getInt(item, "nodes"),
				Quorate:     getInt(item, "quorate"),
				Version:     getInt(item, "version"),
				ClusterID:   getString(item, "id"), // This might need adjustment based on actual ID field
			}, nil
		}
	}
	return nil, fmt.Errorf("cluster info not found")
}

// CollectNodeInfo collects node information
func (c *Collector) CollectNodeInfo() (*ProxmoxNode, error) {
	status, err := c.GetClusterStatus()
	if err != nil {
		return nil, err
	}

	var currentNode map[string]interface{}
	for _, item := range status {
		if item["type"] == "node" && getInt(item, "local") == 1 {
			currentNode = item
			break
		}
	}

	if currentNode == nil {
		return nil, fmt.Errorf("current node not found in cluster status")
	}

	nodeName := getString(currentNode, "name")
	nodeConfig, err := c.GetNodeConfig(nodeName)
	if err != nil {
		logging.Error("Failed to get node config: %v", err)
		// Continue with partial info? Or fail?
		// Let's try to get pveversion from node config
	}

	pveVersion := ""
	if nodeConfig != nil {
		pveVersion = getString(nodeConfig, "pveversion")
	}

	return &ProxmoxNode{
		Name:       nodeName,
		IP:         getString(currentNode, "ip"),
		NodeID:     getInt(currentNode, "nodeid"),
		Online:     getInt(currentNode, "online"),
		Local:      getInt(currentNode, "local"),
		Level:      getString(currentNode, "level"),
		PVEVersion: pveVersion,
	}, nil
}

// CollectLXCInfo collects LXC information for the current node
func (c *Collector) CollectLXCInfo(nodeName string) ([]ProxmoxLXC, error) {
	resources, err := c.GetClusterResources()
	if err != nil {
		return nil, err
	}

	var lxcs []ProxmoxLXC
	for _, item := range resources {
		if getString(item, "type") == "lxc" && getString(item, "node") == nodeName {
			vmid := getInt(item, "vmid")
			config, err := c.GetLXCConfig(nodeName, vmid)
			if err != nil {
				logging.Error("Failed to get config for LXC %d: %v", vmid, err)
				continue
			}

			lxcs = append(lxcs, ProxmoxLXC{
				Name:   getString(item, "name"),
				LXCID:  getString(item, "id"),
				Status: getString(item, "status"),
				Uptime: getInt(item, "uptime"),
				VMID:   vmid,
				Node:   nodeName,
				OSType: getString(config, "ostype"),
			})
		}
	}
	return lxcs, nil
}

// CollectQemuInfo collects QEMU information for the current node
func (c *Collector) CollectQemuInfo(nodeName string) ([]ProxmoxQemu, error) {
	resources, err := c.GetClusterResources()
	if err != nil {
		return nil, err
	}

	var vms []ProxmoxQemu
	for _, item := range resources {
		if getString(item, "type") == "qemu" && getString(item, "node") == nodeName {
			vmid := getInt(item, "vmid")
			config, err := c.GetQemuConfig(nodeName, vmid)
			if err != nil {
				logging.Error("Failed to get config for VM %d: %v", vmid, err)
				continue
			}

			vms = append(vms, ProxmoxQemu{
				Name:    getString(item, "name"),
				QemuID:  getString(item, "id"),
				Status:  getString(item, "status"),
				Uptime:  getInt(item, "uptime"),
				VMID:    vmid,
				Node:    nodeName,
				OSType:  getString(config, "ostype"),
				VMGenID: getString(config, "vmgenid"),
				KVM:     getInt(config, "kvm"),
				Boot:    getString(config, "boot"),
				HostCPU: getString(config, "cpu"),
			})
		}
	}
	return vms, nil
}

// Helper functions to safely get values from map
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if val, ok := m[key]; ok {
		if f, ok := val.(float64); ok {
			return int(f)
		}
		if i, ok := val.(int); ok {
			return i
		}
	}
	return 0
}

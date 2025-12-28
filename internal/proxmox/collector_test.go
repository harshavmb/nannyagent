package proxmox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type MockCommandExecutor struct {
	TestDataDir string
}

func (e *MockCommandExecutor) Execute(command string, args ...string) ([]byte, error) {
	cmdStr := command + " " + strings.Join(args, " ")

	var filename string
	if strings.Contains(cmdStr, "/cluster/status") {
		filename = "cluster-status.out"
	} else if strings.Contains(cmdStr, "/cluster/resources") {
		filename = "cluster-resources.out"
	} else if strings.Contains(cmdStr, "/nodes/node1/status") {
		filename = "node-config.out"
	} else if strings.Contains(cmdStr, "/lxc/106/config") {
		filename = "lxc-config.out"
	} else if strings.Contains(cmdStr, "/qemu/103/config") {
		// Reuse qemu-config.out for VM 103 even though it's for 113 in the file
		filename = "qemu-config.out"
	} else if strings.Contains(cmdStr, "pveversion") {
		return []byte("pve-manager/8.1.3/b46aac3b (running kernel: 6.5.11-7-pve)"), nil
	} else if strings.Contains(cmdStr, "pvecm status") {
		return []byte("Cluster is quorate"), nil
	} else {
		// Return empty JSON object for other configs to avoid errors
		return []byte("{}"), nil
	}

	path := filepath.Join(e.TestDataDir, filename)
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// The files start with `pvesh get ... | jq`.
	// I need to strip the first line.
	lines := strings.Split(string(content), "\n")
	if len(lines) > 1 && strings.HasPrefix(lines[0], "pvesh") {
		return []byte(strings.Join(lines[1:], "\n")), nil
	}

	return content, nil
}

func TestCollector_CollectClusterInfo(t *testing.T) {
	cwd, _ := os.Getwd()
	// Adjust path to point to test_data from internal/proxmox
	testDataDir := filepath.Join(cwd, "../../test_data")

	executor := &MockCommandExecutor{TestDataDir: testDataDir}
	collector := NewCollector(executor)

	info, err := collector.CollectClusterInfo()
	if err != nil {
		t.Fatalf("CollectClusterInfo failed: %v", err)
	}

	if info.ClusterName != "pxcluster" {
		t.Errorf("Expected cluster name 'pxcluster', got '%s'", info.ClusterName)
	}
	if info.Nodes != 3 {
		t.Errorf("Expected 3 nodes, got %d", info.Nodes)
	}
}

func TestCollector_CollectNodeInfo(t *testing.T) {
	cwd, _ := os.Getwd()
	testDataDir := filepath.Join(cwd, "../../test_data")

	executor := &MockCommandExecutor{TestDataDir: testDataDir}
	collector := NewCollector(executor)

	info, err := collector.CollectNodeInfo()
	if err != nil {
		t.Fatalf("CollectNodeInfo failed: %v", err)
	}

	if info.Name != "node3" {
		t.Errorf("Expected node name 'node3', got '%s'", info.Name)
	}
	if info.Local != 1 {
		t.Errorf("Expected local=1, got %d", info.Local)
	}
}

func TestCollector_CollectLXCInfo(t *testing.T) {
	cwd, _ := os.Getwd()
	testDataDir := filepath.Join(cwd, "../../test_data")

	executor := &MockCommandExecutor{TestDataDir: testDataDir}
	collector := NewCollector(executor)

	// We want to test LXC collection for "node3" (since that's where testcontainer is)
	lxcs, err := collector.CollectLXCInfo("node3")
	if err != nil {
		t.Fatalf("CollectLXCInfo failed: %v", err)
	}

	if len(lxcs) == 0 {
		t.Fatalf("Expected LXCs, got 0")
	}

	found := false
	for _, lxc := range lxcs {
		if lxc.VMID == 100 {
			found = true
			if lxc.Name != "testcontainer" {
				t.Errorf("Expected name 'testcontainer', got '%s'", lxc.Name)
			}
			if lxc.Status != "running" {
				t.Errorf("Expected status 'running', got '%s'", lxc.Status)
			}
		}
	}
	if !found {
		t.Errorf("LXC 100 not found")
	}
}

func TestCollector_CollectQemuInfo(t *testing.T) {
	cwd, _ := os.Getwd()
	testDataDir := filepath.Join(cwd, "../../test_data")

	executor := &MockCommandExecutor{TestDataDir: testDataDir}
	collector := NewCollector(executor)

	// We want to test QEMU collection for "node3" (since that's where tensorzero is)
	vms, err := collector.CollectQemuInfo("node3")
	if err != nil {
		t.Fatalf("CollectQemuInfo failed: %v", err)
	}

	if len(vms) == 0 {
		t.Fatalf("Expected VMs, got 0")
	}

	found := false
	for _, vm := range vms {
		if vm.VMID == 103 {
			found = true
			if vm.Name != "tensorzero" {
				t.Errorf("Expected name 'tensorzero', got '%s'", vm.Name)
			}
			// Check config fields (mock returns qemu-config.out for 103)
			if vm.OSType != "l26" {
				t.Errorf("Expected ostype 'l26', got '%s'", vm.OSType)
			}
			if vm.VMGenID != "8869332c-ab8d-4130-973c-ab7547588494" {
				t.Errorf("Expected vmgenid '8869332c-ab8d-4130-973c-ab7547588494', got '%s'", vm.VMGenID)
			}
		}
	}
	if !found {
		t.Errorf("VM 103 not found")
	}
}

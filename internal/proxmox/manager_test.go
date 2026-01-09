package proxmox

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"nannyagent/internal/config"
)

// MockAuthenticator implements Authenticator interface
type MockAuthenticator struct {
	RequestFunc func(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}

func (m *MockAuthenticator) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	if m.RequestFunc != nil {
		return m.RequestFunc(method, url, body, headers)
	}
	return http.StatusOK, []byte("{}"), nil
}

// MockManagerExecutor implements CommandExecutor interface
type MockManagerExecutor struct {
	ExecuteFunc func(command string, args ...string) ([]byte, error)
}

func (m *MockManagerExecutor) Execute(command string, args ...string) ([]byte, error) {
	if m.ExecuteFunc != nil {
		return m.ExecuteFunc(command, args...)
	}
	return []byte{}, nil
}

func TestManager_Start_Stop(t *testing.T) {
	cfg := &config.Config{
		ProxmoxInterval: 1,
		APIBaseURL:      "http://test-api",
	}

	mockExec := &MockManagerExecutor{
		ExecuteFunc: func(command string, args ...string) ([]byte, error) {
			if command == "/usr/bin/pveversion" {
				return []byte("pve-manager/7.0-11/63d8df24 (running kernel: 5.11.22-4-pve)"), nil
			}
			return []byte{}, nil
		},
	}

	mockAuth := &MockAuthenticator{}

	collector := NewCollector(mockExec)
	manager := NewManagerWithCollector(cfg, mockAuth, collector)

	// Start manager
	manager.Start()

	// Wait a bit to ensure runLoop starts
	time.Sleep(100 * time.Millisecond)

	// Stop manager
	manager.Stop()

	// Wait a bit to ensure runLoop exits
	time.Sleep(100 * time.Millisecond)
}

func TestManager_collectAndSend(t *testing.T) {
	cfg := &config.Config{
		ProxmoxInterval: 1,
		APIBaseURL:      "http://test-api",
	}

	mockExec := &MockManagerExecutor{
		ExecuteFunc: func(command string, args ...string) ([]byte, error) {
			if command == "/usr/bin/pveversion" {
				return []byte("pve-manager/7.0-11/63d8df24"), nil
			}
			if command == "pvecm" && args[0] == "status" {
				return []byte("Cluster Status"), nil
			}
			if command == "pvesh" {
				if args[1] == "/cluster/status" {
					return []byte(`[
						{"type": "cluster", "name": "test-cluster", "nodes": 1, "quorate": 1, "version": 2, "id": "cluster-id"},
						{"type": "node", "name": "pve1", "local": 1, "id": "node/pve1", "ip": "192.168.1.1", "nodeid": 1}
					]`), nil
				}
				if args[1] == "/nodes/pve1/status" {
					return []byte(`{"pveversion": "7.0-11"}`), nil
				}
				if args[1] == "/cluster/resources" {
					return []byte(`[
						{"type": "lxc", "node": "pve1", "vmid": 100, "name": "container1", "id": "lxc/100", "status": "running"},
						{"type": "qemu", "node": "pve1", "vmid": 101, "name": "vm1", "id": "qemu/101", "status": "running"}
					]`), nil
				}
				if strings.Contains(args[1], "/lxc/100/config") {
					return []byte(`{"ostype": "debian"}`), nil
				}
				if strings.Contains(args[1], "/qemu/101/config") {
					return []byte(`{"ostype": "l26"}`), nil
				}
			}
			return []byte{}, nil
		},
	}

	sentData := make(map[string]bool)
	mockAuth := &MockAuthenticator{
		RequestFunc: func(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
			if method == "POST" {
				if strings.Contains(url, "/api/proxmox/node") {
					sentData["node"] = true
				} else if strings.Contains(url, "/api/proxmox/cluster") {
					sentData["cluster"] = true
				} else if strings.Contains(url, "/api/proxmox/lxc") {
					sentData["lxc"] = true
				} else if strings.Contains(url, "/api/proxmox/qemu") {
					sentData["qemu"] = true
				}
			}
			return http.StatusOK, []byte("{}"), nil
		},
	}

	collector := NewCollector(mockExec)
	manager := NewManagerWithCollector(cfg, mockAuth, collector)

	// Run collectAndSend directly
	manager.collectAndSend()

	// Verify data sent
	if !sentData["node"] {
		t.Error("Expected node info to be sent")
	}
	if !sentData["cluster"] {
		t.Error("Expected cluster info to be sent")
	}
	if !sentData["lxc"] {
		t.Error("Expected LXC info to be sent")
	}
	if !sentData["qemu"] {
		t.Error("Expected QEMU info to be sent")
	}
}

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewAgent(t *testing.T) {
	a := NewAgent()
	if a == nil {
		t.Fatal("NewAgent() returned nil")
	}
	if a.MetaData == nil {
		t.Error("MetaData map not initialized")
	}
	if a.Offline != false {
		t.Error("Agent should start in online mode")
	}
}

func TestExecuteCommand(t *testing.T) {
	a := NewAgent()
	tests := []struct {
		name    string
		cmd     string
		wantErr bool
	}{
		{"Echo command", "echo 'test'", false},
		{"Multiple commands", "echo 'hello' && echo 'world'", false},
		{"Invalid command", "invalidcommand123", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := a.ExecuteCommand(tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExecuteCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(output) == 0 {
				t.Error("Expected non-empty output for valid command")
			}
		})
	}
}

func TestCollectSystemInfo(t *testing.T) {
	a := NewAgent()
	err := a.collectSystemInfo()
	if err != nil {
		t.Fatalf("collectSystemInfo() failed: %v", err)
	}

	requiredFields := []string{
		"hostname",
		"platform",
		"platform_family",
		"kernel_version",
		"os_version",
		"cpu_model",
		"cpu_cores",
		"memory_total",
		"memory_free",
		"disk_info",
		"timestamp",
	}

	for _, field := range requiredFields {
		if _, ok := a.MetaData[field]; !ok {
			t.Errorf("Missing required field in metadata: %s", field)
		}
	}
}

func TestSaveAndLoadMetadata(t *testing.T) {
	// Create temporary directory for test
	tmpDir, err := os.MkdirTemp("", "nannyagent-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Set home directory to temp directory for test
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	a := NewAgent()
	testData := map[string]interface{}{
		"test_key": "test_value",
		"number":   42,
	}
	a.MetaData = testData

	// Test Save
	if err := a.SaveMetadata(); err != nil {
		t.Fatalf("SaveMetadata() failed: %v", err)
	}

	// Clear metadata and load
	a.MetaData = make(map[string]interface{})
	if err := a.LoadMetadata(); err != nil {
		t.Fatalf("LoadMetadata() failed: %v", err)
	}

	// Verify loaded data matches original
	if a.MetaData["test_key"] != testData["test_key"] {
		t.Errorf("Loaded metadata does not match saved metadata")
	}
}

func TestAgentRegistration(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent" {
			t.Errorf("Expected request to /api/agent, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "test-agent-id",
		})
	}))
	defer server.Close()

	a := NewAgent()
	a.APIURL = server.URL
	a.APIKey = "test-key"

	err := a.RegisterWithAPI()
	if err != nil {
		t.Fatalf("RegisterWithAPI() failed: %v", err)
	}

	if a.ID != "test-agent-id" {
		t.Errorf("Expected agent ID 'test-agent-id', got '%s'", a.ID)
	}
}

func TestOfflineDiagnostic(t *testing.T) {
	a := NewAgent()
	a.Offline = true

	err := a.StartDiagnostic("test prompt")
	if err != nil {
		t.Fatalf("StartDiagnostic() in offline mode failed: %v", err)
	}
}

func TestStartDiagnostic(t *testing.T) {
	// Create test server with mock diagnostic flow
	var diagnosticID string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostic":
			diagnosticID = "test-diagnostic-id"
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":       diagnosticID,
				"commands": []string{"echo 'test'"},
			})
		case "/api/diagnostic/" + diagnosticID + "/continue":
			json.NewEncoder(w).Encode(map[string]interface{}{
				"diagnosis": "Test diagnosis complete",
			})
		default:
			t.Errorf("Unexpected request to %s", r.URL.Path)
		}
	}))
	defer server.Close()

	a := NewAgent()
	a.APIURL = server.URL
	a.APIKey = "test-key"
	a.ID = "test-agent-id"

	err := a.StartDiagnostic("test prompt")
	if err != nil {
		t.Fatalf("StartDiagnostic() failed: %v", err)
	}
}

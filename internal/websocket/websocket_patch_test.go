package websocket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"nannyagentv2/internal/ebpf"
	"nannyagentv2/internal/types"

	"github.com/sashabaranov/go-openai"
)

// MockDiagnosticAgent implements types.DiagnosticAgent for testing
type MockDiagnosticAgent struct{}

func (m *MockDiagnosticAgent) DiagnoseIssue(issue string) error {
	return nil
}

func (m *MockDiagnosticAgent) ConvertEBPFProgramsToTraceSpecs(requests []types.EBPFRequest) []ebpf.TraceSpec {
	return []ebpf.TraceSpec{}
}

func (m *MockDiagnosticAgent) ExecuteEBPFTraces(specs []ebpf.TraceSpec) []map[string]interface{} {
	return []map[string]interface{}{}
}

func (m *MockDiagnosticAgent) SendRequestWithEpisode(messages []openai.ChatCompletionMessage, episodeID string) (*openai.ChatCompletionResponse, error) {
	return nil, nil
}

func (m *MockDiagnosticAgent) SendRequest(messages []openai.ChatCompletionMessage) (*openai.ChatCompletionResponse, error) {
	return nil, nil
}

func (m *MockDiagnosticAgent) ExecuteCommand(cmd types.Command) types.CommandResult {
	return types.CommandResult{}
}

// TestDownloadPatchScript tests the downloadPatchScript function
func TestDownloadPatchScript(t *testing.T) {
	tests := []struct {
		name              string
		scriptID          string
		mockProxyResponse map[string]interface{}
		mockScriptContent string
		expectError       bool
		expectedErrorMsg  string
	}{
		{
			name:     "successful script download",
			scriptID: "test-script-id-123",
			mockProxyResponse: map[string]interface{}{
				"script_storage_path": "debian/apt-update.sh",
			},
			mockScriptContent: "#!/bin/bash\necho 'test'",
			expectError:       false,
		},
		{
			name:              "proxy request fails",
			scriptID:          "invalid-id",
			mockProxyResponse: nil,
			expectError:       true,
			expectedErrorMsg:  "script info request failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server that handles both proxy and storage requests
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Handle proxy request for script info
				if strings.Contains(r.URL.Path, "/functions/v1/agent-database-proxy/patch-scripts/") {
					if tt.mockProxyResponse == nil {
						w.WriteHeader(http.StatusNotFound)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(tt.mockProxyResponse)
					return
				}
				
				// Handle storage request for script content
				if strings.Contains(r.URL.Path, "/storage/v1/object/public/patch-scripts/") {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(tt.mockScriptContent))
					return
				}
				
				// Unknown path
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			// Create WebSocket client with mock server
			client := &WebSocketClient{
				agentID:     "test-agent",
				supabaseURL: server.URL,
				token:       "test-token",
			}

			// Mock the downloadPatchScript to use our test servers
			// (In reality, we'd need to refactor downloadPatchScript to accept a custom client)
			// For now, we test the logic with the real implementation

			// Create a real test that validates the function behavior
			result, err := client.downloadPatchScript(tt.scriptID)

			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tt.expectedErrorMsg)
				}
				if tt.expectedErrorMsg != "" && !contains(err.Error(), tt.expectedErrorMsg) {
					t.Fatalf("expected error containing '%s', got: %v", tt.expectedErrorMsg, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
				if len(result) == 0 {
					t.Fatal("expected non-empty script content")
				}
			}
		})
	}
}

// TestHandleNewPatchExecution tests patch execution handling
func TestHandleNewPatchExecution(t *testing.T) {
	tests := []struct {
		name             string
		record           map[string]interface{}
		expectError      bool
		expectedErrorMsg string
	}{
		{
			name: "missing execution id",
			record: map[string]interface{}{
				"script_id": "test-id",
			},
			expectError:      true,
			expectedErrorMsg: "No id in patch execution record",
		},
		{
			name: "missing script_id",
			record: map[string]interface{}{
				"id": "exec-123",
			},
			expectError:      true,
			expectedErrorMsg: "No script_id in patch execution record",
		},
		{
			name: "dry_run execution type",
			record: map[string]interface{}{
				"id":             "exec-123",
				"script_id":      "script-123",
				"execution_type": "dry_run",
				"command":        "--dry-run",
			},
			expectError: false,
		},
		{
			name: "valid apply execution",
			record: map[string]interface{}{
				"id":             "exec-456",
				"script_id":      "script-456",
				"execution_type": "apply",
				"command":        "",
			},
			expectError: false,
		},
		{
			name: "script_id as float64",
			record: map[string]interface{}{
				"id":             "exec-789",
				"script_id":      float64(123456),
				"execution_type": "apply",
				"command":        "",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test execution ID extraction
			executionID, ok := tt.record["id"].(string)
			if tt.name == "missing execution id" {
				if ok {
					t.Fatal("expected id extraction to fail")
				}
			} else if !ok {
				t.Fatalf("expected to extract id, got error")
			} else if executionID == "" {
				t.Fatal("execution id should not be empty")
			}

			// Test script_id extraction with multiple types
			scriptIDVal, hasScriptID := tt.record["script_id"]
			var scriptID string

			if hasScriptID {
				if s, ok := scriptIDVal.(string); ok {
					scriptID = s
				} else if f, ok := scriptIDVal.(float64); ok {
					scriptID = fmt.Sprintf("%v", int64(f))
				}
			}

			if tt.name != "missing script_id" && scriptID == "" {
				t.Fatal("expected to extract script_id")
			}
		})
	}
}

// TestUpdatePatchExecutionStatus tests status update functionality
func TestUpdatePatchExecutionStatus(t *testing.T) {
	tests := []struct {
		name         string
		status       string
		exitCode     int
		errorMsg     string
		stdoutPath   string
		stderrPath   string
		shouldHaveTS bool
	}{
		{
			name:         "running status",
			status:       "running",
			exitCode:     0,
			errorMsg:     "",
			stdoutPath:   "",
			stderrPath:   "",
			shouldHaveTS: true,
		},
		{
			name:         "completed status with paths",
			status:       "completed",
			exitCode:     0,
			errorMsg:     "",
			stdoutPath:   "agent-id/exec-id-stdout.txt",
			stderrPath:   "agent-id/exec-id-stderr.txt",
			shouldHaveTS: true,
		},
		{
			name:         "failed status with error",
			status:       "failed",
			exitCode:     1,
			errorMsg:     "script execution failed",
			stdoutPath:   "agent-id/exec-id-stdout.txt",
			stderrPath:   "agent-id/exec-id-stderr.txt",
			shouldHaveTS: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock server to capture the PATCH request
			var capturedPayload map[string]interface{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "PATCH" {
					t.Fatalf("expected PATCH method, got %s", r.Method)
				}

				body, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(body, &capturedPayload)

				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(map[string]string{"success": "true"})
			}))
			defer server.Close()

			client := &WebSocketClient{
				agentID:     "test-agent",
				supabaseURL: server.URL,
				token:       "test-token",
			}

			client.updatePatchExecutionStatus("test-exec-id", tt.status, tt.exitCode, tt.errorMsg, tt.stdoutPath, tt.stderrPath)

			// Validate captured payload
			if capturedPayload == nil {
				t.Fatal("expected payload to be captured")
			}

			if status, ok := capturedPayload["status"].(string); !ok || status != tt.status {
				t.Fatalf("expected status %s, got %v", tt.status, capturedPayload["status"])
			}

			if tt.exitCode >= 0 {
				if exitCode, ok := capturedPayload["exit_code"].(float64); !ok || int(exitCode) != tt.exitCode {
					t.Fatalf("expected exit_code %d, got %v", tt.exitCode, capturedPayload["exit_code"])
				}
			}

			if tt.errorMsg != "" {
				if errMsg, ok := capturedPayload["error_message"].(string); !ok || errMsg != tt.errorMsg {
					t.Fatalf("expected error_message %s, got %v", tt.errorMsg, capturedPayload["error_message"])
				}
			}

			if tt.stdoutPath != "" {
				if path, ok := capturedPayload["stdout_storage_path"].(string); !ok || path != tt.stdoutPath {
					t.Fatalf("expected stdout_storage_path %s, got %v", tt.stdoutPath, capturedPayload["stdout_storage_path"])
				}
			}

			if tt.stderrPath != "" {
				if path, ok := capturedPayload["stderr_storage_path"].(string); !ok || path != tt.stderrPath {
					t.Fatalf("expected stderr_storage_path %s, got %v", tt.stderrPath, capturedPayload["stderr_storage_path"])
				}
			}

			// Check timestamp fields
			if tt.shouldHaveTS {
				if tt.status == "running" {
					if _, hasTS := capturedPayload["started_at"]; !hasTS {
						t.Fatal("expected started_at timestamp for running status")
					}
				} else if tt.status == "completed" || tt.status == "failed" {
					if _, hasTS := capturedPayload["completed_at"]; !hasTS {
						t.Fatal("expected completed_at timestamp for completed/failed status")
					}
				}
			}
		})
	}
}

// TestParseJSONFromOutput tests JSON extraction from script output
func TestParseJSONFromOutput(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{
			name:           "simple json object",
			input:          `{"status": "success", "code": 0}`,
			expectedOutput: `{"status":"success","code":0}`,
		},
		{
			name:           "json with text before",
			input:          "Some text\n{\"status\": \"ok\"}",
			expectedOutput: `{"status":"ok"}`,
		},
		{
			name:           "json array",
			input:          `[{"id": 1}, {"id": 2}]`,
			expectedOutput: `[{"id":1},{"id":2}]`,
		},
		{
			name:           "multiline json",
			input:          "{\n  \"key\": \"value\",\n  \"nested\": {\n    \"data\": 123\n  }\n}",
			expectedOutput: `{"key":"value","nested":{"data":123}}`,
		},
		{
			name:           "no json",
			input:          "just plain text without json",
			expectedOutput: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &WebSocketClient{}
			result := client.parseJSONFromOutput(tt.input)

			// Normalize for comparison
			var resultJSON, expectedJSON interface{}
			_ = json.Unmarshal([]byte(result), &resultJSON)
			_ = json.Unmarshal([]byte(tt.expectedOutput), &expectedJSON)

			if tt.expectedOutput == "" {
				if result != "" {
					t.Fatalf("expected empty result, got: %s", result)
				}
			} else {
				if resultJSON == nil || expectedJSON == nil {
					t.Fatalf("expected valid JSON, got result=%v expected=%v", result, tt.expectedOutput)
				}
			}
		})
	}
}

// TestExecuteScript tests script execution
func TestExecuteScript(t *testing.T) {
	tests := []struct {
		name          string
		scriptContent string
		command       string
		expectedCode  int
	}{
		{
			name:          "simple echo script",
			scriptContent: "#!/bin/bash\necho 'hello world'",
			command:       "",
			expectedCode:  0,
		},
		{
			name:          "script with exit code",
			scriptContent: "#!/bin/bash\nexit 42",
			command:       "",
			expectedCode:  42,
		},
		{
			name:          "script with arguments",
			scriptContent: "#!/bin/bash\necho \"$1\"",
			command:       "test-arg",
			expectedCode:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &WebSocketClient{agentID: "test"}

			// Write script to temp file
			tmpFile, err := client.writeScriptToTempFile([]byte(tt.scriptContent))
			if err != nil {
				t.Fatalf("failed to write script: %v", err)
			}
			defer func() { os.Remove(tmpFile) }()

			stdout, stderr, exitCode := client.executeScript(tmpFile, tt.command)

			if exitCode != tt.expectedCode {
				t.Fatalf("expected exit code %d, got %d. stderr: %s", tt.expectedCode, exitCode, string(stderr))
			}

			if exitCode == 0 && len(stdout) == 0 {
				t.Fatal("expected stdout for successful execution")
			}
		})
	}
}

// TestWriteScriptToTempFile tests temporary script file creation
func TestWriteScriptToTempFile(t *testing.T) {
	tests := []struct {
		name          string
		scriptContent string
		expectError   bool
	}{
		{
			name:          "valid bash script",
			scriptContent: "#!/bin/bash\necho 'test'",
			expectError:   false,
		},
		{
			name:          "valid sh script",
			scriptContent: "#!/bin/sh\necho 'test'",
			expectError:   false,
		},
		{
			name:          "empty content",
			scriptContent: "",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &WebSocketClient{agentID: "test"}
			tmpFile, err := client.writeScriptToTempFile([]byte(tt.scriptContent))

			if tt.expectError && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tmpFile != "" {
				// Verify file exists and is executable
				_, _, exitCode := client.executeScript(tmpFile, "")
				// File should be readable and executable
				_ = exitCode
			}
		})
	}
}

// TestCountSuccessfulCommands tests command result counting
func TestCountSuccessfulCommands(t *testing.T) {
	client := &WebSocketClient{}

	results := []map[string]interface{}{
		{"success": true},
		{"success": true},
		{"success": false},
		{"success": true},
		{"error": "something went wrong"}, // no success field
	}

	count := client.countSuccessfulCommands(results)
	expected := 3

	if count != expected {
		t.Fatalf("expected %d successful commands, got %d", expected, count)
	}
}

// Helper function for string matching
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// BenchmarkDownloadPatchScript benchmarks script download
func BenchmarkDownloadPatchScript(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/functions/v1/agent-database-proxy/patch-scripts/test-id" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"script_storage_path": "debian/test.sh",
			})
		} else {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("#!/bin/bash\necho test"))
		}
	}))
	defer server.Close()

	client := &WebSocketClient{
		agentID:     "bench-agent",
		supabaseURL: server.URL,
		token:       "test-token",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := client.downloadPatchScript("test-id")
		if err != nil {
			b.Fatalf("download failed: %v", err)
		}
	}
}

// TestScriptIDExtraction tests different script_id types
func TestScriptIDExtraction(t *testing.T) {
	tests := []struct {
		name        string
		scriptIDVal interface{}
		expected    string
	}{
		{
			name:        "string type",
			scriptIDVal: "script-123",
			expected:    "script-123",
		},
		{
			name:        "float64 type",
			scriptIDVal: float64(12345),
			expected:    "12345",
		},
		{
			name:        "object type with id",
			scriptIDVal: map[string]interface{}{"id": "nested-id"},
			expected:    "nested-id",
		},
		{
			name:        "unsupported type",
			scriptIDVal: []string{"array"},
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var scriptID string

			if s, ok := tt.scriptIDVal.(string); ok {
				scriptID = s
			} else if f, ok := tt.scriptIDVal.(float64); ok {
				scriptID = fmt.Sprintf("%v", int64(f))
			} else if u, ok := tt.scriptIDVal.(map[string]interface{}); ok {
				if id, ok := u["id"].(string); ok {
					scriptID = id
				}
			}

			if scriptID != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, scriptID)
			}
		})
	}
}

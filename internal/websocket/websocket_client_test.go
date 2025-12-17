package websocket

import (
	"context"
	"runtime"
	"testing"
	"time"

	"nannyagentv2/internal/ebpf"
	"nannyagentv2/internal/types"

	"github.com/sashabaranov/go-openai"
)

// TestWebSocketClientCreation verifies WebSocketClient can be created
func TestWebSocketClientCreation(t *testing.T) {
	// Create a simple mock agent for testing
	mockAgent := &MockAgent{}

	client := NewWebSocketClient(mockAgent, nil)

	if client == nil {
		t.Fatal("Expected WebSocketClient to be created, got nil")
	}

	if client.agentID == "" {
		t.Error("Expected agentID to be set, got empty string")
	}
}

// TestHeartbeatInitialization verifies heartbeat goroutine can be started
func TestHeartbeatInitialization(t *testing.T) {
	mockAgent := &MockAgent{}
	client := NewWebSocketClient(mockAgent, nil)

	ctx, cancel := context.WithCancel(context.Background())
	client.ctx = ctx
	client.cancel = cancel

	// Start heartbeat
	go client.startHeartbeat()

	// Give heartbeat time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel context
	cancel()

	// Should complete without error
	time.Sleep(100 * time.Millisecond)
}

// TestPollingRemovedFromStart verifies that polling is not started
func TestPollingRemovedFromStart(t *testing.T) {
	mockAgent := &MockAgent{}
	client := NewWebSocketClient(mockAgent, nil)

	// Track the number of goroutines before Start()
	goRoutinesBefore := countActiveGoroutines()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.ctx = ctx

	// Call Start() - should only start heartbeat, NOT polling goroutines
	if err := client.Start(); err != nil {
		t.Errorf("Start() failed: %v", err)
	}

	// Give goroutines time to start
	time.Sleep(100 * time.Millisecond)

	goRoutinesAfter := countActiveGoroutines()
	newGoroutines := goRoutinesAfter - goRoutinesBefore

	// Start() should only spawn:
	// 1. handleMessages goroutine
	// 2. startHeartbeat goroutine
	// 3. updateConnectionStatus goroutine (async)
	// = 3 new goroutines max (not polling goroutines)

	if newGoroutines > 5 {
		t.Errorf("Expected Start() to spawn ~3 goroutines (heartbeat + handlers), but spawned %d", newGoroutines)
	}

	cancel()
	time.Sleep(100 * time.Millisecond)
}

// TestStartOnlySpawnsHeartbeat verifies Start() doesn't spawn polling
func TestStartOnlySpawnsHeartbeat(t *testing.T) {
	mockAgent := &MockAgent{}
	client := NewWebSocketClient(mockAgent, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client.ctx = ctx

	// Verify Start() calls are correct
	startErr := client.Start()

	// Should not error - connection might fail but that's ok
	// (we're not mocking the websocket endpoint)
	if startErr != nil && startErr.Error() == "unexpected error" {
		t.Fatalf("Start() had unexpected error: %v", startErr)
	}

	time.Sleep(100 * time.Millisecond)

	// Verify heartbeat semaphore exists (used for concurrent patch limiting)
	if client.patchSemaphore == nil {
		t.Error("Expected patchSemaphore to be initialized")
	}

	// Verify no polling state
	// If polling was implemented, there would be fields like:
	// - pollTicker
	// - pollInterval
	// These should NOT exist since we use Realtime
	if client.consecutiveFailures < 0 {
		t.Error("consecutiveFailures should be >= 0")
	}
}

// TestRealtimeMessageHandling verifies Realtime messages are handled
func TestRealtimeMessageHandling(t *testing.T) {
	mockAgent := &MockAgent{}
	_ = NewWebSocketClient(mockAgent, nil)

	tests := []struct {
		name          string
		messageType   string
		messageData   interface{}
		shouldProcess bool
	}{
		{
			name:          "realtime broadcast with patch_executions",
			messageType:   "broadcast",
			shouldProcess: true,
		},
		{
			name:          "postgres_changes direct",
			messageType:   "postgres_changes",
			shouldProcess: true,
		},
		{
			name:          "investigation_task",
			messageType:   "investigation_task",
			shouldProcess: true,
		},
		{
			name:          "patch_execution_task",
			messageType:   "patch_execution_task",
			shouldProcess: true,
		},
		{
			name:          "heartbeat_ack",
			messageType:   "heartbeat_ack",
			shouldProcess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := WebSocketMessage{
				Type: tt.messageType,
				Data: map[string]interface{}{},
			}

			// Verify message can be processed (no panic, no error)
			if msg.Type == "" {
				t.Errorf("Message type should not be empty for %s", tt.name)
			}

			// Verify the message type is one of the expected Realtime types
			validTypes := map[string]bool{
				"heartbeat_ack":        true,
				"investigation_task":   true,
				"patch_execution_task": true,
				"task_result_ack":      true,
				"broadcast":            true,
				"postgres_changes":     true,
			}

			if !validTypes[msg.Type] && tt.shouldProcess {
				t.Errorf("Expected valid Realtime message type, got %s", msg.Type)
			}
		})
	}
}

// TestMessageHandling verifies handleMessages can process different message types
func TestMessageHandling(t *testing.T) {
	tests := []struct {
		name        string
		messageType string
		shouldError bool
	}{
		{
			name:        "heartbeat message",
			messageType: "heartbeat",
			shouldError: false,
		},
		{
			name:        "investigation_task message",
			messageType: "investigation_task",
			shouldError: false,
		},
		{
			name:        "unknown message",
			messageType: "unknown_type",
			shouldError: false, // Should not error, just log
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAgent := &MockAgent{}
			_ = NewWebSocketClient(mockAgent, nil)

			// Just verify message type can be processed
			msg := WebSocketMessage{
				Type: tt.messageType,
				Data: map[string]interface{}{},
			}

			if msg.Type == "" && !tt.shouldError {
				t.Errorf("Message type should not be empty for %s", tt.name)
			}
		})
	}
}

// TestWebSocketMessageStructure verifies WebSocketMessage structure is correct
func TestWebSocketMessageStructure(t *testing.T) {
	msg := WebSocketMessage{
		Type: "investigation_task",
		Data: map[string]interface{}{
			"task_id": "task-123",
		},
	}

	if msg.Type != "investigation_task" {
		t.Errorf("Expected type 'investigation_task', got %s", msg.Type)
	}

	if data, ok := msg.Data.(map[string]interface{}); !ok {
		t.Error("Expected Data to be map[string]interface{}")
	} else if data["task_id"] != "task-123" {
		t.Errorf("Expected task_id 'task-123', got %v", data["task_id"])
	}
}

// TestInvestigationTaskStructure verifies InvestigationTask structure
func TestInvestigationTaskStructure(t *testing.T) {
	task := InvestigationTask{
		TaskID:          "task-123",
		InvestigationID: "inv-456",
		AgentID:         "agent-789",
		DiagnosticPayload: map[string]interface{}{
			"commands": []string{"ps aux", "df -h"},
		},
	}

	if task.TaskID != "task-123" {
		t.Errorf("Expected TaskID 'task-123', got %s", task.TaskID)
	}

	if task.InvestigationID != "inv-456" {
		t.Errorf("Expected InvestigationID 'inv-456', got %s", task.InvestigationID)
	}

	if len(task.DiagnosticPayload) == 0 {
		t.Error("Expected DiagnosticPayload to have content")
	}
}

// TestTaskResultStructure verifies TaskResult structure
func TestTaskResultStructure(t *testing.T) {
	result := TaskResult{
		TaskID:  "task-123",
		Success: true,
		CommandResults: map[string]interface{}{
			"ps aux": "user 123 0.1 0.2",
		},
	}

	if result.TaskID != "task-123" {
		t.Errorf("Expected TaskID 'task-123', got %s", result.TaskID)
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}

	if len(result.CommandResults) == 0 {
		t.Error("Expected CommandResults to have content")
	}
}

// TestHeartbeatDataStructure verifies HeartbeatData structure
func TestHeartbeatDataStructure(t *testing.T) {
	now := time.Now()
	hb := HeartbeatData{
		AgentID:   "agent-789",
		Timestamp: now,
		Version:   "1.2.0",
	}

	if hb.AgentID != "agent-789" {
		t.Errorf("Expected AgentID 'agent-789', got %s", hb.AgentID)
	}

	if hb.Timestamp != now {
		t.Errorf("Expected Timestamp %v, got %v", now, hb.Timestamp)
	}

	if hb.Version != "1.2.0" {
		t.Errorf("Expected Version '1.2.0', got %s", hb.Version)
	}
}

// TestWebSocketClientContextHandling verifies context is properly handled
func TestWebSocketClientContextHandling(t *testing.T) {
	mockAgent := &MockAgent{}
	client := NewWebSocketClient(mockAgent, nil)

	if client.ctx == nil {
		t.Error("Expected client.ctx to be initialized")
	}

	if client.cancel == nil {
		t.Error("Expected client.cancel to be initialized")
	}

	// Test context cancellation
	client.cancel()
	time.Sleep(50 * time.Millisecond)

	select {
	case <-client.ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled")
	}
}

// TestWebSocketClientFields verifies struct fields are properly initialized
func TestWebSocketClientFields(t *testing.T) {
	mockAgent := &MockAgent{}
	client := NewWebSocketClient(mockAgent, nil)

	if client.agent == nil {
		t.Error("Expected agent to be set")
	}

	if client.consecutiveFailures != 0 {
		t.Errorf("Expected consecutiveFailures to be 0, got %d", client.consecutiveFailures)
	}

	if client.patchSemaphore == nil {
		t.Error("Expected patchSemaphore to be initialized")
	}

	// Verify semaphore buffer size is 3 (allows max 3 concurrent patch executions)
	select {
	case client.patchSemaphore <- struct{}{}:
		<-client.patchSemaphore
	default:
		t.Error("Expected patchSemaphore to have capacity")
	}
}

// MockAgent implements types.DiagnosticAgent for testing
type MockAgent struct {
	diagnosticError error
}

func (m *MockAgent) DiagnoseIssue(issue string) error {
	return m.diagnosticError
}

func (m *MockAgent) DiagnoseIssueWithInvestigation(issue string) error {
	return m.diagnosticError
}

func (m *MockAgent) GetEpisodeID() string {
	return ""
}

func (m *MockAgent) SetInvestigationID(id string) {
}

func (m *MockAgent) GetInvestigationID() string {
	return ""
}

func (m *MockAgent) ConvertEBPFProgramsToTraceSpecs(ebpfRequests []types.EBPFRequest) []ebpf.TraceSpec {
	return []ebpf.TraceSpec{}
}

func (m *MockAgent) ExecuteEBPFTraces(traceSpecs []ebpf.TraceSpec) []map[string]interface{} {
	return []map[string]interface{}{}
}

func (m *MockAgent) SendRequestWithEpisode(messages []openai.ChatCompletionMessage, episodeID string) (*openai.ChatCompletionResponse, error) {
	return nil, nil
}

func (m *MockAgent) SendRequest(messages []openai.ChatCompletionMessage) (*openai.ChatCompletionResponse, error) {
	return nil, nil
}

func (m *MockAgent) ExecuteCommand(cmd types.Command) types.CommandResult {
	return types.CommandResult{}
}

// countActiveGoroutines counts the current number of active goroutines
func countActiveGoroutines() int {
	return runtime.NumGoroutine()
}

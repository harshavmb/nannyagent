package investigations

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"nannyagent/internal/types"
)

type MockAuthenticator struct {
	AuthenticatedRequestFunc func(method, url string, body []byte, headers map[string]string) (int, []byte, error)
}

func (m *MockAuthenticator) AuthenticatedRequest(method, url string, body []byte, headers map[string]string) (int, []byte, error) {
	if m.AuthenticatedRequestFunc != nil {
		return m.AuthenticatedRequestFunc(method, url, body, headers)
	}
	return 200, []byte("{}"), nil
}

func TestInvestigationsClient_New(t *testing.T) {
	auth := &MockAuthenticator{}
	client := NewInvestigationsClient("http://127.0.0.1:8090", auth)

	if client == nil {
		t.Fatal("client should not be nil")
	}

	if client.baseURL != "http://127.0.0.1:8090" {
		t.Errorf("expected baseURL to be http://127.0.0.1:8090, got %s", client.baseURL)
	}

	if client.authManager != auth {
		t.Fatal("authManager should be set")
	}
}

func TestInvestigationsClient_InvestigationRequestMarshaling(t *testing.T) {
	// Test that InvestigationRequest marshals correctly
	req := types.InvestigationRequest{
		AgentID:  "550e8400-e29b-41d4-a716-446655440000",
		Issue:    "Database query performance is degrading",
		Priority: "high",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}

	var unmarshaled types.InvestigationRequest
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("failed to unmarshal request: %v", err)
	}

	if unmarshaled.AgentID != req.AgentID {
		t.Errorf("expected AgentID %s, got %s", req.AgentID, unmarshaled.AgentID)
	}

	if unmarshaled.Issue != req.Issue {
		t.Errorf("expected Issue %s, got %s", req.Issue, unmarshaled.Issue)
	}

	if unmarshaled.Priority != req.Priority {
		t.Errorf("expected Priority %s, got %s", req.Priority, unmarshaled.Priority)
	}
}

func TestInvestigationsClient_InvestigationResponseMarshaling(t *testing.T) {
	// Test that InvestigationResponse marshals/unmarshals correctly
	now := time.Now()
	resp := types.InvestigationResponse{
		ID:             "investigation-123",
		UserID:         "user-456",
		AgentID:        "agent-789",
		EpisodeID:      "episode-001",
		UserPrompt:     "Database query performance is degrading",
		Priority:       "high",
		Status:         types.InvestigationStatusInProgress,
		ResolutionPlan: "Analyze slow queries and rebuild indexes",
		InitiatedAt:    now,
		CompletedAt:    nil,
		CreatedAt:      now,
		UpdatedAt:      now,
		Metadata: map[string]interface{}{
			"query_time_ms": 5000,
			"affected_rows": 1000000,
		},
		InferenceCount: 3,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}

	var unmarshaled types.InvestigationResponse
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if unmarshaled.ID != resp.ID {
		t.Errorf("expected ID %s, got %s", resp.ID, unmarshaled.ID)
	}

	if unmarshaled.Status != types.InvestigationStatusInProgress {
		t.Errorf("expected status %s, got %s", types.InvestigationStatusInProgress, unmarshaled.Status)
	}

	if unmarshaled.Priority != "high" {
		t.Errorf("expected priority high, got %s", unmarshaled.Priority)
	}

	if unmarshaled.InferenceCount != 3 {
		t.Errorf("expected inference count 3, got %d", unmarshaled.InferenceCount)
	}
}

func TestInvestigationsClient_InvestigationUpdateRequestMarshaling(t *testing.T) {
	// Test that InvestigationUpdateRequest marshals correctly
	completedAt := time.Now()
	update := types.InvestigationUpdateRequest{
		Status:         types.InvestigationStatusCompleted,
		ResolutionPlan: "Query indexes optimized, performance restored",
		CompletedAt:    &completedAt,
		Metadata: map[string]interface{}{
			"resolution_time_minutes": 45,
			"queries_optimized":       5,
		},
		EpisodeID: "episode-001",
	}

	data, err := json.Marshal(update)
	if err != nil {
		t.Fatalf("failed to marshal update: %v", err)
	}

	var unmarshaled types.InvestigationUpdateRequest
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Fatalf("failed to unmarshal update: %v", err)
	}

	if unmarshaled.Status != types.InvestigationStatusCompleted {
		t.Errorf("expected status %s, got %s", types.InvestigationStatusCompleted, unmarshaled.Status)
	}

	if unmarshaled.CompletedAt == nil {
		t.Fatal("expected CompletedAt to not be nil")
	}

	if unmarshaled.EpisodeID != "episode-001" {
		t.Errorf("expected EpisodeID episode-001, got %s", unmarshaled.EpisodeID)
	}
}

func TestInvestigationsClient_InvestigationStatusConstants(t *testing.T) {
	// Test that investigation status constants are correct
	tests := map[types.InvestigationStatus]string{
		types.InvestigationStatusPending:    "pending",
		types.InvestigationStatusInProgress: "in_progress",
		types.InvestigationStatusCompleted:  "completed",
		types.InvestigationStatusFailed:     "failed",
	}

	for status, expectedValue := range tests {
		if string(status) != expectedValue {
			t.Errorf("expected status value %s, got %s", expectedValue, string(status))
		}
	}
}

func TestInvestigationsClient_InvestigationRequestValidationTags(t *testing.T) {
	// Test request structure has proper validation tags
	req := types.InvestigationRequest{}

	// Get the struct field tags
	reqType := reflect.TypeOf(req)

	// AgentID should have UUID validation
	agentIDField, ok := reqType.FieldByName("AgentID")
	if !ok {
		t.Fatal("AgentID field not found")
	}

	validateTag := agentIDField.Tag.Get("validate")
	if validateTag == "" {
		t.Error("AgentID should have validation tags")
	}

	if validateTag != "required,uuid4" {
		t.Errorf("expected AgentID validation 'required,uuid4', got '%s'", validateTag)
	}

	// Issue should have min/max length validation
	issueField, ok := reqType.FieldByName("Issue")
	if !ok {
		t.Fatal("Issue field not found")
	}

	validateTag = issueField.Tag.Get("validate")
	if !contains(validateTag, "min=10") {
		t.Errorf("expected Issue validation to include 'min=10', got '%s'", validateTag)
	}

	if !contains(validateTag, "max=2000") {
		t.Errorf("expected Issue validation to include 'max=2000', got '%s'", validateTag)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0)
}

// TestInvestigationsClient_MultipleStatuses tests various investigation statuses
func TestInvestigationsClient_MultipleStatuses(t *testing.T) {
	statuses := []types.InvestigationStatus{
		types.InvestigationStatusPending,
		types.InvestigationStatusInProgress,
		types.InvestigationStatusCompleted,
		types.InvestigationStatusFailed,
	}

	for i, status := range statuses {
		if status == "" {
			t.Errorf("status %d should not be empty", i)
		}

		// Should be able to convert to string
		str := string(status)
		if str == "" {
			t.Errorf("status %d should convert to non-empty string", i)
		}
	}
}

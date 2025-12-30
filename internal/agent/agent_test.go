package agent

import (
	"nannyagent/internal/types"
	"testing"
)

// MockAuthManager
type MockAuthManager struct {
	Token *types.AuthToken
}

func (m *MockAuthManager) GetCurrentAgentID() (string, error) {
	return "agent-123", nil
}

func (m *MockAuthManager) LoadToken() (*types.AuthToken, error) {
	return m.Token, nil
}

func (m *MockAuthManager) EnsureAuthenticated() (*types.AuthToken, error) {
	return m.Token, nil
}

func TestNewLinuxDiagnosticAgent(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()
	if agent == nil {
		t.Fatal("Expected agent to be created")
	}
}

func TestNewLinuxDiagnosticAgentWithAuth(t *testing.T) {
	mockAuth := &MockAuthManager{
		Token: &types.AuthToken{AccessToken: "test-token"},
	}
	agent := NewLinuxDiagnosticAgentWithAuth(mockAuth, "http://localhost:8090")
	if agent == nil {
		t.Fatal("Expected agent to be created")
	}
}

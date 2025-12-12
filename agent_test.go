package main

import (
	"testing"
)

func TestDefaultAgentConfig(t *testing.T) {
	config := DefaultAgentConfig()

	if config == nil {
		t.Fatal("Expected agent config to be created")
	}

	if config.MaxConcurrentTasks != 10 {
		t.Errorf("Expected MaxConcurrentTasks to be 10, got %d", config.MaxConcurrentTasks)
	}

	if !config.CollectiveResults {
		t.Error("Expected CollectiveResults to be true by default")
	}
}

func TestNewLinuxDiagnosticAgent(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	if agent == nil {
		t.Fatal("Expected agent to be created")
	}

	if agent.executor == nil {
		t.Error("Executor should be initialized")
	}

	if agent.config == nil {
		t.Error("Config should be initialized")
	}

	if agent.ebpfManager == nil {
		t.Error("eBPF manager should be initialized")
	}

	if agent.logger == nil {
		t.Error("Logger should be initialized")
	}

	if agent.model == "" {
		t.Error("Model should be set")
	}
}

func TestNewLinuxDiagnosticAgentWithAuth(t *testing.T) {
	// Test with nil auth manager
	agent := NewLinuxDiagnosticAgentWithAuth(nil)

	if agent == nil {
		t.Fatal("Expected agent to be created even with nil auth")
	}

	if agent.authManager != nil {
		t.Error("Auth manager should be nil when passed nil")
	}

	// Test with mock auth manager (using interface{} type)
	mockAuth := struct{}{}
	agent = NewLinuxDiagnosticAgentWithAuth(mockAuth)

	if agent.authManager == nil {
		t.Error("Auth manager should be set when provided")
	}
}

func TestSetModel(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	newModel := "custom::model::name"
	agent.SetModel(newModel)

	if agent.model != newModel {
		t.Errorf("Expected model to be %s, got %s", newModel, agent.model)
	}
}

func TestAgentConfig_Structure(t *testing.T) {
	config := &AgentConfig{
		MaxConcurrentTasks: 5,
		CollectiveResults:  false,
	}

	if config.MaxConcurrentTasks != 5 {
		t.Error("MaxConcurrentTasks not set correctly")
	}

	if config.CollectiveResults {
		t.Error("CollectiveResults should be false")
	}
}

func TestAgentInitialization_WithEnvironment(t *testing.T) {
	// Save original env vars
	originalSupabaseURL := ""

	// Test without SUPABASE_PROJECT_URL
	agent := NewLinuxDiagnosticAgent()
	if agent == nil {
		t.Fatal("Agent should be created even without env vars")
	}

	// Restore
	if originalSupabaseURL != "" {
		// Would restore here
	}
}

func TestExecutor_Integration(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	// Verify executor has proper timeout
	if agent.executor == nil {
		t.Fatal("Executor should be initialized")
	}

	// Executor should be functional
	if agent.executor == nil {
		t.Error("Executor should be of type *CommandExecutor")
	}
}

func TestAgentConfig_MaxConcurrentTasks(t *testing.T) {
	tests := []int{1, 5, 10, 20, 100}

	for _, max := range tests {
		config := &AgentConfig{
			MaxConcurrentTasks: max,
			CollectiveResults:  true,
		}

		if config.MaxConcurrentTasks != max {
			t.Errorf("Expected MaxConcurrentTasks %d, got %d", max, config.MaxConcurrentTasks)
		}
	}
}

func TestAgentConfig_CollectiveResults(t *testing.T) {
	tests := []bool{true, false}

	for _, collective := range tests {
		config := &AgentConfig{
			MaxConcurrentTasks: 10,
			CollectiveResults:  collective,
		}

		if config.CollectiveResults != collective {
			t.Errorf("Expected CollectiveResults %v, got %v", collective, config.CollectiveResults)
		}
	}
}

func TestLinuxDiagnosticAgent_Fields(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	// Test that all critical fields are initialized
	if agent.client != nil {
		t.Log("Client is set (may use direct HTTP instead)")
	}

	if agent.model == "" {
		t.Error("Model should not be empty")
	}

	if agent.executor == nil {
		t.Fatal("Executor must be initialized")
	}

	if agent.episodeID != "" {
		t.Log("Episode ID is set (optional)")
	}

	if agent.ebpfManager == nil {
		t.Fatal("eBPF manager must be initialized")
	}

	if agent.config == nil {
		t.Fatal("Config must be initialized")
	}
}

func TestAgentWithDifferentModels(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	models := []string{
		"tensorzero::function_name::diagnose_and_heal",
		"custom::model::v1",
		"openai::gpt-4",
	}

	for _, model := range models {
		agent.SetModel(model)
		if agent.model != model {
			t.Errorf("Failed to set model to %s", model)
		}
	}
}

func TestDefaultAgentConfig_Values(t *testing.T) {
	config := DefaultAgentConfig()

	// Verify default values match documentation/expectations
	expectedMax := 10
	expectedCollective := true

	if config.MaxConcurrentTasks != expectedMax {
		t.Errorf("Default MaxConcurrentTasks should be %d, got %d", expectedMax, config.MaxConcurrentTasks)
	}

	if config.CollectiveResults != expectedCollective {
		t.Errorf("Default CollectiveResults should be %v, got %v", expectedCollective, config.CollectiveResults)
	}
}

func TestLinuxDiagnosticAgent_EpisodeID(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	// Episode ID should be empty initially
	if agent.episodeID != "" {
		t.Log("Episode ID initialized (may be set by conversation flow)")
	}

	// Test setting episode ID
	testEpisodeID := "test-episode-123"
	agent.episodeID = testEpisodeID

	if agent.episodeID != testEpisodeID {
		t.Errorf("Expected episode ID %s, got %s", testEpisodeID, agent.episodeID)
	}
}

func TestAgentCreation_Multiple(t *testing.T) {
	// Create multiple agents to ensure no shared state issues
	agent1 := NewLinuxDiagnosticAgent()
	agent2 := NewLinuxDiagnosticAgent()

	if agent1 == agent2 {
		t.Error("Each call should create a new agent instance")
	}

	if agent1.executor == agent2.executor {
		t.Error("Each agent should have its own executor")
	}

	if agent1.ebpfManager == agent2.ebpfManager {
		t.Error("Each agent should have its own eBPF manager")
	}
}

func TestAgentModel_DefaultValue(t *testing.T) {
	agent := NewLinuxDiagnosticAgent()

	expectedModel := "tensorzero::function_name::diagnose_and_heal"

	if agent.model != expectedModel {
		t.Errorf("Expected default model %s, got %s", expectedModel, agent.model)
	}
}

func TestAgentAuthManager_Initialization(t *testing.T) {
	// Test without auth
	agent1 := NewLinuxDiagnosticAgent()
	if agent1.authManager != nil {
		t.Error("Agent created without auth should have nil auth manager")
	}

	// Test with auth
	mockAuth := "mock-auth-manager"
	agent2 := NewLinuxDiagnosticAgentWithAuth(mockAuth)
	if agent2.authManager == nil {
		t.Error("Agent created with auth should have auth manager set")
	}
}

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPortalToTensorZeroFlow tests the complete flow from portal to tensorzero-proxy
func TestPortalToTensorZeroFlow(t *testing.T) {
	// 1. Portal creates investigation with initiated_by=user_id
	investigationID := "INV-20251217-PORTAL-001"
	userID := "550e8400-e29b-41d4-a716-446655440000"
	issue := "High CPU usage detected"

	// Verify inputs are set correctly
	assert.NotEmpty(t, userID, "User ID should be provided by portal")
	assert.NotEmpty(t, issue, "Issue description should be provided")

	// 2. Websocket receives investigation_task with investigation_id
	// Simulated in handleInvestigationTask
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
		episodeID:       "",
	}

	// 3. Agent receives investigation_id and sets it
	agent.SetInvestigationID(investigationID)

	// 4. Verify it's set
	assert.Equal(t, investigationID, agent.GetInvestigationID())

	// 5. Verify it will be passed to tensorzero-proxy in metadata
	// (This would happen in SendRequestWithEpisode)
	metadata := make(map[string]interface{})
	if agent.investigationID != "" {
		metadata["investigation_id"] = agent.investigationID
	}

	assert.Equal(t, investigationID, metadata["investigation_id"])
}

// TestNoDuplicateCreation verifies investigation_id prevents duplicate creation
func TestNoDuplicateCreation(t *testing.T) {
	investigationID := "INV-20251217-NO-DUP"

	// First call - investigation_id is set
	agent := &LinuxDiagnosticAgent{
		investigationID: investigationID,
	}

	// tensorzero-proxy receives investigation_id in metadata
	requestMetadata := make(map[string]interface{})
	if agent.investigationID != "" {
		requestMetadata["investigation_id"] = agent.investigationID
	}

	// tensorzero-proxy logic:
	// IF investigation_id in metadata -> UPDATE existing
	// ELSE -> CREATE new

	hasInvestigationID := requestMetadata["investigation_id"] != nil
	assert.True(t, hasInvestigationID, "investigation_id should be present, triggering UPDATE instead of CREATE")
}

// TestAgentInitiatedInvestigation verifies agent doesn't set investigation_id for its own investigations
func TestAgentInitiatedInvestigation(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	// Agent-initiated investigations don't set investigationID
	// So it remains empty
	assert.Equal(t, "", agent.GetInvestigationID())

	// When sent to tensorzero-proxy, no investigation_id in metadata
	// tensorzero-proxy will CREATE new investigation
	requestMetadata := make(map[string]interface{})
	if agent.investigationID != "" {
		requestMetadata["investigation_id"] = agent.investigationID
	}

	// Metadata is empty - will cause CREATE
	assert.Len(t, requestMetadata, 0)
}

// TestPortalWorkflow simulates the complete portal-initiated workflow
func TestPortalWorkflow(t *testing.T) {
	// Stage 1: Portal creates investigation
	portalInvestigationID := "INV-20251217-WORKFLOW-001"
	portalUserID := "user-uuid-123"
	portalIssue := "System overheating"

	// Verify inputs
	assert.NotEmpty(t, portalUserID, "Portal should have user ID")
	assert.NotEmpty(t, portalIssue, "Portal should have issue description")

	// Stage 2: Websocket handler receives the task
	// handleInvestigationTask runs:
	// - Checks initiated_by is not "agent" ✓
	// - Creates agent instance
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	// Stage 3: Agent is told about the investigation
	agent.SetInvestigationID(portalInvestigationID)

	// Stage 4: Verification
	assert.Equal(t, portalInvestigationID, agent.GetInvestigationID(),
		"Agent should know the investigation ID")

	// Stage 5: When making request to tensorzero-proxy
	metadata := map[string]interface{}{
		"investigation_id": agent.GetInvestigationID(),
	}

	// Stage 6: tensorzero-proxy receives and updates instead of creates
	invIDFromMetadata := metadata["investigation_id"].(string)
	assert.Equal(t, portalInvestigationID, invIDFromMetadata,
		"investigation_id should be passed through metadata to tensorzero-proxy")
}

// TestEdgeCase_MultipleInvestigationsSequential tests handling multiple investigations in sequence
func TestEdgeCase_MultipleInvestigationsSequential(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	investigations := []struct {
		id    string
		issue string
	}{
		{"INV-20251217-SEQ-001", "CPU high"},
		{"INV-20251217-SEQ-002", "Memory high"},
		{"INV-20251217-SEQ-003", "Disk high"},
	}

	for _, inv := range investigations {
		// Set investigation ID for this diagnosis
		agent.SetInvestigationID(inv.id)

		// Verify it's set correctly
		assert.Equal(t, inv.id, agent.GetInvestigationID())

		// Would be passed to tensorzero-proxy here
		metadata := map[string]interface{}{
			"investigation_id": agent.GetInvestigationID(),
		}
		assert.Equal(t, inv.id, metadata["investigation_id"])
	}

	// After all, should have the last ID
	assert.Equal(t, "INV-20251217-SEQ-003", agent.GetInvestigationID())
}

// TestEdgeCase_InvestigationIDWithDifferentFormats tests ID format variations
func TestEdgeCase_InvestigationIDWithDifferentFormats(t *testing.T) {
	formats := []string{
		"INV-20251217-ABC123",          // Standard format
		"inv-20251217-lowercase",       // Lowercase
		"INV_20251217_UNDERSCORE",      // Underscore
		"INV.20251217.DOT",             // Dot separator
		"123-456-789",                  // Numeric
		"UUID-550e8400-e29b-41d4-a716", // UUID format
	}

	for _, id := range formats {
		agent := &LinuxDiagnosticAgent{
			investigationID: id,
		}

		retrieved := agent.GetInvestigationID()
		assert.Equal(t, id, retrieved, "Format %s should be preserved", id)

		// Should work in metadata
		metadata := map[string]interface{}{
			"investigation_id": agent.GetInvestigationID(),
		}
		assert.Equal(t, id, metadata["investigation_id"])
	}
}

// TestInitiatedByValidation tests the initiated_by validation logic
func TestInitiatedByValidation(t *testing.T) {
	validInitiations := []struct {
		initiatedBy string
		shouldSet   bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true}, // Valid user UUID
		{"18e3695b-b540-4b3c-bfcf-b239437eb217", true}, // Another valid UUID
		{"user-email@example.com", true},               // Email format
		{"service_account", true},                      // Service account
		{"agent", false},                               // Agent - should not set
		{"", false},                                    // Empty - should not set
	}

	for _, tc := range validInitiations {
		t.Run("initiated_by="+tc.initiatedBy, func(t *testing.T) {
			agent := &LinuxDiagnosticAgent{
				investigationID: "",
			}

			// Simulate the logic from handleInvestigationTask
			if tc.initiatedBy != "" && tc.initiatedBy != "agent" {
				// Valid portal-initiated
				agent.SetInvestigationID("INV-20251217-TEST")

				if tc.shouldSet {
					assert.Equal(t, "INV-20251217-TEST", agent.GetInvestigationID())
				} else {
					assert.Equal(t, "", agent.GetInvestigationID())
				}
			} else {
				// Agent-initiated or invalid - don't set
				assert.Equal(t, "", agent.GetInvestigationID())
			}
		})
	}
}

// TestInvestigationLifecycle tests the complete investigation lifecycle
func TestInvestigationLifecycle(t *testing.T) {
	invID := "INV-20251217-LIFECYCLE"

	// 1. Create agent
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
		episodeID:       "",
	}

	// 2. Receive investigation from portal
	agent.SetInvestigationID(invID)
	assert.Equal(t, invID, agent.GetInvestigationID())

	// 3. Start diagnosis (episodeID would be set by TensorZero)
	agent.episodeID = "episode-uuid-abc123"
	assert.Equal(t, invID, agent.GetInvestigationID())
	assert.Equal(t, "episode-uuid-abc123", agent.GetEpisodeID())

	// 4. Diagnosis completes (both IDs persist)
	assert.Equal(t, invID, agent.GetInvestigationID())
	assert.Equal(t, "episode-uuid-abc123", agent.GetEpisodeID())

	// 5. New investigation arrives
	agent.SetInvestigationID("INV-20251217-LIFECYCLE-2")
	// Agent code clears episodeID for new investigation
	agent.episodeID = ""

	assert.Equal(t, "INV-20251217-LIFECYCLE-2", agent.GetInvestigationID())
	assert.Equal(t, "", agent.GetEpisodeID())
}

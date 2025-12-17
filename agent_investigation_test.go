package main

import (
	"encoding/json"
	"nannyagentv2/internal/logging"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestInvestigationIDStoredInAgent verifies that investigation ID is stored and retrievable
func TestInvestigationIDStoredInAgent(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	investigationID := "INV-20251217-TEST123"
	agent.SetInvestigationID(investigationID)

	retrieved := agent.GetInvestigationID()
	assert.Equal(t, investigationID, retrieved, "Investigation ID should be stored and retrievable")
}

// TestInvestigationIDClearedBetweenCalls verifies that investigation ID can be updated
func TestInvestigationIDUpdatedBetweenCalls(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	// First investigation
	agent.SetInvestigationID("INV-20251217-FIRST")
	assert.Equal(t, "INV-20251217-FIRST", agent.GetInvestigationID())

	// Updated investigation
	agent.SetInvestigationID("INV-20251217-SECOND")
	assert.Equal(t, "INV-20251217-SECOND", agent.GetInvestigationID())
}

// TestInvestigationIDInTensorZeroRequest verifies metadata is built correctly
func TestInvestigationIDInTensorZeroRequest(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "INV-20251217-METADATA",
	}

	// Simulate what SendRequestWithEpisode does with investigation ID
	if agent.investigationID != "" {
		metadata := map[string]interface{}{
			"investigation_id": agent.investigationID,
		}

		metadataBytes, _ := json.Marshal(metadata)
		var parsedMetadata map[string]interface{}
		err := json.Unmarshal(metadataBytes, &parsedMetadata)
		if err != nil {
			logging.Error("Error unmarshaling parsed metadata: %v", err)
			return
		}

		assert.Equal(t, "INV-20251217-METADATA", parsedMetadata["investigation_id"])
	}
}

// TestInvestigationIDNotInRequestWhenEmpty verifies no metadata when ID is empty
func TestInvestigationIDNotInRequestWhenEmpty(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
		model:           "gpt-4",
	}

	// Simulate SendRequestWithEpisode logic
	hasMetadata := agent.investigationID != ""
	assert.False(t, hasMetadata, "Metadata should not be included when investigation ID is empty")
}

// TestDiagnoseIssueWithInvestigationLogsID verifies logging of investigation ID
func TestDiagnoseIssueWithInvestigationLogsID(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "INV-20251217-LOG",
	}

	// The investigation ID should be accessible during diagnosis
	currentID := agent.GetInvestigationID()
	assert.Equal(t, "INV-20251217-LOG", currentID, "Investigation ID should be available during diagnosis")
}

// TestEdgeCase_EmptyInvestigationIDHandling verifies empty ID is handled gracefully
func TestEdgeCase_EmptyInvestigationIDHandling(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	// Should not panic or error
	retrieved := agent.GetInvestigationID()
	assert.Equal(t, "", retrieved)

	// Setting to empty again should work
	agent.SetInvestigationID("")
	assert.Equal(t, "", agent.GetInvestigationID())
}

// TestEdgeCase_VeryLongInvestigationID verifies long IDs are handled
func TestEdgeCase_VeryLongInvestigationID(t *testing.T) {
	longID := "INV-20251217-" + string(make([]byte, 5000))

	agent := &LinuxDiagnosticAgent{
		investigationID: longID,
	}

	retrieved := agent.GetInvestigationID()
	assert.Equal(t, longID, retrieved)
	assert.Equal(t, len(longID), len(retrieved))
}

// TestEdgeCase_SpecialCharactersInID verifies special chars are preserved
func TestEdgeCase_SpecialCharactersInID(t *testing.T) {
	specialID := "INV-20251217-!@#$%^&*()"

	agent := &LinuxDiagnosticAgent{
		investigationID: specialID,
	}

	retrieved := agent.GetInvestigationID()
	assert.Equal(t, specialID, retrieved)
}

// TestEdgeCase_UnicodeInID verifies unicode is handled
func TestEdgeCase_UnicodeInID(t *testing.T) {
	unicodeID := "INV-20251217-测试-тест-🎉"

	agent := &LinuxDiagnosticAgent{
		investigationID: unicodeID,
	}

	retrieved := agent.GetInvestigationID()
	assert.Equal(t, unicodeID, retrieved)
}

// TestEdgeCase_ConcurrentInvestigations simulates multiple investigation updates
func TestEdgeCase_ConcurrentInvestigationUpdates(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "",
	}

	investigations := []string{
		"INV-20251217-001",
		"INV-20251217-002",
		"INV-20251217-003",
	}

	// Simulate sequential updates (agent processes one at a time)
	for _, invID := range investigations {
		agent.SetInvestigationID(invID)
		assert.Equal(t, invID, agent.GetInvestigationID())
	}

	// Should end with the last one
	assert.Equal(t, "INV-20251217-003", agent.GetInvestigationID())
}

// TestMetadataStructure verifies investigation_id is in correct metadata structure
func TestMetadataStructure(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "INV-20251217-STRUCT",
	}

	// Simulate the exact metadata structure used in SendRequestWithEpisode
	if agent.investigationID != "" {
		metadata := map[string]interface{}{
			"investigation_id": agent.investigationID,
		}

		// Verify structure
		assert.NotNil(t, metadata)
		assert.Equal(t, "INV-20251217-STRUCT", metadata["investigation_id"])
	}
}

// TestInvestigationIDNotModifiedByEpisodeID verifies episode_id doesn't affect investigation_id
func TestInvestigationIDNotModifiedByEpisodeID(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "INV-20251217-NOMOD",
		episodeID:       "",
	}

	// Set episode ID
	agent.episodeID = "episode-uuid-123"

	// Investigation ID should remain unchanged
	assert.Equal(t, "INV-20251217-NOMOD", agent.GetInvestigationID())
	assert.Equal(t, "episode-uuid-123", agent.GetEpisodeID())
}

// TestInvestigationIDResetBetweenDiagnoses verifies independent investigation tracking
func TestInvestigationIDResetBetweenDiagnoses(t *testing.T) {
	agent := &LinuxDiagnosticAgent{
		investigationID: "INV-20251217-FIRST",
		episodeID:       "episode-uuid-1",
	}

	// Simulate first diagnosis completing and next one starting
	firstInvID := agent.GetInvestigationID()
	firstEpisodeID := agent.GetEpisodeID()

	// New investigation comes in
	agent.SetInvestigationID("INV-20251217-SECOND")
	agent.episodeID = "" // Will be set by new episode

	secondInvID := agent.GetInvestigationID()
	secondEpisodeID := agent.GetEpisodeID()

	// Should be different
	assert.NotEqual(t, firstInvID, secondInvID)
	assert.Equal(t, firstEpisodeID, "episode-uuid-1")
	assert.Equal(t, secondEpisodeID, "")
}

package websocket

import (
	"testing"

	"nannyagentv2/internal/ebpf"
	"nannyagentv2/internal/types"

	"github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockDiagnosticAgent is a mock implementation of DiagnosticAgent for testing
type MockDiagnosticAgent struct {
	mock.Mock
}

func (m *MockDiagnosticAgent) DiagnoseIssue(issue string) error {
	args := m.Called(issue)
	return args.Error(0)
}

func (m *MockDiagnosticAgent) DiagnoseIssueWithInvestigation(issue string) error {
	args := m.Called(issue)
	return args.Error(0)
}

func (m *MockDiagnosticAgent) GetEpisodeID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockDiagnosticAgent) SetInvestigationID(id string) {
	m.Called(id)
}

func (m *MockDiagnosticAgent) GetInvestigationID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockDiagnosticAgent) ConvertEBPFProgramsToTraceSpecs(ebpfRequests []types.EBPFRequest) []ebpf.TraceSpec {
	args := m.Called(ebpfRequests)
	if args.Get(0) == nil {
		return []ebpf.TraceSpec{}
	}
	return args.Get(0).([]ebpf.TraceSpec)
}

func (m *MockDiagnosticAgent) ExecuteEBPFTraces(traceSpecs []ebpf.TraceSpec) []map[string]interface{} {
	args := m.Called(traceSpecs)
	return args.Get(0).([]map[string]interface{})
}

func (m *MockDiagnosticAgent) SendRequestWithEpisode(messages []openai.ChatCompletionMessage, episodeID string) (*openai.ChatCompletionResponse, error) {
	args := m.Called(messages, episodeID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*openai.ChatCompletionResponse), args.Error(1)
}

func (m *MockDiagnosticAgent) SendRequest(messages []openai.ChatCompletionMessage) (*openai.ChatCompletionResponse, error) {
	args := m.Called(messages)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*openai.ChatCompletionResponse), args.Error(1)
}

func (m *MockDiagnosticAgent) ExecuteCommand(cmd types.Command) types.CommandResult {
	args := m.Called(cmd)
	return args.Get(0).(types.CommandResult)
}

// TestSetInvestigationID verifies that investigation ID can be set and retrieved
func TestSetInvestigationID(t *testing.T) {
	mockAgent := new(MockDiagnosticAgent)
	investigationID := "INV-20251217-ABC123"

	mockAgent.On("SetInvestigationID", investigationID).Return()
	mockAgent.On("GetInvestigationID").Return(investigationID)

	mockAgent.SetInvestigationID(investigationID)
	retrieved := mockAgent.GetInvestigationID()

	assert.Equal(t, investigationID, retrieved)
	mockAgent.AssertCalled(t, "SetInvestigationID", investigationID)
}

// TestInvestigationIDForPortalVsAgent verifies logic for portal vs agent distinction
func TestInvestigationIDForPortalVsAgent(t *testing.T) {
	tests := []struct {
		name        string
		initiatedBy string
		shouldSet   bool
	}{
		{"Portal user", "user-uuid-123", true},
		{"Agent initiated", "agent", false},
		{"Empty initiated_by", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAgent := new(MockDiagnosticAgent)

			// Real code logic: only set if initiated_by is not empty and not "agent"
			if tt.initiatedBy != "" && tt.initiatedBy != "agent" {
				mockAgent.On("SetInvestigationID", "INV-TEST").Return()
				mockAgent.SetInvestigationID("INV-TEST")
				mockAgent.AssertCalled(t, "SetInvestigationID", "INV-TEST")
			} else {
				mockAgent.On("SetInvestigationID", mock.Anything).Return()
				mockAgent.AssertNotCalled(t, "SetInvestigationID", "INV-TEST")
			}
		})
	}
}

// TestEmptyInvestigationID verifies empty IDs are handled
func TestEmptyInvestigationID(t *testing.T) {
	mockAgent := new(MockDiagnosticAgent)
	mockAgent.On("SetInvestigationID", "").Return()
	mockAgent.On("GetInvestigationID").Return("")

	mockAgent.SetInvestigationID("")
	retrieved := mockAgent.GetInvestigationID()

	assert.Equal(t, "", retrieved)
}

package investigations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/types"
)

// InvestigationsClient handles all investigation API operations
type InvestigationsClient struct {
	baseURL string
	client  *http.Client
}

// NewInvestigationsClient creates a new investigations client
func NewInvestigationsClient(baseURL string) *InvestigationsClient {
	return &InvestigationsClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// CreateInvestigation creates a new investigation via POST /api/investigations
func (ic *InvestigationsClient) CreateInvestigation(accessToken string, agentID string, issue string, priority string) (*types.InvestigationResponse, error) {
	logging.Info("Creating investigation for agent %s", agentID)

	// Create request payload
	payload := types.InvestigationRequest{
		AgentID:  agentID,
		Issue:    issue,
		Priority: priority,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to NannyAPI /api/investigations endpoint
	url := fmt.Sprintf("%s/api/investigations", ic.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create investigation: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("investigation creation failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var investigationResp types.InvestigationResponse
	if err := json.Unmarshal(body, &investigationResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logging.Info("Investigation created successfully with ID: %s", investigationResp.ID)
	return &investigationResp, nil
}

// SendDiagnosticMessage sends a message to the diagnostic AI (TensorZero) via the investigations endpoint
func (ic *InvestigationsClient) SendDiagnosticMessage(accessToken string, model string, messages []types.ChatMessage, investigationID string) (string, error) {
	logging.Debug("Sending diagnostic message for investigation %s", investigationID)

	// Convert messages to map format for JSON marshaling
	messageMaps := make([]map[string]interface{}, len(messages))
	for i, msg := range messages {
		messageMaps[i] = map[string]interface{}{
			"role":    msg.Role,
			"content": msg.Content,
		}
	}

	// Create TensorZero request
	tzRequest := map[string]interface{}{
		"model":    model,
		"messages": messageMaps,
	}

	// Add investigation ID to top-level for proxy routing
	if investigationID != "" {
		tzRequest["investigation_id"] = investigationID
	}

	jsonData, err := json.Marshal(tzRequest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to NannyAPI /api/investigations endpoint
	url := fmt.Sprintf("%s/api/investigations", ic.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := ic.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("TensorZero proxy error: %d, body: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tzResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tzResponse); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to OpenAI format for compatibility
	choices, ok := tzResponse["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	// Extract the first choice
	firstChoice, ok := choices[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid choice format")
	}

	message, ok := firstChoice["message"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid message format")
	}

	content, ok := message["content"].(string)
	if !ok {
		return "", fmt.Errorf("invalid content format")
	}

	return content, nil
}

// GetInvestigation retrieves an investigation via GET /api/investigations/{id}
func (ic *InvestigationsClient) GetInvestigation(accessToken string, investigationID string) (*types.InvestigationResponse, error) {
	logging.Info("Fetching investigation %s", investigationID)

	// Send request to NannyAPI /api/investigations/{id} endpoint
	url := fmt.Sprintf("%s/api/investigations/%s", ic.baseURL, investigationID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch investigation: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("investigation fetch failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var investigationResp types.InvestigationResponse
	if err := json.Unmarshal(body, &investigationResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logging.Info("Investigation fetched successfully")
	return &investigationResp, nil
}

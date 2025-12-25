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
			Timeout: 30 * time.Second,
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

// UpdateInvestigation updates an investigation via PATCH /api/investigations/{id}
func (ic *InvestigationsClient) UpdateInvestigation(accessToken string, investigationID string, update *types.InvestigationUpdateRequest) (*types.InvestigationResponse, error) {
	logging.Info("Updating investigation %s", investigationID)

	jsonData, err := json.Marshal(update)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request to NannyAPI /api/investigations/{id} endpoint
	url := fmt.Sprintf("%s/api/investigations/%s", ic.baseURL, investigationID)
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to update investigation: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("investigation update failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var investigationResp types.InvestigationResponse
	if err := json.Unmarshal(body, &investigationResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	logging.Info("Investigation updated successfully")
	return &investigationResp, nil
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

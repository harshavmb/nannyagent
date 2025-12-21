package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/types"
)

// PocketBaseClient handles metrics ingestion to PocketBase
type PocketBaseClient struct {
	baseURL string
	client  *http.Client
}

// NewPocketBaseClient creates a new PocketBase metrics client
func NewPocketBaseClient(baseURL string) *PocketBaseClient {
	return &PocketBaseClient{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// IngestMetrics sends system metrics to PocketBase /api/agent endpoint
// agentID is required for upsert operation - metrics will be updated for same agent
func (pc *PocketBaseClient) IngestMetrics(agentID string, accessToken string, systemMetrics *types.SystemMetrics) error {
	logging.Debug("Ingesting metrics for agent %s", agentID)

	// Convert SystemMetrics to PocketBaseSystemMetrics format
	pbMetrics := pc.convertSystemMetrics(systemMetrics)

	// Create the ingest request payload with agent_id for upsert
	payload := types.IngestMetricsRequest{
		Action:        "ingest-metrics",
		AgentID:       agentID,
		SystemMetrics: pbMetrics,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics payload: %w", err)
	}

	// Send request to PocketBase /api/agent endpoint with authorization
	url := fmt.Sprintf("%s/api/agent", pc.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create metrics request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := pc.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for authorization errors
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("metrics ingestion failed: unauthorized - token may be expired")
	}

	// Check for other errors
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("metrics ingestion failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var metricsResp types.IngestMetricsResponse
	if err := json.Unmarshal(body, &metricsResp); err != nil {
		// If response doesn't parse as IngestMetricsResponse, check for generic error
		logging.Warning("Could not parse metrics response: %v", err)
		// Still consider it a success if status was OK
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			logging.Info("Metrics ingested successfully")
			return nil
		}
	}

	if !metricsResp.Success {
		logging.Warning("Metrics ingestion response: %s", metricsResp.Message)
		return fmt.Errorf("metrics ingestion failed: %s", metricsResp.Message)
	}

	logging.Info("Metrics ingested successfully")
	return nil
}

// convertSystemMetrics converts internal SystemMetrics to PocketBase format
func (pc *PocketBaseClient) convertSystemMetrics(systemMetrics *types.SystemMetrics) *types.PocketBaseSystemMetrics {
	// Convert filesystems to PocketBase format
	filesystems := pc.convertFilesystems(systemMetrics.FilesystemInfo)

	// Calculate memory percentage
	memoryPercent := 0.0
	if systemMetrics.MemoryTotal > 0 {
		memoryPercent = math.Round((float64(systemMetrics.MemoryUsed)/float64(systemMetrics.MemoryTotal))*10000) / 100
	}

	// Calculate disk usage percentage
	diskUsagePercent := 0.0
	if systemMetrics.DiskTotal > 0 {
		diskUsagePercent = math.Round((float64(systemMetrics.DiskUsed)/float64(systemMetrics.DiskTotal))*10000) / 100
	}

	// Convert memory from bytes to GB
	memoryUsedGB := float64(systemMetrics.MemoryUsed) / (1024 * 1024 * 1024)
	memoryTotalGB := float64(systemMetrics.MemoryTotal) / (1024 * 1024 * 1024)

	// Convert disk from bytes to GB
	diskUsedGB := float64(systemMetrics.DiskUsed) / (1024 * 1024 * 1024)
	diskTotalGB := float64(systemMetrics.DiskTotal) / (1024 * 1024 * 1024)

	// Convert network from Kbps to Gbps
	networkInGbps := systemMetrics.NetworkInKbps / (1024 * 1024)
	networkOutGbps := systemMetrics.NetworkOutKbps / (1024 * 1024)

	return &types.PocketBaseSystemMetrics{
		CPUPercent:       math.Round(systemMetrics.CPUUsage*100) / 100,
		CPUCores:         systemMetrics.CPUCores,
		MemoryUsedGB:     math.Round(memoryUsedGB*100) / 100,
		MemoryTotalGB:    math.Round(memoryTotalGB*100) / 100,
		MemoryPercent:    memoryPercent,
		DiskUsedGB:       math.Round(diskUsedGB*100) / 100,
		DiskTotalGB:      math.Round(diskTotalGB*100) / 100,
		DiskUsagePercent: diskUsagePercent,
		Filesystems:      filesystems,
		LoadAverage: types.LoadAverage{
			OneMin:     math.Round(systemMetrics.LoadAvg1*100) / 100,
			FiveMin:    math.Round(systemMetrics.LoadAvg5*100) / 100,
			FifteenMin: math.Round(systemMetrics.LoadAvg15*100) / 100,
		},
		NetworkStats: types.NetworkStats{
			InGbps:  math.Round(networkInGbps*100000) / 100000,
			OutGbps: math.Round(networkOutGbps*100000) / 100000,
		},
	}
}

// convertFilesystems converts filesystem info to PocketBase format
func (pc *PocketBaseClient) convertFilesystems(filesystemInfo []types.FilesystemInfo) []types.FilesystemStats {
	if len(filesystemInfo) == 0 {
		return []types.FilesystemStats{}
	}

	filesystems := make([]types.FilesystemStats, 0, len(filesystemInfo))
	for _, fs := range filesystemInfo {
		// Convert bytes to GB
		usedGB := float64(fs.Used) / (1024 * 1024 * 1024)
		freeGB := float64(fs.Free) / (1024 * 1024 * 1024)
		totalGB := float64(fs.Total) / (1024 * 1024 * 1024)

		filesystems = append(filesystems, types.FilesystemStats{
			Device:       fs.Device,
			MountPath:    fs.Mountpoint,
			UsedGB:       math.Round(usedGB*100) / 100,
			FreeGB:       math.Round(freeGB*100) / 100,
			TotalGB:      math.Round(totalGB*100) / 100,
			UsagePercent: math.Round(fs.UsagePercent*100) / 100,
		})
	}

	return filesystems
}

// GetHealthStatus retrieves the health status of an agent
func (pc *PocketBaseClient) GetHealthStatus(accessToken string, agentID string) (*types.HealthResponse, error) {
	logging.Debug("Checking health status for agent: %s", agentID)

	payload := types.HealthRequest{
		Action:  "health",
		AgentID: agentID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal health request: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", pc.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create health request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := pc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get health status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var healthResp types.HealthResponse
	if err := json.Unmarshal(body, &healthResp); err != nil {
		return nil, fmt.Errorf("failed to parse health response: %w", err)
	}

	return &healthResp, nil
}

// ListAgents retrieves the list of agents for the current user
func (pc *PocketBaseClient) ListAgents(accessToken string) (*types.ListAgentsResponse, error) {
	logging.Debug("Listing agents...")

	payload := types.ListAgentsRequest{
		Action: "list",
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal list request: %w", err)
	}

	url := fmt.Sprintf("%s/api/agent", pc.baseURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create list request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	resp, err := pc.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var listResp types.ListAgentsResponse
	if err := json.Unmarshal(body, &listResp); err != nil {
		return nil, fmt.Errorf("failed to parse list response: %w", err)
	}

	return &listResp, nil
}

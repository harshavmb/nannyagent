package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"nannyagentv2/internal/auth"
	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/metrics"
	"nannyagentv2/internal/types"

	"github.com/sashabaranov/go-openai"
)

// InvestigationRequest represents a request from Supabase to start an investigation
type InvestigationRequest struct {
	InvestigationID  string            `json:"investigation_id"`
	ApplicationGroup string            `json:"application_group"`
	Issue            string            `json:"issue"`
	Context          map[string]string `json:"context"`
	Priority         string            `json:"priority"`
	InitiatedBy      string            `json:"initiated_by"`
}

// InvestigationResponse represents the agent's response to an investigation
type InvestigationResponse struct {
	AgentID         string                `json:"agent_id"`
	InvestigationID string                `json:"investigation_id"`
	Status          string                `json:"status"`
	Commands        []types.CommandResult `json:"commands,omitempty"`
	AIResponse      string                `json:"ai_response,omitempty"`
	EpisodeID       string                `json:"episode_id,omitempty"`
	Timestamp       time.Time             `json:"timestamp"`
	Error           string                `json:"error,omitempty"`
}

// InvestigationServer handles reverse investigation requests from Supabase
type InvestigationServer struct {
	agent            types.DiagnosticAgent // Original agent for direct user interactions
	applicationAgent types.DiagnosticAgent // Separate agent for application-initiated investigations
	port             string
	agentID          string
	metricsCollector *metrics.Collector
	authManager      *auth.AuthManager
	startTime        time.Time
	supabaseURL      string
}

// NewInvestigationServer creates a new investigation server
func NewInvestigationServer(agent types.DiagnosticAgent, authManager *auth.AuthManager) *InvestigationServer {
	port := os.Getenv("AGENT_PORT")
	if port == "" {
		port = "1234"
	}

	// Get agent ID from authentication system
	var agentID string
	if authManager != nil {
		if id, err := authManager.GetCurrentAgentID(); err == nil {
			agentID = id

		} else {
			logging.Error("Failed to get agent ID from auth manager: %v", err)
		}
	}

	// Fallback to environment variable or generate one if auth fails
	if agentID == "" {
		agentID = os.Getenv("AGENT_ID")
		if agentID == "" {
			agentID = fmt.Sprintf("agent-%d", time.Now().Unix())
		}
	}

	// Create metrics collector
	metricsCollector := metrics.NewCollector("v2.0.0")

	// TODO: Fix application agent creation - use main agent for now
	// Create a separate agent for application-initiated investigations
	// applicationAgent := NewLinuxDiagnosticAgent()
	// Override the model to use the application-specific function
	// applicationAgent.model = "tensorzero::function_name::diagnose_and_heal_application"

	return &InvestigationServer{
		agent:            agent,
		applicationAgent: agent, // Use same agent for now
		port:             port,
		agentID:          agentID,
		metricsCollector: metricsCollector,
		authManager:      authManager,
		startTime:        time.Now(),
		supabaseURL:      os.Getenv("SUPABASE_PROJECT_URL"),
	}
}

// DiagnoseIssueForApplication handles diagnostic requests initiated from application/portal
func (s *InvestigationServer) DiagnoseIssueForApplication(issue, episodeID string) error {
	// Set the episode ID on the application agent for continuity
	// TODO: Fix episode ID handling with interface
	// s.applicationAgent.episodeID = episodeID
	return s.applicationAgent.DiagnoseIssue(issue)
}

// Start starts the HTTP server and realtime polling for investigation requests
func (s *InvestigationServer) Start() error {
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Investigation endpoint
	mux.HandleFunc("/investigate", s.handleInvestigation)

	// Agent status endpoint
	mux.HandleFunc("/status", s.handleStatus)

	// Start realtime polling for backend-initiated investigations
	if s.supabaseURL != "" && s.authManager != nil {
		go s.startRealtimePolling()
		logging.Info("Realtime investigation polling enabled")
	} else {
		logging.Warning("Realtime investigation polling disabled (missing Supabase config or auth)")
	}

	server := &http.Server{
		Addr:         ":" + s.port,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	logging.Info("Investigation server started on port %s (Agent ID: %s)", s.port, s.agentID)
	return server.ListenAndServe()
}

// handleHealth responds to health check requests
func (s *InvestigationServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]interface{}{
		"status":    "healthy",
		"agent_id":  s.agentID,
		"timestamp": time.Now(),
		"version":   "v2.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleStatus responds with agent status and capabilities
func (s *InvestigationServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Collect current system metrics
	systemMetrics, err := s.metricsCollector.GatherSystemMetrics()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to collect metrics: %v", err), http.StatusInternalServerError)
		return
	}

	// Convert to metrics request format for consistent data structure
	metricsReq := s.metricsCollector.CreateMetricsRequest(s.agentID, systemMetrics)

	response := map[string]interface{}{
		"agent_id":     s.agentID,
		"status":       "ready",
		"capabilities": []string{"system_diagnostics", "ebpf_monitoring", "command_execution", "ai_analysis"},
		"system_info": map[string]interface{}{
			"os":           fmt.Sprintf("%s %s", metricsReq.OSInfo["platform"], metricsReq.OSInfo["platform_version"]),
			"kernel":       metricsReq.KernelVersion,
			"architecture": metricsReq.OSInfo["kernel_arch"],
			"cpu_cores":    metricsReq.OSInfo["cpu_cores"],
			"memory":       metricsReq.MemoryUsage,
			"private_ips":  metricsReq.IPAddress,
			"load_average": fmt.Sprintf("%.2f, %.2f, %.2f",
				metricsReq.LoadAverages["load1"],
				metricsReq.LoadAverages["load5"],
				metricsReq.LoadAverages["load15"]),
			"disk_usage": fmt.Sprintf("Root: %.0fG/%.0fG (%.0f%% used)",
				float64(metricsReq.FilesystemInfo[0].Used)/1024/1024/1024,
				float64(metricsReq.FilesystemInfo[0].Total)/1024/1024/1024,
				metricsReq.DiskUsage),
		},
		"uptime":       time.Since(s.startTime),
		"last_contact": time.Now(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// sendCommandResultsToTensorZero sends command results back to TensorZero and continues conversation
func (s *InvestigationServer) sendCommandResultsToTensorZero(diagnosticResp types.DiagnosticResponse, commandResults []types.CommandResult) (interface{}, error) {
	// Build conversation history like in agent.go
	messages := []openai.ChatCompletionMessage{
		// Add the original diagnostic response as assistant message
		{
			Role: openai.ChatMessageRoleAssistant,
			Content: fmt.Sprintf(`{"response_type":"diagnostic","reasoning":"%s","commands":%s}`,
				diagnosticResp.Reasoning,
				mustMarshalJSON(diagnosticResp.Commands)),
		},
	}

	// Add command results as user message (same as agent.go does)
	resultsJSON, err := json.MarshalIndent(commandResults, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal command results: %w", err)
	}

	messages = append(messages, openai.ChatCompletionMessage{
		Role:    openai.ChatMessageRoleUser,
		Content: string(resultsJSON),
	})

	// Send to TensorZero via application agent's sendRequest method
	logging.Debug("Sending command results to TensorZero for analysis")
	response, err := s.applicationAgent.SendRequest(messages)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to TensorZero: %w", err)
	}

	if len(response.Choices) == 0 {
		return nil, fmt.Errorf("no choices in TensorZero response")
	}

	content := response.Choices[0].Message.Content
	logging.Debug("TensorZero continued analysis: %s", content)

	// Try to parse the response to determine if it's diagnostic or resolution
	var diagnosticNextResp types.DiagnosticResponse
	var resolutionResp types.ResolutionResponse

	// Check if it's another diagnostic response
	if err := json.Unmarshal([]byte(content), &diagnosticNextResp); err == nil && diagnosticNextResp.ResponseType == "diagnostic" {
		logging.Debug("TensorZero requests %d more commands", len(diagnosticNextResp.Commands))
		return map[string]interface{}{
			"type":     "diagnostic",
			"response": diagnosticNextResp,
			"raw":      content,
		}, nil
	}

	// Check if it's a resolution response
	if err := json.Unmarshal([]byte(content), &resolutionResp); err == nil && resolutionResp.ResponseType == "resolution" {

		return map[string]interface{}{
			"type":     "resolution",
			"response": resolutionResp,
			"raw":      content,
		}, nil
	}

	// Return raw response if we can't parse it
	return map[string]interface{}{
		"type": "unknown",
		"raw":  content,
	}, nil
}

// Helper function to marshal JSON without errors
func mustMarshalJSON(v interface{}) string {
	data, _ := json.Marshal(v)
	return string(data)
}

// processInvestigation handles the actual investigation using TensorZero
// This endpoint receives either:
// 1. DiagnosticResponse - Commands and eBPF programs to execute
// 2. ResolutionResponse - Final resolution (no execution needed)
func (s *InvestigationServer) handleInvestigation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed - only POST accepted", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body to determine what type of response this is
	var requestBody map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Check the response_type field to determine how to handle this
	responseType, ok := requestBody["response_type"].(string)
	if !ok {
		http.Error(w, "Missing or invalid response_type field", http.StatusBadRequest)
		return
	}

	logging.Debug("Received investigation payload with response_type: %s", responseType)

	switch responseType {
	case "diagnostic":
		// This is a DiagnosticResponse with commands to execute
		response := s.handleDiagnosticExecution(requestBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case "resolution":
		// This is a ResolutionResponse - final result, just acknowledge
		fmt.Printf("📋 Received final resolution from backend\n")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":  true,
			"message":  "Resolution received and acknowledged",
			"agent_id": s.agentID,
		})

	default:
		http.Error(w, fmt.Sprintf("Unknown response_type: %s", responseType), http.StatusBadRequest)
		return
	}
}

// handleDiagnosticExecution executes commands from a DiagnosticResponse
func (s *InvestigationServer) handleDiagnosticExecution(requestBody map[string]interface{}) map[string]interface{} {
	// Parse as DiagnosticResponse
	var diagnosticResp types.DiagnosticResponse

	// Convert the map back to JSON and then parse it properly
	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return map[string]interface{}{
			"success":  false,
			"error":    fmt.Sprintf("Failed to re-marshal request: %v", err),
			"agent_id": s.agentID,
		}
	}

	if err := json.Unmarshal(jsonData, &diagnosticResp); err != nil {
		return map[string]interface{}{
			"success":  false,
			"error":    fmt.Sprintf("Failed to parse DiagnosticResponse: %v", err),
			"agent_id": s.agentID,
		}
	}

	fmt.Printf("📋 Executing %d commands from backend\n", len(diagnosticResp.Commands))

	// Execute all commands
	commandResults := make([]types.CommandResult, 0, len(diagnosticResp.Commands))

	for _, cmd := range diagnosticResp.Commands {
		fmt.Printf("⚙️  Executing command '%s': %s\n", cmd.ID, cmd.Command)

		// Use the agent's executor to run the command
		result := s.agent.ExecuteCommand(cmd)
		commandResults = append(commandResults, result)

		if result.Error != "" {
			fmt.Printf("Command '%s' had error: %s\n", cmd.ID, result.Error)
		}
	}

	// Send command results back to TensorZero for continued analysis
	fmt.Printf("🔄 Sending %d command results back to TensorZero for continued analysis\n", len(commandResults))

	nextResponse, err := s.sendCommandResultsToTensorZero(diagnosticResp, commandResults)
	if err != nil {
		return map[string]interface{}{
			"success":         false,
			"error":           fmt.Sprintf("Failed to continue TensorZero conversation: %v", err),
			"agent_id":        s.agentID,
			"command_results": commandResults, // Still return the results
		}
	}

	// Return both the command results and the next response from TensorZero
	return map[string]interface{}{
		"success":           true,
		"agent_id":          s.agentID,
		"command_results":   commandResults,
		"commands_executed": len(commandResults),
		"next_response":     nextResponse,
		"timestamp":         time.Now().Format(time.RFC3339),
	}
}

// PendingInvestigation represents a pending investigation from the database
type PendingInvestigation struct {
	ID                string                 `json:"id"`
	InvestigationID   string                 `json:"investigation_id"`
	AgentID           string                 `json:"agent_id"`
	DiagnosticPayload map[string]interface{} `json:"diagnostic_payload"`
	EpisodeID         *string                `json:"episode_id"`
	Status            string                 `json:"status"`
	CreatedAt         time.Time              `json:"created_at"`
}

// startRealtimePolling begins polling for pending investigations
func (s *InvestigationServer) startRealtimePolling() {
	fmt.Printf("🔄 Starting realtime investigation polling for agent %s\n", s.agentID)

	ticker := time.NewTicker(5 * time.Second) // Poll every 5 seconds
	defer ticker.Stop()

	for range ticker.C {
		s.checkForPendingInvestigations()
	}
}

// checkForPendingInvestigations checks for new pending investigations
func (s *InvestigationServer) checkForPendingInvestigations() {
	url := fmt.Sprintf("%s/rest/v1/pending_investigations?agent_id=eq.%s&status=eq.pending&order=created_at.desc",
		s.supabaseURL, s.agentID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return // Silent fail for polling
	}

	// Get token from auth manager
	authToken, err := s.authManager.LoadToken()
	if err != nil {
		return // Silent fail for polling
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken.AccessToken))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return // Silent fail for polling
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return // Silent fail for polling
	}

	var investigations []PendingInvestigation
	err = json.NewDecoder(resp.Body).Decode(&investigations)
	if err != nil {
		return // Silent fail for polling
	}

	for _, investigation := range investigations {
		fmt.Printf("🔍 Found pending investigation: %s\n", investigation.ID)
		go s.handlePendingInvestigation(investigation)
	}
}

// handlePendingInvestigation processes a single pending investigation
func (s *InvestigationServer) handlePendingInvestigation(investigation PendingInvestigation) {
	fmt.Printf("🚀 Processing realtime investigation %s\n", investigation.InvestigationID)

	// Mark as executing
	err := s.updateInvestigationStatus(investigation.ID, "executing", nil, nil)
	if err != nil {
		fmt.Printf("❌ Failed to mark investigation as executing: %v\n", err)
		return
	}

	// Execute diagnostic commands using existing handleDiagnosticExecution method
	results := s.handleDiagnosticExecution(investigation.DiagnosticPayload)

	// Mark as completed with results
	err = s.updateInvestigationStatus(investigation.ID, "completed", results, nil)
	if err != nil {
		fmt.Printf("❌ Failed to mark investigation as completed: %v\n", err)
		return
	}

}

// updateInvestigationStatus updates the status of a pending investigation
func (s *InvestigationServer) updateInvestigationStatus(id, status string, results map[string]interface{}, errorMsg *string) error {
	updateData := map[string]interface{}{
		"status": status,
	}

	if status == "executing" {
		updateData["started_at"] = time.Now().UTC().Format(time.RFC3339)
	} else if status == "completed" {
		updateData["completed_at"] = time.Now().UTC().Format(time.RFC3339)
		if results != nil {
			updateData["command_results"] = results
		}
	} else if status == "failed" && errorMsg != nil {
		updateData["error_message"] = *errorMsg
		updateData["completed_at"] = time.Now().UTC().Format(time.RFC3339)
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("failed to marshal update data: %v", err)
	}

	url := fmt.Sprintf("%s/rest/v1/pending_investigations?id=eq.%s", s.supabaseURL, id)
	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Get token from auth manager
	authToken, err := s.authManager.LoadToken()
	if err != nil {
		return fmt.Errorf("failed to load auth token: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update investigation: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("supabase update error: %d", resp.StatusCode)
	}

	return nil
}

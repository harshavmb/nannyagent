package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"nannyagentv2/internal/ebpf"
	"nannyagentv2/internal/executor"
	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/system"
	"nannyagentv2/internal/types"

	"github.com/sashabaranov/go-openai"
)

// AgentConfig holds configuration for concurrent execution (local to agent)
type AgentConfig struct {
	MaxConcurrentTasks int  `json:"max_concurrent_tasks"`
	CollectiveResults  bool `json:"collective_results"`
}

// DefaultAgentConfig returns default configuration
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		MaxConcurrentTasks: 10,   // Default to 10 concurrent forks
		CollectiveResults:  true, // Send results collectively when all finish
	}
}

//
// LinuxDiagnosticAgent represents the main diagnostic agent

// LinuxDiagnosticAgent represents the main diagnostic agent
type LinuxDiagnosticAgent struct {
	client          *openai.Client
	model           string
	executor        *executor.CommandExecutor
	episodeID       string                // TensorZero episode ID for conversation continuity
	investigationID string                // Investigation ID for portal-created investigations
	ebpfManager     *ebpf.BCCTraceManager // eBPF tracing manager
	config          *AgentConfig          // Configuration for concurrent execution
	authManager     interface{}           // Authentication manager for TensorZero requests
	logger          *logging.Logger
}

// NewLinuxDiagnosticAgent creates a new diagnostic agent
func NewLinuxDiagnosticAgent() *LinuxDiagnosticAgent {
	// Get PocketBase URL for TensorZero proxy
	pocketbaseURL := os.Getenv("POCKETBASE_URL")
	if pocketbaseURL == "" {
		pocketbaseURL = "http://localhost:8090"
	}

	// Default model for diagnostic and healing
	model := "tensorzero::function_name::diagnose_and_heal"

	agent := &LinuxDiagnosticAgent{
		client:   nil, // Not used - we use direct HTTP to PocketBase proxy
		model:    model,
		executor: executor.NewCommandExecutor(10 * time.Second), // 10 second timeout for commands
		config:   DefaultAgentConfig(),                          // Default concurrent execution config
	}

	// Initialize eBPF manager
	agent.ebpfManager = ebpf.NewBCCTraceManager()
	agent.logger = logging.NewLogger()

	return agent
}

// NewLinuxDiagnosticAgentWithAuth creates a new diagnostic agent with authentication
func NewLinuxDiagnosticAgentWithAuth(authManager interface{}) *LinuxDiagnosticAgent {
	// Get PocketBase URL for TensorZero proxy
	pocketbaseURL := os.Getenv("POCKETBASE_URL")
	if pocketbaseURL == "" {
		pocketbaseURL = "http://localhost:8090"
	}

	// Default model for diagnostic and healing
	model := "tensorzero::function_name::diagnose_and_heal"

	agent := &LinuxDiagnosticAgent{
		client:      nil, // Not used - we use direct HTTP to PocketBase proxy
		model:       model,
		executor:    executor.NewCommandExecutor(10 * time.Second), // 10 second timeout for commands
		config:      DefaultAgentConfig(),                          // Default concurrent execution config
		authManager: authManager,                                   // Store auth manager for TensorZero requests
	}

	// Initialize eBPF manager
	agent.ebpfManager = ebpf.NewBCCTraceManager()
	agent.logger = logging.NewLogger()

	return agent
}

// SetModel sets the model for the diagnostic agent
func (a *LinuxDiagnosticAgent) SetModel(model string) {
	a.model = model
}

// GetEpisodeID returns the current episode ID from TensorZero conversation
func (a *LinuxDiagnosticAgent) GetEpisodeID() string {
	return a.episodeID
}

// SetInvestigationID sets the investigation ID for portal-initiated investigations
func (a *LinuxDiagnosticAgent) SetInvestigationID(id string) {
	a.investigationID = id
}

// GetInvestigationID returns the current investigation ID
func (a *LinuxDiagnosticAgent) GetInvestigationID() string {
	return a.investigationID
}

// createInvestigation creates a new investigation record in the backend
func (a *LinuxDiagnosticAgent) createInvestigation(issue string) (string, error) {
	if a.authManager == nil {
		return "", fmt.Errorf("authentication required to create investigation")
	}

	// Get Agent ID and Token
	var agentID string
	var accessToken string

	if authMgr, ok := a.authManager.(interface {
		GetCurrentAgentID() (string, error)
		LoadToken() (*types.AuthToken, error)
	}); ok {
		var err error
		agentID, err = authMgr.GetCurrentAgentID()
		if err != nil {
			return "", fmt.Errorf("failed to get agent ID: %w", err)
		}

		token, err := authMgr.LoadToken()
		if err != nil {
			return "", fmt.Errorf("failed to load token: %w", err)
		}
		accessToken = token.AccessToken
	} else {
		return "", fmt.Errorf("auth manager does not support required interfaces")
	}

	// Create request payload
	reqPayload := map[string]string{
		"agent_id": agentID,
		"issue":    issue,
		"priority": "medium",
	}

	jsonData, err := json.Marshal(reqPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	// Get PocketBase URL
	pocketbaseURL := os.Getenv("POCKETBASE_URL")
	if pocketbaseURL == "" {
		pocketbaseURL = "http://localhost:8090"
	}

	endpoint := fmt.Sprintf("%s/api/investigations", pocketbaseURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send create investigation request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to create investigation (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response to get ID
	var respData struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &respData); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if respData.ID == "" {
		return "", fmt.Errorf("response did not contain investigation ID")
	}

	return respData.ID, nil
}

// DiagnoseIssue starts the diagnostic process for a given issue
// This is used for CLI or direct calls where investigation tracking is not needed
func (a *LinuxDiagnosticAgent) DiagnoseIssue(issue string) error {
	// For CLI mode, we first create an investigation record to get an ID
	// This allows the backend to track the investigation and proxy requests correctly
	logging.Info("Creating investigation record...")
	id, err := a.createInvestigation(issue)
	if err != nil {
		return fmt.Errorf("failed to create investigation record: %w", err)
	}

	a.investigationID = id
	logging.Info("Created investigation ID: %s", id)

	return a.diagnoseIssueInternal(issue, false)
}

// DiagnoseIssueWithInvestigation diagnoses an issue that was initiated by backend/portal
// The investigation_id is tracked externally (websocket handler updates status)
// This prevents creating duplicate investigations
func (a *LinuxDiagnosticAgent) DiagnoseIssueWithInvestigation(issue string) error {
	// IMPORTANT: Clear any previous episodeID to prevent reusing episodes from prior investigations
	a.episodeID = ""
	logging.Info("[DIAGNOSIS_TRACK] Cleared previous episodeID for new investigation")
	logging.Info("[DIAGNOSIS_TRACK] Investigation ID: %s", a.investigationID)
	return a.diagnoseIssueInternal(issue, true)
}

// diagnoseIssueInternal is the core diagnostic logic shared by both methods
// If isBackendInitiated=true, it will NOT reset episodeID at the end (caller will manage it)
// If isBackendInitiated=false, it will reset episodeID (CLI mode)
func (a *LinuxDiagnosticAgent) diagnoseIssueInternal(issue string, isBackendInitiated bool) error {
	logging.Info("Diagnosing issue: %s", issue)
	logging.Info("Gathering system information...")

	// Gather system information
	systemInfo := system.GatherSystemInfo()

	// Format the initial prompt with system information
	initialPrompt := system.FormatSystemInfoForPrompt(systemInfo) + "\n" + issue

	// Start conversation with initial issue including system info
	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleUser,
			Content: initialPrompt,
		},
	}

	for {
		// Send request to TensorZero API via OpenAI SDK
		response, err := a.SendRequestWithEpisode(messages, a.episodeID)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no choices in response")
		}

		content := response.Choices[0].Message.Content
		logging.Debug("AI Response: %s", content)

		// Strip markdown code blocks if present
		content = strings.TrimSpace(content)
		if strings.HasPrefix(content, "```json") {
			content = strings.TrimPrefix(content, "```json")
			content = strings.TrimSuffix(content, "```")
			content = strings.TrimSpace(content)
		} else if strings.HasPrefix(content, "```") {
			content = strings.TrimPrefix(content, "```")
			content = strings.TrimSuffix(content, "```")
			content = strings.TrimSpace(content)
		}

		// Parse the response to determine next action
		var diagnosticResp types.EBPFEnhancedDiagnosticResponse
		var resolutionResp types.ResolutionResponse

		// Try to parse as diagnostic response first (with eBPF support)
		logging.Debug("Attempting to parse response as diagnostic...")
		if err := json.Unmarshal([]byte(content), &diagnosticResp); err == nil && diagnosticResp.ResponseType == "diagnostic" {
			logging.Debug("Successfully parsed as diagnostic response with %d commands", len(diagnosticResp.Commands))
			// Handle diagnostic phase
			logging.Debug("Reasoning: %s", diagnosticResp.Reasoning)

			// Execute commands and collect results
			commandResults := make([]types.CommandResult, 0, len(diagnosticResp.Commands))
			if len(diagnosticResp.Commands) > 0 {
				logging.Info("Executing %d diagnostic commands", len(diagnosticResp.Commands))
				for i, cmdStr := range diagnosticResp.Commands {
					// Convert string command to Command struct (auto-generate ID and description)
					cmd := types.Command{
						ID:          fmt.Sprintf("cmd_%d", i+1),
						Command:     cmdStr,
						Description: fmt.Sprintf("Diagnostic command: %s", cmdStr),
					}
					result := a.executor.Execute(cmd)
					commandResults = append(commandResults, result)

					if result.ExitCode != 0 {
						logging.Warning("Command '%s' failed with exit code %d", cmd.ID, result.ExitCode)
					}
				}
			}

			// Execute eBPF programs if present - support both old and new formats
			var ebpfResults []map[string]interface{}
			if len(diagnosticResp.EBPFPrograms) > 0 {
				logging.Info("AI requested %d eBPF traces for enhanced diagnostics", len(diagnosticResp.EBPFPrograms))

				// Convert EBPFPrograms to TraceSpecs and execute concurrently using the eBPF service
				traceSpecs := a.ConvertEBPFProgramsToTraceSpecs(diagnosticResp.EBPFPrograms)
				ebpfResults = a.ExecuteEBPFTraces(traceSpecs)
			}

			// Prepare combined results as user message
			allResults := map[string]interface{}{
				"command_results":   commandResults,
				"executed_commands": len(commandResults),
			}

			// Include eBPF results if any were executed
			if len(ebpfResults) > 0 {
				allResults["ebpf_results"] = ebpfResults
				allResults["executed_ebpf_programs"] = len(ebpfResults)

				// Extract evidence summary for TensorZero
				evidenceSummary := make([]string, 0)
				for _, result := range ebpfResults {
					target := result["target"]
					eventCount := result["event_count"]
					summary := result["summary"]
					success := result["success"]

					status := "failed"
					if success == true {
						status = "success"
					}

					summaryStr := fmt.Sprintf("%s: %v events (%s) - %s", target, eventCount, status, summary)
					evidenceSummary = append(evidenceSummary, summaryStr)
				}
				allResults["ebpf_evidence_summary"] = evidenceSummary
			}

			resultsJSON, err := json.MarshalIndent(allResults, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal command results: %w", err)
			}

			// Add AI response and command results to conversation
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleAssistant,
				Content: content,
			})
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleUser,
				Content: string(resultsJSON),
			})

			continue
		} else {
			logging.Debug("Failed to parse as diagnostic. Error: %v, ResponseType: '%s'", err, diagnosticResp.ResponseType)
		}

		// Try to parse as resolution response
		if err := json.Unmarshal([]byte(content), &resolutionResp); err == nil && resolutionResp.ResponseType == "resolution" {
			// Handle resolution phase
			logging.Info("=== DIAGNOSIS COMPLETE ===")
			logging.Info("Root Cause: %s", resolutionResp.RootCause)
			logging.Info("Resolution Plan: %s", resolutionResp.ResolutionPlan)
			logging.Info("Confidence: %s", resolutionResp.Confidence)

			// Only reset episode ID for CLI-initiated investigations
			// Backend-initiated investigations keep the episodeID for the caller to use
			if !isBackendInitiated {
				a.episodeID = ""
				logging.Debug("Episode completed, reset episode_id for next conversation")
			} else {
				logging.Debug("Episode completed, keeping episode_id for backend investigation tracking")
			}

			break
		}

		// If we can't parse the response, treat it as an error or unexpected format
		logging.Error("Unexpected response format or error from AI: %s", content)
		break
	}

	return nil
}

// sendRequest sends a request to TensorZero via Supabase proxy (without episode ID)
func (a *LinuxDiagnosticAgent) SendRequest(messages []openai.ChatCompletionMessage) (*openai.ChatCompletionResponse, error) {
	return a.SendRequestWithEpisode(messages, "")
}

// ExecuteCommand executes a command using the agent's executor
func (a *LinuxDiagnosticAgent) ExecuteCommand(cmd types.Command) types.CommandResult {
	return a.executor.Execute(cmd)
}

// sendRequestWithEpisode sends a request to TensorZero via Supabase proxy with episode ID for conversation continuity
func (a *LinuxDiagnosticAgent) SendRequestWithEpisode(messages []openai.ChatCompletionMessage, episodeID string) (*openai.ChatCompletionResponse, error) {
	// Convert messages to the expected format
	messageMaps := make([]map[string]interface{}, len(messages))
	for i, msg := range messages {
		messageMaps[i] = map[string]interface{}{
			"role":    msg.Role,
			"content": msg.Content,
		}
	}

	// Create TensorZero request
	tzRequest := map[string]interface{}{
		"model":    a.model,
		"messages": messageMaps,
	}

	// Add episode ID if provided
	if episodeID != "" {
		tzRequest["tensorzero::episode_id"] = episodeID
	}

	// Add investigation ID to top-level for proxy routing
	// This tells the backend to proxy the request to TensorZero instead of creating a new investigation
	if a.investigationID != "" {
		tzRequest["investigation_id"] = a.investigationID
	}

	// Marshal request
	requestBody, err := json.Marshal(tzRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Get PocketBase URL
	pocketbaseURL := os.Getenv("POCKETBASE_URL")
	if pocketbaseURL == "" {
		pocketbaseURL = "http://localhost:8090"
	}

	// Create HTTP request to investigations endpoint
	// PocketBase routes requests to /api/investigations for TensorZero integration
	endpoint := fmt.Sprintf("%s/api/investigations", pocketbaseURL)
	logging.Debug("Calling investigations endpoint at: %s", endpoint)
	logging.Info("[TENSORZERO_API] POST %s with episodeID: %s", endpoint, episodeID)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Add authentication - REQUIRED for /api/investigations endpoint
	if a.authManager != nil {
		// The authManager should be *auth.AuthManager, so let's use the exact same pattern
		if authMgr, ok := a.authManager.(interface {
			LoadToken() (*types.AuthToken, error)
		}); ok {
			if authToken, err := authMgr.LoadToken(); err == nil && authToken != nil && authToken.AccessToken != "" {
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken.AccessToken))
				logging.Debug("[TENSORZERO_API] Authorization header set with token")
			} else {
				logging.Warning("[TENSORZERO_API] Failed to load auth token for authorization header")
			}
		} else {
			logging.Warning("[TENSORZERO_API] Auth manager does not support LoadToken interface")
		}
	} else {
		logging.Warning("[TENSORZERO_API] No auth manager available for authorization header")
	}

	// Send request with retry logic (up to 5 attempts with longer timeout)
	client := &http.Client{Timeout: 60 * time.Second}
	var resp *http.Response
	var lastErr error

	for attempt := 1; attempt <= 5; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}

		lastErr = err
		logging.Warning("Request attempt %d/5 failed: %v", attempt, err)

		if attempt < 5 {
			// Exponential backoff: 2s, 4s, 8s, 16s
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			logging.Info("Retrying in %v...", backoff)
			time.Sleep(backoff)
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to send request after 5 attempts: %w", lastErr)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check status code
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)

		// Handle 401 Unauthorized - try to refresh token
		if resp.StatusCode == 401 && a.authManager != nil {
			if authMgr, ok := a.authManager.(interface {
				LoadToken() (*types.AuthToken, error)
				RefreshAccessToken(string) (*types.TokenResponse, error)
				SaveToken(*types.AuthToken) error
			}); ok {
				// Load current token to get refresh token
				if currentToken, err := authMgr.LoadToken(); err == nil && currentToken != nil && currentToken.RefreshToken != "" {
					// Refresh the access token
					if tokenResp, err := authMgr.RefreshAccessToken(currentToken.RefreshToken); err == nil {
						// Save the new token
						newToken := &types.AuthToken{
							AccessToken:  tokenResp.AccessToken,
							RefreshToken: tokenResp.RefreshToken,
							TokenType:    tokenResp.TokenType,
							ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
							AgentID:      currentToken.AgentID, // Keep existing agent ID
						}
						if err := authMgr.SaveToken(newToken); err == nil {
							// Update the Authorization header with new token
							req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", newToken.AccessToken))

							// Retry the request with new token
							resp, err = client.Do(req)
							if err != nil {
								return nil, fmt.Errorf("failed to send request after token refresh: %w", err)
							}
							defer func() { _ = resp.Body.Close() }() // If still not 200, fall through to error below
							if resp.StatusCode == 200 {
								// Success! Continue with normal response processing
								goto parseResponse
							}

							body, _ = io.ReadAll(resp.Body)
						}
					}
				}
			}
		}

		return nil, fmt.Errorf("TensorZero proxy error: %d, body: %s", resp.StatusCode, string(body))
	}

parseResponse:

	// Parse response
	var tzResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&tzResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Convert to OpenAI format for compatibility
	choices, ok := tzResponse["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	// Extract the first choice
	firstChoice, ok := choices[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid choice format")
	}

	message, ok := firstChoice["message"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid message format")
	}

	content, ok := message["content"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid content format")
	}

	// Create OpenAI-compatible response
	response := &openai.ChatCompletionResponse{
		Choices: []openai.ChatCompletionChoice{
			{
				Message: openai.ChatCompletionMessage{
					Role:    openai.ChatMessageRoleAssistant,
					Content: content,
				},
			},
		},
	}

	// Update episode ID if provided in response
	if respEpisodeID, ok := tzResponse["episode_id"].(string); ok && respEpisodeID != "" {
		logging.Info("[TENSORZERO_API] Received episode_id from TensorZero: %s", respEpisodeID)
		a.episodeID = respEpisodeID
	}

	return response, nil
}

// ConvertEBPFProgramsToTraceSpecs converts old EBPFProgram format to new TraceSpec format
func (a *LinuxDiagnosticAgent) ConvertEBPFProgramsToTraceSpecs(ebpfPrograms []types.EBPFRequest) []ebpf.TraceSpec {
	var traceSpecs []ebpf.TraceSpec

	for _, prog := range ebpfPrograms {
		spec := a.convertToTraceSpec(prog)
		traceSpecs = append(traceSpecs, spec)
	}

	return traceSpecs
}

// convertToTraceSpec converts an EBPFRequest to a TraceSpec for BCC-style tracing
func (a *LinuxDiagnosticAgent) convertToTraceSpec(prog types.EBPFRequest) ebpf.TraceSpec {
	// Set default duration if not specified
	duration := prog.Duration
	if duration <= 0 {
		duration = 10 // default 10 seconds
	}

	// Detect if target contains a full bpftrace script (has curly braces)
	// This handles both type="bpftrace" and cases where AI uses old type but includes script
	if prog.Type == "bpftrace" || strings.Contains(prog.Target, "{") {
		// For bpftrace type, the target contains the full script
		// We'll use a special marker to indicate this is a raw script
		return ebpf.TraceSpec{
			ProbeType: "bpftrace", // Special type for raw bpftrace scripts
			Target:    prog.Target,
			Format:    prog.Description,
			Arguments: []string{},
			Duration:  duration,
			UID:       -1,
		}
	}

	// Determine probe type based on target and type (legacy format)
	probeType := "p" // default to kprobe
	target := prog.Target

	if strings.HasPrefix(target, "tracepoint:") {
		probeType = "t"
		target = strings.TrimPrefix(target, "tracepoint:")
	} else if strings.HasPrefix(target, "kprobe:") {
		probeType = "p"
		target = strings.TrimPrefix(target, "kprobe:")
	} else if prog.Type == "tracepoint" {
		probeType = "t"
	} else if prog.Type == "kprobe" {
		probeType = "p"
	} else if prog.Type == "kretprobe" {
		probeType = "r"
	} else if prog.Type == "syscall" {
		// Convert syscall names to kprobe targets
		if !strings.HasPrefix(target, "__x64_sys_") && !strings.Contains(target, ":") {
			if strings.HasPrefix(target, "sys_") {
				target = "__x64_" + target
			} else {
				target = "__x64_sys_" + target
			}
		}
		probeType = "p"
	}

	return ebpf.TraceSpec{
		ProbeType: probeType,
		Target:    target,
		Format:    prog.Description, // Use description as format
		Arguments: []string{},       // Start with no arguments for compatibility
		Duration:  duration,
		UID:       -1, // No UID filter (don't default to 0 which means root only)
	}
}

// executeEBPFTraces executes multiple eBPF traces using the eBPF service
func (a *LinuxDiagnosticAgent) ExecuteEBPFTraces(traceSpecs []ebpf.TraceSpec) []map[string]interface{} {
	if len(traceSpecs) == 0 {
		return []map[string]interface{}{}
	}

	a.logger.Info("Executing %d eBPF traces in parallel", len(traceSpecs))

	// Track trace IDs and their specs
	type traceInfo struct {
		index   int
		spec    ebpf.TraceSpec
		traceID string
		err     error
	}
	traces := make([]traceInfo, 0, len(traceSpecs))

	// Start all traces in parallel
	maxDuration := 0
	for i, spec := range traceSpecs {
		a.logger.Debug("Starting trace %d: %s", i, spec.Target)

		traceID, err := a.ebpfManager.StartTrace(spec)
		traces = append(traces, traceInfo{
			index:   i,
			spec:    spec,
			traceID: traceID,
			err:     err,
		})

		if err != nil {
			a.logger.Error("Failed to start trace %d: %v", i, err)
		} else {
			// Track the maximum duration
			if spec.Duration > maxDuration {
				maxDuration = spec.Duration
			}
		}
	}

	// Wait for the longest trace duration + buffer for output capture
	if maxDuration > 0 {
		a.logger.Info("Waiting %d seconds for all traces to complete", maxDuration)
		time.Sleep(time.Duration(maxDuration)*time.Second + 500*time.Millisecond)
	}

	// Collect results from all traces
	results := make([]map[string]interface{}, 0, len(traces))
	for _, trace := range traces {
		if trace.err != nil {
			result := map[string]interface{}{
				"index":   trace.index,
				"target":  trace.spec.Target,
				"success": false,
				"error":   trace.err.Error(),
			}
			results = append(results, result)
			continue
		}

		// Get the trace result
		traceResult, err := a.ebpfManager.GetTraceResult(trace.traceID)
		if err != nil {
			a.logger.Error("Failed to get results for trace %d: %v", trace.index, err)
			result := map[string]interface{}{
				"index":   trace.index,
				"target":  trace.spec.Target,
				"success": false,
				"error":   err.Error(),
			}
			results = append(results, result)
			continue
		}

		// Build successful result
		result := map[string]interface{}{
			"index":             trace.index,
			"target":            trace.spec.Target,
			"success":           true,
			"event_count":       traceResult.EventCount,
			"events_per_second": traceResult.Statistics.EventsPerSecond,
			"duration":          traceResult.EndTime.Sub(traceResult.StartTime).Seconds(),
			"summary":           traceResult.Summary,
		}

		// Include raw output for bpftrace scripts (aggregation results)
		if traceResult.EventCount > 0 {
			// Concatenate all event messages (which contain the raw bpftrace output)
			var rawOutput strings.Builder
			for _, event := range traceResult.Events {
				if event.Message != "" {
					rawOutput.WriteString(event.Message)
					rawOutput.WriteString("\n")
				}
			}
			if rawOutput.Len() > 0 {
				result["output"] = strings.TrimSpace(rawOutput.String())
			}
		}

		results = append(results, result)

		a.logger.Debug("Completed trace %d: %d events", trace.index, traceResult.EventCount)
	}

	a.logger.Info("Completed %d eBPF traces", len(results))
	return results
}

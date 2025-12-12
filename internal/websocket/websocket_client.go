package websocket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"nannyagentv2/internal/auth"
	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/metrics"
	"nannyagentv2/internal/types"

	"github.com/gorilla/websocket"
	"github.com/sashabaranov/go-openai"
)

// Helper function for minimum of two integers

// WebSocketMessage represents a message sent over WebSocket
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// InvestigationTask represents a task sent to the agent
type InvestigationTask struct {
	TaskID            string                 `json:"task_id"`
	InvestigationID   string                 `json:"investigation_id"`
	AgentID           string                 `json:"agent_id"`
	DiagnosticPayload map[string]interface{} `json:"diagnostic_payload"`
	EpisodeID         string                 `json:"episode_id,omitempty"`
}

// TaskResult represents the result of a completed task
type TaskResult struct {
	TaskID         string                 `json:"task_id"`
	Success        bool                   `json:"success"`
	CommandResults map[string]interface{} `json:"command_results,omitempty"`
	Error          string                 `json:"error,omitempty"`
}

// HeartbeatData represents heartbeat information
type HeartbeatData struct {
	AgentID   string    `json:"agent_id"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

// WebSocketClient handles WebSocket connection to Supabase backend
type WebSocketClient struct {
	agent               types.DiagnosticAgent // DiagnosticAgent interface
	conn                *websocket.Conn
	agentID             string
	authManager         *auth.AuthManager
	metricsCollector    *metrics.Collector
	supabaseURL         string
	token               string
	ctx                 context.Context
	cancel              context.CancelFunc
	consecutiveFailures int           // Track consecutive connection failures
	rebootMutex         sync.Mutex    // Mutex to prevent concurrent reboot attempts
	rebootInProgress    bool          // Flag to prevent concurrent reboot attempts
	patchSemaphore      chan struct{} // Semaphore to limit concurrent patch executions
}

// NewWebSocketClient creates a new WebSocket client
func NewWebSocketClient(agent types.DiagnosticAgent, authManager *auth.AuthManager) *WebSocketClient {
	// Get agent ID from authentication system
	var agentID string
	if authManager != nil {
		if id, err := authManager.GetCurrentAgentID(); err == nil {
			agentID = id
			// Agent ID retrieved successfully
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

	supabaseURL := os.Getenv("SUPABASE_PROJECT_URL")
	if supabaseURL == "" {
		logging.Error("SUPABASE_PROJECT_URL environment variable is required")
	}

	// Create metrics collector
	metricsCollector := metrics.NewCollector("v2.0.0")

	ctx, cancel := context.WithCancel(context.Background())

	return &WebSocketClient{
		agent:            agent,
		agentID:          agentID,
		authManager:      authManager,
		metricsCollector: metricsCollector,
		supabaseURL:      supabaseURL,
		ctx:              ctx,
		cancel:           cancel,
		patchSemaphore:   make(chan struct{}, 3), // Allow max 3 concurrent patch executions
	}
}

// Start starts the WebSocket connection and message handling
func (w *WebSocketClient) Start() error {
	// Starting WebSocket client

	if err := w.connect(); err != nil {
		return fmt.Errorf("failed to establish WebSocket connection: %v", err)
	}

	// Start message reading loop
	go w.handleMessages()

	// Start heartbeat
	go w.startHeartbeat()

	// Start database polling for pending investigations
	go w.pollPendingInvestigations()

	// Start database polling for patch executions
	go w.pollPatchExecutions()

	// WebSocket client started
	return nil
}

// Stop closes the WebSocket connection
func (c *WebSocketClient) Stop() {
	// Update database that we're disconnecting
	c.updateConnectionStatus(false)

	c.cancel()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// getAuthToken retrieves authentication token
func (c *WebSocketClient) getAuthToken() error {
	if c.authManager == nil {
		return fmt.Errorf("auth manager not available")
	}

	token, err := c.authManager.EnsureAuthenticated()
	if err != nil {
		return fmt.Errorf("authentication failed: %v", err)
	}

	c.token = token.AccessToken
	return nil
}

// connect establishes WebSocket connection
func (c *WebSocketClient) connect() error {
	// Get fresh auth token
	if err := c.getAuthToken(); err != nil {
		return fmt.Errorf("failed to get auth token: %v", err)
	}

	// Convert HTTP URL to WebSocket URL
	wsURL := strings.Replace(c.supabaseURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += "/functions/v1/websocket-agent-handler"

	// Connecting to WebSocket

	// Set up headers
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+c.token)

	// Connect
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, resp, err := dialer.Dial(wsURL, headers)
	if err != nil {
		c.consecutiveFailures++
		if c.consecutiveFailures >= 5 && resp != nil {
			logging.Error("WebSocket handshake failed with status: %d (failure #%d)", resp.StatusCode, c.consecutiveFailures)
		}
		return fmt.Errorf("websocket connection failed: %v", err)
	}

	c.conn = conn
	// WebSocket client connected

	// Update database that we're connected
	go c.updateConnectionStatus(true)

	return nil
}

// handleMessages processes incoming WebSocket messages
func (c *WebSocketClient) handleMessages() {
	defer func() {
		// Update database that we're disconnected
		c.updateConnectionStatus(false)

		if c.conn != nil {
			// Closing WebSocket connection
			_ = c.conn.Close()
		}
	}()

	// Started WebSocket message listener
	connectionStart := time.Now()

	for {
		select {
		case <-c.ctx.Done():
			// Only log context cancellation if there have been failures
			if c.consecutiveFailures >= 5 {
				logging.Debug("Context cancelled after %v, stopping message handler", time.Since(connectionStart))
			}
			return
		default:
			// Set read deadline to detect connection issues
			_ = c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))

			var message WebSocketMessage
			readStart := time.Now()
			err := c.conn.ReadJSON(&message)
			readDuration := time.Since(readStart)

			if err != nil {
				connectionDuration := time.Since(connectionStart)

				// Only log specific errors after failure threshold
				if c.consecutiveFailures >= 5 {
					if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
						logging.Debug("WebSocket closed normally after %v: %v", connectionDuration, err)
					} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
						logging.Error("ABNORMAL CLOSE after %v (code 1006 = server-side timeout/kill): %v", connectionDuration, err)
						logging.Debug("Last read took %v, connection lived %v", readDuration, connectionDuration)
					} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						logging.Warning("READ TIMEOUT after %v: %v", connectionDuration, err)
					} else {
						logging.Error("WebSocket error after %v: %v", connectionDuration, err)
					}
				}

				// Track consecutive failures for diagnostic threshold
				c.consecutiveFailures++

				// Only show diagnostics after multiple failures
				if c.consecutiveFailures >= 5 {
					logging.Debug("DIAGNOSTIC - Connection failed #%d after %v", c.consecutiveFailures, connectionDuration)
				}

				// Attempt reconnection instead of returning immediately
				go c.attemptReconnection()
				return
			}

			// Received WebSocket message successfully - reset failure counter
			c.consecutiveFailures = 0

			switch message.Type {
			case "connection_ack":
				// Connection acknowledged

			case "heartbeat_ack":
				// Heartbeat acknowledged

			case "investigation_task":
				// Received investigation task - processing
				go c.handleInvestigationTask(message.Data)

			case "task_result_ack":
				// Task result acknowledged

			default:
				logging.Warning("Unknown message type: %s", message.Type)
			}
		}
	}
}

// handleInvestigationTask processes investigation tasks from the backend
func (c *WebSocketClient) handleInvestigationTask(data interface{}) {
	// Parse task data
	taskBytes, err := json.Marshal(data)
	if err != nil {
		logging.Error("Error marshaling task data: %v", err)
		return
	}

	var task InvestigationTask
	err = json.Unmarshal(taskBytes, &task)
	if err != nil {
		logging.Error("Error unmarshaling investigation task: %v", err)
		return
	}

	// Execute diagnostic commands
	results, err := c.executeDiagnosticCommands(task.DiagnosticPayload)

	// Prepare task result
	taskResult := TaskResult{
		TaskID:  task.TaskID,
		Success: err == nil,
	}

	if err != nil {
		taskResult.Error = err.Error()
		logging.Error("Task execution failed: %v", err)
	} else {
		taskResult.CommandResults = results
	}

	// Send result back
	c.sendTaskResult(taskResult)
}

// executeDiagnosticCommands executes the commands from a diagnostic response
func (c *WebSocketClient) executeDiagnosticCommands(diagnosticPayload map[string]interface{}) (map[string]interface{}, error) {
	results := map[string]interface{}{
		"agent_id":        c.agentID,
		"execution_time":  time.Now().UTC().Format(time.RFC3339),
		"command_results": []map[string]interface{}{},
	}

	// Extract commands from diagnostic payload
	commands, ok := diagnosticPayload["commands"].([]interface{})
	if !ok {
		// Don't return error, just proceed with empty commands
		commands = []interface{}{}
	}

	var commandResults []map[string]interface{}

	for i, cmd := range commands {
		var id, command, description string

		// Handle both string commands and object commands
		if cmdStr, ok := cmd.(string); ok {
			// Simple string command format: ["ps aux", "netstat -tulpn"]
			id = fmt.Sprintf("cmd_%d", i+1)
			command = cmdStr
			description = fmt.Sprintf("Command: %s", cmdStr)
		} else if cmdMap, ok := cmd.(map[string]interface{}); ok {
			// Object format: [{"id": "...", "command": "...", "description": "..."}]
			id, _ = cmdMap["id"].(string)
			command, _ = cmdMap["command"].(string)
			description, _ = cmdMap["description"].(string)

			// If id is missing, generate one
			if id == "" {
				id = fmt.Sprintf("cmd_%d", i+1)
				logging.Debug("Command id missing, using default: %s", id)
			}
			// If description is missing, generate one
			if description == "" {
				description = fmt.Sprintf("Command: %s", command)
				logging.Debug("Command description missing, using default: %s", description)
			}
		} else {
			// Unknown format, skip
			continue
		}

		if command == "" {
			continue
		}

		// Execute the command
		output, exitCode, err := c.executeCommand(command)

		result := map[string]interface{}{
			"id":          id,
			"command":     command,
			"description": description,
			"output":      output,
			"exit_code":   exitCode,
			"success":     err == nil && exitCode == 0,
		}

		if err != nil {
			result["error"] = err.Error()
		}

		commandResults = append(commandResults, result)
	}

	results["command_results"] = commandResults
	results["total_commands"] = len(commandResults)
	results["successful_commands"] = c.countSuccessfulCommands(commandResults)

	// Execute eBPF programs if present
	ebpfPrograms, hasEBPF := diagnosticPayload["ebpf_programs"].([]interface{})
	if hasEBPF && len(ebpfPrograms) > 0 {
		ebpfResults := c.executeEBPFPrograms(ebpfPrograms)
		results["ebpf_results"] = ebpfResults
		results["total_ebpf_programs"] = len(ebpfPrograms)
	}

	return results, nil
}

// executeEBPFPrograms executes eBPF monitoring programs using the real eBPF manager
func (c *WebSocketClient) executeEBPFPrograms(ebpfPrograms []interface{}) []map[string]interface{} {
	var ebpfRequests []types.EBPFRequest

	// Convert interface{} to EBPFRequest structs
	for _, prog := range ebpfPrograms {
		progMap, ok := prog.(map[string]interface{})
		if !ok {
			continue
		}

		name, _ := progMap["name"].(string)
		progType, _ := progMap["type"].(string)
		target, _ := progMap["target"].(string)
		duration, _ := progMap["duration"].(float64)
		description, _ := progMap["description"].(string)

		if name == "" || progType == "" || target == "" {
			continue
		}

		ebpfRequests = append(ebpfRequests, types.EBPFRequest{
			Name:        name,
			Type:        progType,
			Target:      target,
			Duration:    int(duration),
			Description: description,
		})
	}

	// Execute eBPF programs using the agent's new BCC concurrent execution logic
	traceSpecs := c.agent.ConvertEBPFProgramsToTraceSpecs(ebpfRequests)
	return c.agent.ExecuteEBPFTraces(traceSpecs)
}

// executeCommandsFromPayload executes commands from a payload and returns results
func (c *WebSocketClient) executeCommandsFromPayload(commands []interface{}) []map[string]interface{} {
	var commandResults []map[string]interface{}

	for _, cmd := range commands {
		cmdMap, ok := cmd.(map[string]interface{})
		if !ok {
			continue
		}

		id, _ := cmdMap["id"].(string)
		command, _ := cmdMap["command"].(string)
		description, _ := cmdMap["description"].(string)

		if command == "" {
			continue
		}

		// Execute the command
		output, exitCode, err := c.executeCommand(command)

		result := map[string]interface{}{
			"id":          id,
			"command":     command,
			"description": description,
			"output":      output,
			"exit_code":   exitCode,
			"success":     err == nil && exitCode == 0,
		}

		if err != nil {
			result["error"] = err.Error()
			logging.Warning("Command [%s] failed: %v (exit code: %d)", id, err, exitCode)
		}

		commandResults = append(commandResults, result)
	}

	return commandResults
}

// executeCommand executes a shell command and returns output, exit code, and error
func (c *WebSocketClient) executeCommand(command string) (string, int, error) {
	if command == "" {
		return "", -1, fmt.Errorf("empty command")
	}

	// Create command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Execute command using /bin/bash -c to ensure proper handling of shell features such as pipes (|), redirects (>, <), and glob patterns (*, ?).
	// Direct execution (without a shell) does not support these features, which can cause commands containing them to fail or behave incorrectly.
	// This approach matches the behavior of the agent's executor and fixes issues seen with previous implementations that did not use a shell.
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c", command)
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	exitCode := 0

	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	logging.Debug("Command [%s] executed with exit code %d", command, exitCode)
	return string(output), exitCode, err
}

// countSuccessfulCommands counts the number of successful commands
func (c *WebSocketClient) countSuccessfulCommands(results []map[string]interface{}) int {
	count := 0
	for _, result := range results {
		if success, ok := result["success"].(bool); ok && success {
			count++
		}
	}
	return count
}

// sendTaskResult sends a task result back to the backend
func (c *WebSocketClient) sendTaskResult(result TaskResult) {
	message := WebSocketMessage{
		Type: "task_result",
		Data: result,
	}

	err := c.conn.WriteJSON(message)
	if err != nil {
		logging.Error("Error sending task result: %v", err)
	}
}

// startHeartbeat sends periodic heartbeat messages
func (c *WebSocketClient) startHeartbeat() {
	ticker := time.NewTicker(30 * time.Second) // Heartbeat every 30 seconds
	defer ticker.Stop()

	// Starting heartbeat

	for {
		select {
		case <-c.ctx.Done():
			logging.Debug("Heartbeat stopped due to context cancellation")
			return
		case <-ticker.C:
			// Sending heartbeat
			heartbeat := WebSocketMessage{
				Type: "heartbeat",
				Data: HeartbeatData{
					AgentID:   c.agentID,
					Timestamp: time.Now(),
					Version:   "v2.0.0",
				},
			}

			err := c.conn.WriteJSON(heartbeat)
			if err != nil {
				logging.Error("Error sending heartbeat: %v", err)
				logging.Debug("Heartbeat failed, connection likely dead")
				return
			}
			// Heartbeat sent
		}
	}
}

// pollPendingInvestigations polls the database for pending investigations
func (c *WebSocketClient) pollPendingInvestigations() {
	// Starting database polling
	ticker := time.NewTicker(5 * time.Second) // Poll every 5 seconds
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.checkForPendingInvestigations()
		}
	}
}

// checkForPendingInvestigations checks the database for new pending investigations via proxy
func (c *WebSocketClient) checkForPendingInvestigations() {
	// Use Edge Function proxy instead of direct database access
	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/pending-investigations", c.supabaseURL)

	// Poll database for pending investigations

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		// Request creation failed
		return
	}

	// Only JWT token needed for proxy - no API keys exposed
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Database request failed
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		return
	}

	var investigations []types.PendingInvestigation
	err = json.NewDecoder(resp.Body).Decode(&investigations)
	if err != nil {
		// Response decode failed
		return
	}

	for _, investigation := range investigations {
		go c.handlePendingInvestigation(investigation)
	}
}

// handlePendingInvestigation processes a pending investigation from database polling
func (c *WebSocketClient) handlePendingInvestigation(investigation types.PendingInvestigation) {
	// Processing pending investigation

	// Mark as executing
	err := c.updateInvestigationStatus(investigation.ID, "executing", nil, nil)
	if err != nil {
		return
	}

	// Execute diagnostic commands
	results, err := c.executeDiagnosticCommands(investigation.DiagnosticPayload)

	// Prepare the base results map we'll send to DB
	resultsForDB := map[string]interface{}{
		"agent_id":        c.agentID,
		"execution_time":  time.Now().UTC().Format(time.RFC3339),
		"command_results": results,
	}

	// If command execution failed, mark investigation as failed
	if err != nil {
		errorMsg := err.Error()
		// Include partial results when possible
		if results != nil {
			resultsForDB["command_results"] = results
		}
		_ = c.updateInvestigationStatus(investigation.ID, "failed", resultsForDB, &errorMsg)
		// Investigation failed
		return
	}

	// Try to continue the TensorZero conversation by sending command results back
	// Build messages: assistant = diagnostic payload, user = command results
	diagJSON, _ := json.Marshal(investigation.DiagnosticPayload)
	commandsJSON, _ := json.MarshalIndent(results, "", "  ")

	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleAssistant,
			Content: string(diagJSON),
		},
		{
			Role:    openai.ChatMessageRoleUser,
			Content: string(commandsJSON),
		},
	}

	// Use the episode ID from the investigation to maintain conversation continuity
	episodeID := ""
	if investigation.EpisodeID != nil {
		episodeID = *investigation.EpisodeID
	}

	// Continue conversation until resolution (same as agent)
	var finalAIContent string
	for {
		tzResp, tzErr := c.agent.SendRequestWithEpisode(messages, episodeID)
		if tzErr != nil {
			logging.Warning("TensorZero continuation failed: %v", tzErr)
			// Fall back to marking completed with command results only
			_ = c.updateInvestigationStatus(investigation.ID, "completed", resultsForDB, nil)
			return
		}

		if len(tzResp.Choices) == 0 {
			logging.Warning("No choices in TensorZero response")
			_ = c.updateInvestigationStatus(investigation.ID, "completed", resultsForDB, nil)
			return
		}

		aiContent := tzResp.Choices[0].Message.Content
		if len(aiContent) > 300 {
			// AI response received successfully
		} else {
			logging.Debug("AI Response: %s", aiContent)
		}

		// Check if this is a resolution response (final)
		var resolutionResp struct {
			ResponseType   string `json:"response_type"`
			RootCause      string `json:"root_cause"`
			ResolutionPlan string `json:"resolution_plan"`
			Confidence     string `json:"confidence"`
		}

		logging.Debug("Analyzing AI response type...")

		if err := json.Unmarshal([]byte(aiContent), &resolutionResp); err == nil && resolutionResp.ResponseType == "resolution" {
			// This is the final resolution - show summary and complete
			logging.Info("=== DIAGNOSIS COMPLETE ===")
			logging.Info("Root Cause: %s", resolutionResp.RootCause)
			logging.Info("Resolution Plan: %s", resolutionResp.ResolutionPlan)
			logging.Info("Confidence: %s", resolutionResp.Confidence)
			finalAIContent = aiContent
			break
		}

		// Check if this is another diagnostic response requiring more commands
		var diagnosticResp struct {
			ResponseType string        `json:"response_type"`
			Commands     []interface{} `json:"commands"`
			EBPFPrograms []interface{} `json:"ebpf_programs"`
		}

		if err := json.Unmarshal([]byte(aiContent), &diagnosticResp); err == nil && diagnosticResp.ResponseType == "diagnostic" {
			logging.Debug("AI requested additional diagnostics, executing...")

			// Execute additional commands if any
			additionalResults := map[string]interface{}{
				"command_results": []map[string]interface{}{},
			}

			if len(diagnosticResp.Commands) > 0 {
				logging.Debug("Executing %d additional diagnostic commands", len(diagnosticResp.Commands))
				commandResults := c.executeCommandsFromPayload(diagnosticResp.Commands)
				additionalResults["command_results"] = commandResults
			}

			// Execute additional eBPF programs if any
			if len(diagnosticResp.EBPFPrograms) > 0 {
				ebpfResults := c.executeEBPFPrograms(diagnosticResp.EBPFPrograms)
				additionalResults["ebpf_results"] = ebpfResults
			}

			// Add AI response and additional results to conversation
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleAssistant,
				Content: aiContent,
			})

			additionalResultsJSON, _ := json.MarshalIndent(additionalResults, "", "  ")
			messages = append(messages, openai.ChatCompletionMessage{
				Role:    openai.ChatMessageRoleUser,
				Content: string(additionalResultsJSON),
			})

			continue
		}

		// If neither resolution nor diagnostic, treat as final response
		logging.Warning("Unknown response type - treating as final response")
		finalAIContent = aiContent
		break
	}

	// Attach final AI response to results for DB and mark as completed_with_analysis
	resultsForDB["ai_response"] = finalAIContent
	_ = c.updateInvestigationStatus(investigation.ID, "completed_with_analysis", resultsForDB, nil)
}

// updateInvestigationStatus updates the status of a pending investigation
func (c *WebSocketClient) updateInvestigationStatus(id, status string, results map[string]interface{}, errorMsg *string) error {
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

	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/pending-investigations/%s", c.supabaseURL, id)
	req, err := http.NewRequest("PATCH", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// Only JWT token needed for proxy - no API keys exposed
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update investigation: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("supabase update error: %d", resp.StatusCode)
	}

	return nil
}

// attemptReconnection attempts to reconnect the WebSocket with backoff
func (c *WebSocketClient) attemptReconnection() {
	backoffDurations := []time.Duration{
		2 * time.Second,
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		30 * time.Second,
	}

	for i, backoff := range backoffDurations {
		select {
		case <-c.ctx.Done():
			return
		default:
			c.consecutiveFailures++

			// Only show messages after 5 consecutive failures
			if c.consecutiveFailures >= 5 {
				logging.Info("Attempting WebSocket reconnection (attempt %d/%d) - %d consecutive failures", i+1, len(backoffDurations), c.consecutiveFailures)
			}

			time.Sleep(backoff)

			if err := c.connect(); err != nil {
				if c.consecutiveFailures >= 5 {
					logging.Warning("Reconnection attempt %d failed: %v", i+1, err)
				}
				continue
			}

			// Successfully reconnected - reset failure counter
			if c.consecutiveFailures >= 5 {
				logging.Info("WebSocket reconnected successfully after %d failures", c.consecutiveFailures)
			}
			c.consecutiveFailures = 0
			go c.handleMessages() // Restart message handling
			return
		}
	}

	logging.Error("Failed to reconnect after %d attempts, giving up", len(backoffDurations))
}

// updateConnectionStatus updates the agent's websocket connection status in the database
func (w *WebSocketClient) updateConnectionStatus(connected bool) {
	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/connection-status", w.supabaseURL)

	payload := map[string]interface{}{
		"connected": connected,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logging.Debug("Failed to marshal connection status payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		logging.Debug("Failed to create connection status request: %v", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logging.Debug("Failed to send connection status update: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		logging.Debug("Connection status update returned non-200 status: %d", resp.StatusCode)
	}
}

// pollPatchExecutions polls the database for pending patch executions
func (w *WebSocketClient) pollPatchExecutions() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	// Create a separate ticker for heartbeat (every 30 seconds)
	heartbeatTicker := time.NewTicker(30 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			w.checkForPendingPatchExecutions()
		case <-heartbeatTicker.C:
			// Send heartbeat to refresh connection timestamp
			go w.updateConnectionStatus(true)
		}
	}
}

// checkForPendingPatchExecutions checks the database for new pending patch executions
func (w *WebSocketClient) checkForPendingPatchExecutions() {
	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/patch-executions", w.supabaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logging.Debug("Failed to create patch executions request: %v", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logging.Debug("Failed to fetch pending patch executions: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		logging.Debug("Patch executions request returned non-200 status: %d", resp.StatusCode)
		return
	}

	var executions []types.PatchExecution
	err = json.NewDecoder(resp.Body).Decode(&executions)
	if err != nil {
		logging.Debug("Failed to decode patch executions response: %v", err)
		return
	}

	for _, execution := range executions {
		// Use semaphore to limit concurrent patch executions
		go func(exec types.PatchExecution) {
			select {
			case w.patchSemaphore <- struct{}{}: // Acquire semaphore
				defer func() { <-w.patchSemaphore }() // Release semaphore
				w.handlePendingPatchExecution(exec)
			case <-w.ctx.Done():
				// Context cancelled before acquiring semaphore; do not proceed
				return
			}
		}(execution)
	}
}

// handlePendingPatchExecution handles a pending patch execution
func (w *WebSocketClient) handlePendingPatchExecution(execution types.PatchExecution) {
	scriptID := ""
	if execution.ScriptID != nil {
		scriptID = *execution.ScriptID
	}
	logging.Info("Processing patch execution %s (type: %s, script_id: %s)", execution.ID, execution.ExecutionType, scriptID)

	// Download and validate script
	scriptContent, err := w.downloadPatchScript(scriptID)
	if err != nil {
		w.updatePatchExecutionStatus(execution.ID, "failed", 1, err.Error(), "", "")
		return
	}

	// Write script to temporary file
	tmpFile, err := w.writeScriptToTempFile(scriptContent)
	if err != nil {
		w.updatePatchExecutionStatus(execution.ID, "failed", 1, err.Error(), "", "")
		return
	}
	defer func() { _ = os.Remove(tmpFile) }()

	// Update status to running
	w.updatePatchExecutionStatus(execution.ID, "running", 0, "", "", "")

	// Execute the script
	stdout, stderr, exitCode := w.executeScript(tmpFile, execution.Command)

	// Process and upload results
	w.processExecutionResults(execution, stdout, stderr, exitCode)

	logging.Info("Patch execution %s completed with exit code %d", execution.ID, exitCode)
}

// downloadPatchScript downloads and validates a patch script from storage
func (w *WebSocketClient) downloadPatchScript(scriptID string) ([]byte, error) {
	// Get script storage path from database via proxy
	scriptInfoURL := fmt.Sprintf("%s/functions/v1/agent-database-proxy/patch-scripts/%s", w.supabaseURL, scriptID)
	req, err := http.NewRequest("GET", scriptInfoURL, nil)
	if err != nil {
		logging.Error("Failed to create script info request: %v", err)
		return nil, fmt.Errorf("failed to get script info: %v", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))

	client := &http.Client{Timeout: 10 * time.Second}
	scriptInfoResp, err := client.Do(req)
	if err != nil {
		logging.Error("Failed to fetch script info: %v", err)
		return nil, fmt.Errorf("failed to fetch script info: %v", err)
	}
	defer func() { _ = scriptInfoResp.Body.Close() }()

	if scriptInfoResp.StatusCode != 200 {
		logging.Error("Script info request returned status %d", scriptInfoResp.StatusCode)
		return nil, fmt.Errorf("script info fetch failed with status %d", scriptInfoResp.StatusCode)
	}

	var scriptInfo struct {
		ScriptStoragePath string `json:"script_storage_path"`
	}
	if err := json.NewDecoder(scriptInfoResp.Body).Decode(&scriptInfo); err != nil {
		logging.Error("Failed to decode script info: %v", err)
		return nil, fmt.Errorf("failed to decode script info: %v", err)
	}

	// Download the script from storage
	scriptURL := fmt.Sprintf("%s/storage/v1/object/public/patch-scripts/%s", w.supabaseURL, scriptInfo.ScriptStoragePath)
	scriptResp, err := http.Get(scriptURL)
	if err != nil {
		logging.Error("Failed to download script: %v", err)
		return nil, fmt.Errorf("failed to download script: %v", err)
	}
	defer func() { _ = scriptResp.Body.Close() }()

	if scriptResp.StatusCode != 200 {
		logging.Error("Script download returned status %d", scriptResp.StatusCode)
		return nil, fmt.Errorf("script download failed with status %d", scriptResp.StatusCode)
	}

	scriptContent, err := io.ReadAll(scriptResp.Body)
	if err != nil {
		logging.Error("Failed to read script content: %v", err)
		return nil, fmt.Errorf("failed to read script: %v", err)
	}

	// Basic validation: check if script appears to be a shell script
	// Note: Scripts are sourced from authenticated and authorized storage,
	// but we perform basic validation as a safety measure
	if len(scriptContent) == 0 {
		logging.Error("Downloaded script is empty")
		return nil, fmt.Errorf("downloaded script is empty")
	}
	scriptStr := string(scriptContent)
	if !strings.HasPrefix(scriptStr, "#!") {
		logging.Error("Script does not start with shebang (#!), refusing to execute")
		return nil, fmt.Errorf("script does not start with shebang (#!)")
	}
	// Validate shebang against whitelist of allowed interpreters
	lines := strings.Split(scriptStr, "\n")
	shebang := lines[0]
	allowedInterpreters := []string{
		"#!/bin/bash",
		"#!/bin/sh",
		"#!/usr/bin/env bash",
		"#!/usr/bin/env sh",
	}
	isValid := false
	for _, allowed := range allowedInterpreters {
		if strings.HasPrefix(shebang, allowed) {
			isValid = true
			break
		}
	}
	if !isValid {
		logging.Error("Script uses non-standard interpreter: %s, refusing to execute", shebang)
		return nil, fmt.Errorf("script uses non-standard interpreter: %s", shebang)
	}

	return scriptContent, nil
}

// writeScriptToTempFile writes script content to a temporary file and makes it executable
func (w *WebSocketClient) writeScriptToTempFile(scriptContent []byte) (string, error) {
	tmpFile, err := os.CreateTemp("", "patch-script-*.sh")
	if err != nil {
		logging.Error("Failed to create temp file: %v", err)
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write(scriptContent); err != nil {
		logging.Error("Failed to write script content: %v", err)
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write script: %v", err)
	}

	if err := tmpFile.Chmod(0755); err != nil {
		logging.Error("Failed to make script executable: %v", err)
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to chmod script: %v", err)
	}

	tmpFilePath := tmpFile.Name()
	_ = tmpFile.Close()
	return tmpFilePath, nil
}

// executeScript executes a patch script and returns stdout, stderr, and exit code
func (w *WebSocketClient) executeScript(scriptPath string, command string) ([]byte, []byte, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if command != "" {
		// Split command into arguments to avoid command injection
		// Note: This uses simple space splitting with strings.Fields() which does not
		// handle quoted arguments, escaped spaces, or other shell metacharacters.
		// For production use with complex arguments, consider:
		// 1. Using a proper shell parser like github.com/google/shlex
		// 2. Implementing argument validation/whitelisting
		// 3. Restricting the command field to a predefined set of safe options
		// Current implementation assumes command contains simple space-separated arguments
		args := strings.Fields(command)
		cmd = exec.CommandContext(ctx, scriptPath, args...)
	} else {
		cmd = exec.CommandContext(ctx, scriptPath)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return stdout.Bytes(), stderr.Bytes(), exitCode
}

// processExecutionResults processes script execution results and uploads them to storage
func (w *WebSocketClient) processExecutionResults(execution types.PatchExecution, stdout, stderr []byte, exitCode int) {
	// Parse JSON from stdout
	jsonData := w.parseJSONFromOutput(string(stdout))

	// Upload stdout, stderr, and JSON output to storage
	outputPath := fmt.Sprintf("%s/%s-stdout.txt", w.agentID, execution.ID)
	errorPath := fmt.Sprintf("%s/%s-stderr.txt", w.agentID, execution.ID)
	jsonPath := fmt.Sprintf("%s/%s-output.json", w.agentID, execution.ID)

	w.uploadOutputToStorage(outputPath, stdout)
	w.uploadOutputToStorage(errorPath, stderr)

	// Upload JSON output to storage if present
	if jsonData != "" {
		w.uploadOutputToStorage(jsonPath, []byte(jsonData))
	}

	// Determine final status
	status := "completed"
	if exitCode != 0 {
		status = "failed"
	}

	// Update execution status (no JSON in database, only storage paths)
	w.updatePatchExecutionStatus(execution.ID, status, exitCode, "", outputPath, errorPath)

	// Perform reboot if requested and execution was successful
	if execution.ShouldReboot && exitCode == 0 && execution.ExecutionType == "apply" {
		go w.performReboot(execution.ID)
	}
}

// parseJSONFromOutput extracts JSON data from script output
func (w *WebSocketClient) parseJSONFromOutput(output string) string {
	var (
		jsonLines []string
		inJSON    bool
		braces    int
		brackets  int
	)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Look for the start of a JSON object or array
		if !inJSON {
			if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				inJSON = true
				jsonLines = nil
				braces = 0
				brackets = 0
			} else {
				continue
			}
		}
		// Accumulate lines
		jsonLines = append(jsonLines, trimmed)
		// Count braces and brackets
		for _, r := range trimmed {
			switch r {
			case '{':
				braces++
			case '}':
				braces--
			case '[':
				brackets++
			case ']':
				brackets--
			}
		}
		// If we've closed all opened braces/brackets, try to parse
		if inJSON && braces == 0 && brackets == 0 {
			jsonStr := strings.Join(jsonLines, "\n")
			var testJSON interface{}
			if json.Unmarshal([]byte(jsonStr), &testJSON) == nil {
				return jsonStr
			}
			// If parsing fails, reset and keep looking
			inJSON = false
			jsonLines = nil
		}
	}

	return ""
}

// uploadOutputToStorage uploads execution output to storage bucket
func (w *WebSocketClient) uploadOutputToStorage(path string, content []byte) {
	url := fmt.Sprintf("%s/storage/v1/object/patch-execution-outputs/%s", w.supabaseURL, path)

	req, err := http.NewRequest("POST", url, bytes.NewReader(content))
	if err != nil {
		logging.Error("Failed to create upload request: %v", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Failed to upload output: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		logging.Error("Upload failed with status %d: %s", resp.StatusCode, string(body))
	}
}

// updatePatchExecutionStatus updates the status of a patch execution
func (w *WebSocketClient) updatePatchExecutionStatus(executionID, status string, exitCode int, errorMessage, stdoutPath, stderrPath string) {
	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/patch-executions/%s", w.supabaseURL, executionID)

	payload := map[string]interface{}{
		"status":    status,
		"exit_code": exitCode,
	}

	if errorMessage != "" {
		payload["error_message"] = errorMessage
	}
	if stdoutPath != "" {
		payload["stdout_storage_path"] = stdoutPath
	}
	if stderrPath != "" {
		payload["stderr_storage_path"] = stderrPath
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logging.Error("Failed to marshal status update: %v", err)
		return
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewReader(jsonData))
	if err != nil {
		logging.Error("Failed to create status update request: %v", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Failed to update patch execution status: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		logging.Error("Status update failed with status %d: %s", resp.StatusCode, string(body))
	}
}

// performReboot initiates a system reboot after a delay
func (w *WebSocketClient) performReboot(executionID string) {
	// Prevent multiple concurrent reboot attempts
	w.rebootMutex.Lock()
	if w.rebootInProgress {
		w.rebootMutex.Unlock()
		logging.Warning("Reboot already in progress, ignoring duplicate reboot request for execution %s", executionID)
		return
	}
	w.rebootInProgress = true
	w.rebootMutex.Unlock()

	logging.Info("Reboot requested for execution %s, waiting 30 seconds...", executionID)

	// Update execution with reboot timestamp
	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/patch-executions/%s", w.supabaseURL, executionID)

	payload := map[string]interface{}{
		"rebooted_at": time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		logging.Error("Failed to marshal reboot payload: %v", err)
	} else {
		req, err := http.NewRequest("PATCH", url, bytes.NewReader(jsonData))
		if err != nil {
			logging.Error("Failed to create PATCH request for reboot timestamp: %v", err)
		} else {
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.token))
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				logging.Error("Failed to send PATCH request for reboot timestamp: %v", err)
			} else {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	}

	// Wait 30 seconds before rebooting
	time.Sleep(30 * time.Second)

	// Initiate reboot
	if os.Geteuid() != 0 {
		logging.Error("Insufficient privileges to reboot: must be run as root")
		return
	}
	cmd := exec.Command("systemctl", "reboot")
	if err := cmd.Run(); err != nil {
		logging.Error("Failed to execute reboot command: %v", err)
	}
}

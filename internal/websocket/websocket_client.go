package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
	consecutiveFailures int // Track consecutive connection failures
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

	// WebSocket client started
	return nil
}

// Stop closes the WebSocket connection
func (c *WebSocketClient) Stop() {
	c.cancel()
	if c.conn != nil {
		c.conn.Close()
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
	return nil
}

// handleMessages processes incoming WebSocket messages
func (c *WebSocketClient) handleMessages() {
	defer func() {
		if c.conn != nil {
			// Closing WebSocket connection
			c.conn.Close()
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
			c.conn.SetReadDeadline(time.Now().Add(90 * time.Second))

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

	// Processing investigation task

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
		// Task executed successfully
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
		return nil, fmt.Errorf("no commands found in diagnostic payload")
	}

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

		// Executing command

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
	// Parse command into parts
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", -1, fmt.Errorf("empty command")
	}

	// Create command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
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
	defer resp.Body.Close()

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
		c.updateInvestigationStatus(investigation.ID, "failed", resultsForDB, &errorMsg)
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
			c.updateInvestigationStatus(investigation.ID, "completed", resultsForDB, nil)
			return
		}

		if len(tzResp.Choices) == 0 {
			logging.Warning("No choices in TensorZero response")
			c.updateInvestigationStatus(investigation.ID, "completed", resultsForDB, nil)
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
	c.updateInvestigationStatus(investigation.ID, "completed_with_analysis", resultsForDB, nil)
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
	defer resp.Body.Close()

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

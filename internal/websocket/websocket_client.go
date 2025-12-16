package websocket

import (
	"bytes"
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

	// Try initial connection, but if it fails, still start the message handler
	// which will handle reconnection with backoff
	if err := w.connect(); err != nil {
		logging.Warning("Initial WebSocket connection failed (will retry): %v", err)
		w.consecutiveFailures = 1 // Mark as failed so reconnection will trigger
	} else {
		logging.Info("Initial WebSocket connection established successfully")
	}

	// Start message reading loop - this will handle reconnection if needed
	go w.handleMessages()

	// Start heartbeat
	go w.startHeartbeat()

	// WebSocket client started (will connect immediately or reconnect)
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

	// Join the realtime channel with postgres_changes configuration
	// This must be done BEFORE listening for messages
	joinMsg := map[string]interface{}{
		"event": "phx_join",
		"topic": "realtime:public",
		"payload": map[string]interface{}{
			"config": map[string]interface{}{
				"postgres_changes": []map[string]interface{}{
					{
						"event":  "INSERT",
						"schema": "public",
						"table":  "pending_investigations",
						"filter": "agent_id=eq." + c.agentID,
					},
					{
						"event":  "INSERT",
						"schema": "public",
						"table":  "patch_executions",
						"filter": "agent_id=eq." + c.agentID,
					},
				},
			},
		},
		"ref": "1",
	}

	if err := c.conn.WriteJSON(joinMsg); err != nil {
		logging.Error("Failed to join realtime channel: %v", err)
		c.conn.Close()
		return err
	}
	logging.Info("Joined realtime channel with postgres_changes subscriptions")

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
			// If connection hasn't been established yet, wait a bit before retrying
			if c.conn == nil {
				// Only log after multiple failures
				if c.consecutiveFailures >= 5 {
					logging.Debug("No connection yet, waiting before retry (failure #%d)", c.consecutiveFailures)
				}

				time.Sleep(1 * time.Second)
				c.consecutiveFailures++

				// After too many consecutive failures, attempt reconnection
				if c.consecutiveFailures >= 10 {
					logging.Info("Too many connection failures, attempting reconnection...")
					go c.attemptReconnection()
					return
				}
				continue
			}

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

			case "broadcast":
				// Broadcast messages may contain postgres_changes data
				// When subscribing to postgres_changes, we receive them as broadcast events
				go c.handleDatabaseChange(message.Data)

			case "postgres_changes":
				// Direct database change notification (alternative format)
				go c.handleDatabaseChange(message.Data)

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

// handleDatabaseChange processes PostgreSQL change notifications from Realtime
func (c *WebSocketClient) handleDatabaseChange(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		logging.Debug("Invalid database change format: %T", data)
		return
	}

	// The postgres_changes event comes as a broadcast message with the following structure:
	// {
	//   "payload": {
	//     "data": {
	//       "schema": "public",
	//       "table": "pending_investigations",
	//       "eventType": "INSERT",
	//       "new": {...}
	//     },
	//     "ids": [...]
	//   }
	// }

	payload, ok := dataMap["payload"].(map[string]interface{})
	if !ok {
		logging.Debug("Missing or invalid payload in database change")
		return
	}

	eventData, ok := payload["data"].(map[string]interface{})
	if !ok {
		logging.Debug("Missing or invalid data in postgres_changes payload")
		return
	}

	table, ok := eventData["table"].(string)
	if !ok {
		logging.Debug("Missing table in database change")
		return
	}

	eventType, ok := eventData["eventType"].(string)
	if !ok {
		logging.Debug("Missing eventType in database change")
		return
	}

	// Only process INSERT events
	if eventType != "INSERT" {
		return
	}

	newRecord, ok := eventData["new"].(map[string]interface{})
	if !ok {
		logging.Debug("Missing new record in database change")
		return
	}

	switch table {
	case "pending_investigations":
		logging.Info("Received new investigation via Realtime postgres_changes")
		c.handleNewInvestigation(newRecord)

	case "patch_executions":
		logging.Info("Received new patch execution via Realtime postgres_changes")
		c.handleNewPatchExecution(newRecord)

	default:
		logging.Debug("Unknown table in database change: %s", table)
	}
}

// handleNewInvestigation processes a newly inserted investigation record
func (c *WebSocketClient) handleNewInvestigation(record map[string]interface{}) {
	investigationID, _ := record["investigation_id"].(string)
	if investigationID == "" {
		// Try to get id field instead
		idField, _ := record["id"].(string)
		investigationID = idField
	}

	var diagnosticPayload map[string]interface{}
	if payload, ok := record["diagnostic_payload"]; ok {
		if payloadMap, ok := payload.(map[string]interface{}); ok {
			diagnosticPayload = payloadMap
		}
	}

	if diagnosticPayload == nil {
		logging.Error("No diagnostic payload in investigation record")
		return
	}

	logging.Info("Processing investigation %s", investigationID)

	// Execute diagnostic commands
	_, err := c.executeDiagnosticCommands(diagnosticPayload)

	if err != nil {
		logging.Error("Investigation %s execution failed: %v", investigationID, err)
		return
	}

	logging.Info("Investigation %s completed successfully", investigationID)
}

// handleNewPatchExecution processes a newly inserted patch execution record
func (c *WebSocketClient) handleNewPatchExecution(record map[string]interface{}) {
	executionID, _ := record["execution_id"].(string)
	if executionID == "" {
		idField, _ := record["id"].(string)
		executionID = idField
	}

	scriptContent, _ := record["script_content"].(string)
	patchName, _ := record["patch_name"].(string)

	if scriptContent == "" {
		logging.Error("No script content in patch execution record")
		return
	}

	// Acquire semaphore to limit concurrent patch executions
	c.patchSemaphore <- struct{}{}
	defer func() { <-c.patchSemaphore }()

	logging.Info("Executing patch %s (execution: %s)", patchName, executionID)

	// Execute patch script
	cmd := exec.Command("bash", "-c", scriptContent)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		logging.Error("Patch %s execution failed: %v", patchName, err)
		return
	}

	logging.Info("Patch %s completed successfully in %v (execution: %s)", patchName, duration, executionID)
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

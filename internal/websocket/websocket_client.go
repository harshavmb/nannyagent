package websocket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

	"github.com/google/shlex"
	"github.com/gorilla/websocket"
)

// allowedInterpreters contains the list of allowed script interpreters for security
var allowedInterpreters = map[string]bool{
	"/bin/bash":     true,
	"/usr/bin/bash": true,
	"bash":          true,
	"/bin/sh":       true,
	"/usr/bin/sh":   true,
	"sh":            true,
}

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
	connMutex           sync.RWMutex // Protect concurrent access to conn
	writeMutex          sync.Mutex   // Protects websocket writes
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

	// Get PocketBase URL (websocket support is optional)
	pocketbaseURL := os.Getenv("POCKETBASE_URL")
	if pocketbaseURL == "" {
		pocketbaseURL = os.Getenv("API_BASE_URL")
	}
	if pocketbaseURL == "" {
		pocketbaseURL = "http://localhost:8090"
	}
	logging.Debug("WebSocket client using base URL: %s", pocketbaseURL)

	// Create metrics collector
	metricsCollector := metrics.NewCollector("v2.0.0")

	ctx, cancel := context.WithCancel(context.Background())

	return &WebSocketClient{
		agent:            agent,
		agentID:          agentID,
		authManager:      authManager,
		metricsCollector: metricsCollector,
		supabaseURL:      pocketbaseURL,
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
	}

	// Start message reading loop - this will handle reconnection if needed
	go w.handleMessages()

	// WebSocket client started (will connect immediately or reconnect)
	return nil
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

	c.connMutex.Lock()
	c.conn = conn
	c.connMutex.Unlock()

	// Update database that we're connected
	go c.updateConnectionStatus(true)

	return nil
}

// handleMessages processes incoming WebSocket messages
func (c *WebSocketClient) handleMessages() {
	defer func() {
		// Update database that we're disconnected
		c.updateConnectionStatus(false)

		c.connMutex.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
		}
		c.connMutex.Unlock()
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// If connection hasn't been established yet, wait a bit before retrying
			c.connMutex.RLock()
			conn := c.conn
			c.connMutex.RUnlock()

			if conn == nil {
				go c.attemptReconnection()
				return
			}

			// Must lock around ReadJSON to prevent concurrent writes
			c.writeMutex.Lock()
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			var message WebSocketMessage
			err := conn.ReadJSON(&message)
			c.writeMutex.Unlock()

			if err != nil {
				// Attempt reconnection instead of returning immediately
				go c.attemptReconnection()
				return
			}

			// Received WebSocket message successfully - reset failure counter
			c.consecutiveFailures = 0

			switch message.Type {
			case "investigation_task":
				// Received investigation task
				go c.handleInvestigationTask(message.Data)

			case "patch_execution_task":
				// Received patch execution task
				go c.handlePatchExecutionTask(message.Data)
			}
		}
	}
}

// handleInvestigationTask processes investigation tasks from the backend
func (c *WebSocketClient) handleInvestigationTask(data interface{}) {
	logging.Info("[WEBSOCKET_TASK] Received investigation_task message")
	// Parse task data
	taskBytes, err := json.Marshal(data)
	if err != nil {
		logging.Error("[WEBSOCKET_TASK] Error marshaling task data: %v", err)
		return
	}

	var task InvestigationTask
	err = json.Unmarshal(taskBytes, &task)
	if err != nil {
		logging.Error("[WEBSOCKET_TASK] Error unmarshaling investigation task: %v", err)
		return
	}
	logging.Info("[WEBSOCKET_TASK] Parsed task - ID: %s, initiated_by: %s", task.InvestigationID, task.DiagnosticPayload["initiated_by"])

	// Check if investigation has a timestamp field to validate timeliness
	if createdAtStr, ok := task.DiagnosticPayload["created_at"].(string); ok {
		createdAt, err := time.Parse(time.RFC3339, createdAtStr)
		if err == nil {
			timeSinceCreation := time.Since(createdAt)
			maxAge := 5 * time.Minute

			if timeSinceCreation > maxAge {
				logging.Error("Investigation %s received %v after creation (max age: %v). Discarding stale investigation.",
					task.InvestigationID, timeSinceCreation, maxAge)
				return
			}
		}
	}

	// Check if investigation has initiated_by set (should NOT be from agent creating new ones)
	initiatedBy, hasInitiatedBy := task.DiagnosticPayload["initiated_by"].(string)
	logging.Info("[WEBSOCKET_TASK] Checking initiated_by - has: %v, value: '%s'", hasInitiatedBy, initiatedBy)
	if !hasInitiatedBy || initiatedBy == "" || initiatedBy == "agent" {
		logging.Warning("[WEBSOCKET_TASK] Investigation %s has invalid initiated_by: '%s'. Skipping agent-initiated investigations.",
			task.InvestigationID, initiatedBy)
		return
	}
	logging.Info("[WEBSOCKET_TASK] Investigation %s passed initiated_by check, proceeding", task.InvestigationID)

	// Update investigation status to in_progress
	logging.Info("[WEBSOCKET_TASK] Updating investigation %s status to in_progress", task.InvestigationID)
	if err := c.updateInvestigationStatus(task.InvestigationID, "in_progress"); err != nil {
		logging.Error("[WEBSOCKET_TASK] Failed to update investigation %s status to in_progress: %v", task.InvestigationID, err)
	}

	// Check if this is an AI-driven investigation (has 'issue' field)
	issueDesc, hasIssue := task.DiagnosticPayload["issue"].(string)
	logging.Info("[WEBSOCKET_TASK] Investigation %s has issue field: %v, issue: %s", task.InvestigationID, hasIssue, issueDesc)

	var taskResult TaskResult
	taskResult.TaskID = task.TaskID

	if hasIssue && issueDesc != "" {
		// AI-driven investigation - pass investigation_id for tracking
		// Use the backend-initiated variant to prevent creating duplicate investigations
		// Set the investigation ID on the agent so it passes it to tensorzero-proxy
		c.agent.SetInvestigationID(task.InvestigationID)

		err := c.diagnoseIssueWithTracking(issueDesc, task.InvestigationID)

		taskResult.Success = err == nil
		if err != nil {
			taskResult.Error = err.Error()
			// Update status to failed if diagnosis failed
			_ = c.updateInvestigationStatus(task.InvestigationID, "failed")
		} else {
			// Update status to completed on success
			_ = c.updateInvestigationStatus(task.InvestigationID, "completed")
		}
	} else {
		// Direct command execution
		results, err := c.executeDiagnosticCommands(task.DiagnosticPayload)

		taskResult.Success = err == nil
		if err != nil {
			taskResult.Error = err.Error()
			_ = c.updateInvestigationStatus(task.InvestigationID, "failed")
		} else {
			taskResult.CommandResults = results
			_ = c.updateInvestigationStatus(task.InvestigationID, "completed")
		}
	}

	// Send result back
	c.sendTaskResult(taskResult)
}

// handlePatchExecutionTask processes a patch execution task message (direct from WebSocket)
func (c *WebSocketClient) handlePatchExecutionTask(data interface{}) {
	// Convert data to map
	taskBytes, err := json.Marshal(data)
	if err != nil {
		logging.Error("Error marshaling patch task data: %v", err)
		return
	}

	var task map[string]interface{}
	err = json.Unmarshal(taskBytes, &task)
	if err != nil {
		logging.Error("Error unmarshaling patch task: %v", err)
		return
	}

	// Call the existing handler with the full task data
	c.handleNewPatchExecution(task)
}

// handleNewPatchExecution processes a newly inserted patch execution record
func (c *WebSocketClient) handleNewPatchExecution(record map[string]interface{}) {
	executionID, _ := record["id"].(string)
	if executionID == "" {
		logging.Error("No id in patch execution record")
		return
	}

	// Check if execution is too old (discard if created more than 1 minute ago)
	// This prevents processing stale executions from the database
	if createdAt, ok := record["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, createdAt); err == nil {
			if time.Since(t) > time.Minute {
				logging.Warning("Discarding patch execution %s: created %v ago (too old)", executionID, time.Since(t))
				return
			}
		}
	}

	executionType, _ := record["execution_type"].(string)
	command, _ := record["command"].(string) // Can be "--dry-run" or empty

	// Get script_id from record - try multiple possible types
	scriptIDVal, hasScriptID := record["script_id"]
	var scriptID string

	if hasScriptID {
		// Try string first
		if s, ok := scriptIDVal.(string); ok {
			scriptID = s
		} else if f, ok := scriptIDVal.(float64); ok {
			scriptID = fmt.Sprintf("%v", int64(f))
		} else if u, ok := scriptIDVal.(map[string]interface{}); ok {
			// In case it's a nested object
			if id, ok := u["id"].(string); ok {
				scriptID = id
			}
		}
	}

	if scriptID == "" {
		logging.Error("No script_id in patch execution record. Available fields: %v", record)
		return
	}

	// Acquire semaphore to limit concurrent patch executions
	c.patchSemaphore <- struct{}{}
	defer func() { <-c.patchSemaphore }()

	// Log what we're doing
	if executionType == "dry_run" {
		logging.Info("Processing dry_run for script %s (execution: %s)", scriptID, executionID)
	} else {
		logging.Info("Processing patch execution %s with script_id %s", executionID, scriptID)
	}

	// Download script from Supabase Storage
	scriptContent, err := c.downloadPatchScript(scriptID)
	if err != nil {
		logging.Error("Failed to download patch script: %v", err)
		c.updatePatchExecutionStatus(executionID, "failed", 1, fmt.Sprintf("Download failed: %v", err), "", "")
		return
	}

	// Save script to temporary file
	tmpFile, err := c.writeScriptToTempFile(scriptContent)
	if err != nil {
		logging.Error("Failed to create temp file: %v", err)
		c.updatePatchExecutionStatus(executionID, "failed", 1, fmt.Sprintf("Temp file creation failed: %v", err), "", "")
		return
	}
	defer os.Remove(tmpFile)

	logging.Info("Executing patch (execution: %s)", executionID)

	// Update status to running
	c.updatePatchExecutionStatus(executionID, "running", 0, "", "", "")

	// Execute patch script with output capture (pass command for --dry-run if present)
	stdout, stderr, exitCode := c.executeScript(tmpFile, command)

	// Process and upload results
	c.processExecutionResults(record, executionID, stdout, stderr, exitCode)
}

// writeScriptToTempFile writes script content to a temporary file and makes it executable
func (c *WebSocketClient) writeScriptToTempFile(scriptContent []byte) (string, error) {
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

	if err := os.Chmod(tmpFile.Name(), 0700); err != nil {
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
func (c *WebSocketClient) executeScript(scriptPath string, command string) ([]byte, []byte, int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	args, err := shlex.Split(command)
	if err != nil {
		return nil, []byte(fmt.Errorf("invalid command syntax: %w", err).Error()), 1
	}

	cmd = exec.CommandContext(ctx, scriptPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
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
func (c *WebSocketClient) processExecutionResults(record map[string]interface{}, executionID string, stdout, stderr []byte, exitCode int) {
	// Parse JSON from stdout
	jsonData := c.parseJSONFromOutput(string(stdout))

	// Upload stdout, stderr, and JSON output to storage
	outputPath := fmt.Sprintf("%s/%s-stdout.txt", c.agentID, executionID)
	errorPath := fmt.Sprintf("%s/%s-stderr.txt", c.agentID, executionID)
	jsonPath := fmt.Sprintf("%s/%s-output.json", c.agentID, executionID)

	c.uploadOutputToStorage(outputPath, stdout)
	c.uploadOutputToStorage(errorPath, stderr)

	// Upload JSON output to storage if present
	if jsonData != "" {
		c.uploadOutputToStorage(jsonPath, []byte(jsonData))
	}

	// Determine final status
	status := "completed"
	if exitCode != 0 {
		status = "failed"
	}

	// Update execution status with storage paths
	c.updatePatchExecutionStatus(executionID, status, exitCode, "", outputPath, errorPath)

	logging.Info("Patch execution %s completed with exit code %d (storage paths uploaded)", executionID, exitCode)
}

// parseJSONFromOutput extracts JSON data from script output
func (c *WebSocketClient) parseJSONFromOutput(output string) string {
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
func (c *WebSocketClient) uploadOutputToStorage(path string, content []byte) {
	baseURL := strings.TrimSuffix(c.supabaseURL, "/")
	url := fmt.Sprintf("%s/storage/v1/object/patch-execution-outputs/%s", baseURL, path)

	req, err := http.NewRequest("POST", url, bytes.NewReader(content))
	if err != nil {
		logging.Error("Failed to create upload request: %v", err)
		return
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
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

	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	c.connMutex.RLock()
	defer c.connMutex.RUnlock()
	if c.conn == nil {
		logging.Error("Cannot send task result: connection is nil")
		return
	}

	if err := c.conn.WriteJSON(message); err != nil {
		logging.Error("Error sending task result: %v", err)
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

// downloadPatchScript downloads a patch script from Supabase Storage using the script_id
// It fetches the script_storage_path from the patch_scripts table via Edge Function proxy
func (c *WebSocketClient) downloadPatchScript(scriptID string) ([]byte, error) {
	baseURL := strings.TrimSuffix(c.supabaseURL, "/")

	// First, fetch the script_storage_path from the patch_scripts table via proxy
	scriptInfoURL := fmt.Sprintf("%s/functions/v1/agent-database-proxy/patch-scripts/%s", baseURL, scriptID)
	req, err := http.NewRequest("GET", scriptInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create script info request: %v", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch script info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("script info request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var scriptInfo struct {
		ScriptStoragePath string `json:"script_storage_path"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&scriptInfo); err != nil {
		return nil, fmt.Errorf("failed to decode script info: %v", err)
	}

	// Now download the script from Storage
	storageURL := fmt.Sprintf("%s/storage/v1/object/public/patch-scripts/%s", baseURL, scriptInfo.ScriptStoragePath)

	logging.Debug("Downloading patch script from: %s", storageURL)

	req, err = http.NewRequest("GET", storageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %v", err)
	}

	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download script: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	scriptContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read script content: %v", err)
	}

	// Validation: script must not be empty
	if len(scriptContent) == 0 {
		return nil, fmt.Errorf("script is empty")
	}

	// Validation: script must start with a valid shebang
	lines := strings.SplitN(string(scriptContent), "\n", 2)
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "#!") {
		return nil, fmt.Errorf("script does not start with a valid shebang")
	}

	// Validation: only allow bash or sh as interpreters
	shebang := strings.TrimSpace(lines[0][2:]) // Remove "#!" and trim
	// Split shebang into interpreter and args
	fields := strings.Fields(shebang)
	if len(fields) == 0 {
		return nil, fmt.Errorf("shebang does not specify an interpreter")
	}
	interpreter := fields[0]
	if !allowedInterpreters[interpreter] {
		return nil, fmt.Errorf("interpreter %q is not allowed", interpreter)
	}

	return scriptContent, nil
}

// updatePatchExecutionStatus updates the status of a patch execution with proper fields
func (c *WebSocketClient) updatePatchExecutionStatus(executionID, status string, exitCode int, errorMessage, stdoutPath, stderrPath string) {
	baseURL := strings.TrimSuffix(c.supabaseURL, "/")
	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/patch-executions/%s", baseURL, executionID)

	payload := map[string]interface{}{
		"status": status,
	}

	// Always set exit code if provided
	if exitCode >= 0 {
		payload["exit_code"] = exitCode
	}

	// Set storage paths
	if stdoutPath != "" {
		payload["stdout_storage_path"] = stdoutPath
	}
	if stderrPath != "" {
		payload["stderr_storage_path"] = stderrPath
	}

	// Set error message
	if errorMessage != "" {
		payload["error_message"] = errorMessage
	}

	// Set timestamps based on status
	now := time.Now().UTC().Format(time.RFC3339)
	switch status {
	case "running", "in_progress":
		payload["started_at"] = now
	case "completed", "failed":
		payload["completed_at"] = now
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

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
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
		return
	}

	logging.Info("Updated patch execution %s status to %s", executionID, status)
}

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

// updateInvestigationStatus updates the status and episode_id of an investigation
func (c *WebSocketClient) updateInvestigationStatus(investigationID, status string) error {
	return c.updateInvestigationStatusWithEpisode(investigationID, status, "")
}

// updateInvestigationStatusWithEpisode updates investigation status and stores episode_id
func (c *WebSocketClient) updateInvestigationStatusWithEpisode(investigationID, status, episodeID string) error {
	if investigationID == "" {
		return fmt.Errorf("investigation_id is required")
	}

	url := fmt.Sprintf("%s/functions/v1/agent-database-proxy/update-investigation", c.supabaseURL)
	logging.Info("[API_CALL] PATCH %s", url)

	payload := map[string]interface{}{
		"investigation_id": investigationID,
		"status":           status,
	}

	if episodeID != "" {
		payload["episode_id"] = episodeID
	}

	logging.Info("[API_CALL] Payload: %+v", payload)
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("PATCH", url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	logging.Info("[API_CALL] Response status: %d", resp.StatusCode)
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		logging.Error("[API_CALL] Error response: %s", string(body))
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	logging.Info("[API_CALL] Investigation %s status successfully updated to %s", investigationID, status)
	return nil
}

// diagnoseIssueWithTracking wraps agent.DiagnoseIssueWithInvestigation and captures episode_id
func (c *WebSocketClient) diagnoseIssueWithTracking(issue, investigationID string) error {
	logging.Info("[DIAGNOSIS_TRACK] Starting diagnosis tracking for investigation %s", investigationID)
	// Call the agent's DiagnoseIssueWithInvestigation for backend-initiated investigations
	// This prevents creating duplicate investigations
	logging.Info("[DIAGNOSIS_TRACK] Calling agent.DiagnoseIssueWithInvestigation for %s", investigationID)
	err := c.agent.DiagnoseIssueWithInvestigation(issue)
	if err != nil {
		logging.Error("[DIAGNOSIS_TRACK] Diagnosis failed: %v", err)
		return err
	}
	logging.Info("[DIAGNOSIS_TRACK] Diagnosis completed for %s", investigationID)

	// After diagnosis completes, get the episode_id from the agent
	episodeID := c.agent.GetEpisodeID()
	logging.Info("[DIAGNOSIS_TRACK] Retrieved episode_id: %s for investigation %s", episodeID, investigationID)
	if episodeID != "" {
		// Update investigation with episode_id
		logging.Info("[DIAGNOSIS_TRACK] Updating investigation %s with episode_id: %s", investigationID, episodeID)
		if updateErr := c.updateInvestigationStatusWithEpisode(investigationID, "completed", episodeID); updateErr != nil {
			logging.Error("[DIAGNOSIS_TRACK] Failed to update investigation %s with episode_id: %v", investigationID, updateErr)
		}
	} else {
		logging.Warning("[DIAGNOSIS_TRACK] No episode_id returned, updating with completed status only")
		if updateErr := c.updateInvestigationStatus(investigationID, "completed"); updateErr != nil {
			logging.Error("[DIAGNOSIS_TRACK] Failed to update investigation %s status: %v", investigationID, updateErr)
		}
	}

	return nil
}

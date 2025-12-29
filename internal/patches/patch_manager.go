package patches

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"nannyagent/internal/logging"
	"nannyagent/internal/types"
)

// execCommand allows mocking exec.Command in tests
var execCommand = exec.Command

// PatchManager handles patch operations
type PatchManager struct {
	baseURL     string
	authManager interface {
		AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error)
	}
	agentID string
}

// NewPatchManager creates a new patch manager
func NewPatchManager(baseURL string, authManager interface {
	AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error)
}, agentID string) *PatchManager {
	return &PatchManager{
		baseURL:     baseURL,
		authManager: authManager,
		agentID:     agentID,
	}
}

// HandlePatchOperation processes a patch operation request
func (pm *PatchManager) HandlePatchOperation(payload types.AgentPatchPayload) error {
	logging.Info("Processing patch operation: %s (Mode: %s)", payload.OperationID, payload.Mode)

	// Create temporary directory for execution
	tmpDir, err := os.MkdirTemp("", "nanny-patch-*")
	if err != nil {
		return pm.reportFailure(payload.OperationID, fmt.Sprintf("Failed to create temp dir: %v", err))
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// 1. Download script
	scriptPath := filepath.Join(tmpDir, "patch_script")
	if err := pm.downloadScript(payload.ScriptURL, scriptPath); err != nil {
		return pm.reportFailure(payload.OperationID, fmt.Sprintf("Failed to download script from %v: %v", payload.ScriptURL, err))
	}

	// 2. Validate SHA256
	if err := pm.validateScript(payload.ScriptURL, scriptPath); err != nil {
		return pm.reportFailure(payload.OperationID, fmt.Sprintf("Script validation failed: %v", err))
	}

	// 3. Make executable
	if err := os.Chmod(scriptPath, 0700); err != nil {
		return pm.reportFailure(payload.OperationID, fmt.Sprintf("Failed to make script executable: %v", err))
	}

	// 4. Execute script
	// Pass arguments: mode (dry-run/apply) and any extra args
	// Check if `--` is present in mode, if not add that prefix
	// so as to pass it as an argument
	var mode string
	if !strings.HasPrefix(payload.Mode, "--") {
		mode = fmt.Sprintf("%s%s", "--", payload.Mode)
	} else {
		mode = payload.Mode
	}

	// if mode is apply, we shouldn't pass any args
	// patch scripts by default apply all changes unless in dry-run
	var args []string
	if mode != "--apply" {
		args = []string{mode}
	}
	if payload.ScriptArgs != "" {
		args = append(args, payload.ScriptArgs)
	}

	var cmd *exec.Cmd
	if payload.LXCID != "" {
		// Run on LXC container using pct exec
		// Command: pct exec <vmid> -- bash -c "$(cat <scriptPath>)" -- <args>
		// Note: We need to read the script content to pass it to bash -c
		scriptContent, err := os.ReadFile(scriptPath)
		if err != nil {
			return pm.reportFailure(payload.OperationID, fmt.Sprintf("Failed to read script for LXC execution: %v", err))
		}

		// Use VMID if available (preferred for Proxmox), otherwise fallback to LXCID
		targetID := payload.LXCID
		if payload.VMID != "" {
			targetID = payload.VMID
		}

		// Execute the script inside the container by piping it to bash -s
		// This avoids copying the file to the container, avoids ARG_MAX limits, and hides content from ps.
		// bash -s reads commands from stdin
		pctArgs := []string{"exec", targetID, "--", "bash", "-s", "--"}
		pctArgs = append(pctArgs, args...)

		cmd = execCommand("pct", pctArgs...)
		cmd.Stdin = bytes.NewReader(scriptContent)
	} else {
		// Run on Host
		cmd = execCommand(scriptPath, args...)
	}

	// Capture stdout and stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	// 5. Parse output (expecting JSON on stdout for package list)
	// The script should output JSON array of PatchPackageInfo on success if it modified packages
	// But we also capture raw stdout/stderr for debugging

	// 6. Upload results
	result := types.AgentPatchResult{
		OperationID: payload.OperationID,
		Success:     exitCode == 0,
		Duration:    duration.Milliseconds(),
		LXCID:       payload.LXCID,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	if !result.Success {
		result.ErrorMsg = fmt.Sprintf("Exit code %d: %s", exitCode, stderrBuf.String())
	}

	// Try to parse package list from stdout if successful
	if result.Success {
		// Look for JSON array in stdout
		// This is a simple heuristic - scripts should output clean JSON if they want structured data
		// Or we can just upload the raw output
		var packages []types.PatchPackageInfo
		if jsonErr := json.Unmarshal(stdoutBuf.Bytes(), &packages); jsonErr == nil {
			result.PackageList = packages
		}
	}

	return pm.uploadResults(payload.OperationID, exitCode, stdoutBuf.Bytes(), stderrBuf.Bytes(), result)
}

// downloadScript downloads the script from the URL
func (pm *PatchManager) downloadScript(url string, destPath string) error {
	// If URL is relative, prepend base URL
	fullURL := url
	if !strings.HasPrefix(url, "http") {
		fullURL = fmt.Sprintf("%s%s", pm.baseURL, url)
	}

	resp, err := pm.authManager.AuthenticatedDo("GET", fullURL, nil, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status: %d", resp.StatusCode)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	_, err = io.Copy(out, resp.Body)
	return err
}

// validateScript checks the SHA256 of the downloaded script against the API
func (pm *PatchManager) validateScript(scriptURL, filePath string) error {
	// Calculate local SHA256
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	localSHA := hex.EncodeToString(hash.Sum(nil))

	// Extract script ID from URL (format: /api/files/collection/ID/filename)
	// or we might need a different way to get the ID.
	// The prompt says: `"/api/scripts/{id}/validate"`
	// But we receive `script_url` which is the file download URL.
	// We need to extract the ID from the URL or have it passed in the payload.
	// Looking at handlers.go: scriptURL := fmt.Sprintf("/api/files/%s/%s/%s", scriptsCollection.Id, scriptRecord.Id, scriptRecord.GetString("file"))
	// So the ID is the 3rd component after /api/files/

	// Parse URL to get ID
	// Example: /api/files/scripts_collection_id/RECORD_ID/filename.sh
	// We need RECORD_ID

	// Simple parsing assuming standard NannyAPI file URL structure
	// Remove query params if any
	cleanURL := scriptURL
	if idx := strings.IndexByte(cleanURL, '?'); idx != -1 {
		cleanURL = cleanURL[:idx]
	}

	// This might be tricky with URL path separators vs OS separators.
	// Let's use string splitting
	urlParts := strings.Split(cleanURL, "/")
	if len(urlParts) < 3 {
		return fmt.Errorf("cannot extract script ID from URL: %s", scriptURL)
	}

	// The ID should be the second to last part (before filename)
	scriptID := urlParts[len(urlParts)-2]

	// Call validation endpoint
	validateURL := fmt.Sprintf("%s/api/scripts/%s/validate", pm.baseURL, scriptID)
	resp, err := pm.authManager.AuthenticatedDo("GET", validateURL, nil, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("validation API failed with status: %d", resp.StatusCode)
	}

	var validateResp struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
		Name   string `json:"name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&validateResp); err != nil {
		return fmt.Errorf("failed to decode validation response: %w", err)
	}

	if validateResp.SHA256 != localSHA {
		return fmt.Errorf("SHA256 mismatch! Expected: %s, Got: %s", validateResp.SHA256, localSHA)
	}

	logging.Info("Script validation successful (SHA256: %s)", localSHA)
	return nil
}

// uploadResults uploads the execution results
func (pm *PatchManager) uploadResults(operationID string, exitCode int, stdout, stderr []byte, result types.AgentPatchResult) error {
	// We need to upload files using multipart form data
	// But for simplicity, let's first try to use the endpoint structure from handlers.go
	// func HandlePatchResult(app core.App, c *core.RequestEvent)
	// It expects: exit_code, stdout_file, stderr_file

	// Create multipart body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add exit code
	_ = writer.WriteField("exit_code", fmt.Sprintf("%d", exitCode))

	// Add lxc_id if present
	if result.LXCID != "" {
		_ = writer.WriteField("lxc_id", result.LXCID)
	}

	// Add stdout file
	part, err := writer.CreateFormFile("stdout_file", "stdout.txt")
	if err != nil {
		return err
	}
	_, _ = part.Write(stdout)

	// Add stderr file
	part, err = writer.CreateFormFile("stderr_file", "stderr.txt")
	if err != nil {
		return err
	}
	_, _ = part.Write(stderr)

	_ = writer.Close()

	// Send request
	url := fmt.Sprintf("%s/api/patches/%s/result", pm.baseURL, operationID)
	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
	}

	resp, err := pm.authManager.AuthenticatedDo("POST", url, body.Bytes(), headers)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Read body for error message
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to upload results (status %d): %s", resp.StatusCode, string(respBody))
	}

	logging.Info("Patch results uploaded successfully for operation %s", operationID)
	return nil
}

// reportFailure is a helper to report immediate failures before execution
func (pm *PatchManager) reportFailure(operationID, errorMsg string) error {
	logging.Error("Patch operation failed: %s", errorMsg)

	// Upload failure result
	return pm.uploadResults(operationID, 1, nil, []byte(errorMsg), types.AgentPatchResult{
		OperationID: operationID,
		Success:     false,
		ErrorMsg:    errorMsg,
		Timestamp:   time.Now().Format(time.RFC3339),
	})
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/sashabaranov/go-openai"
)

// DiagnosticResponse represents the diagnostic phase response from AI
type DiagnosticResponse struct {
	ResponseType string    `json:"response_type"`
	Reasoning    string    `json:"reasoning"`
	Commands     []Command `json:"commands"`
}

// ResolutionResponse represents the resolution phase response from AI
type ResolutionResponse struct {
	ResponseType   string `json:"response_type"`
	RootCause      string `json:"root_cause"`
	ResolutionPlan string `json:"resolution_plan"`
	Confidence     string `json:"confidence"`
}

// Command represents a command to be executed
type Command struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// CommandResult represents the result of executing a command
type CommandResult struct {
	ID       string `json:"id"`
	Command  string `json:"command"`
	Output   string `json:"output"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// LinuxDiagnosticAgent represents the main agent
type LinuxDiagnosticAgent struct {
	client    *openai.Client
	model     string
	executor  *CommandExecutor
	episodeID string // TensorZero episode ID for conversation continuity
}

// NewLinuxDiagnosticAgent creates a new diagnostic agent
func NewLinuxDiagnosticAgent() *LinuxDiagnosticAgent {
	endpoint := os.Getenv("NANNYAPI_ENDPOINT")
	if endpoint == "" {
		// Default endpoint - OpenAI SDK will append /chat/completions automatically
		endpoint = "http://nannyapi.local:3000/openai/v1"
	}

	model := os.Getenv("NANNYAPI_MODEL")
	if model == "" {
		model = "nannyapi::function_name::diagnose_and_heal"
		fmt.Printf("Warning: Using default model '%s'. Set NANNYAPI_MODEL environment variable for your specific function.\n", model)
	}

	// Create OpenAI client with custom base URL
	// Note: The OpenAI SDK automatically appends "/chat/completions" to the base URL
	config := openai.DefaultConfig("")
	config.BaseURL = endpoint
	client := openai.NewClientWithConfig(config)

	return &LinuxDiagnosticAgent{
		client:   client,
		model:    model,
		executor: NewCommandExecutor(10 * time.Second), // 10 second timeout for commands
	}
}

// DiagnoseIssue starts the diagnostic process for a given issue
func (a *LinuxDiagnosticAgent) DiagnoseIssue(issue string) error {
	fmt.Printf("Diagnosing issue: %s\n", issue)
	fmt.Println("Gathering system information...")

	// Gather system information
	systemInfo := GatherSystemInfo()

	// Format the initial prompt with system information
	initialPrompt := FormatSystemInfoForPrompt(systemInfo) + "\n" + issue

	// Start conversation with initial issue including system info
	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleUser,
			Content: initialPrompt,
		},
	}

	for {
		// Send request to TensorZero API via OpenAI SDK
		response, err := a.sendRequest(messages)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no choices in response")
		}

		content := response.Choices[0].Message.Content
		fmt.Printf("\nAI Response:\n%s\n", content)

		// Parse the response to determine next action
		var diagnosticResp DiagnosticResponse
		var resolutionResp ResolutionResponse

		// Try to parse as diagnostic response first
		if err := json.Unmarshal([]byte(content), &diagnosticResp); err == nil && diagnosticResp.ResponseType == "diagnostic" {
			// Handle diagnostic phase
			fmt.Printf("\nReasoning: %s\n", diagnosticResp.Reasoning)

			if len(diagnosticResp.Commands) == 0 {
				fmt.Println("No commands to execute in diagnostic phase")
				break
			}

			// Execute commands and collect results
			commandResults := make([]CommandResult, 0, len(diagnosticResp.Commands))
			for _, cmd := range diagnosticResp.Commands {
				fmt.Printf("\nExecuting command '%s': %s\n", cmd.ID, cmd.Command)
				result := a.executor.Execute(cmd)
				commandResults = append(commandResults, result)

				fmt.Printf("Output:\n%s\n", result.Output)
				if result.Error != "" {
					fmt.Printf("Error: %s\n", result.Error)
				}
			}

			// Prepare command results as user message
			resultsJSON, err := json.MarshalIndent(commandResults, "", "  ")
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
		}

		// Try to parse as resolution response
		if err := json.Unmarshal([]byte(content), &resolutionResp); err == nil && resolutionResp.ResponseType == "resolution" {
			// Handle resolution phase
			fmt.Printf("\n=== DIAGNOSIS COMPLETE ===\n")
			fmt.Printf("Root Cause: %s\n", resolutionResp.RootCause)
			fmt.Printf("Resolution Plan: %s\n", resolutionResp.ResolutionPlan)
			fmt.Printf("Confidence: %s\n", resolutionResp.Confidence)
			break
		}

		// If we can't parse the response, treat it as an error or unexpected format
		fmt.Printf("Unexpected response format or error from AI:\n%s\n", content)
		break
	}

	return nil
}

// TensorZeroRequest represents a request structure compatible with TensorZero's episode_id
type TensorZeroRequest struct {
	Model     string                         `json:"model"`
	Messages  []openai.ChatCompletionMessage `json:"messages"`
	EpisodeID string                         `json:"tensorzero::episode_id,omitempty"`
}

// TensorZeroResponse represents TensorZero's response with episode_id
type TensorZeroResponse struct {
	openai.ChatCompletionResponse
	EpisodeID string `json:"episode_id"`
}

// sendRequest sends a request to the TensorZero API with tensorzero::episode_id support
func (a *LinuxDiagnosticAgent) sendRequest(messages []openai.ChatCompletionMessage) (*openai.ChatCompletionResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create TensorZero-compatible request
	tzRequest := TensorZeroRequest{
		Model:    a.model,
		Messages: messages,
	}

	// Include tensorzero::episode_id for conversation continuity (if we have one)
	if a.episodeID != "" {
		tzRequest.EpisodeID = a.episodeID
	}

	fmt.Printf("Debug: Sending request to model: %s", a.model)
	if a.episodeID != "" {
		fmt.Printf(" (episode: %s)", a.episodeID)
	}
	fmt.Println()

	// Marshal the request
	requestBody, err := json.Marshal(tzRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	endpoint := os.Getenv("NANNYAPI_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://nannyapi.local:3000/openai/v1"
	}

	// Ensure the endpoint ends with /chat/completions
	if endpoint[len(endpoint)-1] != '/' {
		endpoint += "/"
	}
	endpoint += "chat/completions"

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Make the request
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse TensorZero response
	var tzResponse TensorZeroResponse
	if err := json.Unmarshal(body, &tzResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Extract episode_id from first response
	if a.episodeID == "" && tzResponse.EpisodeID != "" {
		a.episodeID = tzResponse.EpisodeID
		fmt.Printf("Debug: Extracted episode ID: %s\n", a.episodeID)
	}

	return &tzResponse.ChatCompletionResponse, nil
}

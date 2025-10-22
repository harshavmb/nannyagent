package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/sashabaranov/go-openai"
)

// EBPFEnhancedDiagnosticResponse represents an AI response that includes eBPF program requests
type EBPFEnhancedDiagnosticResponse struct {
	ResponseType string        `json:"response_type"`
	Reasoning    string        `json:"reasoning"`
	Commands     []Command     `json:"commands"`
	EBPFPrograms []EBPFRequest `json:"ebpf_programs,omitempty"`
	Description  string        `json:"description,omitempty"`
}

// DiagnoseWithEBPF performs diagnosis using both regular commands and eBPF monitoring
func (a *LinuxDiagnosticAgent) DiagnoseWithEBPF(issue string) error {
	fmt.Printf("Diagnosing issue with eBPF monitoring: %s\n", issue)
	fmt.Println("Gathering system information and eBPF capabilities...")

	// Gather system information
	systemInfo := GatherSystemInfo()

	// Get eBPF capabilities if manager is available
	var ebpfInfo string
	if a.ebpfManager != nil {
		capabilities := a.ebpfManager.GetCapabilities()
		summary := a.ebpfManager.GetSummary()

		commonPrograms := "\nCommon eBPF programs available: 3 programs including UDP monitoring, TCP monitoring, and syscall tracing via Cilium eBPF library"

		ebpfInfo = fmt.Sprintf(`
eBPF MONITORING CAPABILITIES:
- Available capabilities: %v  
- Manager status: %v%s

eBPF USAGE INSTRUCTIONS:
You can request eBPF monitoring by including "ebpf_programs" in your diagnostic response:
{
  "response_type": "diagnostic", 
  "reasoning": "Need to trace system calls to debug the issue",
  "commands": [...regular commands...],
  "ebpf_programs": [
    {
      "name": "syscall_monitor",
      "type": "tracepoint", 
      "target": "syscalls/sys_enter_openat",
      "duration": 15,
      "filters": {"comm": "process_name"},
      "description": "Monitor file open operations"
    }
  ]
}

Available eBPF program types:
- tracepoint: Monitor kernel tracepoints (e.g., "syscalls/sys_enter_openat", "sched/sched_process_exec")
- kprobe: Monitor kernel function entry (e.g., "tcp_connect", "vfs_read") 
- kretprobe: Monitor kernel function return (e.g., "tcp_connect", "vfs_write")

Common targets:
- syscalls/sys_enter_openat (file operations)
- syscalls/sys_enter_execve (process execution) 
- tcp_connect, tcp_sendmsg (network activity)
- vfs_read, vfs_write (file I/O)
`, capabilities, summary, commonPrograms)
	} else {
		ebpfInfo = "\neBPF monitoring not available on this system"
	}

	// Create enhanced system prompt
	initialPrompt := FormatSystemInfoForPrompt(systemInfo) + ebpfInfo +
		fmt.Sprintf("\nISSUE DESCRIPTION: %s", issue)

	// Start conversation
	messages := []openai.ChatCompletionMessage{
		{
			Role:    openai.ChatMessageRoleUser,
			Content: initialPrompt,
		},
	}

	for {
		// Send request to AI
		response, err := a.sendRequest(messages)
		if err != nil {
			return fmt.Errorf("failed to send request: %w", err)
		}

		if len(response.Choices) == 0 {
			return fmt.Errorf("no choices in response")
		}

		content := response.Choices[0].Message.Content
		fmt.Printf("\nAI Response:\n%s\n", content)

		// Try to parse as eBPF-enhanced diagnostic response
		var ebpfResp EBPFEnhancedDiagnosticResponse
		if err := json.Unmarshal([]byte(content), &ebpfResp); err == nil && ebpfResp.ResponseType == "diagnostic" {
			fmt.Printf("\nReasoning: %s\n", ebpfResp.Reasoning)

			// Execute both regular commands and eBPF programs
			result, err := a.executeWithEBPFPrograms(ebpfResp)
			if err != nil {
				return fmt.Errorf("failed to execute with eBPF: %w", err)
			}

			// Add results to conversation
			resultsJSON, err := json.MarshalIndent(result, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal results: %w", err)
			}

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

		// Try to parse as regular diagnostic response
		var diagnosticResp DiagnosticResponse
		if err := json.Unmarshal([]byte(content), &diagnosticResp); err == nil && diagnosticResp.ResponseType == "diagnostic" {
			fmt.Printf("\nReasoning: %s\n", diagnosticResp.Reasoning)

			if len(diagnosticResp.Commands) == 0 {
				fmt.Println("No commands to execute")
				break
			}

			// Execute regular commands only
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

			// Add results to conversation
			resultsJSON, err := json.MarshalIndent(commandResults, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal results: %w", err)
			}

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
		var resolutionResp ResolutionResponse
		if err := json.Unmarshal([]byte(content), &resolutionResp); err == nil && resolutionResp.ResponseType == "resolution" {
			fmt.Printf("\n=== DIAGNOSIS COMPLETE ===\n")
			fmt.Printf("Root Cause: %s\n", resolutionResp.RootCause)
			fmt.Printf("Resolution Plan: %s\n", resolutionResp.ResolutionPlan)
			fmt.Printf("Confidence: %s\n", resolutionResp.Confidence)

			// Show any active eBPF programs
			if a.ebpfManager != nil {
				activePrograms := a.ebpfManager.ListActivePrograms()
				if len(activePrograms) > 0 {
					fmt.Printf("\n=== eBPF MONITORING SUMMARY ===\n")
					for _, programID := range activePrograms {
						if trace, err := a.ebpfManager.GetProgramResults(programID); err == nil {
							fmt.Printf("Program %s: %s\n", programID, trace.Summary)
						}
					}
				}
			}

			break
		}

		// Unknown response format
		fmt.Printf("Unexpected response format:\n%s\n", content)
		break
	}

	return nil
}

// executeWithEBPFPrograms executes regular commands alongside eBPF programs
func (a *LinuxDiagnosticAgent) executeWithEBPFPrograms(resp EBPFEnhancedDiagnosticResponse) (map[string]interface{}, error) {
	result := map[string]interface{}{
		"command_results": make([]CommandResult, 0),
		"ebpf_results":    make(map[string]*EBPFTrace),
	}

	var ebpfProgramIDs []string

	// Debug: Check if eBPF programs were requested
	fmt.Printf("DEBUG: AI requested %d eBPF programs\n", len(resp.EBPFPrograms))
	if a.ebpfManager == nil {
		fmt.Printf("DEBUG: eBPF manager is nil\n")
	} else {
		fmt.Printf("DEBUG: eBPF manager available, capabilities: %v\n", a.ebpfManager.GetCapabilities())
	}

	// Start eBPF programs if requested and available
	if len(resp.EBPFPrograms) > 0 && a.ebpfManager != nil {
		fmt.Printf("Starting %d eBPF monitoring programs...\n", len(resp.EBPFPrograms))

		for _, program := range resp.EBPFPrograms {
			programID, err := a.ebpfManager.StartEBPFProgram(program)
			if err != nil {
				log.Printf("Failed to start eBPF program %s: %v", program.Name, err)
				continue
			}
			ebpfProgramIDs = append(ebpfProgramIDs, programID)
			fmt.Printf("Started eBPF program: %s (%s on %s)\n", programID, program.Type, program.Target)
		}

		// Give eBPF programs time to start
		time.Sleep(200 * time.Millisecond)
	}

	// Execute regular commands
	commandResults := make([]CommandResult, 0, len(resp.Commands))
	for _, cmd := range resp.Commands {
		fmt.Printf("\nExecuting command '%s': %s\n", cmd.ID, cmd.Command)
		cmdResult := a.executor.Execute(cmd)
		commandResults = append(commandResults, cmdResult)

		fmt.Printf("Output:\n%s\n", cmdResult.Output)
		if cmdResult.Error != "" {
			fmt.Printf("Error: %s\n", cmdResult.Error)
		}
	}

	result["command_results"] = commandResults

	// If no eBPF programs were requested but we have eBPF capability and this seems network-related,
	// automatically start UDP monitoring
	if len(ebpfProgramIDs) == 0 && a.ebpfManager != nil && len(resp.EBPFPrograms) == 0 {
		fmt.Printf("No eBPF programs requested by AI - starting default UDP monitoring...\n")

		defaultUDPPrograms := []EBPFRequest{
			{
				Name:        "udp_sendmsg_auto",
				Type:        "kprobe",
				Target:      "udp_sendmsg",
				Duration:    10,
				Description: "Monitor UDP send operations",
			},
			{
				Name:        "udp_recvmsg_auto",
				Type:        "kprobe",
				Target:      "udp_recvmsg",
				Duration:    10,
				Description: "Monitor UDP receive operations",
			},
		}

		for _, program := range defaultUDPPrograms {
			programID, err := a.ebpfManager.StartEBPFProgram(program)
			if err != nil {
				log.Printf("Failed to start default eBPF program %s: %v", program.Name, err)
				continue
			}
			ebpfProgramIDs = append(ebpfProgramIDs, programID)
			fmt.Printf("Started default eBPF program: %s (%s on %s)\n", programID, program.Type, program.Target)
		}
	}

	// Wait for eBPF programs to complete and collect results
	if len(ebpfProgramIDs) > 0 {
		fmt.Printf("Waiting for %d eBPF programs to complete...\n", len(ebpfProgramIDs))

		// Wait for the longest duration + buffer
		maxDuration := 0
		for _, program := range resp.EBPFPrograms {
			if program.Duration > maxDuration {
				maxDuration = program.Duration
			}
		}

		waitTime := time.Duration(maxDuration+2) * time.Second
		if waitTime < 5*time.Second {
			waitTime = 5 * time.Second
		}

		time.Sleep(waitTime)

		// Collect results
		ebpfResults := make(map[string]*EBPFTrace)
		for _, programID := range ebpfProgramIDs {
			if trace, err := a.ebpfManager.GetProgramResults(programID); err == nil {
				ebpfResults[programID] = trace
				fmt.Printf("Collected eBPF results from %s: %d events\n", programID, trace.EventCount)
			} else {
				log.Printf("Failed to get results from eBPF program %s: %v", programID, err)
			}
		}

		result["ebpf_results"] = ebpfResults
	}

	return result, nil
}

// GetEBPFCapabilitiesPrompt returns eBPF capabilities formatted for AI prompts
func (a *LinuxDiagnosticAgent) GetEBPFCapabilitiesPrompt() string {
	if a.ebpfManager == nil {
		return "eBPF monitoring not available"
	}

	capabilities := a.ebpfManager.GetCapabilities()
	summary := a.ebpfManager.GetSummary()

	return fmt.Sprintf(`
eBPF MONITORING SYSTEM STATUS:
- Capabilities: %v
- Manager Status: %v

INTEGRATION INSTRUCTIONS:
To request eBPF monitoring, include "ebpf_programs" array in diagnostic responses.
Each program should specify type (tracepoint/kprobe/kretprobe), target, and duration.
eBPF programs will run in parallel with regular diagnostic commands.
`, capabilities, summary)
}

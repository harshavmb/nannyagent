package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// EBPFEvent represents an event captured by eBPF programs
type EBPFEvent struct {
	Timestamp   int64                  `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	ProcessID   int                    `json:"process_id"`
	ProcessName string                 `json:"process_name"`
	UserID      int                    `json:"user_id"`
	Data        map[string]interface{} `json:"data"`
}

// EBPFTrace represents a collection of eBPF events for a specific investigation
type EBPFTrace struct {
	TraceID     string      `json:"trace_id"`
	StartTime   time.Time   `json:"start_time"`
	EndTime     time.Time   `json:"end_time"`
	Capability  string      `json:"capability"`
	Events      []EBPFEvent `json:"events"`
	Summary     string      `json:"summary"`
	EventCount  int         `json:"event_count"`
	ProcessList []string    `json:"process_list"`
}

// EBPFRequest represents a request to run eBPF monitoring
type EBPFRequest struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`     // "tracepoint", "kprobe", "kretprobe"
	Target      string            `json:"target"`   // tracepoint path or function name
	Duration    int               `json:"duration"` // seconds
	Filters     map[string]string `json:"filters,omitempty"`
	Description string            `json:"description"`
}

// EBPFManagerInterface defines the interface for eBPF managers
type EBPFManagerInterface interface {
	GetCapabilities() map[string]bool
	GetSummary() map[string]interface{}
	StartEBPFProgram(req EBPFRequest) (string, error)
	GetProgramResults(programID string) (*EBPFTrace, error)
	StopProgram(programID string) error
	ListActivePrograms() []string
}

// SimpleEBPFManager implements basic eBPF functionality using bpftrace
type SimpleEBPFManager struct {
	programs       map[string]*RunningProgram
	programsLock   sync.RWMutex
	capabilities   map[string]bool
	programCounter int
}

// RunningProgram represents an active eBPF program
type RunningProgram struct {
	ID        string
	Request   EBPFRequest
	Process   *exec.Cmd
	Events    []EBPFEvent
	StartTime time.Time
	Cancel    context.CancelFunc
}

// NewSimpleEBPFManager creates a new simple eBPF manager
func NewSimpleEBPFManager() *SimpleEBPFManager {
	manager := &SimpleEBPFManager{
		programs:     make(map[string]*RunningProgram),
		capabilities: make(map[string]bool),
	}

	// Test capabilities
	manager.testCapabilities()
	return manager
}

// testCapabilities checks what eBPF capabilities are available
func (em *SimpleEBPFManager) testCapabilities() {
	// Test if bpftrace is available
	if _, err := exec.LookPath("bpftrace"); err == nil {
		em.capabilities["bpftrace"] = true
	}

	// Test root privileges (required for eBPF)
	em.capabilities["root_access"] = os.Geteuid() == 0

	// Test kernel version (simplified check)
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err == nil {
		version := strings.TrimSpace(string(output))
		em.capabilities["kernel_ebpf"] = strings.Contains(version, "4.") || strings.Contains(version, "5.") || strings.Contains(version, "6.")
	} else {
		em.capabilities["kernel_ebpf"] = false
	}

	log.Printf("eBPF capabilities: %+v", em.capabilities)
}

// GetCapabilities returns the available eBPF capabilities
func (em *SimpleEBPFManager) GetCapabilities() map[string]bool {
	em.programsLock.RLock()
	defer em.programsLock.RUnlock()

	caps := make(map[string]bool)
	for k, v := range em.capabilities {
		caps[k] = v
	}
	return caps
}

// GetSummary returns a summary of the eBPF manager state
func (em *SimpleEBPFManager) GetSummary() map[string]interface{} {
	em.programsLock.RLock()
	defer em.programsLock.RUnlock()

	return map[string]interface{}{
		"capabilities":    em.capabilities,
		"active_programs": len(em.programs),
		"program_ids":     em.ListActivePrograms(),
	}
}

// StartEBPFProgram starts a new eBPF monitoring program
func (em *SimpleEBPFManager) StartEBPFProgram(req EBPFRequest) (string, error) {
	if !em.capabilities["bpftrace"] {
		return "", fmt.Errorf("bpftrace not available")
	}

	if !em.capabilities["root_access"] {
		return "", fmt.Errorf("root access required for eBPF programs")
	}

	em.programsLock.Lock()
	defer em.programsLock.Unlock()

	// Generate program ID
	em.programCounter++
	programID := fmt.Sprintf("prog_%d", em.programCounter)

	// Create bpftrace script
	script, err := em.generateBpftraceScript(req)
	if err != nil {
		return "", fmt.Errorf("failed to generate script: %w", err)
	}

	// Start bpftrace process
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Duration)*time.Second)
	cmd := exec.CommandContext(ctx, "bpftrace", "-e", script)

	program := &RunningProgram{
		ID:        programID,
		Request:   req,
		Process:   cmd,
		Events:    []EBPFEvent{},
		StartTime: time.Now(),
		Cancel:    cancel,
	}

	// Start the program
	if err := cmd.Start(); err != nil {
		cancel()
		return "", fmt.Errorf("failed to start bpftrace: %w", err)
	}

	em.programs[programID] = program

	// Monitor the program in a goroutine
	go em.monitorProgram(programID)

	log.Printf("Started eBPF program %s for %s", programID, req.Name)
	return programID, nil
}

// generateBpftraceScript creates a bpftrace script based on the request
func (em *SimpleEBPFManager) generateBpftraceScript(req EBPFRequest) (string, error) {
	switch req.Type {
	case "network":
		return `
BEGIN {
	printf("Starting network monitoring...\n");
}

tracepoint:syscalls:sys_enter_connect,
tracepoint:syscalls:sys_enter_accept,
tracepoint:syscalls:sys_enter_recvfrom,
tracepoint:syscalls:sys_enter_sendto {
	printf("NETWORK|%d|%s|%d|%s\n", nsecs, probe, pid, comm);
}

END {
	printf("Network monitoring completed\n");
}`, nil

	case "process":
		return `
BEGIN {
	printf("Starting process monitoring...\n");
}

tracepoint:syscalls:sys_enter_execve,
tracepoint:syscalls:sys_enter_fork,
tracepoint:syscalls:sys_enter_clone {
	printf("PROCESS|%d|%s|%d|%s\n", nsecs, probe, pid, comm);
}

END {
	printf("Process monitoring completed\n");
}`, nil

	case "file":
		return `
BEGIN {
	printf("Starting file monitoring...\n");
}

tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat,
tracepoint:syscalls:sys_enter_read,
tracepoint:syscalls:sys_enter_write {
	printf("FILE|%d|%s|%d|%s\n", nsecs, probe, pid, comm);
}

END {
	printf("File monitoring completed\n");
}`, nil

	default:
		return "", fmt.Errorf("unsupported eBPF program type: %s", req.Type)
	}
}

// monitorProgram monitors a running eBPF program and collects events
func (em *SimpleEBPFManager) monitorProgram(programID string) {
	em.programsLock.Lock()
	program, exists := em.programs[programID]
	if !exists {
		em.programsLock.Unlock()
		return
	}
	em.programsLock.Unlock()

	// Wait for the program to complete
	err := program.Process.Wait()

	// Clean up
	program.Cancel()

	em.programsLock.Lock()
	if err != nil {
		log.Printf("eBPF program %s completed with error: %v", programID, err)
	} else {
		log.Printf("eBPF program %s completed successfully", programID)
	}

	// Parse output and generate events (simplified for demo)
	// In a real implementation, you would parse the bpftrace output
	program.Events = []EBPFEvent{
		{
			Timestamp:   time.Now().Unix(),
			EventType:   program.Request.Type,
			ProcessID:   0,
			ProcessName: "example",
			UserID:      0,
			Data: map[string]interface{}{
				"description": "Sample eBPF event",
				"program_id":  programID,
			},
		},
	}
	em.programsLock.Unlock()

	log.Printf("Generated %d events for program %s", len(program.Events), programID)
}

// GetProgramResults returns the results of a completed program
func (em *SimpleEBPFManager) GetProgramResults(programID string) (*EBPFTrace, error) {
	em.programsLock.RLock()
	defer em.programsLock.RUnlock()

	program, exists := em.programs[programID]
	if !exists {
		return nil, fmt.Errorf("program %s not found", programID)
	}

	// Check if program is still running
	if program.Process.ProcessState == nil {
		return nil, fmt.Errorf("program %s is still running", programID)
	}

	events := make([]EBPFEvent, len(program.Events))
	copy(events, program.Events)

	processes := make([]string, 0)
	processMap := make(map[string]bool)
	for _, event := range events {
		if !processMap[event.ProcessName] {
			processes = append(processes, event.ProcessName)
			processMap[event.ProcessName] = true
		}
	}

	trace := &EBPFTrace{
		TraceID:     programID,
		StartTime:   program.StartTime,
		EndTime:     time.Now(),
		Capability:  program.Request.Type,
		Events:      events,
		EventCount:  len(events),
		ProcessList: processes,
		Summary:     fmt.Sprintf("Collected %d events for %s monitoring", len(events), program.Request.Type),
	}

	return trace, nil
}

// StopProgram stops a running eBPF program
func (em *SimpleEBPFManager) StopProgram(programID string) error {
	em.programsLock.Lock()
	defer em.programsLock.Unlock()

	program, exists := em.programs[programID]
	if !exists {
		return fmt.Errorf("program %s not found", programID)
	}

	// Cancel the context and kill the process
	program.Cancel()
	if program.Process.Process != nil {
		program.Process.Process.Kill()
	}

	delete(em.programs, programID)
	log.Printf("Stopped eBPF program %s", programID)
	return nil
}

// ListActivePrograms returns a list of active program IDs
func (em *SimpleEBPFManager) ListActivePrograms() []string {
	em.programsLock.RLock()
	defer em.programsLock.RUnlock()

	programs := make([]string, 0, len(em.programs))
	for id := range em.programs {
		programs = append(programs, id)
	}
	return programs
}

// GetCommonEBPFRequests returns predefined eBPF programs for common use cases
func (em *SimpleEBPFManager) GetCommonEBPFRequests() []EBPFRequest {
	return []EBPFRequest{
		{
			Name:        "network_activity",
			Type:        "network",
			Target:      "syscalls:sys_enter_connect,sys_enter_accept,sys_enter_recvfrom,sys_enter_sendto",
			Duration:    30,
			Description: "Monitor network connections and data transfers",
		},
		{
			Name:        "process_activity",
			Type:        "process",
			Target:      "syscalls:sys_enter_execve,sys_enter_fork,sys_enter_clone",
			Duration:    30,
			Description: "Monitor process creation and execution",
		},
		{
			Name:        "file_access",
			Type:        "file",
			Target:      "syscalls:sys_enter_open,sys_enter_openat,sys_enter_read,sys_enter_write",
			Duration:    30,
			Description: "Monitor file system access and I/O operations",
		},
	}
}

// Helper functions - using system_info.go functions
// isRoot and checkKernelVersion are available from system_info.go

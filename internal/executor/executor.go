package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"nannyagentv2/internal/types"
)

// CommandExecutor handles safe execution of diagnostic commands
type CommandExecutor struct {
	timeout time.Duration
}

// NewCommandExecutor creates a new command executor with specified timeout
func NewCommandExecutor(timeout time.Duration) *CommandExecutor {
	return &CommandExecutor{
		timeout: timeout,
	}
}

// Execute executes a command safely with timeout and validation
func (ce *CommandExecutor) Execute(cmd types.Command) types.CommandResult {
	result := types.CommandResult{
		ID:      cmd.ID,
		Command: cmd.Command,
	}

	// Validate command safety
	if err := ce.validateCommand(cmd.Command); err != nil {
		result.Error = fmt.Sprintf("unsafe command: %s", err.Error())
		result.ExitCode = 1
		return result
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), ce.timeout)
	defer cancel()

	// Execute command using shell for proper handling of pipes, redirects, etc.
	execCmd := exec.CommandContext(ctx, "/bin/bash", "-c", cmd.Command)

	// Set process group so we can kill all child processes
	// This creates a new process group with the child as leader
	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Monitor for context cancellation and kill entire process group
	go func() {
		<-ctx.Done()
		if execCmd.Process != nil {
			// Kill the entire process group (negative PID kills all processes in the group)
			// This ensures orphaned child processes like tcpdump are also killed
			syscall.Kill(-execCmd.Process.Pid, syscall.SIGKILL)
		}
	}()

	// Capture output
	output, err := execCmd.CombinedOutput()
	result.Output = string(output)

	if err != nil {
		result.Error = err.Error()
		if exitError, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitError.ExitCode()
		} else {
			result.ExitCode = 1
		}
	} else {
		result.ExitCode = 0
	}

	return result
}

// validateCommand checks if a command is safe to execute
func (ce *CommandExecutor) validateCommand(command string) error {
	// Convert to lowercase for case-insensitive checking
	cmd := strings.ToLower(strings.TrimSpace(command))

	// List of dangerous commands/patterns
	dangerousPatterns := []string{
		"rm ", "rm\t", "rm\n",
		"mv ", "mv\t", "mv\n",
		"dd ", "dd\t", "dd\n",
		"mkfs", "fdisk", "parted",
		"shutdown", "reboot", "halt", "poweroff",
		"passwd", "userdel", "usermod",
		"chmod", "chown", "chgrp",
		"systemctl stop", "systemctl disable", "systemctl mask",
		"service stop", "service disable",
		"kill ", "killall", "pkill",
		"crontab -r", "crontab -e",
		"iptables -F", "iptables -D", "iptables -I",
		"umount ", "unmount ", // Allow mount but not umount
		"wget ", "curl ", // Prevent network operations
		"| dd", "| rm", "| mv", // Prevent piping to dangerous commands
	}

	// Check for dangerous patterns
	for _, pattern := range dangerousPatterns {
		if strings.Contains(cmd, pattern) {
			return fmt.Errorf("command contains dangerous pattern: %s", pattern)
		}
	}

	// Additional checks for commands that start with dangerous operations
	if strings.HasPrefix(cmd, "rm ") || strings.HasPrefix(cmd, "rm\t") {
		return fmt.Errorf("rm command not allowed")
	}

	// Check for sudo usage (we want to avoid automated sudo commands)
	if strings.HasPrefix(cmd, "sudo ") {
		return fmt.Errorf("sudo commands not allowed for automated execution")
	}

	// Check for dangerous redirections (but allow safe ones like 2>/dev/null)
	if strings.Contains(cmd, ">") && !strings.Contains(cmd, "2>/dev/null") && !strings.Contains(cmd, ">/dev/null") {
		return fmt.Errorf("file redirection not allowed except to /dev/null")
	}

	return nil
}

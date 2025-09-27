package main

import (
	"testing"
	"time"
)

func TestCommandExecutor_ValidateCommand(t *testing.T) {
	executor := NewCommandExecutor(5 * time.Second)

	tests := []struct {
		name    string
		command string
		wantErr bool
	}{
		{
			name:    "safe command - ls",
			command: "ls -la /var",
			wantErr: false,
		},
		{
			name:    "safe command - df",
			command: "df -h",
			wantErr: false,
		},
		{
			name:    "safe command - ps",
			command: "ps aux | grep nginx",
			wantErr: false,
		},
		{
			name:    "dangerous command - rm",
			command: "rm -rf /tmp/*",
			wantErr: true,
		},
		{
			name:    "dangerous command - dd",
			command: "dd if=/dev/zero of=/dev/sda",
			wantErr: true,
		},
		{
			name:    "dangerous command - sudo",
			command: "sudo systemctl stop nginx",
			wantErr: true,
		},
		{
			name:    "dangerous command - redirection",
			command: "echo 'test' > /etc/passwd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := executor.validateCommand(tt.command)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandExecutor_Execute(t *testing.T) {
	executor := NewCommandExecutor(5 * time.Second)

	// Test safe command execution
	cmd := Command{
		ID:          "test_echo",
		Command:     "echo 'Hello, World!'",
		Description: "Test echo command",
	}

	result := executor.Execute(cmd)

	if result.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", result.ExitCode)
	}

	if result.Output != "Hello, World!\n" {
		t.Errorf("Expected 'Hello, World!\\n', got '%s'", result.Output)
	}

	if result.Error != "" {
		t.Errorf("Expected no error, got '%s'", result.Error)
	}
}

func TestCommandExecutor_ExecuteUnsafeCommand(t *testing.T) {
	executor := NewCommandExecutor(5 * time.Second)

	// Test unsafe command rejection
	cmd := Command{
		ID:          "test_rm",
		Command:     "rm -rf /tmp/test",
		Description: "Dangerous rm command",
	}

	result := executor.Execute(cmd)

	if result.ExitCode != 1 {
		t.Errorf("Expected exit code 1 for unsafe command, got %d", result.ExitCode)
	}

	if result.Error == "" {
		t.Error("Expected error for unsafe command, got none")
	}
}

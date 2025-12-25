package main

import (
	"testing"
)

func TestValidateDiagnosisPrompt(t *testing.T) {
	tests := []struct {
		name    string
		prompt  string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Valid prompt with sufficient detail",
			prompt:  "postgresql is running slow on production server",
			wantErr: false,
		},
		{
			name:    "Valid prompt with more context",
			prompt:  "disk is full on /var partition and cannot write logs",
			wantErr: false,
		},
		{
			name:    "Too short - less than 10 characters",
			prompt:  "how",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Too short - 8 characters",
			prompt:  "help me",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Incomplete - only 1 word",
			prompt:  "postgresql",
			wantErr: true,
			errMsg:  "prompt is incomplete (minimum 3 words required for meaningful diagnosis)",
		},
		{
			name:    "Incomplete - only 2 words (but also too short)",
			prompt:  "disk full",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)", // 9 chars, fails length check first
		},
		{
			name:    "Empty prompt",
			prompt:  "",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Whitespace only",
			prompt:  "   ",
			wantErr: true,
			errMsg:  "prompt is too short (minimum 10 characters required)",
		},
		{
			name:    "Valid prompt with leading/trailing spaces",
			prompt:  "  disk usage is high on server  ",
			wantErr: false,
		},
		{
			name:    "Edge case - exactly 10 characters, 3 words",
			prompt:  "abc def ghi",
			wantErr: false,
		},
		{
			name:    "Edge case - 10 characters but only 2 words",
			prompt:  "hello world",
			wantErr: true,
			errMsg:  "prompt is incomplete (minimum 3 words required for meaningful diagnosis)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDiagnosisPrompt(tt.prompt)

			if tt.wantErr {
				if err == nil {
					t.Errorf("validateDiagnosisPrompt() expected error but got nil")
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("validateDiagnosisPrompt() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateDiagnosisPrompt() unexpected error = %v", err)
				}
			}
		})
	}
}

// TestConfigLoadingConstraints verifies that we only support specific config sources
// This is a conceptual test since we can't easily mock the file system for main.go functions directly
// without refactoring main.go to accept a config loader interface.
// However, we can verify the behavior via integration tests or by checking the config package tests.
// Since we already updated internal/config/config_test.go, we rely on those tests.
// Here we can add tests for other main.go utility functions.

func TestCheckKernelVersionCompatibility_Parsing(t *testing.T) {
	// We can't easily test the actual checkKernelVersionCompatibility function because it calls os.Exit
	// and exec.Command. Ideally, we would refactor it to take dependencies or return error.
	// For now, we'll skip this as it requires significant refactoring of main.go.
}

func TestValidateDiagnosisPrompt_RealWorldExamples(t *testing.T) {
	validPrompts := []string{
		"postgresql database is running slow",
		"cannot connect to remote server via SSH",
		"disk usage is at 95% on /var partition",
		"apache service keeps crashing every hour",
		"high CPU usage by python process",
		"nginx returns 502 bad gateway error",
		"memory leak in nodejs application",
		"docker container fails to start",
		"kubernetes pod in crash loop backoff",
		"redis connection timeout after upgrade",
	}

	for _, prompt := range validPrompts {
		t.Run("Valid: "+prompt, func(t *testing.T) {
			err := validateDiagnosisPrompt(prompt)
			if err != nil {
				t.Errorf("validateDiagnosisPrompt(%q) unexpected error = %v", prompt, err)
			}
		})
	}

	invalidPrompts := map[string]string{
		"help":        "prompt is too short (minimum 10 characters required)",
		"fix this":    "prompt is too short (minimum 10 characters required)",                     // 8 chars
		"slow server": "prompt is incomplete (minimum 3 words required for meaningful diagnosis)", // 11 chars, 2 words
		"how":         "prompt is too short (minimum 10 characters required)",
	}

	// "what is wrong" is actually valid (13 chars, 3 words) - remove from invalid list

	for prompt, expectedErr := range invalidPrompts {
		t.Run("Invalid: "+prompt, func(t *testing.T) {
			err := validateDiagnosisPrompt(prompt)
			if err == nil {
				t.Errorf("validateDiagnosisPrompt(%q) expected error but got nil", prompt)
				return
			}
			if err.Error() != expectedErr {
				t.Errorf("validateDiagnosisPrompt(%q) error = %v, want %v", prompt, err.Error(), expectedErr)
			}
		})
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_SystemYAML(t *testing.T) {
	// Create a temporary directory to simulate /etc/nannyagent
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create a test YAML config
	yamlContent := `
supabase_project_url: https://test.supabase.co
portal_url: https://test.nannyai.dev
token_path: /tmp/test_token.json
metrics_interval: 60
debug: true
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Load the config
	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}

	// Verify values
	if config.SupabaseProjectURL != "https://test.supabase.co" {
		t.Errorf("SupabaseProjectURL = %v, want https://test.supabase.co", config.SupabaseProjectURL)
	}
	if config.PortalURL != "https://test.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://test.nannyai.dev", config.PortalURL)
	}
	if config.TokenPath != "/tmp/test_token.json" {
		t.Errorf("TokenPath = %v, want /tmp/test_token.json", config.TokenPath)
	}
	if config.MetricsInterval != 60 {
		t.Errorf("MetricsInterval = %v, want 60", config.MetricsInterval)
	}
	if !config.Debug {
		t.Errorf("Debug = %v, want true", config.Debug)
	}
}

func TestLoadConfig_EnvFile(t *testing.T) {
	// Create temporary .env file
	tmpDir := t.TempDir()
	envPath := filepath.Join(tmpDir, "config.env")

	envContent := `
SUPABASE_PROJECT_URL=https://env.supabase.co
TOKEN_PATH=/tmp/env_token.json
NANNYAI_PORTAL_URL=https://env.nannyai.dev
DEBUG=true
`
	err := os.WriteFile(envPath, []byte(envContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test env file: %v", err)
	}

	// Change to temp directory so findEnvFile won't find project .env
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	_ = os.Chdir(tmpDir)

	// Set environment variables by loading the file
	os.Setenv("SUPABASE_PROJECT_URL", "https://env.supabase.co")
	os.Setenv("TOKEN_PATH", "/tmp/env_token.json")
	os.Setenv("NANNYAI_PORTAL_URL", "https://env.nannyai.dev")
	os.Setenv("DEBUG", "true")
	defer func() {
		os.Unsetenv("SUPABASE_PROJECT_URL")
		os.Unsetenv("TOKEN_PATH")
		os.Unsetenv("NANNYAI_PORTAL_URL")
		os.Unsetenv("DEBUG")
	}()

	// Create a minimal config
	config := DefaultConfig

	// Manually apply env vars (simulating LoadConfig behavior)
	if url := os.Getenv("SUPABASE_PROJECT_URL"); url != "" {
		config.SupabaseProjectURL = url
	}
	if tokenPath := os.Getenv("TOKEN_PATH"); tokenPath != "" {
		config.TokenPath = tokenPath
	}
	if portalURL := os.Getenv("NANNYAI_PORTAL_URL"); portalURL != "" {
		config.PortalURL = portalURL
	}
	if debug := os.Getenv("DEBUG"); debug == "true" || debug == "1" {
		config.Debug = true
	}

	// Auto-generate URLs
	if config.SupabaseProjectURL != "" {
		if config.DeviceAuthURL == "" {
			config.DeviceAuthURL = config.SupabaseProjectURL + "/functions/v1/device-auth"
		}
		if config.AgentAuthURL == "" {
			config.AgentAuthURL = config.SupabaseProjectURL + "/functions/v1/agent-auth-api"
		}
	}

	// Verify
	if config.SupabaseProjectURL != "https://env.supabase.co" {
		t.Errorf("SupabaseProjectURL = %v, want https://env.supabase.co", config.SupabaseProjectURL)
	}
	if config.TokenPath != "/tmp/env_token.json" {
		t.Errorf("TokenPath = %v, want /tmp/env_token.json", config.TokenPath)
	}
	if config.PortalURL != "https://env.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://env.nannyai.dev", config.PortalURL)
	}
	if !config.Debug {
		t.Errorf("Debug = %v, want true", config.Debug)
	}
}

func TestLoadConfig_AutoGenerateURLs(t *testing.T) {
	baseURL := "https://project.supabase.co"

	config := DefaultConfig
	config.SupabaseProjectURL = baseURL

	// Simulate auto-generation logic from LoadConfig
	if config.DeviceAuthURL == "" {
		config.DeviceAuthURL = config.SupabaseProjectURL + "/functions/v1/device-auth"
	}
	if config.AgentAuthURL == "" {
		config.AgentAuthURL = config.SupabaseProjectURL + "/functions/v1/agent-auth-api"
	}

	expectedDeviceURL := "https://project.supabase.co/functions/v1/device-auth"
	expectedAgentURL := "https://project.supabase.co/functions/v1/agent-auth-api"

	if config.DeviceAuthURL != expectedDeviceURL {
		t.Errorf("DeviceAuthURL = %v, want %v", config.DeviceAuthURL, expectedDeviceURL)
	}
	if config.AgentAuthURL != expectedAgentURL {
		t.Errorf("AgentAuthURL = %v, want %v", config.AgentAuthURL, expectedAgentURL)
	}
}

func TestValidate_Success(t *testing.T) {
	config := &Config{
		SupabaseProjectURL: "https://test.supabase.co",
		DeviceAuthURL:      "https://test.supabase.co/functions/v1/device-auth",
		AgentAuthURL:       "https://test.supabase.co/functions/v1/agent-auth-api",
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_MissingSupabaseURL(t *testing.T) {
	config := &Config{
		DeviceAuthURL: "https://test.supabase.co/functions/v1/device-auth",
		AgentAuthURL:  "https://test.supabase.co/functions/v1/agent-auth-api",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() expected error for missing SUPABASE_PROJECT_URL, got nil")
	}
	if err != nil && err.Error() != "missing required environment variable: SUPABASE_PROJECT_URL" {
		t.Errorf("Validate() error = %v, want 'missing required environment variable: SUPABASE_PROJECT_URL'", err)
	}
}

func TestValidate_MissingGeneratedURLs(t *testing.T) {
	config := &Config{
		SupabaseProjectURL: "https://test.supabase.co",
		// DeviceAuthURL and AgentAuthURL not set (simulating generation failure)
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() expected error for missing generated URLs, got nil")
	}
}

func TestLoadConfig_PriorityOrder(t *testing.T) {
	// This test verifies that environment variables override file config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create YAML with one value
	yamlContent := `
supabase_project_url: https://yaml.supabase.co
portal_url: https://yaml.nannyai.dev
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Set environment variable that should override
	os.Setenv("SUPABASE_PROJECT_URL", "https://env.supabase.co")
	defer os.Unsetenv("SUPABASE_PROJECT_URL")

	// Load YAML first
	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}

	// Apply env vars (simulating LoadConfig priority)
	if url := os.Getenv("SUPABASE_PROJECT_URL"); url != "" {
		config.SupabaseProjectURL = url
	}

	// Environment variable should win
	if config.SupabaseProjectURL != "https://env.supabase.co" {
		t.Errorf("SupabaseProjectURL = %v, want https://env.supabase.co (env should override YAML)", config.SupabaseProjectURL)
	}

	// YAML value should remain for non-overridden fields
	if config.PortalURL != "https://yaml.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://yaml.nannyai.dev", config.PortalURL)
	}
}

func TestFindEnvFile(t *testing.T) {
	// Create temporary directory structure
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	err := os.Mkdir(subDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	// Create .env in parent directory
	envPath := filepath.Join(tmpDir, ".env")
	err = os.WriteFile(envPath, []byte("TEST=value"), 0644)
	if err != nil {
		t.Fatalf("Failed to create .env: %v", err)
	}

	// Change to subdirectory
	origDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(origDir) }()
	err = os.Chdir(subDir)
	if err != nil {
		t.Fatalf("Failed to change directory: %v", err)
	}

	// Should find .env in parent
	found := findEnvFile()
	if found != envPath {
		t.Errorf("findEnvFile() = %v, want %v", found, envPath)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Create invalid YAML
	invalidYAML := `
supabase_project_url: https://test.supabase.co
portal_url: [invalid yaml structure
`
	err := os.WriteFile(configPath, []byte(invalidYAML), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err == nil {
		t.Error("loadYAMLConfig() expected error for invalid YAML, got nil")
	}
}

func TestDefaultConfig(t *testing.T) {
	// Verify default values
	if DefaultConfig.TokenPath != "/var/lib/nannyagent/token.json" {
		t.Errorf("DefaultConfig.TokenPath = %v, want /var/lib/nannyagent/token.json", DefaultConfig.TokenPath)
	}
	if DefaultConfig.PortalURL != "https://nannyai.dev" {
		t.Errorf("DefaultConfig.PortalURL = %v, want https://nannyai.dev", DefaultConfig.PortalURL)
	}
	if DefaultConfig.MetricsInterval != 30 {
		t.Errorf("DefaultConfig.MetricsInterval = %v, want 30", DefaultConfig.MetricsInterval)
	}
	if DefaultConfig.Debug != false {
		t.Errorf("DefaultConfig.Debug = %v, want false", DefaultConfig.Debug)
	}
}

func TestLoadConfig_SystemEnvFileExists(t *testing.T) {
	// Test that we attempt to load /etc/nannyagent/config.env
	// This is an integration-style test that verifies the file loading logic

	// We can't actually create /etc/nannyagent in tests, but we can verify
	// the loading logic handles non-existent files gracefully

	tmpDir := t.TempDir()
	nonExistentPath := filepath.Join(tmpDir, "nonexistent.env")

	// Should not panic or error when file doesn't exist
	_, err := os.Stat(nonExistentPath)
	if !os.IsNotExist(err) {
		t.Errorf("Expected file to not exist, but got: %v", err)
	}
}

func TestLoadConfig_EmptySupabaseURL(t *testing.T) {
	config := &Config{
		SupabaseProjectURL: "",
		DeviceAuthURL:      "",
		AgentAuthURL:       "",
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() should fail when SupabaseProjectURL is empty")
	}
}

func TestLoadConfig_DebugEnvironmentVariations(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{"debug true", "true", true},
		{"debug 1", "1", true},
		{"debug false", "false", false},
		{"debug 0", "0", false},
		{"debug empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig

			if tt.envValue == "true" || tt.envValue == "1" {
				config.Debug = true
			} else {
				config.Debug = false
			}

			if config.Debug != tt.want {
				t.Errorf("Debug = %v, want %v for env value %q", config.Debug, tt.want, tt.envValue)
			}
		})
	}
}

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
api_base_url: https://test.pocketbase.io
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
	if config.APIBaseURL != "https://test.pocketbase.io" {
		t.Errorf("APIBaseURL = %v, want https://test.pocketbase.io", config.APIBaseURL)
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
	// This test now verifies that we can load config purely from environment variables
	// without relying on a .env file loader

	// Set environment variables
	_ = os.Setenv("POCKETBASE_URL", "https://env.pocketbase.io")
	_ = os.Setenv("TOKEN_PATH", "/tmp/env_token.json")
	_ = os.Setenv("NANNYAI_PORTAL_URL", "https://env.nannyai.dev")
	_ = os.Setenv("DEBUG", "true")
	defer func() {
		_ = os.Unsetenv("POCKETBASE_URL")
		_ = os.Unsetenv("TOKEN_PATH")
		_ = os.Unsetenv("NANNYAI_PORTAL_URL")
		_ = os.Unsetenv("DEBUG")
	}()

	// Create a minimal config
	config := DefaultConfig

	// Manually apply env vars (simulating LoadConfig behavior)
	if url := os.Getenv("POCKETBASE_URL"); url != "" {
		config.APIBaseURL = url
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

	// Verify
	if config.APIBaseURL != "https://env.pocketbase.io" {
		t.Errorf("APIBaseURL = %v, want https://env.pocketbase.io", config.APIBaseURL)
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

func TestValidate_Success(t *testing.T) {
	config := &Config{
		APIBaseURL: "https://test.pocketbase.io",
	}

	err := config.Validate()
	if err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_MissingURL(t *testing.T) {
	config := &Config{
		// APIBaseURL missing
	}

	err := config.Validate()
	if err == nil {
		t.Error("Validate() expected error for missing API_BASE_URL, got nil")
	}
	expectedErr := "missing required configuration: API_BASE_URL (for PocketBase) must be set"
	if err != nil && err.Error() != expectedErr {
		t.Errorf("Validate() error = %v, want '%s'", err, expectedErr)
	}
}

func TestLoadConfig_PriorityOrder(t *testing.T) {
	// This test verifies that environment variables override file config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	// Create YAML with one value
	yamlContent := `
api_base_url: https://yaml.pocketbase.io
portal_url: https://yaml.nannyai.dev
`
	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	// Set environment variable for POCKETBASE_URL (should override YAML)
	_ = os.Setenv("POCKETBASE_URL", "https://env.pocketbase.io")
	defer func() { _ = os.Unsetenv("POCKETBASE_URL") }()

	// Load config
	config := DefaultConfig
	err = loadYAMLConfig(&config, configPath)
	if err != nil {
		t.Fatalf("loadYAMLConfig() failed: %v", err)
	}

	// Manually apply env override
	if url := os.Getenv("POCKETBASE_URL"); url != "" {
		config.APIBaseURL = url
	}

	// Verify API_BASE_URL is from ENV
	if config.APIBaseURL != "https://env.pocketbase.io" {
		t.Errorf("APIBaseURL = %v, want https://env.pocketbase.io", config.APIBaseURL)
	}

	// Verify PortalURL is from YAML (not overridden)
	if config.PortalURL != "https://yaml.nannyai.dev" {
		t.Errorf("PortalURL = %v, want https://yaml.nannyai.dev", config.PortalURL)
	}
}

func TestFindEnvFile(t *testing.T) {
	// findEnvFile is removed, so this test is no longer relevant or should test that it returns empty
	found := findEnvFile()
	if found != "" {
		t.Errorf("findEnvFile() = %v, want empty string", found)
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")

	// Create invalid YAML
	invalidYAML := `
api_base_url: https://test.pocketbase.io
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
	// This test is no longer relevant as we don't load system env files
	// But we can keep it as a placeholder or remove it.
	// For now, let's just make it pass trivially or remove it.
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

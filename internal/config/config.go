package config

import (
	"fmt"
	"os"
	"path/filepath"

	"nannyagentv2/internal/logging"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Supabase Configuration
	SupabaseProjectURL string `yaml:"supabase_project_url"`

	// Edge Function Endpoints (auto-generated from SupabaseProjectURL)
	DeviceAuthURL string `yaml:"device_auth_url"`
	AgentAuthURL  string `yaml:"agent_auth_url"`

	// Portal URL for device authorization
	PortalURL string `yaml:"portal_url"`

	// Agent Configuration
	TokenPath       string `yaml:"token_path"`
	MetricsInterval int    `yaml:"metrics_interval"`

	// Debug/Development
	Debug bool `yaml:"debug"`
}

var DefaultConfig = Config{
	TokenPath:       "/var/lib/nannyagent/token.json", // Default to system directory
	PortalURL:       "https://nannyai.dev",            // Default portal URL
	MetricsInterval: 30,
	Debug:           false,
}

// LoadConfig loads configuration from YAML or .env file
func LoadConfig() (*Config, error) {
	config := DefaultConfig

	// Priority order for loading configuration:
	// 1. /etc/nannyagent/config.yaml (system-wide YAML)
	// 2. /etc/nannyagent/config.env (system-wide .env for backward compatibility)
	// 3. ./config.yaml (local YAML for development)
	// 4. ./.env file (local .env for development)
	// 5. Environment variables (highest priority overrides)

	configLoaded := false

	// Try system-wide YAML config first
	if err := loadYAMLConfig(&config, "/etc/nannyagent/config.yaml"); err == nil {
		logging.Info("Loaded configuration from /etc/nannyagent/config.yaml")
		configLoaded = true
	}

	// Try system-wide .env config (backward compatibility)
	if !configLoaded {
		if _, err := os.Stat("/etc/nannyagent/config.env"); err == nil {
			if err := godotenv.Load("/etc/nannyagent/config.env"); err != nil {
				logging.Warning("Could not load /etc/nannyagent/config.env: %v", err)
			} else {
				logging.Info("Loaded configuration from /etc/nannyagent/config.env")
				configLoaded = true
			}
		}
	}

	// Try local YAML config
	if !configLoaded {
		if err := loadYAMLConfig(&config, "config.yaml"); err == nil {
			logging.Info("Loaded configuration from ./config.yaml")
			configLoaded = true
		}
	}

	// If system config not found, try local .env file
	if !configLoaded {
		envFile := findEnvFile()
		if envFile != "" {
			if err := godotenv.Load(envFile); err != nil {
				logging.Warning("Could not load .env file from %s: %v", envFile, err)
			} else {
				logging.Info("Loaded configuration from %s", envFile)
				configLoaded = true
			}
		}
	}

	if !configLoaded {
		logging.Warning("No configuration file found. Using environment variables only.")
	}

	// Load from environment variables (highest priority - overrides file config)
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

	// Auto-generate edge function URLs from project URL if not explicitly set
	if config.SupabaseProjectURL != "" {
		if config.DeviceAuthURL == "" {
			config.DeviceAuthURL = fmt.Sprintf("%s/functions/v1/device-auth", config.SupabaseProjectURL)
		}
		if config.AgentAuthURL == "" {
			config.AgentAuthURL = fmt.Sprintf("%s/functions/v1/agent-auth-api", config.SupabaseProjectURL)
		}
	}

	// Validate required configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// loadYAMLConfig loads configuration from a YAML file
func loadYAMLConfig(config *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return fmt.Errorf("failed to parse YAML config: %w", err)
	}

	return nil
}

// Validate checks if all required configuration is present
func (c *Config) Validate() error {
	// Only SUPABASE_PROJECT_URL is required
	// DeviceAuthURL and AgentAuthURL are auto-generated from it
	if c.SupabaseProjectURL == "" {
		return fmt.Errorf("missing required environment variable: SUPABASE_PROJECT_URL")
	}

	// Ensure auto-generated URLs are present (should be set by LoadConfig)
	if c.DeviceAuthURL == "" || c.AgentAuthURL == "" {
		return fmt.Errorf("failed to generate API endpoints from SUPABASE_PROJECT_URL")
	}

	return nil
}

// findEnvFile looks for .env file in current directory and parent directories
func findEnvFile() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		envPath := filepath.Join(dir, ".env")
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

// PrintConfig prints the current configuration (masking sensitive values)
func (c *Config) PrintConfig() {
	if !c.Debug {
		return
	}

	logging.Debug("Configuration:")
	logging.Debug("  Supabase Project URL: %s", c.SupabaseProjectURL)
	logging.Debug("  Metrics Interval: %d seconds", c.MetricsInterval)
	logging.Debug("  Debug: %v", c.Debug)
}

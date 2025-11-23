package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"nannyagentv2/internal/logging"

	"github.com/joho/godotenv"
)

type Config struct {
	// Supabase Configuration
	SupabaseProjectURL string

	// Edge Function Endpoints (auto-generated from SupabaseProjectURL)
	DeviceAuthURL string
	AgentAuthURL  string

	// Portal URL for device authorization
	PortalURL string

	// Agent Configuration
	TokenPath       string
	MetricsInterval int

	// Debug/Development
	Debug bool
}

var DefaultConfig = Config{
	TokenPath:       "/var/lib/nannyagent/token.json", // Default to system directory
	PortalURL:       "https://nannyai.dev",            // Default portal URL
	MetricsInterval: 30,
	Debug:           false,
}

// LoadConfig loads configuration from environment variables and .env file
func LoadConfig() (*Config, error) {
	config := DefaultConfig

	// Priority order for loading configuration:
	// 1. /etc/nannyagent/config.env (system-wide installation)
	// 2. Current directory .env file (development)
	// 3. Parent directory .env file (development)

	configLoaded := false

	// Try system-wide config first
	if _, err := os.Stat("/etc/nannyagent/config.env"); err == nil {
		if err := godotenv.Load("/etc/nannyagent/config.env"); err != nil {
			logging.Warning("Could not load /etc/nannyagent/config.env: %v", err)
		} else {
			logging.Info("Loaded configuration from /etc/nannyagent/config.env")
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

	// Load from environment variables
	if url := os.Getenv("SUPABASE_PROJECT_URL"); url != "" {
		config.SupabaseProjectURL = url
	}

	if tokenPath := os.Getenv("TOKEN_PATH"); tokenPath != "" {
		config.TokenPath = tokenPath
	} else {
		// Default to /var/lib/nannyagent/ if not set
		config.TokenPath = "/var/lib/nannyagent/token.json"
	}

	if portalURL := os.Getenv("NANNYAI_PORTAL_URL"); portalURL != "" {
		config.PortalURL = portalURL
	}

	if debug := os.Getenv("DEBUG"); debug == "true" || debug == "1" {
		config.Debug = true
	}

	// Auto-generate edge function URLs from project URL
	if config.SupabaseProjectURL != "" {
		config.DeviceAuthURL = fmt.Sprintf("%s/functions/v1/device-auth", config.SupabaseProjectURL)
		config.AgentAuthURL = fmt.Sprintf("%s/functions/v1/agent-auth-api", config.SupabaseProjectURL)
	}

	// Validate required configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// Validate checks if all required configuration is present
func (c *Config) Validate() error {
	var missing []string

	if c.SupabaseProjectURL == "" {
		missing = append(missing, "SUPABASE_PROJECT_URL")
	}

	if c.DeviceAuthURL == "" {
		missing = append(missing, "DEVICE_AUTH_URL (or SUPABASE_PROJECT_URL)")
	}

	if c.AgentAuthURL == "" {
		missing = append(missing, "AGENT_AUTH_URL (or SUPABASE_PROJECT_URL)")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
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

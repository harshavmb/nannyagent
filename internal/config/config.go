package config

import (
	"fmt"
	"os"

	"nannyagentv2/internal/logging"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// NannyAPI Configuration (primary)
	APIBaseURL string `yaml:"nannyapi_url"`

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

// LoadConfig loads configuration from YAML or environment variables
func LoadConfig() (*Config, error) {
	config := DefaultConfig

	// Priority order for loading configuration:
	// 1. /etc/nannyagent/config.yaml (system-wide YAML)
	// 2. Environment variables (highest priority overrides)

	configLoaded := false

	// Try system-wide YAML config first
	if err := loadYAMLConfig(&config, "/etc/nannyagent/config.yaml"); err == nil {
		logging.Info("Loaded configuration from /etc/nannyagent/config.yaml")
		configLoaded = true
	}

	if !configLoaded {
		logging.Warning("No configuration file found at /etc/nannyagent/config.yaml. Using environment variables only.")
	}

	// Load from environment variables (highest priority - overrides file config)
	// NannyAPI configuration (primary)
	if url := os.Getenv("NANNYAPI_URL"); url != "" {
		config.APIBaseURL = url
	}
	// Support NANNYAPI_URL for backward compatibility
	if config.APIBaseURL == "" {
		if url := os.Getenv("NANNYAPI_URL"); url != "" {
			config.APIBaseURL = url
		}
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
	if c.APIBaseURL == "" {
		return fmt.Errorf("missing required configuration: NANNYAPI_URL (for NannyAPI) must be set")
	}

	return nil
}

// findEnvFile is removed as we no longer support .env files
func findEnvFile() string {
	return ""
}

// PrintConfig prints the current configuration (masking sensitive values)
func (c *Config) PrintConfig() {
	if !c.Debug {
		return
	}

	logging.Debug("Configuration:")
	logging.Debug("  API Base URL: %s", c.APIBaseURL)
	logging.Debug("  Metrics Interval: %d seconds", c.MetricsInterval)
	logging.Debug("  Debug: %v", c.Debug)
}

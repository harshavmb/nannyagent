package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nannyagentv2/internal/config"
	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/types"
)

const (
	// Token storage location (secure directory)
	TokenStorageDir  = "/var/lib/nannyagent"
	TokenStorageFile = ".agent_token.json"
	RefreshTokenFile = ".refresh_token"

	// Polling configuration
	MaxPollAttempts = 60 // 5 minutes (60 * 5 seconds)
	PollInterval    = 5 * time.Second
)

// AuthManager handles all authentication-related operations
type AuthManager struct {
	config *config.Config
	client *http.Client
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *config.Config) *AuthManager {
	return &AuthManager{
		config: cfg,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// EnsureTokenStorageDir creates the token storage directory if it doesn't exist
func (am *AuthManager) EnsureTokenStorageDir() error {
	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root to create secure token storage directory")
	}

	// Create directory with restricted permissions (0700 - only root can access)
	if err := os.MkdirAll(TokenStorageDir, 0700); err != nil {
		return fmt.Errorf("failed to create token storage directory: %w", err)
	}

	return nil
}

// StartDeviceAuthorization initiates the OAuth device authorization flow
func (am *AuthManager) StartDeviceAuthorization() (*types.DeviceAuthResponse, error) {
	// Use hostname as client_id for better identification on the portal
	hostname := getHostname()
	clientID := fmt.Sprintf("nannyagent-%s", hostname)

	payload := map[string]interface{}{
		"client_id": clientID,
		"scope":     []string{"agent:register"},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/device/authorize", am.config.DeviceAuthURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to start device authorization: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device authorization failed with status %d: %s", resp.StatusCode, string(body))
	}

	var deviceResp types.DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Override verification URI with portal URL from config
	if am.config.PortalURL != "" {
		deviceResp.VerificationURI = fmt.Sprintf("%s/agents/register", am.config.PortalURL)
	}

	return &deviceResp, nil
}

// PollForToken polls the token endpoint until authorization is complete
func (am *AuthManager) PollForToken(deviceCode string) (*types.TokenResponse, error) {
	logging.Info("Waiting for user authorization...")

	for attempts := 0; attempts < MaxPollAttempts; attempts++ {
		tokenReq := types.TokenRequest{
			GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
			DeviceCode: deviceCode,
		}

		jsonData, err := json.Marshal(tokenReq)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal token request: %w", err)
		}

		url := fmt.Sprintf("%s/token", am.config.DeviceAuthURL)
		req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
		if err != nil {
			return nil, fmt.Errorf("failed to create token request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := am.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to poll for token: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			return nil, fmt.Errorf("failed to read token response: %w", err)
		}

		var tokenResp types.TokenResponse
		if err := json.Unmarshal(body, &tokenResp); err != nil {
			return nil, fmt.Errorf("failed to parse token response: %w", err)
		}

		if tokenResp.Error != "" {
			if tokenResp.Error == "authorization_pending" {
				fmt.Print(".")
				time.Sleep(PollInterval)
				continue
			}
			return nil, fmt.Errorf("authorization failed: %s", tokenResp.ErrorDescription)
		}

		if tokenResp.AccessToken != "" {
			logging.Info("Authorization successful!")
			return &tokenResp, nil
		}

		time.Sleep(PollInterval)
	}

	return nil, fmt.Errorf("authorization timed out after %d attempts", MaxPollAttempts)
}

// RefreshAccessToken refreshes an expired access token using the refresh token
func (am *AuthManager) RefreshAccessToken(refreshToken string) (*types.TokenResponse, error) {
	tokenReq := types.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: refreshToken,
	}

	jsonData, err := json.Marshal(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	url := fmt.Sprintf("%s/token", am.config.DeviceAuthURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := am.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp types.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token refresh failed: %s", tokenResp.ErrorDescription)
	}

	return &tokenResp, nil
}

// SaveToken saves the authentication token to secure local storage
func (am *AuthManager) SaveToken(token *types.AuthToken) error {
	if err := am.EnsureTokenStorageDir(); err != nil {
		return fmt.Errorf("failed to ensure token storage directory: %w", err)
	}

	// Save main token file
	tokenPath := am.getTokenPath()
	jsonData, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := os.WriteFile(tokenPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	// Also save refresh token separately for backup recovery
	if token.RefreshToken != "" {
		refreshTokenPath := filepath.Join(TokenStorageDir, RefreshTokenFile)
		if err := os.WriteFile(refreshTokenPath, []byte(token.RefreshToken), 0600); err != nil {
			// Don't fail if refresh token backup fails, just log
			logging.Warning("Failed to save backup refresh token: %v", err)
		}
	}

	return nil
} // LoadToken loads the authentication token from secure local storage
func (am *AuthManager) LoadToken() (*types.AuthToken, error) {
	tokenPath := am.getTokenPath()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token types.AuthToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt.Add(-5 * time.Minute)) {
		return nil, fmt.Errorf("token is expired or expiring soon")
	}

	return &token, nil
}

// IsTokenExpired checks if a token needs refresh
func (am *AuthManager) IsTokenExpired(token *types.AuthToken) bool {
	// Consider token expired if it expires within the next 5 minutes
	return time.Now().After(token.ExpiresAt.Add(-5 * time.Minute))
}

// RegisterDevice performs the complete device registration flow
func (am *AuthManager) RegisterDevice() (*types.AuthToken, error) {
	// Step 1: Start device authorization
	deviceAuth, err := am.StartDeviceAuthorization()
	if err != nil {
		return nil, fmt.Errorf("failed to start device authorization: %w", err)
	}

	logging.Info("Please visit: %s", deviceAuth.VerificationURI)
	logging.Info("And enter code: %s", deviceAuth.UserCode)

	// Step 2: Poll for token
	tokenResp, err := am.PollForToken(deviceAuth.DeviceCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	// Step 3: Create token storage
	token := &types.AuthToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		AgentID:      tokenResp.AgentID,
	}

	// Step 4: Save token
	if err := am.SaveToken(token); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}

	return token, nil
}

// EnsureAuthenticated ensures the agent has a valid token, refreshing if necessary
func (am *AuthManager) EnsureAuthenticated() (*types.AuthToken, error) {
	// Try to load existing token
	token, err := am.LoadToken()
	if err == nil && !am.IsTokenExpired(token) {
		return token, nil
	}

	// Try to refresh with existing refresh token (even if access token is missing/expired)
	var refreshToken string
	if err == nil && token.RefreshToken != "" {
		// Use refresh token from loaded token
		refreshToken = token.RefreshToken
	} else {
		// Try to load refresh token from main token file even if load failed
		if existingToken, loadErr := am.loadTokenIgnoringExpiry(); loadErr == nil && existingToken.RefreshToken != "" {
			refreshToken = existingToken.RefreshToken
		} else {
			// Try to load refresh token from backup file
			if backupRefreshToken, backupErr := am.loadRefreshTokenFromBackup(); backupErr == nil {
				refreshToken = backupRefreshToken
				logging.Debug("Found backup refresh token, attempting to use it...")
			}
		}
	}

	if refreshToken != "" {
		logging.Debug("Attempting to refresh access token...")

		refreshResp, refreshErr := am.RefreshAccessToken(refreshToken)
		if refreshErr == nil {
			// Get existing agent_id from current token or backup
			var agentID string
			if err == nil && token.AgentID != "" {
				agentID = token.AgentID
			} else if existingToken, loadErr := am.loadTokenIgnoringExpiry(); loadErr == nil {
				agentID = existingToken.AgentID
			}

			// Create new token with refreshed values
			newToken := &types.AuthToken{
				AccessToken:  refreshResp.AccessToken,
				RefreshToken: refreshToken, // Keep existing refresh token
				TokenType:    refreshResp.TokenType,
				ExpiresAt:    time.Now().Add(time.Duration(refreshResp.ExpiresIn) * time.Second),
				AgentID:      agentID, // Preserve agent_id
			}

			// Update refresh token if a new one was provided
			if refreshResp.RefreshToken != "" {
				newToken.RefreshToken = refreshResp.RefreshToken
			}

			if saveErr := am.SaveToken(newToken); saveErr == nil {
				return newToken, nil
			}
		} else {
			fmt.Printf("WARNING: Token refresh failed: %v\n", refreshErr)
		}
	}

	fmt.Println("Initiating new device registration...")
	return am.RegisterDevice()
}

// loadTokenIgnoringExpiry loads token file without checking expiry
func (am *AuthManager) loadTokenIgnoringExpiry() (*types.AuthToken, error) {
	tokenPath := am.getTokenPath()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read token file: %w", err)
	}

	var token types.AuthToken
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return &token, nil
}

// loadRefreshTokenFromBackup tries to load refresh token from backup file
func (am *AuthManager) loadRefreshTokenFromBackup() (string, error) {
	refreshTokenPath := filepath.Join(TokenStorageDir, RefreshTokenFile)

	data, err := os.ReadFile(refreshTokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to read refresh token backup: %w", err)
	}

	refreshToken := strings.TrimSpace(string(data))
	if refreshToken == "" {
		return "", fmt.Errorf("refresh token backup is empty")
	}

	return refreshToken, nil
}

// GetCurrentAgentID retrieves the agent ID from cache or JWT token
func (am *AuthManager) GetCurrentAgentID() (string, error) {
	// First try to read from local cache
	agentID, err := am.loadCachedAgentID()
	if err == nil && agentID != "" {
		return agentID, nil
	}

	// Cache miss - extract from JWT token and cache it
	token, err := am.LoadToken()
	if err != nil {
		return "", fmt.Errorf("failed to load token: %w", err)
	}

	// Extract agent ID from JWT 'sub' field
	agentID, err = am.extractAgentIDFromJWT(token.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to extract agent ID from JWT: %w", err)
	}

	// Cache the agent ID for future use
	if err := am.cacheAgentID(agentID); err != nil {
		// Log warning but don't fail - we still have the agent ID
		fmt.Printf("Warning: Failed to cache agent ID: %v\n", err)
	}

	return agentID, nil
}

// extractAgentIDFromJWT decodes the JWT token and extracts the agent ID from 'sub' field
func (am *AuthManager) extractAgentIDFromJWT(tokenString string) (string, error) {
	// Basic JWT decoding without verification (since we trust Supabase)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT token format")
	}

	// Decode the payload (second part)
	payload := parts[1]

	// Add padding if needed for base64 decoding
	for len(payload)%4 != 0 {
		payload += "="
	}

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return "", fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// The agent ID is in the 'sub' field (subject)
	if agentID, ok := claims["sub"].(string); ok && agentID != "" {
		return agentID, nil
	}

	return "", fmt.Errorf("agent ID (sub) not found in JWT claims")
}

// loadCachedAgentID reads the cached agent ID from local storage
func (am *AuthManager) loadCachedAgentID() (string, error) {
	agentIDPath := filepath.Join(TokenStorageDir, "agent_id")

	data, err := os.ReadFile(agentIDPath)
	if err != nil {
		return "", fmt.Errorf("failed to read cached agent ID: %w", err)
	}

	agentID := strings.TrimSpace(string(data))
	if agentID == "" {
		return "", fmt.Errorf("cached agent ID is empty")
	}

	return agentID, nil
}

// cacheAgentID stores the agent ID in local cache
func (am *AuthManager) cacheAgentID(agentID string) error {
	// Ensure the directory exists
	if err := am.EnsureTokenStorageDir(); err != nil {
		return fmt.Errorf("failed to ensure storage directory: %w", err)
	}

	agentIDPath := filepath.Join(TokenStorageDir, "agent_id")

	// Write agent ID to file with secure permissions
	if err := os.WriteFile(agentIDPath, []byte(agentID), 0600); err != nil {
		return fmt.Errorf("failed to write agent ID cache: %w", err)
	}

	return nil
}

func (am *AuthManager) getTokenPath() string {
	if am.config.TokenPath != "" {
		return am.config.TokenPath
	}
	return filepath.Join(TokenStorageDir, TokenStorageFile)
}

func getHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "unknown"
}

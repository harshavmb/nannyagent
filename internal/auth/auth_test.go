package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nannyagentv2/internal/config"
	"nannyagentv2/internal/types"
)

func TestNewAuthManager(t *testing.T) {
	cfg := &config.Config{
		DeviceAuthURL: "https://test.auth.com",
		PortalURL:     "https://test.portal.com",
	}

	am := NewAuthManager(cfg)

	if am == nil {
		t.Fatal("Expected AuthManager to be created")
	}
	if am.config != cfg {
		t.Error("Config not set correctly")
	}
	if am.client == nil {
		t.Error("HTTP client not initialized")
	}
}

func TestEnsureTokenStorageDir(t *testing.T) {
	// Skip if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	// Clean up first
	_ = os.RemoveAll(TokenStorageDir)

	err := am.EnsureTokenStorageDir()
	if err != nil {
		t.Fatalf("Failed to create token storage dir: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(TokenStorageDir)
	if err != nil {
		t.Fatalf("Token storage dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Token storage path is not a directory")
	}

	// Verify permissions (should be 0700)
	mode := info.Mode().Perm()
	if mode != 0700 {
		t.Errorf("Expected permissions 0700, got %v", mode)
	}
}

func TestEnsureTokenStorageDir_NonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("Skipping non-root test when running as root")
	}

	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	err := am.EnsureTokenStorageDir()
	if err == nil {
		t.Error("Expected error when not running as root")
	}
}

func TestStartDeviceAuthorization(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/device/authorize" {
			t.Errorf("Expected path /device/authorize, got %s", r.URL.Path)
		}

		resp := types.DeviceAuthResponse{
			DeviceCode:      "test_device_code",
			UserCode:        "TEST123",
			VerificationURI: "https://example.com/verify",
			ExpiresIn:       900,
			Interval:        5,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		DeviceAuthURL: server.URL,
		PortalURL:     "https://custom.portal.com",
	}
	am := NewAuthManager(cfg)

	resp, err := am.StartDeviceAuthorization()
	if err != nil {
		t.Fatalf("Failed to start device authorization: %v", err)
	}

	if resp.DeviceCode != "test_device_code" {
		t.Errorf("Expected device code 'test_device_code', got '%s'", resp.DeviceCode)
	}
	if resp.UserCode != "TEST123" {
		t.Errorf("Expected user code 'TEST123', got '%s'", resp.UserCode)
	}
	// Verify portal URL was overridden
	if resp.VerificationURI != "https://custom.portal.com/agents/register" {
		t.Errorf("Expected verification URI to use portal URL, got '%s'", resp.VerificationURI)
	}
}

func TestPollForToken_Success(t *testing.T) {
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++

		var req types.TokenRequest
		json.NewDecoder(r.Body).Decode(&req)

		// First two attempts: return pending
		if attempt <= 2 {
			resp := types.TokenResponse{
				Error:            "authorization_pending",
				ErrorDescription: "User has not completed authorization",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Third attempt: return success
		resp := types.TokenResponse{
			AccessToken:  "test_access_token",
			RefreshToken: "test_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		DeviceAuthURL: server.URL,
	}
	am := NewAuthManager(cfg)

	// Note: Using default poll interval for this test
	resp, err := am.PollForToken("test_device_code")
	if err != nil {
		t.Fatalf("Failed to poll for token: %v", err)
	}

	if resp.AccessToken != "test_access_token" {
		t.Errorf("Expected access token 'test_access_token', got '%s'", resp.AccessToken)
	}
	if resp.RefreshToken != "test_refresh_token" {
		t.Errorf("Expected refresh token 'test_refresh_token', got '%s'", resp.RefreshToken)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req types.TokenRequest
		json.NewDecoder(r.Body).Decode(&req)

		if req.GrantType != "refresh_token" {
			t.Errorf("Expected grant_type 'refresh_token', got '%s'", req.GrantType)
		}
		if req.RefreshToken != "old_refresh_token" {
			t.Errorf("Expected refresh_token 'old_refresh_token', got '%s'", req.RefreshToken)
		}

		resp := types.TokenResponse{
			AccessToken:  "new_access_token",
			RefreshToken: "new_refresh_token",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &config.Config{
		DeviceAuthURL: server.URL,
	}
	am := NewAuthManager(cfg)

	resp, err := am.RefreshAccessToken("old_refresh_token")
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	if resp.AccessToken != "new_access_token" {
		t.Errorf("Expected new access token, got '%s'", resp.AccessToken)
	}
}

func TestSaveAndLoadToken(t *testing.T) {
	// Skip if not running as root (token storage requires root)
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	// Create temp directory for test
	tmpDir := t.TempDir()

	cfg := &config.Config{
		TokenPath: filepath.Join(tmpDir, "test_token.json"),
	}
	am := NewAuthManager(cfg)

	// Create test token
	token := &types.AuthToken{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		AgentID:      "test_agent_id",
	}

	// Save token
	err := am.SaveToken(token)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Load token
	loadedToken, err := am.LoadToken()
	if err != nil {
		t.Fatalf("Failed to load token: %v", err)
	}

	// Verify
	if loadedToken.AccessToken != token.AccessToken {
		t.Errorf("Access token mismatch: expected '%s', got '%s'", token.AccessToken, loadedToken.AccessToken)
	}
	if loadedToken.RefreshToken != token.RefreshToken {
		t.Errorf("Refresh token mismatch: expected '%s', got '%s'", token.RefreshToken, loadedToken.RefreshToken)
	}
	if loadedToken.AgentID != token.AgentID {
		t.Errorf("Agent ID mismatch: expected '%s', got '%s'", token.AgentID, loadedToken.AgentID)
	}
}

func TestLoadToken_Expired(t *testing.T) {
	// Skip if not running as root (token storage requires root)
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	tmpDir := t.TempDir()

	cfg := &config.Config{
		TokenPath: filepath.Join(tmpDir, "test_token.json"),
	}
	am := NewAuthManager(cfg)

	// Create expired token
	token := &types.AuthToken{
		AccessToken:  "test_access_token",
		RefreshToken: "test_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Already expired
		AgentID:      "test_agent_id",
	}

	// Save token
	err := am.SaveToken(token)
	if err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	// Try to load expired token
	_, err = am.LoadToken()
	if err == nil {
		t.Error("Expected error when loading expired token")
	}
}

func TestIsTokenExpired(t *testing.T) {
	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "Valid token (1 hour)",
			expiresAt: time.Now().Add(1 * time.Hour),
			expected:  false,
		},
		{
			name:      "Expiring soon (4 minutes)",
			expiresAt: time.Now().Add(4 * time.Minute),
			expected:  true,
		},
		{
			name:      "Already expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := &types.AuthToken{
				ExpiresAt: tt.expiresAt,
			}

			result := am.IsTokenExpired(token)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestExtractAgentIDFromJWT(t *testing.T) {
	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	// Create a simple JWT with agent ID in 'sub' field
	// Format: header.payload.signature
	// Payload: {"sub":"test_agent_123","exp":1234567890}
	// Base64 encode (URL encoding without padding)
	headerB64 := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	payloadB64 := "eyJzdWIiOiJ0ZXN0X2FnZW50XzEyMyIsImV4cCI6MTIzNDU2Nzg5MH0"
	signature := "fake_signature"

	jwt := headerB64 + "." + payloadB64 + "." + signature

	agentID, err := am.extractAgentIDFromJWT(jwt)
	if err != nil {
		t.Fatalf("Failed to extract agent ID: %v", err)
	}

	if agentID != "test_agent_123" {
		t.Errorf("Expected agent ID 'test_agent_123', got '%s'", agentID)
	}
}

func TestExtractAgentIDFromJWT_InvalidFormat(t *testing.T) {
	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	invalidJWTs := []string{
		"invalid",
		"invalid.jwt",
		"",
	}

	for _, jwt := range invalidJWTs {
		_, err := am.extractAgentIDFromJWT(jwt)
		if err == nil {
			t.Errorf("Expected error for invalid JWT: %s", jwt)
		}
	}
}

func TestCacheAndLoadAgentID(t *testing.T) {
	// Skip if not running as root (since we need to write to /var/lib/nannyagent)
	if os.Geteuid() != 0 {
		t.Skip("Skipping test that requires root privileges")
	}

	cfg := &config.Config{}
	am := NewAuthManager(cfg)

	// Ensure storage dir exists
	err := am.EnsureTokenStorageDir()
	if err != nil {
		t.Fatalf("Failed to create storage dir: %v", err)
	}

	// Cache agent ID
	testAgentID := "test_agent_456"
	err = am.cacheAgentID(testAgentID)
	if err != nil {
		t.Fatalf("Failed to cache agent ID: %v", err)
	}

	// Load cached agent ID
	cachedID, err := am.loadCachedAgentID()
	if err != nil {
		t.Fatalf("Failed to load cached agent ID: %v", err)
	}

	if cachedID != testAgentID {
		t.Errorf("Expected cached agent ID '%s', got '%s'", testAgentID, cachedID)
	}
}

func TestGetTokenPath(t *testing.T) {
	tests := []struct {
		name         string
		configPath   string
		expectedPath string
	}{
		{
			name:         "Custom token path",
			configPath:   "/custom/path/token.json",
			expectedPath: "/custom/path/token.json",
		},
		{
			name:         "Default token path",
			configPath:   "",
			expectedPath: filepath.Join(TokenStorageDir, TokenStorageFile),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				TokenPath: tt.configPath,
			}
			am := NewAuthManager(cfg)

			path := am.getTokenPath()
			if path != tt.expectedPath {
				t.Errorf("Expected path '%s', got '%s'", tt.expectedPath, path)
			}
		})
	}
}

func TestGetHostname(t *testing.T) {
	hostname := getHostname()

	if hostname == "" {
		t.Error("Hostname should not be empty")
	}

	// Should return "unknown" only if os.Hostname() fails
	// In most test environments, it should return a valid hostname
	if hostname != "unknown" {
		// Verify it's a reasonable hostname (not empty, no special chars)
		if len(hostname) == 0 {
			t.Error("Hostname length should be > 0")
		}
	}
}

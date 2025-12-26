package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"nannyagent/internal/config"
	"nannyagent/internal/types"
)

func TestAuthenticatedDo_ExpiredToken(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "auth_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	tokenPath := filepath.Join(tmpDir, "token.json")

	// Create an expired token
	expiredToken := &types.AuthToken{
		AccessToken:  "expired_access_token",
		RefreshToken: "valid_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		AgentID:      "test_agent_id",
	}

	tokenData, _ := json.Marshal(expiredToken)
	if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
		t.Fatalf("Failed to write expired token: %v", err)
	}

	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a refresh request
		if r.Method == "POST" && r.URL.Path == "/api/agent" {
			var req types.RefreshRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.Action == "refresh" && req.RefreshToken == "valid_refresh_token" {
				// Return new token
				resp := types.TokenResponse{
					AccessToken:  "new_access_token",
					RefreshToken: "new_refresh_token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					AgentID:      "test_agent_id",
				}
				err := json.NewEncoder(w).Encode(resp)
				if err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					return
				}
				return
			}
		}

		// Check if it's the actual request
		if r.URL.Path == "/api/test" {
			authHeader := r.Header.Get("Authorization")
			switch authHeader {
			case "Bearer new_access_token":
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("success"))
				if err != nil {
					http.Error(w, "Failed to write response", http.StatusInternalServerError)
					return
				}
				return
			case "Bearer expired_access_token":
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		http.Error(w, "Not found or unauthorized", http.StatusNotFound)
	}))
	defer ts.Close()

	// Initialize AuthManager
	cfg := &config.Config{
		APIBaseURL: ts.URL,
		TokenPath:  tokenPath,
	}
	am := NewAuthManager(cfg)

	// Perform AuthenticatedDo
	resp, err := am.AuthenticatedDo("GET", ts.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("AuthenticatedDo failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify that the token file was updated
	newTokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	var newToken types.AuthToken
	if err := json.Unmarshal(newTokenData, &newToken); err != nil {
		t.Fatalf("Failed to parse new token: %v", err)
	}

	if newToken.AccessToken != "new_access_token" {
		t.Errorf("Token file was not updated with new access token")
	}
}

func TestAuthenticatedDo_401Retry(t *testing.T) {
	// Create temp directory for token storage
	tmpDir, err := os.MkdirTemp("", "auth_test_401")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tokenPath := filepath.Join(tmpDir, "token.json")

	// Create a valid token (locally)
	validToken := &types.AuthToken{
		AccessToken:  "valid_access_token_locally",
		RefreshToken: "valid_refresh_token",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour), // Valid for 1 hour
		AgentID:      "test_agent_id",
	}

	tokenData, _ := json.Marshal(validToken)
	if err := os.WriteFile(tokenPath, tokenData, 0600); err != nil {
		t.Fatalf("Failed to write token: %v", err)
	}

	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a refresh request
		if r.Method == "POST" && r.URL.Path == "/api/agent" {
			var req types.RefreshRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}

			if req.Action == "refresh" && req.RefreshToken == "valid_refresh_token" {
				// Return new token
				resp := types.TokenResponse{
					AccessToken:  "new_access_token",
					RefreshToken: "new_refresh_token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
					AgentID:      "test_agent_id",
				}
				err := json.NewEncoder(w).Encode(resp)
				if err != nil {
					http.Error(w, "Failed to encode response", http.StatusInternalServerError)
					return
				}
				return
			}
		}

		// Check if it's the actual request
		if r.URL.Path == "/api/test" {
			authHeader := r.Header.Get("Authorization")
			switch authHeader {
			case "Bearer new_access_token":
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte("success"))
				if err != nil {
					http.Error(w, "Failed to write response", http.StatusInternalServerError)
					return
				}
				return
			case "Bearer valid_access_token_locally":
				// Simulate 401 even if token looks valid locally
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}

		http.Error(w, "Not found or unauthorized", http.StatusNotFound)
	}))
	defer ts.Close()

	// Initialize AuthManager
	cfg := &config.Config{
		APIBaseURL: ts.URL,
		TokenPath:  tokenPath,
	}
	am := NewAuthManager(cfg)

	// Perform AuthenticatedDo
	resp, err := am.AuthenticatedDo("GET", ts.URL+"/api/test", nil, nil)
	if err != nil {
		t.Fatalf("AuthenticatedDo failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Verify that the token file was updated
	newTokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("Failed to read token file: %v", err)
	}

	var newToken types.AuthToken
	if err := json.Unmarshal(newTokenData, &newToken); err != nil {
		t.Fatalf("Failed to parse new token: %v", err)
	}

	if newToken.AccessToken != "new_access_token" {
		t.Errorf("Token file was not updated with new access token")
	}
}

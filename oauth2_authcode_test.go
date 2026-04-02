package pagerduty

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestGenerateCodeVerifier(t *testing.T) {
	v, err := generateCodeVerifier()
	if err != nil {
		t.Fatalf("generateCodeVerifier() error: %v", err)
	}
	if len(v) != 64 {
		t.Errorf("expected verifier length 64, got %d", len(v))
	}

	// Ensure two calls produce different values
	v2, _ := generateCodeVerifier()
	if v == v2 {
		t.Error("expected two different verifiers")
	}
}

func TestGenerateCodeChallenge(t *testing.T) {
	verifier := "test-verifier-1234567890"
	challenge := generateCodeChallenge(verifier)
	if challenge == "" {
		t.Error("expected non-empty challenge")
	}
	if challenge == verifier {
		t.Error("challenge should not equal verifier")
	}

	// Same input should produce same output
	challenge2 := generateCodeChallenge(verifier)
	if challenge != challenge2 {
		t.Error("same verifier should produce same challenge")
	}
}

func TestCachedTokenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")

	cfg := AuthCodeTokenSourceConfig{
		ClientID:      "test-client-id",
		Scopes:        []string{"read", "write"},
		TokenFilePath: tokenPath,
	}

	ts := &authCodeTokenSource{
		config: cfg,
		oauthCfg: oauth2.Config{
			ClientID: cfg.ClientID,
		},
	}

	// Save a token
	tok := &oauth2.Token{
		AccessToken:  "test-access-token",
		TokenType:    "Bearer",
		RefreshToken: "test-refresh-token",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	if err := ts.saveCachedToken(tok); err != nil {
		t.Fatalf("saveCachedToken() error: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected file permissions 0600, got %o", info.Mode().Perm())
	}

	// Load it back
	loaded, err := ts.loadCachedToken()
	if err != nil {
		t.Fatalf("loadCachedToken() error: %v", err)
	}

	if loaded.AccessToken != tok.AccessToken {
		t.Errorf("access token mismatch: got %q, want %q", loaded.AccessToken, tok.AccessToken)
	}
	if loaded.RefreshToken != tok.RefreshToken {
		t.Errorf("refresh token mismatch: got %q, want %q", loaded.RefreshToken, tok.RefreshToken)
	}
	if loaded.TokenType != tok.TokenType {
		t.Errorf("token type mismatch: got %q, want %q", loaded.TokenType, tok.TokenType)
	}
}

func TestCachedTokenClientIDMismatch(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")

	// Write a token with one client ID
	cached := cachedAuthCodeToken{
		AccessToken: "test",
		TokenType:   "Bearer",
		ClientID:    "old-client-id",
		Scopes:      "read write",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(tokenPath, data, 0600)

	// Try to load with a different client ID
	ts := &authCodeTokenSource{
		config: AuthCodeTokenSourceConfig{
			ClientID:      "new-client-id",
			Scopes:        []string{"read", "write"},
			TokenFilePath: tokenPath,
		},
	}

	_, err := ts.loadCachedToken()
	if err == nil {
		t.Error("expected error for client ID mismatch, got nil")
	}
}

func TestCachedTokenScopesMismatch(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")

	// Write a token with one set of scopes
	cached := cachedAuthCodeToken{
		AccessToken: "test",
		TokenType:   "Bearer",
		ClientID:    "test-client",
		Scopes:      "read",
		Expiry:      time.Now().Add(1 * time.Hour),
	}
	data, _ := json.Marshal(cached)
	os.WriteFile(tokenPath, data, 0600)

	// Try to load with different scopes
	ts := &authCodeTokenSource{
		config: AuthCodeTokenSourceConfig{
			ClientID:      "test-client",
			Scopes:        []string{"read", "write"},
			TokenFilePath: tokenPath,
		},
	}

	_, err := ts.loadCachedToken()
	if err == nil {
		t.Error("expected error for scopes mismatch, got nil")
	}
}

func TestRemoveCachedAuthCodeToken(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.json")

	// Create a file
	os.WriteFile(tokenPath, []byte("test"), 0600)

	if err := RemoveCachedAuthCodeToken(tokenPath); err != nil {
		t.Fatalf("RemoveCachedAuthCodeToken() error: %v", err)
	}

	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Error("expected token file to be removed")
	}

	// Removing a non-existent file should not error
	if err := RemoveCachedAuthCodeToken(tokenPath); err != nil {
		t.Errorf("RemoveCachedAuthCodeToken() on non-existent file: %v", err)
	}
}

func TestDefaultOAuthTokenPath(t *testing.T) {
	path, err := DefaultOAuthTokenPath()
	if err != nil {
		t.Fatalf("DefaultOAuthTokenPath() error: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
	if filepath.Base(path) != "oauth_token.json" {
		t.Errorf("expected filename oauth_token.json, got %s", filepath.Base(path))
	}
}

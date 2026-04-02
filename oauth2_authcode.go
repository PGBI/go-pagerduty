package pagerduty

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	defaultAuthorizationEndpoint = "https://identity.pagerduty.com/oauth/authorize"
	defaultTokenEndpoint         = "https://identity.pagerduty.com/oauth/token"
	defaultRedirectHost          = "localhost"
	defaultRedirectPath          = "/callback"
)

// AuthCodeTokenSourceConfig configures the OAuth 2.0 Authorization Code flow
// with PKCE for interactive CLI authentication.
type AuthCodeTokenSourceConfig struct {
	// ClientID is the OAuth 2.0 client ID registered with PagerDuty.
	ClientID string

	// Scopes are the OAuth 2.0 scopes to request.
	Scopes []string

	// TokenFilePath is the path to cache the OAuth token on disk.
	// If empty, tokens are not cached.
	TokenFilePath string

	// AuthorizationEndpoint overrides the default PagerDuty authorization URL.
	AuthorizationEndpoint string

	// TokenEndpoint overrides the default PagerDuty token URL.
	TokenEndpoint string

	// OpenBrowser is a function that opens a URL in the user's browser.
	// If nil, the URL is printed to stderr for the user to open manually.
	OpenBrowser func(url string) error
}

// authCodeTokenSource implements oauth2.TokenSource using the Authorization
// Code flow with PKCE. It caches tokens to a file and refreshes them
// automatically when possible.
type authCodeTokenSource struct {
	config   AuthCodeTokenSourceConfig
	oauthCfg oauth2.Config
}

// NewAuthCodeTokenSource creates an oauth2.TokenSource that authenticates
// using the OAuth 2.0 Authorization Code flow with PKCE. This is suitable
// for CLI tools where the user can interact with a browser.
//
// The returned TokenSource will:
//  1. Check for a cached token on disk (if TokenFilePath is set)
//  2. If the cached token is expired but has a refresh token, refresh it
//  3. If no valid token exists, launch the browser-based OAuth flow
//  4. Cache the resulting token to disk
func NewAuthCodeTokenSource(ctx context.Context, cfg AuthCodeTokenSourceConfig) oauth2.TokenSource {
	authEndpoint := cfg.AuthorizationEndpoint
	if authEndpoint == "" {
		authEndpoint = defaultAuthorizationEndpoint
	}

	tokenEndpoint := cfg.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = defaultTokenEndpoint
	}

	ts := &authCodeTokenSource{
		config: cfg,
		oauthCfg: oauth2.Config{
			ClientID: cfg.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authEndpoint,
				TokenURL: tokenEndpoint,
			},
			Scopes: cfg.Scopes,
		},
	}

	return oauth2.ReuseTokenSource(nil, ts)
}

// Token returns a valid OAuth 2.0 token, either from cache or by running the
// interactive authorization flow.
func (s *authCodeTokenSource) Token() (*oauth2.Token, error) {
	// Try loading a cached token first
	if s.config.TokenFilePath != "" {
		tok, err := s.loadCachedToken()
		if err == nil && tok != nil {
			// If the token has a refresh token and is expired, try refreshing
			if tok.Valid() {
				return tok, nil
			}
			if tok.RefreshToken != "" {
				newTok, err := s.oauthCfg.TokenSource(context.Background(), tok).Token()
				if err == nil {
					_ = s.saveCachedToken(newTok)
					return newTok, nil
				}
				// Refresh failed; fall through to interactive flow
			}
		}
	}

	// Run the interactive authorization code flow
	tok, err := s.runAuthCodeFlow()
	if err != nil {
		return nil, fmt.Errorf("oauth authorization code flow failed: %w", err)
	}

	// Cache the token
	if s.config.TokenFilePath != "" {
		if err := s.saveCachedToken(tok); err != nil {
			// Non-fatal: warn but return the token
			fmt.Fprintf(os.Stderr, "Warning: could not cache OAuth token: %v\n", err)
		}
	}

	return tok, nil
}

// runAuthCodeFlow performs the full OAuth 2.0 Authorization Code flow with PKCE.
func (s *authCodeTokenSource) runAuthCodeFlow() (*oauth2.Token, error) {
	// Generate PKCE code verifier and challenge
	verifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE code verifier: %w", err)
	}
	challenge := generateCodeChallenge(verifier)

	// Generate state parameter for CSRF protection
	state, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state parameter: %w", err)
	}

	// Start a local HTTP server to receive the callback
	listener, err := net.Listen("tcp", defaultRedirectHost+":0")
	if err != nil {
		return nil, fmt.Errorf("failed to start local callback server: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://%s:%d%s", defaultRedirectHost, port, defaultRedirectPath)
	s.oauthCfg.RedirectURL = redirectURI

	// Build the authorization URL
	authURL := s.oauthCfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Prompt the user to open the browser
	fmt.Fprintf(os.Stderr, "\nOpening browser for PagerDuty authentication...\n")
	fmt.Fprintf(os.Stderr, "If the browser does not open, visit this URL:\n\n  %s\n\n", authURL)

	if s.config.OpenBrowser != nil {
		if err := s.config.OpenBrowser(authURL); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not open browser: %v\n", err)
		}
	}

	// Wait for the callback
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(defaultRedirectPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errCh <- fmt.Errorf("state mismatch in OAuth callback")
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			errCh <- fmt.Errorf("authorization error: %s: %s", errMsg, desc)
			fmt.Fprintf(w, "<html><body><h1>Authentication Failed</h1><p>%s: %s</p><p>You can close this window.</p></body></html>", errMsg, desc)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			errCh <- fmt.Errorf("no authorization code in callback")
			http.Error(w, "No code received", http.StatusBadRequest)
			return
		}

		fmt.Fprintf(w, "<html><body><h1>Authentication Successful</h1><p>You can close this window and return to the terminal.</p></body></html>")
		codeCh <- code
	})

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("callback server error: %w", err)
		}
	}()

	// Wait for the code or an error, with a timeout
	var code string
	select {
	case code = <-codeCh:
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("timed out waiting for OAuth callback (5 minutes)")
	}

	// Shut down the callback server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)

	// Exchange the authorization code for a token
	tok, err := s.oauthCfg.Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	return tok, nil
}

// cachedAuthCodeToken is the on-disk format for cached OAuth tokens.
type cachedAuthCodeToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	ClientID     string    `json:"client_id"`
	Scopes       string    `json:"scopes"`
}

func (s *authCodeTokenSource) loadCachedToken() (*oauth2.Token, error) {
	data, err := os.ReadFile(s.config.TokenFilePath)
	if err != nil {
		return nil, err
	}

	var cached cachedAuthCodeToken
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil, err
	}

	// Invalidate if client ID or scopes changed
	if cached.ClientID != s.config.ClientID {
		return nil, fmt.Errorf("cached token client ID mismatch")
	}
	requestedScopes := strings.Join(s.config.Scopes, " ")
	if strings.TrimSpace(cached.Scopes) != strings.TrimSpace(requestedScopes) {
		return nil, fmt.Errorf("cached token scopes mismatch")
	}

	return &oauth2.Token{
		AccessToken:  cached.AccessToken,
		TokenType:    cached.TokenType,
		RefreshToken: cached.RefreshToken,
		Expiry:       cached.Expiry,
	}, nil
}

func (s *authCodeTokenSource) saveCachedToken(tok *oauth2.Token) error {
	cached := cachedAuthCodeToken{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
		ClientID:     s.config.ClientID,
		Scopes:       strings.Join(s.config.Scopes, " "),
	}

	data, err := json.MarshalIndent(cached, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal token: %w", err)
	}

	if err := os.WriteFile(s.config.TokenFilePath, data, 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// RemoveCachedAuthCodeToken deletes the cached OAuth token file.
func RemoveCachedAuthCodeToken(tokenFilePath string) error {
	if err := os.Remove(tokenFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove cached token: %w", err)
	}
	return nil
}

// generateCodeVerifier creates a cryptographically random PKCE code verifier.
func generateCodeVerifier() (string, error) {
	return generateRandomString(64)
}

// generateCodeChallenge creates a PKCE S256 code challenge from a verifier.
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// generateRandomString creates a cryptographically random URL-safe string.
func generateRandomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length], nil
}

// WithAuthCodeOAuth configures the client to use the OAuth 2.0 Authorization
// Code flow with PKCE for authentication. This is the recommended method for
// CLI tools where a user can interact with a browser.
func WithAuthCodeOAuth(ctx context.Context, cfg AuthCodeTokenSourceConfig) ClientOptions {
	ts := NewAuthCodeTokenSource(ctx, cfg)
	return func(c *Client) {
		c.authType = scopedOAuthAppToken
		c.tokenSource = ts
	}
}

// DefaultOAuthTokenPath returns the default path for caching OAuth tokens,
// which is ~/.config/pagerduty/oauth_token.json.
func DefaultOAuthTokenPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not determine home directory: %w", err)
		}
		configDir = home + "/.config"
	}

	dir := configDir + "/pagerduty"
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("could not create config directory %s: %w", dir, err)
	}

	return dir + "/oauth_token.json", nil
}

// OAuthLoginURL returns the authorization URL for manual OAuth flows where
// the caller wants to handle the redirect themselves. This is useful for
// testing or non-interactive environments.
func OAuthLoginURL(clientID string, redirectURI string, scopes []string) string {
	params := url.Values{
		"client_id":             {clientID},
		"redirect_uri":         {redirectURI},
		"response_type":        {"code"},
		"scope":                {strings.Join(scopes, " ")},
		"code_challenge_method": {"S256"},
	}
	return defaultAuthorizationEndpoint + "?" + params.Encode()
}

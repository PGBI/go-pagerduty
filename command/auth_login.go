package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/PagerDuty/go-pagerduty"
	log "github.com/sirupsen/logrus"
	"github.com/mitchellh/cli"
)

type AuthLogin struct {
	Meta
}

func AuthLoginCommand() (cli.Command, error) {
	return &AuthLogin{}, nil
}

func (c *AuthLogin) Help() string {
	helpText := `
	pd auth login  Authenticate with PagerDuty using OAuth 2.0

	Opens a browser window for you to log in to PagerDuty. The resulting
	OAuth token is cached locally so you don't need to log in again until
	the token expires.

	Options:

	  -oauth-client-id  OAuth 2.0 client ID (required)
	  -oauth-scopes     OAuth 2.0 scopes (comma-separated, default: read,write)
	  -loglevel         Logging level
`
	return strings.TrimSpace(helpText)
}

func (c *AuthLogin) Synopsis() string {
	return "Authenticate with PagerDuty using OAuth 2.0 (browser-based)"
}

func (c *AuthLogin) Run(args []string) int {
	var oauthClientID string
	var oauthScopes string
	var loglevel string

	flags := c.Meta.FlagSet("auth login")
	flags.Usage = func() { fmt.Println(c.Help()) }
	flags.StringVar(&oauthClientID, "oauth-client-id", "", "OAuth 2.0 client ID")
	flags.StringVar(&oauthScopes, "oauth-scopes", "", "OAuth 2.0 scopes (comma-separated)")
	flags.StringVar(&loglevel, "loglevel", "", "Logging level")

	if err := flags.Parse(args); err != nil {
		log.Error(err)
		return 1
	}

	// Also try loading from config
	c.Meta.setupLogging()
	if err := c.Meta.loadConfig(); err != nil {
		log.Debug("Could not load config: ", err)
	}

	// CLI flags override config
	if oauthClientID != "" {
		c.Meta.OAuthClientID = oauthClientID
	}
	if oauthScopes != "" {
		c.Meta.OAuthScopes = oauthScopes
	}

	if c.Meta.OAuthClientID == "" {
		log.Error("--oauth-client-id is required")
		fmt.Println(c.Help())
		return 1
	}

	scopes := []string{"read", "write"}
	if c.Meta.OAuthScopes != "" {
		scopes = strings.Split(c.Meta.OAuthScopes, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	tokenPath, err := pagerduty.DefaultOAuthTokenPath()
	if err != nil {
		log.Errorf("Failed to determine token path: %v", err)
		return 1
	}

	cfg := pagerduty.AuthCodeTokenSourceConfig{
		ClientID:      c.Meta.OAuthClientID,
		Scopes:        scopes,
		TokenFilePath: tokenPath,
		OpenBrowser:   openBrowser,
	}

	ts := pagerduty.NewAuthCodeTokenSource(context.Background(), cfg)

	// Force a token fetch (this triggers the browser flow if needed)
	tok, err := ts.Token()
	if err != nil {
		log.Errorf("Authentication failed: %v", err)
		return 1
	}

	fmt.Fprintf(flags.Output(), "✓ Successfully authenticated with PagerDuty.\n")
	fmt.Fprintf(flags.Output(), "  Token cached at: %s\n", tokenPath)
	if !tok.Expiry.IsZero() {
		fmt.Fprintf(flags.Output(), "  Token expires: %s\n", tok.Expiry.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Fprintf(flags.Output(), "\nYou can now use -oauth -oauth-client-id=%s with any pd command,\n", c.Meta.OAuthClientID)
	fmt.Fprintf(flags.Output(), "or add the following to ~/.pd.yml:\n\n")
	fmt.Fprintf(flags.Output(), "  oauth: true\n")
	fmt.Fprintf(flags.Output(), "  oauth_client_id: %s\n", c.Meta.OAuthClientID)

	return 0
}

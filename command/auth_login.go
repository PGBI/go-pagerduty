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

	No configuration is needed — just run:

	  pd auth login

	Options (all optional):

	  -oauth-client-id  Override the default OAuth client ID
	  -oauth-scopes     Override scopes (comma-separated, default: read,write)
	  -loglevel         Logging level
`
	return strings.TrimSpace(helpText)
}

func (c *AuthLogin) Synopsis() string {
	return "Authenticate with PagerDuty using OAuth 2.0 (browser-based)"
}

func (c *AuthLogin) Run(args []string) int {
	flags := c.Meta.FlagSet("auth login")
	flags.Usage = func() { fmt.Println(c.Help()) }

	if err := flags.Parse(args); err != nil {
		log.Error(err)
		return 1
	}

	// Load config for any overrides
	c.Meta.setupLogging()
	if err := c.Meta.loadConfig(); err != nil {
		log.Debug("Could not load config: ", err)
	}

	clientID := c.Meta.resolveOAuthClientID()
	scopes := c.Meta.resolveOAuthScopes()

	tokenPath, err := pagerduty.DefaultOAuthTokenPath()
	if err != nil {
		log.Errorf("Failed to determine token path: %v", err)
		return 1
	}

	cfg := pagerduty.AuthCodeTokenSourceConfig{
		ClientID:      clientID,
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
	fmt.Fprintf(flags.Output(), "\nYou can now use any pd command with -oauth, e.g.:\n\n")
	fmt.Fprintf(flags.Output(), "  pd incident list -oauth\n\n")
	fmt.Fprintf(flags.Output(), "Or add to ~/.pd.yml to make it the default:\n\n")
	fmt.Fprintf(flags.Output(), "  oauth: true\n")

	return 0
}

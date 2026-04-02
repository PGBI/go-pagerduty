package main

import (
	"fmt"
	"strings"

	"github.com/PagerDuty/go-pagerduty"
	log "github.com/sirupsen/logrus"
	"github.com/mitchellh/cli"
)

type AuthLogout struct {
	Meta
}

func AuthLogoutCommand() (cli.Command, error) {
	return &AuthLogout{}, nil
}

func (c *AuthLogout) Help() string {
	helpText := `
	pd auth logout  Remove cached OAuth token

	Removes the locally cached OAuth token. You will need to log in
	again the next time you use -oauth.
`
	return strings.TrimSpace(helpText)
}

func (c *AuthLogout) Synopsis() string {
	return "Remove cached PagerDuty OAuth token"
}

func (c *AuthLogout) Run(args []string) int {
	flags := c.Meta.FlagSet("auth logout")
	flags.Usage = func() { fmt.Println(c.Help()) }

	if err := flags.Parse(args); err != nil {
		log.Error(err)
		return 1
	}

	tokenPath, err := pagerduty.DefaultOAuthTokenPath()
	if err != nil {
		log.Errorf("Failed to determine token path: %v", err)
		return 1
	}

	if err := pagerduty.RemoveCachedAuthCodeToken(tokenPath); err != nil {
		log.Errorf("Failed to remove cached token: %v", err)
		return 1
	}

	fmt.Println("✓ OAuth token removed. You will need to log in again.")
	return 0
}

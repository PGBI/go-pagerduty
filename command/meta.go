package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/PagerDuty/go-pagerduty"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type ArrayFlags []string

func (a *ArrayFlags) String() string {
	return strings.Join(*a, ",")
}

func (a *ArrayFlags) Set(v string) error {
	if *a == nil {
		*a = make([]string, 0, 1)
	}
	*a = append(*a, v)
	return nil
}

type Meta struct {
	Authtoken     string `yaml:"authtoken"`
	Loglevel      string `yaml:"loglevel"`
	UseOAuth      bool   `yaml:"oauth"`
	OAuthClientID string `yaml:"oauth_client_id"`
	OAuthScopes   string `yaml:"oauth_scopes"`
}

type FlagSetFlags uint

func (m *Meta) FlagSet(n string) *flag.FlagSet {
	f := flag.NewFlagSet(n, flag.ContinueOnError)
	f.StringVar(&m.Authtoken, "authtoken", "", "PagerDuty API authentication token")
	f.StringVar(&m.Loglevel, "loglevel", "", "Logging level")
	f.BoolVar(&m.UseOAuth, "oauth", false, "Use OAuth 2.0 browser-based authentication (no token on disk required)")
	f.StringVar(&m.OAuthClientID, "oauth-client-id", "", "OAuth 2.0 client ID (required with --oauth)")
	f.StringVar(&m.OAuthScopes, "oauth-scopes", "", "OAuth 2.0 scopes (comma-separated, default: read write)")
	return f
}

func (m *Meta) Client() *pagerduty.Client {
	if m.UseOAuth {
		return m.oauthClient()
	}
	return pagerduty.NewClient(m.Authtoken)
}

func (m *Meta) oauthClient() *pagerduty.Client {
	tokenPath, err := pagerduty.DefaultOAuthTokenPath()
	if err != nil {
		log.Fatalf("Failed to determine OAuth token path: %v", err)
	}

	scopes := []string{"read", "write"}
	if m.OAuthScopes != "" {
		scopes = strings.Split(m.OAuthScopes, ",")
		for i := range scopes {
			scopes[i] = strings.TrimSpace(scopes[i])
		}
	}

	cfg := pagerduty.AuthCodeTokenSourceConfig{
		ClientID:      m.OAuthClientID,
		Scopes:        scopes,
		TokenFilePath: tokenPath,
		OpenBrowser:   openBrowser,
	}

	return pagerduty.NewClient("", pagerduty.WithAuthCodeOAuth(context.Background(), cfg))
}

func (m *Meta) Help() string {
	helpText := `
	Common options:

	-authtoken    PagerDuty API authentication token
	-loglevel     Logging level
	-oauth        Use OAuth 2.0 browser-based authentication
	-oauth-client-id  OAuth 2.0 client ID (required with -oauth)
	-oauth-scopes     OAuth 2.0 scopes (comma-separated, default: read,write)
`
	return strings.TrimSpace(helpText)
}

func (m *Meta) validate() error {
	if m.UseOAuth {
		if m.OAuthClientID == "" {
			return fmt.Errorf("--oauth-client-id is required when using --oauth")
		}
		return nil
	}
	if m.Authtoken == "" {
		return fmt.Errorf("Authtoken can not be blank. Use -authtoken or -oauth for browser-based login.")
	}
	return nil
}

func (m *Meta) Setup() error {
	m.setupLogging()
	if err := m.loadConfig(); err != nil {
		log.Warn(err)
	}
	return m.validate()
}

func (m *Meta) setupLogging() {
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	switch m.Loglevel {
	case "info", "":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.Fatal("Unknown log level", m.Loglevel)
	}
}

func (m *Meta) loadConfig() error {
	path, err := homedir.Dir()
	if err != nil {
		return err
	}
	configFile := filepath.Join(path, ".pd.yml")
	if _, err := os.Stat(configFile); err != nil {
		return err
	}
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	other := &Meta{}
	if err := yaml.Unmarshal(data, other); err != nil {
		return err
	}
	if m.Authtoken == "" {
		m.Authtoken = other.Authtoken
	}
	if m.Loglevel == "" {
		m.Loglevel = other.Loglevel
	}
	// Load OAuth settings from config file if not set via flags
	if !m.UseOAuth && other.UseOAuth {
		m.UseOAuth = other.UseOAuth
	}
	if m.OAuthClientID == "" {
		m.OAuthClientID = other.OAuthClientID
	}
	if m.OAuthScopes == "" {
		m.OAuthScopes = other.OAuthScopes
	}
	return nil
}

// openBrowser opens the specified URL in the user's default browser.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform %s", runtime.GOOS)
	}
	return cmd.Start()
}

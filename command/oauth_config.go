package main

// defaultOAuthClientID is the OAuth 2.0 client ID registered with PagerDuty
// for this CLI application. It uses the Authorization Code flow with PKCE
// (a public client), so embedding the client ID here is safe and expected —
// the same pattern used by gh (GitHub CLI), gcloud, az, etc.
//
// To register your own, visit:
//   https://developer.pagerduty.com/docs/app-integration-development/
//
// Select "OAuth 2.0" and configure:
//   - Authorization Code Grant with PKCE
//   - Redirect URI: http://localhost (any port)
const defaultOAuthClientID = "REPLACE_WITH_YOUR_REGISTERED_CLIENT_ID"

// defaultOAuthScopes are the default scopes requested during the OAuth flow.
// These grant read and write access to the PagerDuty API on behalf of the user.
var defaultOAuthScopes = []string{"read", "write"}

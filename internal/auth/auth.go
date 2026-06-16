// Package auth implements the device-authorization sign-in for the skycloak-mcp
// CLI.
//
// `skycloak-mcp init` runs the OAuth 2.0 Device Authorization Grant (RFC 8628)
// against the Skycloak realm, exchanges the resulting user token for a
// workspace-scoped Skycloak API key, and stores that key in the operating
// system keychain. `skycloak-mcp run` then loads the key from the keychain.
//
// A SKYCLOAK_API_KEY environment variable always takes precedence, so CI and
// other headless callers keep a non-interactive path and never need a browser.
package auth

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/zalando/go-keyring"
)

// keyringService is the service name under which the API key is stored.
const keyringService = "skycloak-mcp"

// Production defaults. Overridable via env for dev / self-hosted control planes.
const (
	defaultIssuer    = "https://login.app.skycloak.io/realms/skycloak"
	defaultClientID  = "skycloak-mcp"
	defaultDashboard = "https://app.skycloak.io"
)

// Config resolves the endpoints and client identity the sign-in needs.
type Config struct {
	// Issuer is the OIDC issuer URL, e.g.
	// https://login.app.skycloak.io/realms/skycloak. Its
	// .well-known/openid-configuration is used to discover the device and
	// token endpoints (we never hard-code them).
	Issuer string
	// ClientID is the public device-grant OAuth client registered in the realm.
	ClientID string
	// DashboardURL is the base URL that serves POST /api/api-keys (the Skycloak
	// dashboard backend), which differs from the tool API host (api.skycloak.io).
	DashboardURL string
}

// ConfigFromEnv builds a Config from the environment, defaulting to production.
//
//	SKYCLOAK_ISSUER         OIDC issuer (realm) URL
//	SKYCLOAK_CLIENT_ID      public device-grant client id
//	SKYCLOAK_DASHBOARD_URL  base URL serving /api/api-keys
func ConfigFromEnv() Config {
	return Config{
		Issuer:       getenv("SKYCLOAK_ISSUER", defaultIssuer),
		ClientID:     getenv("SKYCLOAK_CLIENT_ID", defaultClientID),
		DashboardURL: strings.TrimRight(getenv("SKYCLOAK_DASHBOARD_URL", defaultDashboard), "/"),
	}
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// keyringUser namespaces the stored secret by issuer so keys for different
// environments (dev vs prod) do not collide on one machine.
func (c Config) keyringUser() string { return c.Issuer }

// ErrNoCredential is returned by LoadAPIKey when nothing is stored and no
// SKYCLOAK_API_KEY env var is set.
var ErrNoCredential = errors.New("not signed in: run `skycloak-mcp init` (or set SKYCLOAK_API_KEY)")

// LoadAPIKey returns the API key the server should use: the SKYCLOAK_API_KEY
// env var if set (CI / headless), otherwise the key saved by `init` in the
// keychain. It never returns a key from disk in plaintext.
func LoadAPIKey(cfg Config) (string, error) {
	if k := os.Getenv("SKYCLOAK_API_KEY"); k != "" {
		return k, nil
	}
	secret, err := keyring.Get(keyringService, cfg.keyringUser())
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNoCredential
	}
	if err != nil {
		return "", fmt.Errorf("read keychain: %w", err)
	}
	if secret == "" {
		return "", ErrNoCredential
	}
	return secret, nil
}

// storeAPIKey saves the minted key in the OS keychain.
func storeAPIKey(cfg Config, key string) error {
	return keyring.Set(keyringService, cfg.keyringUser(), key)
}

// Logout removes the stored credential for this issuer. It is a no-op (nil
// error) if nothing is stored.
func Logout(cfg Config) error {
	err := keyring.Delete(keyringService, cfg.keyringUser())
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

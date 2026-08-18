package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/sky-cloak/skycloak-mcp/internal/oauth"
)

// oidcMetadata is the subset of the OpenID Connect discovery document we use.
type oidcMetadata struct {
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
}

// discover fetches {issuer}/.well-known/openid-configuration. We discover the
// device and token endpoints rather than hard-coding Keycloak's URL layout, so
// the same code works against any compliant issuer.
func discover(ctx context.Context, hc *http.Client, issuer string) (oidcMetadata, error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return oidcMetadata{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return oidcMetadata{}, fmt.Errorf("discover %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return oidcMetadata{}, fmt.Errorf("discover %s: unexpected status %d", url, resp.StatusCode)
	}
	var m oidcMetadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return oidcMetadata{}, fmt.Errorf("decode discovery document: %w", err)
	}
	if m.DeviceAuthorizationEndpoint == "" || m.TokenEndpoint == "" {
		return oidcMetadata{}, fmt.Errorf("issuer %s does not advertise the device authorization grant", issuer)
	}
	return m, nil
}

// DevicePrompt carries what the user must see in order to approve the sign-in.
type DevicePrompt struct {
	VerificationURI         string
	VerificationURIComplete string
	UserCode                string
	ExpiresAt               time.Time
}

// deviceLogin runs the RFC 8628 device authorization grant and returns the user
// access token. prompt is invoked exactly once with the verification URL and
// user code; the underlying x/oauth2 helper handles polling, the server's
// interval, and slow_down responses until the user approves or the code
// expires.
func deviceLogin(ctx context.Context, hc *http.Client, cfg Config, prompt func(DevicePrompt)) (*oauth2.Token, error) {
	meta, err := discover(ctx, hc, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	conf := &oauth2.Config{
		ClientID: cfg.ClientID,
		Endpoint: oauth2.Endpoint{
			TokenURL:      meta.TokenEndpoint,
			DeviceAuthURL: meta.DeviceAuthorizationEndpoint,
		},
		Scopes: oauth.OIDCScopes,
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, hc)

	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("start device authorization: %w", err)
	}
	prompt(DevicePrompt{
		VerificationURI:         da.VerificationURI,
		VerificationURIComplete: da.VerificationURIComplete,
		UserCode:                da.UserCode,
		ExpiresAt:               da.Expiry,
	})
	tok, err := conf.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, fmt.Errorf("device authorization did not complete: %w", err)
	}
	return tok, nil
}

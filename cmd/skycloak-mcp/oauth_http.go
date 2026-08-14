package main

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/sky-cloak/skycloak-mcp/internal/oauth"
	"github.com/sky-cloak/skycloak-mcp/internal/tools"
)

// resourceMetadataPath is where RFC 9728 protected-resource metadata lives for
// a resource whose identifier is a bare origin.
const resourceMetadataPath = "/.well-known/oauth-protected-resource"

// oauthEnabled reports whether this server can accept a Keycloak access token.
// It needs both an issuer to verify tokens against and a dashboard to exchange
// them at; without either, the server is API-key only.
func (c httpConfig) oauthEnabled() bool {
	return c.issuer != "" && c.dashboardURL != ""
}

// publicBaseURL is the URL clients reach this server on, which RFC 9728 calls
// the resource identifier. A configured value wins; otherwise it is derived
// from the request so a deployment needs no extra configuration to be
// discoverable. Deriving it is safe here: the value only ever comes back to the
// caller that supplied the Host, and the authorization server it points at is
// fixed by configuration.
func publicBaseURL(configured string, r *http.Request) string {
	if configured != "" {
		return strings.TrimRight(configured, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	// Behind an ingress the TLS terminates upstream, so the only evidence of the
	// client's scheme is the forwarded header. Take the first hop.
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		if first := strings.TrimSpace(strings.Split(fwd, ",")[0]); first != "" {
			scheme = first
		}
	}
	return scheme + "://" + r.Host
}

// protectedResourceMetadataHandler serves the discovery document that tells a
// client which authorization server to use. resourceSuffix is appended to the
// base URL so the document served under `/.well-known/...-resource/mcp`
// identifies `<base>/mcp`, as RFC 9728 §3.1 requires.
func protectedResourceMetadataHandler(cfg httpConfig, resourceSuffix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md := &oauthex.ProtectedResourceMetadata{
			Resource:               publicBaseURL(cfg.publicURL, r) + resourceSuffix,
			AuthorizationServers:   []string{cfg.issuer},
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "Skycloak MCP",
			ResourceDocumentation:  "https://github.com/sky-cloak/skycloak-mcp",
		}
		auth.ProtectedResourceMetadataHandler(md).ServeHTTP(w, r)
	})
}

// challengeHeader builds the WWW-Authenticate value for an unauthenticated
// request. With OAuth on it names the metadata document, which is the only
// thing a first-time client has to follow to reach the browser flow.
func challengeHeader(cfg httpConfig, r *http.Request) string {
	challenge := `Bearer realm="skycloak-mcp"`
	if cfg.oauthEnabled() {
		challenge += `, resource_metadata="` + publicBaseURL(cfg.publicURL, r) + resourceMetadataPath + `"`
	}
	return challenge
}

// resolvedCredential is the Skycloak API key a request will act with, plus what
// that key may do when it is knowable.
type resolvedCredential struct {
	apiKey string
	// scopes is nil when the credential's grant is not enumerable (an API key),
	// which registers every tool.
	scopes tools.Scopes
}

type resolvedCredentialKey struct{}

func withResolvedCredential(ctx context.Context, c resolvedCredential) context.Context {
	return context.WithValue(ctx, resolvedCredentialKey{}, c)
}

func resolvedCredentialFrom(ctx context.Context) (resolvedCredential, bool) {
	c, ok := ctx.Value(resolvedCredentialKey{}).(resolvedCredential)
	return c, ok
}

// errNoScopes means the exchange succeeded but granted nothing, so the session
// would have no tools at all. Refusing says why; an empty tool list does not.
var errNoScopes = errors.New("your Skycloak role grants no access to this workspace")

// oauthBridge turns a realm access token into the session key a request runs
// on. It is nil when the server is API-key only.
type oauthBridge struct {
	verifier  *oauth.Verifier
	exchanger *oauth.Exchanger
}

func newOAuthBridge(cfg httpConfig) *oauthBridge {
	if !cfg.oauthEnabled() {
		return nil
	}
	return &oauthBridge{
		verifier:  oauth.NewVerifier(cfg.issuer, nil),
		exchanger: oauth.NewExchanger(cfg.dashboardURL, nil),
	}
}

// resolve verifies the token and exchanges it for a workspace-scoped key.
//
// Nothing here logs the token or the key: both are live credentials, and this
// runs on every request.
func (b *oauthBridge) resolve(ctx context.Context, token, workspaceID string) (resolvedCredential, error) {
	if b == nil {
		// No authorization server configured, so a non-key bearer is not something
		// this server can make sense of.
		return resolvedCredential{}, oauth.ErrInvalidToken
	}
	claims, err := b.verifier.Verify(ctx, token)
	if err != nil {
		return resolvedCredential{}, err
	}
	session, err := b.exchanger.Session(ctx, token, claims.Subject, workspaceID)
	if err != nil {
		return resolvedCredential{}, err
	}
	if len(session.Scopes) == 0 {
		return resolvedCredential{}, errNoScopes
	}
	return resolvedCredential{apiKey: session.APIKey, scopes: tools.NewScopes(session.Scopes)}, nil
}

// writeOAuthError maps a failed resolution onto a status the client can act on.
func writeOAuthError(w http.ResponseWriter, r *http.Request, cfg httpConfig, err error) {
	var ambiguous *oauth.AmbiguousWorkspaceError
	switch {
	case errors.Is(err, oauth.ErrInvalidToken):
		// Re-challenge: the client's token is stale or wrong, and the challenge is
		// how it learns to start the flow again.
		w.Header().Set("WWW-Authenticate", challengeHeader(cfg, r))
		http.Error(w, "the access token was not accepted; sign in again", http.StatusUnauthorized)
	case errors.As(err, &ambiguous):
		http.Error(w, ambiguous.Error(), http.StatusBadRequest)
	case errors.Is(err, oauth.ErrBadRequest):
		// The caller asked for something that does not parse, typically a bad
		// ?workspace= value. Their request to fix, not their permissions.
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, errNoScopes), errors.Is(err, oauth.ErrNotPermitted):
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		// The exchange itself failed. That is our dependency, not the caller's
		// request, so say so without echoing anything the dashboard returned.
		http.Error(w, "could not obtain a Skycloak session key; try again shortly", http.StatusBadGateway)
	}
}

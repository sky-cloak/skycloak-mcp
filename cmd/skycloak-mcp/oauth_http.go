package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
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
	return requestScheme(r) + "://" + r.Host
}

// requestScheme works out the scheme the client used.
//
// Behind an ingress the TLS terminates upstream, so the forwarded header is the
// only evidence; when even that is missing, anything but a loopback host is
// assumed to be HTTPS. Guessing `http` there would publish a resource
// identifier that does not match the URL the client connected on, and a
// conforming client rejects the mismatch rather than proceeding.
func requestScheme(r *http.Request) string {
	// Only the two schemes we could actually be served over. The header is
	// attacker-controlled on a direct connection and this value is interpolated
	// into a quoted WWW-Authenticate parameter, so echoing it back verbatim would
	// let a `"` inject a second resource_metadata into the challenge the client
	// parses to find its authorization server.
	switch first := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); first {
	case "http", "https":
		return first
	}
	if r.TLS != nil {
		return "https"
	}
	if isLoopbackHost(r.Host) {
		return "http"
	}
	return "https"
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
			ScopesSupported:        oauth.OIDCScopes,
			BearerMethodsSupported: []string{"header"},
			ResourceName:           "Skycloak MCP",
			ResourceDocumentation:  "https://skycloak.io/docs/mcp/",
		}
		auth.ProtectedResourceMetadataHandler(md).ServeHTTP(w, r)
	})
}

// challengeHeader builds the WWW-Authenticate value for an unauthenticated
// request. With OAuth on it names the metadata document, which is the only
// thing a first-time client has to follow to reach the browser flow, and the
// scopes that flow must ask for (RFC 6750 §3). Naming them twice is deliberate:
// a client reads whichever of the two it supports, and the go-sdk client
// prefers the challenge over the document's `scopes_supported`.
//
// The document it names is the one whose `resource` matches the URL the client
// actually used: a client that connected to `<origin>/mcp` and is handed the
// bare-origin document sees a resource that is not the URL it asked for, and a
// strict client treats that mismatch as a reason to stop (RFC 9728 §3.3).
func challengeHeader(cfg httpConfig, r *http.Request) string {
	challenge := `Bearer realm="skycloak-mcp"`
	if cfg.oauthEnabled() {
		challenge += `, resource_metadata="` + publicBaseURL(cfg.publicURL, r) + resourceMetadataPath + metadataSuffixFor(r) + `"`
		challenge += `, scope="` + strings.Join(oauth.OIDCScopes, " ") + `"`
	}
	return challenge
}

// metadataSuffixFor maps the MCP endpoint the caller used onto the metadata
// document that describes it.
func metadataSuffixFor(r *http.Request) string {
	if strings.TrimSuffix(r.URL.Path, "/") == "/mcp" {
		return "/mcp"
	}
	return ""
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

// oauthStage names the step a request was refused at. The three fail for
// entirely different reasons and are answered with statuses that overlap, so
// the stage travels with the error rather than being guessed from it later.
type oauthStage string

const (
	stageVerify   oauthStage = "verify"
	stageExchange oauthStage = "exchange"
	stageScopes   oauthStage = "scopes"
)

// oauthFailure is a refusal plus what the request had established by then.
type oauthFailure struct {
	stage oauthStage
	// subject is empty at the verify stage: there is no verified caller yet.
	subject   string
	workspace string
	err       error
}

func (f *oauthFailure) Error() string { return f.err.Error() }
func (f *oauthFailure) Unwrap() error { return f.err }

// resolve verifies the token and exchanges it for a workspace-scoped key.
//
// Nothing here logs the token or the key: both are live credentials, and this
// runs on every request.
func (b *oauthBridge) resolve(ctx context.Context, token, workspaceID string) (resolvedCredential, error) {
	if b == nil {
		// No authorization server configured, so a non-key bearer is not something
		// this server can make sense of.
		return resolvedCredential{}, &oauthFailure{stage: stageVerify, workspace: workspaceID, err: oauth.ErrInvalidToken}
	}
	claims, err := b.verifier.Verify(ctx, token)
	if err != nil {
		return resolvedCredential{}, &oauthFailure{stage: stageVerify, workspace: workspaceID, err: err}
	}
	session, err := b.exchanger.Session(ctx, token, claims.Subject, workspaceID)
	if err != nil {
		return resolvedCredential{}, &oauthFailure{stage: stageExchange, subject: claims.Subject, workspace: workspaceID, err: err}
	}
	if len(session.Scopes) == 0 {
		return resolvedCredential{}, &oauthFailure{stage: stageScopes, subject: claims.Subject, workspace: workspaceID, err: errNoScopes}
	}
	return resolvedCredential{apiKey: session.APIKey, scopes: tools.NewScopes(session.Scopes)}, nil
}

// writeOAuthError maps a failed resolution onto a status the client can act on,
// and records why. The body deliberately says little, so the log line is the
// only place a rejected sign-in leaves a trace.
func writeOAuthError(w http.ResponseWriter, r *http.Request, cfg httpConfig, err error) {
	status, body := http.StatusBadGateway, "could not obtain a Skycloak session key; try again shortly"
	var ambiguous *oauth.AmbiguousWorkspaceError
	switch {
	case errors.Is(err, oauth.ErrInvalidToken):
		// Re-challenge: the client's token is stale or wrong, and the challenge is
		// how it learns to start the flow again.
		w.Header().Set("WWW-Authenticate", challengeHeader(cfg, r))
		status, body = http.StatusUnauthorized, "the access token was not accepted; sign in again"
	case errors.As(err, &ambiguous):
		status, body = http.StatusBadRequest, ambiguous.Error()
	case errors.Is(err, oauth.ErrBadRequest):
		// The caller asked for something that does not parse, typically a bad
		// ?workspace= value. Their request to fix, not their permissions.
		status, body = http.StatusBadRequest, err.Error()
	case errors.Is(err, errNoScopes), errors.Is(err, oauth.ErrNotPermitted):
		status, body = http.StatusForbidden, err.Error()
	default:
		// The exchange itself failed. That is our dependency, not the caller's
		// request, so say so without echoing anything the dashboard returned.
	}
	logOAuthRejection(cfg, status, err)
	http.Error(w, body, status)
}

// logOAuthRejection writes one line per refused request: the stage that failed,
// the status the caller got, and what the failing dependency said.
//
// The caller is identified by the token's subject only, and only once it has
// been verified. The access token, the Authorization header and the minted API
// key are all credentials and never appear; every value here comes from an
// error message or from configuration.
func logOAuthRejection(cfg httpConfig, status int, err error) {
	fields := []string{"stage=unknown", fmt.Sprintf("status=%d", status)}

	var failure *oauthFailure
	if errors.As(err, &failure) {
		fields[0] = "stage=" + string(failure.stage)
		if failure.subject != "" {
			// Quoted: the subject is a claim from a token, so it is only as
			// well-behaved as the realm that issued it, and a newline in it would
			// otherwise forge a second log line.
			fields = append(fields, "subject="+strconv.Quote(failure.subject))
		}
		if failure.workspace != "" {
			fields = append(fields, "workspace="+failure.workspace)
		}
		if failure.stage == stageExchange {
			// Which dashboard we called: a deployment pointed at the wrong control
			// plane fails exactly like a broken one otherwise.
			fields = append(fields, "dashboard_host="+hostOf(cfg.dashboardURL))
		}
	}

	var verifyErr *oauth.VerifyError
	if errors.As(err, &verifyErr) {
		fields = append(fields, "reason="+string(verifyErr.Reason))
	}
	// Absent when the dashboard never answered at all, which a missing field says
	// more plainly than a zero would.
	var statusErr *oauth.StatusError
	if errors.As(err, &statusErr) {
		fields = append(fields, fmt.Sprintf("dashboard_status=%d", statusErr.Status))
	}

	fields = append(fields, "err="+quoteDetail(err.Error()))
	cfg.logf("oauth request rejected: %s", strings.Join(fields, " "))
}

// maxLoggedDetail caps the error text a rejection line carries. Part of that
// text is the caller's own: the key id sits in the unsigned token header and is
// bounded only by how much of a request the server will read, so an uncapped
// line lets one unauthenticated request write a log entry its own size.
const maxLoggedDetail = 256

// quoteDetail bounds and quotes an error message for the log. Quoting is what
// keeps a newline in it from forging a second line; the cut can land inside a
// multi-byte rune, which quoting renders as an escape rather than broken output.
func quoteDetail(msg string) string {
	if len(msg) > maxLoggedDetail {
		return strconv.Quote(msg[:maxLoggedDetail]) + "(truncated)"
	}
	return strconv.Quote(msg)
}

// logStartupConfig records the wiring this process resolved, once. Both of the
// last two production problems were a value nobody could read back from a
// running pod: a public URL advertising the wrong scheme, and a deployment
// exchanging tokens at the wrong dashboard.
func logStartupConfig(cfg httpConfig) {
	publicURL := cfg.publicURL
	if publicURL == "" {
		publicURL = "(derived per request)"
	}
	cfg.logf("http config: oauth=%t issuer=%s dashboard=%s public_url=%s endpoint=%s allow_writes=%t",
		cfg.oauthEnabled(), orNone(cfg.issuer), orNone(cfg.dashboardURL), publicURL, cfg.endpoint, cfg.allowWrites)
}

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// hostOf reduces a configured base URL to its host, which is the part that says
// which environment is being called.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

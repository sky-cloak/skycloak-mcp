package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeRealm serves OIDC discovery and a JWKS, and mints access tokens signed
// with its own throwaway key. It stands in for the Skycloak Keycloak realm.
type fakeRealm struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeRealm(t *testing.T) *fakeRealm {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &fakeRealm{key: key}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   f.srv.URL,
			"jwks_uri": f.srv.URL + "/certs",
		})
	})
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "test-kid", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRealm) token(t *testing.T, subject string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": f.srv.URL,
		"sub": subject,
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	})
	tok.Header["kid"] = "test-kid"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// fakeSessionKeyAPI stands in for the dashboard's POST /api/mcp/session-key.
type fakeSessionKeyAPI struct {
	srv *httptest.Server

	mu         sync.Mutex
	calls      int
	workspaces []string
	authz      []string

	scopes []string
	status int
	body   any
}

func newFakeSessionKeyAPI(t *testing.T, scopes []string) *fakeSessionKeyAPI {
	t.Helper()
	d := &fakeSessionKeyAPI{scopes: scopes}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mcp/session-key" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &req)

		d.mu.Lock()
		d.calls++
		n := d.calls
		d.workspaces = append(d.workspaces, req["workspace_id"])
		d.authz = append(d.authz, r.Header.Get("Authorization"))
		status, body, scopes := d.status, d.body, d.scopes
		d.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"api_key":      "sk_sc_session_" + string(rune('0'+n)),
			"workspace_id": "ws-1",
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"scopes":       scopes,
		})
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeSessionKeyAPI) snapshot() (int, []string, []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, append([]string(nil), d.workspaces...), append([]string(nil), d.authz...)
}

// writeSessionScopes is what an owner's session key carries.
var writeSessionScopes = []string{
	"clusters:read", "clusters:write", "clusters:events:read", "clusters:insights:read",
	"clusters:logs:read", "clusters:security:read", "clusters:security:write",
	"clusters:exports:read", "clusters:exports:write", "clusters:imports:read", "clusters:imports:write",
	"clusters:extensions:read", "clusters:extensions:write",
	"realms:read", "realms:write", "realm-users:read", "realm-users:write",
	"realm-roles:read", "realm-roles:write", "realm-groups:read", "realm-groups:write",
	"applications:read", "applications:write", "identity-providers:read", "identity-providers:write",
	"domains:read", "domains:write", "themes:read", "themes:write", "branding:read", "branding:write",
	"extensions:read", "extensions:write", "smtp:read", "smtp:write",
	"siem:read", "siem:write", "webhooks:read", "webhooks:write",
}

// readSessionScopes is what a member's session key carries.
func readSessionScopes() []string {
	var out []string
	for _, s := range writeSessionScopes {
		if !strings.HasSuffix(s, ":write") {
			out = append(out, s)
		}
	}
	return out
}

// oauthStack wires a realm, a dashboard, an upstream API and the handler.
type oauthStack struct {
	realm    *fakeRealm
	dash     *fakeSessionKeyAPI
	upstream *fakeUpstream
	ts       *httptest.Server
}

func newOAuthStack(t *testing.T, scopes []string) *oauthStack {
	t.Helper()
	st := &oauthStack{
		realm:    newFakeRealm(t),
		dash:     newFakeSessionKeyAPI(t, scopes),
		upstream: newFakeUpstream(t),
	}
	st.ts = httptest.NewServer(newHTTPHandler(httpConfig{
		endpoint:     st.upstream.srv.URL,
		apiVersion:   "v1",
		userAgent:    "test",
		allowWrites:  true,
		issuer:       st.realm.srv.URL,
		dashboardURL: st.dash.srv.URL,
	}))
	t.Cleanup(st.ts.Close)
	return st
}

// The whole point: a client that presents a realm access token and no Skycloak
// key gets a working session, running on a key minted for it.
func TestOAuthTokenIsExchangedForASessionKey(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)
	token := st.realm.token(t, "user-1")

	resp := mcpPost(t, st.ts.URL, token, "", initBody)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize = %d, want 200: %s", resp.StatusCode, truncate(body))
	}

	resp = mcpPost(t, st.ts.URL, token, "", listClustersBody)
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tool call = %d, want 200: %s", resp.StatusCode, truncate(body))
	}

	keys := st.upstream.seenKeys()
	if len(keys) == 0 {
		t.Fatal("the tool call never reached upstream")
	}
	for _, k := range keys {
		if !strings.HasPrefix(k, "sk_sc_session_") {
			t.Fatalf("upstream saw %q, want the minted session key", k)
		}
	}

	_, _, authz := st.dash.snapshot()
	if authz[0] != "Bearer "+token {
		t.Fatalf("the dashboard was called with %q, want the caller's access token", authz[0])
	}
}

// A read-only member must not be shown the write tools their key would 403 on.
func TestOAuthSessionScopesTailorTheToolList(t *testing.T) {
	for _, tt := range []struct {
		name      string
		scopes    []string
		wantWrite bool
	}{
		{"owner", writeSessionScopes, true},
		{"member", readSessionScopes(), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := newOAuthStack(t, tt.scopes)
			token := st.realm.token(t, "user-"+tt.name)

			resp := mcpPost(t, st.ts.URL, token, "", initBody)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			resp = mcpPost(t, st.ts.URL, token, "", `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if got := strings.Contains(string(body), "skycloak_delete_realm"); got != tt.wantWrite {
				t.Fatalf("write tool exposed = %v, want %v", got, tt.wantWrite)
			}
			if !strings.Contains(string(body), "skycloak_list_clusters") {
				t.Fatalf("read tools missing from a %s session: %s", tt.name, truncate(body))
			}
		})
	}
}

// A bearer that is not a token this realm issued must be refused, and told how
// to authenticate properly rather than passed upstream as an API key.
func TestOAuthRejectsTokensItCannotVerify(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)
	other := newFakeRealm(t)

	for _, tt := range []struct{ name, token string }{
		{"another realm's token", other.token(t, "user-1")},
		{"garbage", "not.a.jwt"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			resp := mcpPost(t, st.ts.URL, tt.token, "", initBody)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("challenge = %q, want it to point at the metadata document", resp.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

// A Skycloak API key must keep working exactly as before once OAuth is on, or
// every scripted client breaks.
func TestAPIKeysStillWorkWhenOAuthIsEnabled(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)

	resp := mcpPost(t, st.ts.URL, "sk_sc_direct", "", initBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	resp = mcpPost(t, st.ts.URL, "sk_sc_direct", "", listClustersBody)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, truncate(body))
	}

	found := false
	for _, k := range st.upstream.seenKeys() {
		if k == "sk_sc_direct" {
			found = true
		}
	}
	if !found {
		t.Fatalf("upstream never saw the caller's own key; saw %v", st.upstream.seenKeys())
	}
	if calls, _, _ := st.dash.snapshot(); calls != 0 {
		t.Fatalf("an API key triggered %d session-key exchanges, want 0", calls)
	}
}

// ?workspace= has to reach the mint, or a user in several workspaces can never
// pick one.
func TestWorkspaceQueryParameterReachesTheExchange(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)
	token := st.realm.token(t, "user-1")

	resp := mcpPost(t, st.ts.URL+"?workspace=ws-chosen", token, "", initBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	_, workspaces, _ := st.dash.snapshot()
	if len(workspaces) == 0 || workspaces[0] != "ws-chosen" {
		t.Fatalf("dashboard saw workspaces %v, want ws-chosen", workspaces)
	}
}

// A user in several workspaces gets a 400 they can act on: it has to name the
// query parameter and the workspaces, not just say "bad request".
func TestAmbiguousWorkspaceIsAnActionableError(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)
	st.dash.mu.Lock()
	st.dash.status = http.StatusBadRequest
	st.dash.body = map[string]any{
		"error":      "You belong to more than one workspace; specify workspace_id",
		"workspaces": []map[string]string{{"id": "ws-a", "name": "Acme"}, {"id": "ws-b", "name": "Beta"}},
	}
	st.dash.mu.Unlock()

	resp := mcpPost(t, st.ts.URL, st.realm.token(t, "user-1"), "", initBody)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	for _, want := range []string{"?workspace=", "ws-a", "Acme", "ws-b"} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("body %q does not mention %q", truncate(body), want)
		}
	}
}

// The dashboard's refusals have to keep their meaning: "you may not" is 403,
// "that is not a workspace id" is 400, and a broken dashboard is 502 rather
// than something the caller will waste time re-authenticating over.
func TestDashboardRefusalsKeepTheirStatus(t *testing.T) {
	for _, tt := range []struct {
		name     string
		status   int
		body     any
		want     int
		wantText string
	}{
		{"not permitted", http.StatusForbidden, map[string]string{"error": "Email verification required"}, http.StatusForbidden, "Email verification required"},
		{"bad workspace id", http.StatusBadRequest, map[string]string{"error": "Invalid workspace ID"}, http.StatusBadRequest, "Invalid workspace ID"},
		{"dashboard down", http.StatusInternalServerError, map[string]string{"error": "boom"}, http.StatusBadGateway, "session key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			st := newOAuthStack(t, writeSessionScopes)
			st.dash.mu.Lock()
			st.dash.status, st.dash.body = tt.status, tt.body
			st.dash.mu.Unlock()

			resp := mcpPost(t, st.ts.URL, st.realm.token(t, "user-1"), "", initBody)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != tt.want {
				t.Fatalf("status = %d, want %d: %s", resp.StatusCode, tt.want, truncate(body))
			}
			if !strings.Contains(string(body), tt.wantText) {
				t.Fatalf("body %q does not mention %q", truncate(body), tt.wantText)
			}
		})
	}
}

// The session key is minted once and reused; a mint per MCP request would
// rotate the caller's key on every tool call.
func TestSessionKeyIsMintedOncePerCaller(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)
	token := st.realm.token(t, "user-1")

	for range 3 {
		resp := mcpPost(t, st.ts.URL, token, "", initBody)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if calls, _, _ := st.dash.snapshot(); calls != 1 {
		t.Fatalf("the dashboard was called %d times for one caller, want 1", calls)
	}
}

// One caller's session key must never serve another caller's request.
func TestOAuthSessionsAreIsolatedPerSubject(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)

	for _, sub := range []string{"user-a", "user-b"} {
		token := st.realm.token(t, sub)
		resp := mcpPost(t, st.ts.URL, token, "", initBody)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		resp = mcpPost(t, st.ts.URL, token, "", listClustersBody)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	calls, _, _ := st.dash.snapshot()
	if calls != 2 {
		t.Fatalf("two subjects produced %d mints, want 2", calls)
	}
	seen := map[string]bool{}
	for _, k := range st.upstream.seenKeys() {
		seen[k] = true
	}
	if len(seen) < 2 {
		t.Fatalf("both callers went upstream with the same key: %v", seen)
	}
}

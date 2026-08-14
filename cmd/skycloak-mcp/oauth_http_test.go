package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// oauthConfig is the minimum httpConfig that turns the OAuth path on.
func oauthConfig(issuer, dashboard string) httpConfig {
	return httpConfig{issuer: issuer, dashboardURL: dashboard, allowWrites: true}
}

// A client with no credential discovers how to authenticate from RFC 9728
// metadata. Without it `claude mcp add` has nothing to go on but the 401.
func TestProtectedResourceMetadataIsServedUnauthenticated(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(oauthConfig("https://login.example/realms/skycloak", "https://app.example")))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var md struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if md.Resource != ts.URL {
		t.Fatalf("resource = %q, want %q", md.Resource, ts.URL)
	}
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != "https://login.example/realms/skycloak" {
		t.Fatalf("authorization_servers = %v, want the realm issuer", md.AuthorizationServers)
	}
}

// SKYCLOAK_PUBLIC_URL wins over the request's own origin, so a deployment
// behind a proxy that rewrites Host still advertises the URL clients use.
func TestProtectedResourceMetadataPrefersConfiguredPublicURL(t *testing.T) {
	cfg := oauthConfig("https://login.example/realms/skycloak", "https://app.example")
	cfg.publicURL = "https://mcp.example.io/"
	ts := httptest.NewServer(newHTTPHandler(cfg))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var md struct {
		Resource string `json:"resource"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if md.Resource != "https://mcp.example.io" {
		t.Fatalf("resource = %q, want the configured public URL without its trailing slash", md.Resource)
	}
}

// The 401 has to name the metadata document, or a client that has never seen
// this server cannot find the authorization server (RFC 9728 §5.1).
func TestUnauthenticatedChallengeAdvertisesResourceMetadata(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(oauthConfig("https://login.example/realms/skycloak", "https://app.example")))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	want := `resource_metadata="` + ts.URL + `/.well-known/oauth-protected-resource"`
	if !strings.Contains(challenge, want) {
		t.Fatalf("WWW-Authenticate = %q, want it to contain %s", challenge, want)
	}
}

// Only the protected-resource document lives here. The authorization server is
// Keycloak, and it is where clients register and get tokens; answering anything
// on those paths would make this server look like an authorization server it is
// not, which is what sent clients into a failing registration before.
func TestOnlyTheResourceMetadataPathIsServed(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(oauthConfig("https://login.example/realms/skycloak", "https://app.example")))
	defer ts.Close()

	for _, path := range []string{"/.well-known/oauth-authorization-server", "/register", "/authorize", "/token"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET %s = %d, want 404", path, resp.StatusCode)
		}
	}
}

// A client that connected to <origin>/mcp looks for the document under the
// path-inserted form, and the resource it names has to match the URL it used.
func TestResourceMetadataIsServedForThePathInsertedForm(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(oauthConfig("https://login.example/realms/skycloak", "https://app.example")))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var md struct {
		Resource string `json:"resource"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if md.Resource != ts.URL+"/mcp" {
		t.Fatalf("resource = %q, want %q", md.Resource, ts.URL+"/mcp")
	}
}

// An API-key-only server has nothing to verify a token against, so every bearer
// it gets is a key, whatever its shape. Splitting bearers by prefix must not
// break a caller whose key does not carry the one we expect.
func TestBearerIsAlwaysAKeyWhenOAuthIsOff(t *testing.T) {
	upstream := newFakeUpstream(t)
	ts := httptest.NewServer(newHTTPHandler(httpConfig{
		endpoint: upstream.srv.URL, apiVersion: "v1", userAgent: "test", allowWrites: false,
	}))
	defer ts.Close()

	resp := mcpPost(t, ts.URL, "legacy-key-no-prefix", "", initBody)
	_ = resp.Body.Close()
	resp = mcpPost(t, ts.URL, "legacy-key-no-prefix", "", listClustersBody)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	for _, k := range upstream.seenKeys() {
		if k == "legacy-key-no-prefix" {
			return
		}
	}
	t.Fatalf("upstream never saw the caller's key; saw %v", upstream.seenKeys())
}

// With no authorization server configured the server is API-key only, and must
// keep saying so: advertising OAuth it cannot complete sends clients into a
// Dynamic Client Registration attempt that fails.
func TestMetadataIsAbsentWhenOAuthIsNotConfigured(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(httpConfig{allowWrites: true}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/.well-known/oauth-protected-resource")
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

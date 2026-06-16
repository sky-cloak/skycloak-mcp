package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestConfigFromEnv_DefaultsAndOverrides(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		t.Setenv("SKYCLOAK_ISSUER", "")
		t.Setenv("SKYCLOAK_CLIENT_ID", "")
		t.Setenv("SKYCLOAK_DASHBOARD_URL", "")
		c := ConfigFromEnv()
		if c.Issuer != defaultIssuer || c.ClientID != defaultClientID || c.DashboardURL != defaultDashboard {
			t.Fatalf("unexpected defaults: %+v", c)
		}
	})
	t.Run("overrides and trims trailing slash", func(t *testing.T) {
		t.Setenv("SKYCLOAK_ISSUER", "https://login.app.dev.skycloak.io/realms/skycloak-dev")
		t.Setenv("SKYCLOAK_CLIENT_ID", "skycloak-mcp")
		t.Setenv("SKYCLOAK_DASHBOARD_URL", "https://app.dev.skycloak.io/")
		c := ConfigFromEnv()
		if c.DashboardURL != "https://app.dev.skycloak.io" {
			t.Fatalf("trailing slash not trimmed: %q", c.DashboardURL)
		}
		if c.Issuer != "https://login.app.dev.skycloak.io/realms/skycloak-dev" {
			t.Fatalf("issuer override lost: %q", c.Issuer)
		}
	})
}

func TestLoadAPIKey_EnvWins(t *testing.T) {
	keyring.MockInit()
	t.Setenv("SKYCLOAK_API_KEY", "sk_sc_env")
	got, err := LoadAPIKey(Config{Issuer: "iss"})
	if err != nil || got != "sk_sc_env" {
		t.Fatalf("env key should win: got %q err %v", got, err)
	}
}

func TestLoadAPIKey_KeychainRoundTrip(t *testing.T) {
	keyring.MockInit()
	t.Setenv("SKYCLOAK_API_KEY", "") // force the keychain path
	cfg := Config{Issuer: "https://login.app.skycloak.io/realms/skycloak"}

	if _, err := LoadAPIKey(cfg); err != ErrNoCredential {
		t.Fatalf("expected ErrNoCredential, got %v", err)
	}
	if err := storeAPIKey(cfg, "sk_sc_stored"); err != nil {
		t.Fatalf("store: %v", err)
	}
	got, err := LoadAPIKey(cfg)
	if err != nil || got != "sk_sc_stored" {
		t.Fatalf("load after store: got %q err %v", got, err)
	}
	if err := Logout(cfg); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := LoadAPIKey(cfg); err != ErrNoCredential {
		t.Fatalf("expected ErrNoCredential after logout, got %v", err)
	}
	// Logout is idempotent.
	if err := Logout(cfg); err != nil {
		t.Fatalf("second logout should be a no-op: %v", err)
	}
}

func TestParseWorkspaces(t *testing.T) {
	cases := map[string]struct {
		in   string
		want int
	}{
		"bare array":          {`[{"id":"a","name":"A"},{"id":"b","name":"B"}]`, 2},
		"workspaces envelope": {`{"workspaces":[{"id":"a","name":"A"}]}`, 1},
		"data envelope":       {`{"data":[{"id":"a","name":"A"}]}`, 1},
		"drops empty ids":     {`[{"id":"a"},{"name":"no id"}]`, 1},
		"empty":               {`[]`, 0},
		"garbage":             {`not json`, 0},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := parseWorkspaces([]byte(tc.in)); len(got) != tc.want {
				t.Fatalf("got %d workspaces, want %d (%v)", len(got), tc.want, got)
			}
		})
	}
}

func TestDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(oidcMetadata{
			TokenEndpoint:               "https://kc/token",
			DeviceAuthorizationEndpoint: "https://kc/device",
		})
	}))
	defer srv.Close()

	m, err := discover(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if m.TokenEndpoint != "https://kc/token" || m.DeviceAuthorizationEndpoint != "https://kc/device" {
		t.Fatalf("unexpected metadata: %+v", m)
	}

	// An issuer that does not advertise the device grant is an error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(oidcMetadata{TokenEndpoint: "https://kc/token"})
	}))
	defer bad.Close()
	if _, err := discover(context.Background(), bad.Client(), bad.URL); err == nil {
		t.Fatal("expected error when device endpoint is missing")
	}
}

func TestResolveScopes_FiltersWritesAndCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/api-keys/scopes" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(scopesResponse{Scopes: []string{
			"clusters:read", "clusters:write", "clusters:credentials:read", "realms:read",
		}})
	}))
	defer srv.Close()
	cfg := Config{DashboardURL: srv.URL}

	ro := resolveScopes(context.Background(), srv.Client(), cfg, "tkn", false)
	if !equalSet(ro, []string{"clusters:read", "realms:read"}) {
		t.Fatalf("read-only scopes wrong: %v", ro)
	}
	rw := resolveScopes(context.Background(), srv.Client(), cfg, "tkn", true)
	if !equalSet(rw, []string{"clusters:read", "clusters:write", "realms:read"}) {
		t.Fatalf("read+write scopes wrong (credentials must still be excluded): %v", rw)
	}
}

func TestMintAPIKey_SendsAuthAndWorkspace(t *testing.T) {
	var gotAuth, gotWS string
	var gotBody mintRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/api-keys" {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotWS = r.Header.Get("X-Workspace-ID")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(mintResponse{FullKey: "sk_sc_minted"})
	}))
	defer srv.Close()
	cfg := Config{DashboardURL: srv.URL}

	key, err := mintAPIKey(context.Background(), srv.Client(), cfg, "tkn", "ws-123", []string{"clusters:read"}, "skycloak-mcp@host", 0)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if key != "sk_sc_minted" {
		t.Fatalf("key: %q", key)
	}
	if gotAuth != "Bearer tkn" {
		t.Fatalf("auth header: %q", gotAuth)
	}
	if gotWS != "ws-123" {
		t.Fatalf("workspace header: %q", gotWS)
	}
	if gotBody.Name == "" || len(gotBody.Scopes) != 1 {
		t.Fatalf("body: %+v", gotBody)
	}
}

func TestGetDefaultWorkspace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/workspaces/default" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(workspace{ID: "ws-default", Name: "Acme"})
	}))
	defer srv.Close()

	got := getDefaultWorkspace(context.Background(), srv.Client(), Config{DashboardURL: srv.URL}, "tkn")
	if got.ID != "ws-default" || got.Name != "Acme" {
		t.Fatalf("default workspace: %+v", got)
	}

	// Non-200 yields a zero workspace (caller falls back to listing).
	bad := httptest.NewServer(http.NotFoundHandler())
	defer bad.Close()
	if z := getDefaultWorkspace(context.Background(), bad.Client(), Config{DashboardURL: bad.URL}, "tkn"); z.ID != "" {
		t.Fatalf("expected zero workspace on non-200, got %+v", z)
	}
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[string]int, len(a))
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

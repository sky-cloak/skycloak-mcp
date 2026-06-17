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

func TestMintCLIKey(t *testing.T) {
	var gotAuth string
	var gotBody cliKeyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/cli/keys" {
			http.Error(w, "bad route", http.StatusNotFound)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"full_key": "sk_sc_cli",
			"api_key":  map[string]any{"workspace_id": "ws-7"},
		})
	}))
	defer srv.Close()
	cfg := Config{DashboardURL: srv.URL}

	// Read-only: no scopes sent (the server applies its read-only default).
	key, ws, err := mintCLIKey(context.Background(), srv.Client(), cfg, "tkn", InitOptions{})
	if err != nil || key != "sk_sc_cli" || ws != "ws-7" {
		t.Fatalf("mint: key=%q ws=%q err=%v", key, ws, err)
	}
	if gotAuth != "Bearer tkn" {
		t.Fatalf("auth header: %q", gotAuth)
	}
	if len(gotBody.Scopes) != 0 {
		t.Fatalf("read-only must send no scopes, got %v", gotBody.Scopes)
	}

	// --allow-writes: write scopes sent and workspace_id forwarded; never credentials.
	if _, _, err = mintCLIKey(context.Background(), srv.Client(), cfg, "tkn", InitOptions{AllowWrites: true, WorkspaceID: "ws-x"}); err != nil {
		t.Fatalf("mint writes: %v", err)
	}
	if len(gotBody.Scopes) == 0 || gotBody.WorkspaceID != "ws-x" {
		t.Fatalf("writes/workspace not forwarded: %+v", gotBody)
	}
	for _, s := range gotBody.Scopes {
		if s == "clusters:credentials:read" {
			t.Fatalf("must never request clusters:credentials:read")
		}
	}
}

package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
		t.Setenv("SKYCLOAK_ISSUER", "https://login.example.test/realms/example")
		t.Setenv("SKYCLOAK_CLIENT_ID", "skycloak-mcp")
		t.Setenv("SKYCLOAK_DASHBOARD_URL", "https://app.example.test/")
		c := ConfigFromEnv()
		if c.DashboardURL != "https://app.example.test" {
			t.Fatalf("trailing slash not trimmed: %q", c.DashboardURL)
		}
		if c.Issuer != "https://login.example.test/realms/example" {
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

// The CLI sign-in has the same stake in `openid` as the hosted OAuth path: the
// key it mints comes from the dashboard, which validates the device token
// against Keycloak's userinfo endpoint and gets a 403 for a token granted
// without it.
func TestDeviceLoginRequestsTheOIDCScopes(t *testing.T) {
	var gotScope string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token_endpoint":                "http://" + r.Host + "/token",
				"device_authorization_endpoint": "http://" + r.Host + "/device",
			})
		case "/device":
			_ = r.ParseForm()
			gotScope = r.Form.Get("scope")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "UC",
				"verification_uri": "https://kc/device", "interval": 1, "expires_in": 300,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Stop at the prompt: the authorization request is already on the wire by
	// then, and polling for an approval nobody will give just costs a second.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, _ = deviceLogin(ctx, srv.Client(), Config{Issuer: srv.URL, ClientID: "cli"}, func(DevicePrompt) { cancel() })

	for _, want := range []string{"openid", "profile", "email"} {
		if !strings.Contains(gotScope, want) {
			t.Fatalf("device authorization scope = %q, want it to contain %q", gotScope, want)
		}
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

// The browser consent page lists only Keycloak scopes, so the CLI must state
// what the key itself will be able to do before the user approves.
func TestPrintGrantNotice(t *testing.T) {
	t.Run("read-only mentions read-only and never claims writes", func(t *testing.T) {
		var b strings.Builder
		printGrantNotice(&b, InitOptions{})
		got := b.String()
		if !strings.Contains(got, "read-only") {
			t.Fatalf("expected read-only notice, got %q", got)
		}
		if strings.Contains(got, "MODIFY") {
			t.Fatalf("read-only notice must not claim write access, got %q", got)
		}
	})

	t.Run("allow-writes names the write powers", func(t *testing.T) {
		var b strings.Builder
		printGrantNotice(&b, InitOptions{AllowWrites: true})
		got := b.String()
		for _, want := range []string{"MODIFY", "clusters", "realms"} {
			if !strings.Contains(got, want) {
				t.Fatalf("expected %q in write notice, got %q", want, got)
			}
		}
	})

	t.Run("expiry is stated either way", func(t *testing.T) {
		var b strings.Builder
		printGrantNotice(&b, InitOptions{})
		if !strings.Contains(b.String(), "does not expire") {
			t.Fatalf("expected no-expiry warning, got %q", b.String())
		}
		var c strings.Builder
		printGrantNotice(&c, InitOptions{TTL: 2 * time.Hour})
		if !strings.Contains(c.String(), "expires in 2h") {
			t.Fatalf("expected TTL notice, got %q", c.String())
		}
	})
}

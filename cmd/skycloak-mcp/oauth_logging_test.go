package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// safeBuffer collects log output written from the handler's goroutine while the
// test reads it from its own.
type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// signed mints a token with arbitrary claims and key id, so a test can produce
// each distinct way verification can fail.
func (f *fakeRealm) signed(t *testing.T, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// Every rejected request has to leave a line naming the stage that failed and
// the status the caller got. Without it a "credentials rejected" report has four
// very different causes and no way to tell them apart.
func TestRejectedOAuthRequestsAreLogged(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, st *oauthStack) string // returns the bearer to send
		want  []string
	}{
		{
			name: "expired token",
			setup: func(t *testing.T, st *oauthStack) string {
				return st.realm.signed(t, "test-kid", jwt.MapClaims{
					"iss": st.realm.srv.URL, "sub": "user-1",
					"exp": time.Now().Add(-time.Hour).Unix(),
				})
			},
			want: []string{"stage=verify", "status=401", "reason=expired"},
		},
		{
			name: "wrong issuer",
			setup: func(t *testing.T, st *oauthStack) string {
				return st.realm.signed(t, "test-kid", jwt.MapClaims{
					"iss": "https://login.evil.example/realms/skycloak", "sub": "user-1",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
			},
			want: []string{"stage=verify", "status=401", "reason=wrong_issuer"},
		},
		{
			name: "signed by another realm",
			setup: func(t *testing.T, _ *oauthStack) string {
				return newFakeRealm(t).token(t, "user-1")
			},
			want: []string{"stage=verify", "status=401", "reason=bad_signature"},
		},
		{
			name: "unknown key id",
			setup: func(t *testing.T, st *oauthStack) string {
				return st.realm.signed(t, "rotated-out", jwt.MapClaims{
					"iss": st.realm.srv.URL, "sub": "user-1",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
			},
			want: []string{"stage=verify", "status=401", "reason=unknown_key_id"},
		},
		{
			name: "not an access token",
			setup: func(t *testing.T, st *oauthStack) string {
				return st.realm.signed(t, "test-kid", jwt.MapClaims{
					"iss": st.realm.srv.URL, "sub": "user-1", "typ": "ID",
					"exp": time.Now().Add(time.Hour).Unix(),
				})
			},
			want: []string{"stage=verify", "status=401", "reason=wrong_token_type"},
		},
		{
			name: "malformed bearer",
			setup: func(*testing.T, *oauthStack) string { return "not.a.jwt" },
			want:  []string{"stage=verify", "status=401", "reason=malformed"},
		},
		{
			name: "dashboard broken",
			setup: func(t *testing.T, st *oauthStack) string {
				st.dash.mu.Lock()
				st.dash.status, st.dash.body = http.StatusInternalServerError, map[string]string{"error": "boom"}
				st.dash.mu.Unlock()
				return st.realm.token(t, "user-1")
			},
			want: []string{"stage=exchange", "status=502", "dashboard_status=500", "subject=\"user-1\""},
		},
		{
			name: "dashboard refuses the caller",
			setup: func(t *testing.T, st *oauthStack) string {
				st.dash.mu.Lock()
				st.dash.status, st.dash.body = http.StatusForbidden, map[string]string{"error": "Email verification required"}
				st.dash.mu.Unlock()
				return st.realm.token(t, "user-1")
			},
			want: []string{"stage=exchange", "status=403", "dashboard_status=403"},
		},
		{
			name: "grant is empty",
			setup: func(t *testing.T, st *oauthStack) string {
				return st.realm.token(t, "user-1")
			},
			want: []string{"stage=scopes", "status=403", "subject=\"user-1\""},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			scopes := writeSessionScopes
			if tt.name == "grant is empty" {
				scopes = nil
			}
			st := newOAuthStack(t, scopes)
			bearer := tt.setup(t, st)

			resp := mcpPost(t, st.ts.URL, bearer, "", initBody)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			got := st.logs.String()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("log %q does not contain %q", got, want)
				}
			}
		})
	}
}

// The dashboard host is the other half of a silent misconfiguration: a dev
// deployment exchanging tokens against production looks identical in the logs
// until the host is named.
func TestExchangeFailureLogsTheDashboardBeingCalled(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)
	st.dash.mu.Lock()
	st.dash.status, st.dash.body = http.StatusInternalServerError, map[string]string{"error": "boom"}
	st.dash.mu.Unlock()

	resp := mcpPost(t, st.ts.URL, st.realm.token(t, "user-1"), "", initBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	host, err := url.Parse(st.dash.srv.URL)
	if err != nil {
		t.Fatalf("parse dashboard url: %v", err)
	}
	if got := st.logs.String(); !strings.Contains(got, "dashboard_host="+host.Host) {
		t.Fatalf("log %q does not name the dashboard host %q", got, host.Host)
	}
}

// The reason this logging did not exist. A live credential must not reach the
// log, on any rejection path: not the access token, not a piece of it, not the
// header that carried it, and not the key the dashboard minted.
func TestOAuthRejectionLogsNeverCarryCredentials(t *testing.T) {
	// An empty grant is the worst case: the dashboard did mint a key, and the
	// request is refused with that key in hand.
	st := newOAuthStack(t, nil)
	token := st.realm.token(t, "user-1")

	resp := mcpPost(t, st.ts.URL, token, "", initBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	got := st.logs.String()
	if got == "" {
		t.Fatal("the rejection was not logged at all")
	}
	for _, secret := range append(tokenParts(token), token, "Bearer "+token, "sk_sc_session_") {
		if strings.Contains(got, secret) {
			t.Fatalf("log leaked %q: %s", secret, got)
		}
	}
}

// tokenParts is every segment of a JWT long enough to be a credential on its
// own; the header is short and shared, so it is not one.
func tokenParts(token string) []string {
	var out []string
	for _, part := range strings.Split(token, ".") {
		if len(part) > 32 {
			out = append(out, part)
		}
	}
	return out
}

// A verification failure happens before there is a verified subject, so nothing
// identifies the caller. It must not invent one.
func TestVerificationFailureLogsNoSubject(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)

	resp := mcpPost(t, st.ts.URL, "not.a.jwt", "", initBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if got := st.logs.String(); strings.Contains(got, "subject=") {
		t.Fatalf("log %q claims a subject a failed verification never established", got)
	}
}

// An accepted request is not a rejection and must stay quiet: this path runs on
// every call.
func TestSuccessfulResolutionIsNotLogged(t *testing.T) {
	st := newOAuthStack(t, writeSessionScopes)

	resp := mcpPost(t, st.ts.URL, st.realm.token(t, "user-1"), "", initBody)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if got := st.logs.String(); got != "" {
		t.Fatalf("a successful request logged %q, want nothing", got)
	}
}

// The last two production problems were both silent misconfiguration, so the
// resolved wiring goes in the log at startup where an operator can read it back.
func TestStartupLogsTheResolvedConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  httpConfig
		want []string
	}{
		{
			name: "oauth configured",
			cfg: httpConfig{
				endpoint:     "https://api.skycloak.io",
				issuer:       "https://login.skycloak.io/realms/skycloak",
				dashboardURL: "https://app.skycloak.io",
				publicURL:    "https://mcp.skycloak.io",
			},
			want: []string{
				"oauth=true",
				"issuer=https://login.skycloak.io/realms/skycloak",
				"dashboard=https://app.skycloak.io",
				"public_url=https://mcp.skycloak.io",
				"endpoint=https://api.skycloak.io",
			},
		},
		{
			name: "api key only",
			cfg:  httpConfig{endpoint: "https://api.skycloak.io"},
			want: []string{"oauth=false", "public_url=(derived per request)"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf safeBuffer
			cfg := tt.cfg
			cfg.logger = log.New(&buf, "", 0)

			logStartupConfig(cfg)

			got := buf.String()
			if strings.Count(strings.TrimSpace(got), "\n") != 0 {
				t.Fatalf("startup logged %d lines, want one: %s", strings.Count(got, "\n"), got)
			}
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("startup line %q does not contain %q", got, want)
				}
			}
		})
	}
}

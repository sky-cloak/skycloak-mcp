package oauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDashboard stands in for app.skycloak.io's POST /api/mcp/session-key.
type fakeDashboard struct {
	srv *httptest.Server

	mu       sync.Mutex
	calls    int
	tokens   []string
	requests []map[string]string

	status int
	body   any
	// keyFor lets a test vary the minted key per call.
	keyFor func(n int) map[string]any
}

func newFakeDashboard(t *testing.T) *fakeDashboard {
	t.Helper()
	d := &fakeDashboard{status: http.StatusOK}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/mcp/session-key" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req map[string]string
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &req)

		d.mu.Lock()
		d.calls++
		n := d.calls
		d.tokens = append(d.tokens, r.Header.Get("Authorization"))
		d.requests = append(d.requests, req)
		status, body, keyFor := d.status, d.body, d.keyFor
		d.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		switch {
		case body != nil:
			_ = json.NewEncoder(w).Encode(body)
		case keyFor != nil:
			_ = json.NewEncoder(w).Encode(keyFor(n))
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"api_key":      "sk_sc_minted",
				"workspace_id": "11111111-1111-1111-1111-111111111111",
				"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"scopes":       []string{"clusters:read", "realms:read"},
			})
		}
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *fakeDashboard) snapshot() (int, []string, []map[string]string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls, append([]string(nil), d.tokens...), append([]map[string]string(nil), d.requests...)
}

func TestSessionExchangesTheTokenForAnAPIKey(t *testing.T) {
	dash := newFakeDashboard(t)
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	s, err := ex.Session(t.Context(), "the-access-token", "user-1", "")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}
	if s.APIKey != "sk_sc_minted" {
		t.Fatalf("api key = %q, want sk_sc_minted", s.APIKey)
	}
	if s.WorkspaceID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("workspace = %q", s.WorkspaceID)
	}
	if len(s.Scopes) != 2 {
		t.Fatalf("scopes = %v, want the two the dashboard returned", s.Scopes)
	}

	_, tokens, reqs := dash.snapshot()
	if tokens[0] != "Bearer the-access-token" {
		t.Fatalf("Authorization = %q, want the caller's access token", tokens[0])
	}
	if _, ok := reqs[0]["workspace_id"]; ok {
		t.Fatalf("workspace_id sent when none was asked for: %v", reqs[0])
	}
}

// A requested workspace has to reach the dashboard, or `?workspace=` silently
// does nothing and the session acts on the wrong tenant.
func TestSessionPassesTheRequestedWorkspace(t *testing.T) {
	dash := newFakeDashboard(t)
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	if _, err := ex.Session(t.Context(), "tok", "user-1", "ws-abc"); err != nil {
		t.Fatalf("Session: %v", err)
	}
	_, _, reqs := dash.snapshot()
	if reqs[0]["workspace_id"] != "ws-abc" {
		t.Fatalf("workspace_id = %q, want ws-abc", reqs[0]["workspace_id"])
	}
}

// The key lasts an hour; minting one per MCP request would rotate the caller's
// key on every tool call.
func TestSessionIsCachedPerSubjectAndWorkspace(t *testing.T) {
	dash := newFakeDashboard(t)
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	for range 3 {
		if _, err := ex.Session(t.Context(), "tok", "user-1", ""); err != nil {
			t.Fatalf("Session: %v", err)
		}
	}
	if calls, _, _ := dash.snapshot(); calls != 1 {
		t.Fatalf("dashboard called %d times for 3 sessions, want 1", calls)
	}

	// A different user, and the same user on a different workspace, are both
	// separate sessions.
	if _, err := ex.Session(t.Context(), "tok", "user-2", ""); err != nil {
		t.Fatalf("Session: %v", err)
	}
	if _, err := ex.Session(t.Context(), "tok", "user-1", "ws-other"); err != nil {
		t.Fatalf("Session: %v", err)
	}
	if calls, _, _ := dash.snapshot(); calls != 3 {
		t.Fatalf("dashboard called %d times, want 3 (one per subject/workspace pair)", calls)
	}
}

// The key expires in an hour. A session that keeps handing out a lapsed key
// turns into a 401 on every tool call.
func TestSessionRefreshesBeforeTheKeyExpires(t *testing.T) {
	dash := newFakeDashboard(t)
	dash.keyFor = func(n int) map[string]any {
		return map[string]any{
			"api_key":      "sk_sc_key_" + string(rune('0'+n)),
			"workspace_id": "ws-1",
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"scopes":       []string{"clusters:read"},
		}
	}
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	first, err := ex.Session(t.Context(), "tok", "user-1", "")
	if err != nil {
		t.Fatalf("Session: %v", err)
	}

	// Step to inside the refresh window: still valid, but close enough that a
	// long tool call would outlive it.
	near := first.ExpiresAt.Add(-refreshSkew / 2)
	ex.clock = func() time.Time { return near }

	second, err := ex.Session(t.Context(), "tok", "user-1", "")
	if err != nil {
		t.Fatalf("Session after expiry: %v", err)
	}
	if second.APIKey == first.APIKey {
		t.Fatalf("session was not refreshed: still holding %q", second.APIKey)
	}
}

// A caller in several workspaces gets a 400 listing them. That has to reach the
// user as something they can act on, not "exchange failed".
func TestSessionSurfacesTheAmbiguousWorkspaceChoice(t *testing.T) {
	dash := newFakeDashboard(t)
	dash.status = http.StatusBadRequest
	dash.body = map[string]any{
		"error": "You belong to more than one workspace; specify workspace_id",
		"workspaces": []map[string]string{
			{"id": "aaa", "name": "Acme"},
			{"id": "bbb", "name": "Beta"},
		},
	}
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	_, err := ex.Session(t.Context(), "tok", "user-1", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	var ambiguous *AmbiguousWorkspaceError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("error = %v (%T), want an *AmbiguousWorkspaceError", err, err)
	}
	if len(ambiguous.Choices) != 2 || ambiguous.Choices[0].Name != "Acme" {
		t.Fatalf("choices = %+v, want both workspaces with their names", ambiguous.Choices)
	}
	for _, want := range []string{"aaa", "Acme", "bbb", "Beta"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q does not name %q", err.Error(), want)
		}
	}
}

func TestSessionClassifiesRefusals(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		want   error
	}{
		{"token rejected", http.StatusUnauthorized, ErrNotPermitted},
		{"not a member", http.StatusForbidden, ErrNotPermitted},
		{"dashboard broken", http.StatusInternalServerError, ErrExchangeFailed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dash := newFakeDashboard(t)
			dash.status = tt.status
			dash.body = map[string]string{"error": "nope"}
			ex := NewExchanger(dash.srv.URL, dash.srv.Client())

			_, err := ex.Session(t.Context(), "tok", "user-1", "")
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want it to unwrap to %v", err, tt.want)
			}
		})
	}
}

// Neither the access token nor the minted key may appear in an error a caller
// or a log line could see.
func TestSessionErrorsNeverEchoSecrets(t *testing.T) {
	dash := newFakeDashboard(t)
	dash.status = http.StatusInternalServerError
	dash.body = map[string]string{"error": "boom"}
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	_, err := ex.Session(t.Context(), "super-secret-token", "user-1", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("error leaked the access token: %v", err)
	}
}

// An MCP client opens with several requests at once. The dashboard keeps one
// live key per user and rotates it in place, so two concurrent mints would
// leave one of the two requests holding a key that has already been replaced.
func TestConcurrentFirstRequestsMintOneKey(t *testing.T) {
	dash := newFakeDashboard(t)
	dash.keyFor = func(n int) map[string]any {
		time.Sleep(20 * time.Millisecond) // widen the window a racer would slip through
		return map[string]any{
			"api_key":      "sk_sc_key_" + string(rune('0'+n)),
			"workspace_id": "ws-1",
			"expires_at":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"scopes":       []string{"clusters:read"},
		}
	}
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	var wg sync.WaitGroup
	got := make([]string, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := ex.Session(t.Context(), "tok", "user-1", "")
			if err != nil {
				t.Errorf("Session: %v", err)
				return
			}
			got[i] = s.APIKey
		}(i)
	}
	wg.Wait()

	if calls, _, _ := dash.snapshot(); calls != 1 {
		t.Fatalf("8 concurrent requests minted %d keys, want 1", calls)
	}
	for i, k := range got {
		if k != got[0] {
			t.Fatalf("caller %d got %q, caller 0 got %q; they must share one session", i, k, got[0])
		}
	}
}

// A failed exchange must not be remembered as a session, or one blip locks the
// caller out until the entry ages away.
func TestSessionDoesNotCacheFailures(t *testing.T) {
	dash := newFakeDashboard(t)
	dash.status = http.StatusInternalServerError
	dash.body = map[string]string{"error": "boom"}
	ex := NewExchanger(dash.srv.URL, dash.srv.Client())

	if _, err := ex.Session(t.Context(), "tok", "user-1", ""); err == nil {
		t.Fatal("expected an error")
	}

	dash.mu.Lock()
	dash.status, dash.body = http.StatusOK, nil
	dash.mu.Unlock()

	if _, err := ex.Session(t.Context(), "tok", "user-1", ""); err != nil {
		t.Fatalf("second attempt after the dashboard recovered: %v", err)
	}
}

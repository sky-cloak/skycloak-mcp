package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetThemeSettings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/theme-settings" {
			t.Errorf("method/path = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, `{"exact_theme_names":true}`)
	}))
	defer srv.Close()

	s, err := newTestClient(srv.URL).GetThemeSettings(context.Background())
	if err != nil {
		t.Fatalf("GetThemeSettings: %v", err)
	}
	if !s.ExactThemeNames {
		t.Fatalf("ExactThemeNames = %v, want true", s.ExactThemeNames)
	}
}

func TestUpdateThemeSettings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/theme-settings" {
			t.Errorf("method/path = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, `{"exact_theme_names":true}`)
	}))
	defer srv.Close()

	s, err := newTestClient(srv.URL).UpdateThemeSettings(context.Background(), true)
	if err != nil {
		t.Fatalf("UpdateThemeSettings: %v", err)
	}
	if !s.ExactThemeNames {
		t.Fatalf("ExactThemeNames = %v, want true", s.ExactThemeNames)
	}
}

// A key minted for anything but a workspace owner or admin gets 403 even with
// themes:write, per the API contract; the client must surface that as an
// *APIError rather than swallowing it.
func TestUpdateThemeSettingsForbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"key has no user, or user is not a workspace owner or admin"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).UpdateThemeSettings(context.Background(), true)
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.StatusCode != 403 {
		t.Fatalf("want 403 *APIError, got %T (%v)", err, err)
	}
}

func TestRestartClusterInstancesImmediate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/clusters/"+cuid+"/restart-instances" {
			t.Errorf("method/path = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 202, `{"deferred":false,"impact":"Brief interruption to sign-in for a few seconds per instance."}`)
	}))
	defer srv.Close()

	out, err := newTestClient(srv.URL).RestartClusterInstances(context.Background(), cuid)
	if err != nil {
		t.Fatalf("RestartClusterInstances: %v", err)
	}
	if out.Deferred || out.NextWindow != "" || out.Impact == "" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}

func TestRestartClusterInstancesDeferred(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 202, `{"deferred":true,"next_window":"2026-09-20T02:00:00Z","impact":"Deferred to the maintenance window."}`)
	}))
	defer srv.Close()

	out, err := newTestClient(srv.URL).RestartClusterInstances(context.Background(), cuid)
	if err != nil {
		t.Fatalf("RestartClusterInstances: %v", err)
	}
	if !out.Deferred || out.NextWindow != "2026-09-20T02:00:00Z" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
}

// The restart-instances 409 carries a "code" field the generated ErrorBody
// schema does not declare; the client re-parses the raw body so it survives.
func TestRestartClusterInstancesConflictCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"title":"Conflict","status":409,"detail":"cluster is busy","code":"cluster_busy"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).RestartClusterInstances(context.Background(), cuid)
	apiErr, ok := AsAPIError(err)
	if !ok || apiErr.StatusCode != 409 {
		t.Fatalf("want 409 *APIError, got %T (%v)", err, err)
	}
	if apiErr.Problem.Code != "cluster_busy" {
		t.Fatalf("Problem.Code = %q, want cluster_busy", apiErr.Problem.Code)
	}
}

func TestGetThemeIncludesRestartRequired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `{"id":"`+cuid+`","name":"corporate","status":"deployed","theme_types":["login"],"file_size":100,"restart_required":true}`)
	}))
	defer srv.Close()

	th, err := newTestClient(srv.URL).GetTheme(context.Background(), cuid, cuid)
	if err != nil {
		t.Fatalf("GetTheme: %v", err)
	}
	if !th.RestartRequired {
		t.Fatalf("RestartRequired = %v, want true", th.RestartRequired)
	}
}

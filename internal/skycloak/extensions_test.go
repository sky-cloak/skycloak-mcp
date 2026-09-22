package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const extID = "55555555-5555-5555-5555-555555555555"

// The catalog's version is the one number a caller needs to tell which build
// a marketplace extension ships, so the client must carry it through.
func TestListExtensionsCarriesVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/extensions" {
			t.Errorf("method/path = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, `[{"id":"`+extID+`","name":"Email OTP","source":"platform","version":"1.5.0",
			"keycloak_versions":["26"],"parameter_type":"env","parameters":[],"previous_versions":[],
			"created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z"}]`)
	}))
	defer srv.Close()

	exts, err := newTestClient(srv.URL).ListExtensions(context.Background())
	if err != nil {
		t.Fatalf("ListExtensions: %v", err)
	}
	if len(exts) != 1 || exts[0].Version != "1.5.0" {
		t.Fatalf("exts = %+v, want one row with Version 1.5.0", exts)
	}
}

// available_version is nullable on the wire; both a value and null must
// decode, the latter to an empty string rather than an error.
func TestListClusterExtensionsCarriesAvailableVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/clusters/"+cuid+"/extensions" {
			t.Errorf("method/path = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, `[
			{"extension_id":"`+extID+`","extension_name":"Email OTP","extension_source":"platform",
			 "installed_version":"1.3.5","available_version":"1.5.0","status":"active","upgrade_available":true,
			 "installed_at":"2026-09-01T00:00:00Z","parameters":{}},
			{"extension_id":"`+extID+`","extension_name":"Magic Link","extension_source":"platform",
			 "installed_version":"unknown","available_version":null,"status":"active","upgrade_available":false,
			 "installed_at":"2026-09-01T00:00:00Z","parameters":{}}]`)
	}))
	defer srv.Close()

	exts, err := newTestClient(srv.URL).ListClusterExtensions(context.Background(), cuid)
	if err != nil {
		t.Fatalf("ListClusterExtensions: %v", err)
	}
	if len(exts) != 2 {
		t.Fatalf("len = %d, want 2", len(exts))
	}
	if exts[0].InstalledVersion != "1.3.5" || exts[0].AvailableVersion != "1.5.0" || !exts[0].UpgradeAvailable {
		t.Errorf("row 0 = %+v", exts[0])
	}
	if exts[1].AvailableVersion != "" {
		t.Errorf("row 1 AvailableVersion = %q, want empty for null", exts[1].AvailableVersion)
	}
}

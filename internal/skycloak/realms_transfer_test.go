package skycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

const rexUID = "22222222-2222-2222-2222-222222222222"

// The source-kind values are a closed enum in the API. Compare them against the
// spec rather than against the code that produces them: a literal that merely
// agrees with itself would pass while every real import 400s.
func TestRealmImportSourceKindsMatchTheSpec(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "apiclient", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc struct {
		Components struct {
			Schemas struct {
				RealmImportSourceKind struct {
					Enum []string `yaml:"enum"`
				} `yaml:"RealmImportSourceKind"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	spec := doc.Components.Schemas.RealmImportSourceKind.Enum
	if len(spec) == 0 {
		t.Fatal("no RealmImportSourceKind enum in the spec; the test is looking in the wrong place")
	}

	ours := map[string]bool{RealmImportSourceUpload: true, RealmImportSourceStored: true}
	for _, want := range spec {
		if !ours[want] {
			t.Errorf("spec allows source_kind %q but no constant produces it", want)
		}
		delete(ours, want)
	}
	for leftover := range ours {
		t.Errorf("we would send source_kind %q, which the spec does not allow", leftover)
	}
}

func TestCreateRealmExport(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method = %q", r.Method)
		}
		if want := "/clusters/" + cuid + "/realms/app/exports"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if got := r.Header.Get("API-Key"); got != "sk_sc_test_aaa_bbb" {
			t.Errorf("API-Key header = %q", got)
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		writeJSON(w, 202, `{"id":"`+rexUID+`","cluster_id":"`+cuid+`","realm":"app","scope":"full","status":"pending","progress":0,"created_at":"2026-08-13T00:00:00Z"}`)
	}))
	defer srv.Close()

	e, err := newTestClient(srv.URL).CreateRealmExport(context.Background(), cuid, "app", "hunter2")
	if err != nil {
		t.Fatalf("CreateRealmExport: %v", err)
	}
	if gotBody["encryption_password"] != "hunter2" {
		t.Fatalf("encryption_password not sent: %+v", gotBody)
	}
	if e.ID != rexUID || e.Realm != "app" || e.Status != "pending" {
		t.Fatalf("unexpected export: %+v", e)
	}
}

func TestGetRealmExportDecodesCompletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/realm-exports/" + rexUID; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(w, 200, `{"id":"`+rexUID+`","cluster_id":"`+cuid+`","realm":"app","scope":"full","status":"completed","progress":100,"download_url":"https://example/dl","sha256_checksum":"abc","created_at":"2026-08-13T00:00:00Z"}`)
	}))
	defer srv.Close()

	e, err := newTestClient(srv.URL).GetRealmExport(context.Background(), rexUID)
	if err != nil {
		t.Fatalf("GetRealmExport: %v", err)
	}
	if e.Status != "completed" || e.DownloadURL != "https://example/dl" || e.SHA256Checksum != "abc" {
		t.Fatalf("unexpected export: %+v", e)
	}
}

func TestCreateRealmImportUpload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/clusters/" + cuid + "/realms/import/upload-url"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(w, 200, `{"upload_url":"https://example/put","s3_key":"imports/abc"}`)
	}))
	defer srv.Close()

	u, err := newTestClient(srv.URL).CreateRealmImportUpload(context.Background(), cuid)
	if err != nil {
		t.Fatalf("CreateRealmImportUpload: %v", err)
	}
	if u.UploadURL != "https://example/put" || u.S3Key != "imports/abc" {
		t.Fatalf("unexpected upload: %+v", u)
	}
}

func TestCreateRealmImportSendsChosenSource(t *testing.T) {
	for _, tt := range []struct {
		name    string
		req     CreateRealmImportRequest
		wantKey string
		wantVal string
	}{
		{"upload", CreateRealmImportRequest{SourceKind: RealmImportSourceUpload, UploadS3Key: "imports/abc"}, "upload_s3_key", "imports/abc"},
		{"stored export", CreateRealmImportRequest{SourceKind: RealmImportSourceStored, SourceExportID: rexUID}, "source_export_id", rexUID},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var gotBody map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if want := "/clusters/" + cuid + "/realms/import"; r.URL.Path != want {
					t.Errorf("path = %q, want %q", r.URL.Path, want)
				}
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &gotBody)
				writeJSON(w, 202, `{"id":"`+rexUID+`","cluster_id":"`+cuid+`","realm":"app","source_kind":"`+tt.req.SourceKind+`","status":"pending","progress":0,"created_at":"2026-08-13T00:00:00Z"}`)
			}))
			defer srv.Close()

			i, err := newTestClient(srv.URL).CreateRealmImport(context.Background(), cuid, tt.req)
			if err != nil {
				t.Fatalf("CreateRealmImport: %v", err)
			}
			if gotBody["source_kind"] != tt.req.SourceKind {
				t.Errorf("source_kind = %v, want %q", gotBody["source_kind"], tt.req.SourceKind)
			}
			if gotBody[tt.wantKey] != tt.wantVal {
				t.Errorf("%s = %v, want %q", tt.wantKey, gotBody[tt.wantKey], tt.wantVal)
			}
			if i.SourceKind != tt.req.SourceKind {
				t.Errorf("decoded source_kind = %q", i.SourceKind)
			}
		})
	}
}

func TestGetRealmImportDecodesFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/realm-imports/" + rexUID; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(w, 200, `{"id":"`+rexUID+`","cluster_id":"`+cuid+`","realm":"app","source_kind":"upload","status":"failed","progress":40,"error_message":"version mismatch","created_at":"2026-08-13T00:00:00Z"}`)
	}))
	defer srv.Close()

	i, err := newTestClient(srv.URL).GetRealmImport(context.Background(), rexUID)
	if err != nil {
		t.Fatalf("GetRealmImport: %v", err)
	}
	if i.Status != "failed" || i.ErrorMessage != "version mismatch" {
		t.Fatalf("unexpected import: %+v", i)
	}
}

func TestDownloadThemeContentReturnsRawBytes(t *testing.T) {
	archive := []byte("PK\x03\x04binary\x00bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "/clusters/" + cuid + "/themes/" + rexUID + "/content"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(archive)
	}))
	defer srv.Close()

	got, err := newTestClient(srv.URL).DownloadThemeContent(context.Background(), cuid, rexUID)
	if err != nil {
		t.Fatalf("DownloadThemeContent: %v", err)
	}
	if !bytes.Equal(got, archive) {
		t.Fatalf("got %q, want the archive bytes unchanged", got)
	}
}

// A non-2xx must not be mistaken for archive content.
func TestDownloadThemeContentSurfacesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"title":"Not Found","status":404,"detail":"no such theme"}`))
	}))
	defer srv.Close()

	if _, err := newTestClient(srv.URL).DownloadThemeContent(context.Background(), cuid, rexUID); err == nil {
		t.Fatal("expected an error for a 404, got nil")
	} else if apiErr, ok := AsAPIError(err); !ok || apiErr.StatusCode != 404 {
		t.Fatalf("expected a 404 APIError, got %v", err)
	}
}

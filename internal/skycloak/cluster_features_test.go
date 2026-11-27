package skycloak

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const featuresClusterID = "11111111-1111-1111-1111-111111111111"

func TestGetClusterFeatures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/clusters/"+featuresClusterID+"/features" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, `{"features":["cimd"],"change":{"state":"pending","next_window":"2026-12-01T03:00:00Z"}}`)
	}))
	defer srv.Close()

	got, err := newTestClient(srv.URL).GetClusterFeatures(context.Background(), featuresClusterID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Features) != 1 || got.Features[0] != "cimd" || got.Change == nil || got.Change.State != "pending" || got.Change.NextWindow != "2026-12-01T03:00:00Z" {
		t.Fatalf("got %+v", got)
	}
}

func TestGetClusterFeaturesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 404, `{"title":"Not found","status":404}`)
	}))
	defer srv.Close()
	if _, err := newTestClient(srv.URL).GetClusterFeatures(context.Background(), featuresClusterID); err == nil {
		t.Fatal("expected an error")
	}
}

func TestSetClusterFeaturesSendsApplyNow(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/clusters/"+featuresClusterID+"/features" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		writeJSON(w, 200, `{"features":["cimd"],"restarts_keycloak":true,"change":{"state":"applying"},"impact":"Brief outage."}`)
	}))
	defer srv.Close()

	got, err := newTestClient(srv.URL).SetClusterFeatures(context.Background(), featuresClusterID, []string{"cimd"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"apply_now":true`) || !strings.Contains(body, `"features":["cimd"]`) {
		t.Fatalf("body = %s", body)
	}
	if !got.RestartsKeycloak || got.Change == nil || got.Change.State != "applying" || got.Impact != "Brief outage." {
		t.Fatalf("got %+v", got)
	}
}

func TestSetClusterFeaturesEmptySetSendsList(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		writeJSON(w, 200, `{"features":[],"restarts_keycloak":false}`)
	}))
	defer srv.Close()

	got, err := newTestClient(srv.URL).SetClusterFeatures(context.Background(), featuresClusterID, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "apply_now") || !strings.Contains(body, `"features":[]`) {
		t.Fatalf("body = %s", body)
	}
	if got.RestartsKeycloak || got.Features == nil {
		t.Fatalf("got %+v", got)
	}
}

func TestSetClusterFeaturesRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 422, `{"title":"Unprocessable","status":422,"detail":"cimd needs Keycloak 26.8 or later"}`)
	}))
	defer srv.Close()
	_, err := newTestClient(srv.URL).SetClusterFeatures(context.Background(), featuresClusterID, []string{"cimd"}, false)
	if err == nil || !strings.Contains(err.Error(), "26.8") {
		t.Fatalf("err = %v", err)
	}
}

func TestListClusterFeaturesMapsFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/cluster-features" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		writeJSON(w, 200, `[{"name":"cimd","display_name":"CIMD","preview":false,"experimental":true,"dangerous":true,"min_version":"26.8.0"},{"name":"token-exchange","display_name":"Token exchange","preview":true}]`)
	}))
	defer srv.Close()

	got, err := newTestClient(srv.URL).ListClusterFeatures(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got[0].Experimental || !got[0].Dangerous || got[0].MinVersion != "26.8.0" {
		t.Fatalf("got %+v", got)
	}
	if got[1].Experimental || got[1].Dangerous || got[1].MinVersion != "" || !got[1].Preview {
		t.Fatalf("got %+v", got[1])
	}
}

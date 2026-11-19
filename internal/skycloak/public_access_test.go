package skycloak

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func clusterBody(publicAccess string) string {
	return `{"id":"` + cuid + `","name":"prod","status":"available"` + publicAccess + `}`
}

func TestGetClusterPublicAccess(t *testing.T) {
	for _, want := range []bool{true, false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/clusters/"+cuid {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			if want {
				writeJSON(w, 200, clusterBody(`,"public_access":true`))
			} else {
				writeJSON(w, 200, clusterBody(`,"public_access":false`))
			}
		}))
		pa, err := newTestClient(srv.URL).GetClusterPublicAccess(t.Context(), cuid)
		srv.Close()
		if err != nil || pa.Enabled != want {
			t.Fatalf("want enabled=%v, got %+v err=%v", want, pa, err)
		}
	}
}

func TestGetClusterPublicAccessWithoutTheFieldIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, clusterBody(""))
	}))
	defer srv.Close()
	if pa, err := newTestClient(srv.URL).GetClusterPublicAccess(t.Context(), cuid); err == nil {
		t.Fatalf("want an error, got %+v", pa)
	}
}

func TestSetClusterPublicAccessSendsOnlyThatField(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/clusters/"+cuid {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 200, clusterBody(`,"public_access":false`))
	}))
	defer srv.Close()

	pa, err := newTestClient(srv.URL).SetClusterPublicAccess(t.Context(), cuid, false)
	if err != nil || pa.Enabled {
		t.Fatalf("got %+v err=%v", pa, err)
	}
	if len(body) != 1 || body["public_access"] != false {
		t.Fatalf("body = %v, want only public_access=false", body)
	}
}

func TestSetClusterPublicAccessKeepsTheRefusal(t *testing.T) {
	for _, status := range []int{403, 409, 422} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, status, `{"detail":"refused"}`)
		}))
		_, err := newTestClient(srv.URL).SetClusterPublicAccess(t.Context(), cuid, false)
		srv.Close()
		apiErr, ok := AsAPIError(err)
		if !ok || apiErr.StatusCode != status || apiErr.Problem.Detail != "refused" {
			t.Fatalf("status %d: err = %v", status, err)
		}
	}
}

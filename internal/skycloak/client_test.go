package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const cuid = "11111111-1111-1111-1111-111111111111"

func newTestClient(url string) *Client {
	return New(url, "sk_sc_test_aaa_bbb", "2026-03-01")
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func TestListClusters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apikey"); got != "sk_sc_test_aaa_bbb" {
			t.Errorf("apikey header = %q", got)
		}
		if r.URL.Path != "/clusters" {
			t.Errorf("path = %q", r.URL.Path)
		}
		writeJSON(w, 200, `[{"id":"`+cuid+`","name":"prod","status":"available"}]`)
	}))
	defer srv.Close()

	clusters, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(clusters) != 1 || clusters[0].Name != "prod" {
		t.Fatalf("unexpected clusters: %+v", clusters)
	}
}

func TestCreateRealm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/clusters/"+cuid+"/realms" {
			writeJSON(w, http.StatusCreated, `{"name":"acme","display_name":"Acme","enabled":true}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	realm, err := newTestClient(srv.URL).CreateRealm(context.Background(), cuid, Realm{Name: "acme", DisplayName: "Acme"})
	if err != nil || realm.Name != "acme" || !realm.Enabled {
		t.Fatalf("CreateRealm: %+v, %v", realm, err)
	}
}

func TestProblemError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"missing scope clusters:read"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{})
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("want *APIError, got %T (%v)", err, err)
	}
	if apiErr.StatusCode != 403 || apiErr.Problem.Detail == "" {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
}

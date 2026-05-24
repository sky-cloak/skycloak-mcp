package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListClusters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("apikey"); got != "sk_sc_test_aaa_bbb" {
			t.Errorf("apikey header = %q, want sk_sc_test_aaa_bbb", got)
		}
		if got := r.Header.Get("API-Version"); got != "2026-03-01" {
			t.Errorf("API-Version header = %q, want 2026-03-01", got)
		}
		if r.URL.Path != "/clusters" || r.URL.Query().Get("limit") != "10" {
			t.Errorf("unexpected request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"c1","name":"prod","status":"available"}]`))
	}))
	defer srv.Close()

	c := New(srv.URL, "sk_sc_test_aaa_bbb", "2026-03-01")
	clusters, err := c.ListClusters(context.Background(), ListClustersParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(clusters) != 1 || clusters[0].Name != "prod" {
		t.Fatalf("unexpected clusters: %+v", clusters)
	}
}

func TestProblemError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"title":"Forbidden","status":403,"detail":"missing scope clusters:read"}`))
	}))
	defer srv.Close()

	c := New(srv.URL, "key", "")
	_, err := c.ListClusters(context.Background(), ListClustersParams{})
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("want *APIError, got %T (%v)", err, err)
	}
	if apiErr.StatusCode != 403 || apiErr.Problem.Detail == "" {
		t.Fatalf("unexpected APIError: %+v", apiErr)
	}
}

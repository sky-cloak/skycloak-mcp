package skycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

// us-west is its own location, not a spelling of us, so the client must carry
// it both ways without folding it into the East region.
func TestClusterLocationUSWestRoundTrips(t *testing.T) {
	const westCluster = `{"id":"` + cuid + `","name":"west","status":"available","location":"us-west"}`
	var created map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/clusters":
			writeJSON(w, 200, `[`+westCluster+`,{"id":"22222222-2222-2222-2222-222222222222","name":"east","status":"available","location":"us"}]`)
		case r.Method == http.MethodGet && r.URL.Path == "/clusters/"+cuid:
			writeJSON(w, 200, westCluster)
		case r.Method == http.MethodPost && r.URL.Path == "/clusters":
			body, _ := io.ReadAll(r.Body)
			if err := json.Unmarshal(body, &created); err != nil {
				t.Errorf("create body: %v", err)
			}
			writeJSON(w, http.StatusCreated, westCluster)
		case r.Method == http.MethodGet && r.URL.Path == "/cluster-locations":
			writeJSON(w, 200, `[{"location":"us","name":"US East","available":true},{"location":"us-west","name":"US West","available":false}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newTestClient(srv.URL)
	ctx := context.Background()

	list, err := c.ListClusters(ctx, ListClustersParams{})
	if err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	if len(list) != 2 || list[0].Location != "us-west" || list[1].Location != "us" {
		t.Fatalf("ListClusters locations = %+v, want us-west then us", list)
	}

	got, err := c.GetCluster(ctx, cuid)
	if err != nil || got.Location != "us-west" {
		t.Fatalf("GetCluster = %+v, %v; want location us-west", got, err)
	}

	cl, err := c.CreateCluster(ctx, CreateClusterRequest{Name: "west", Size: "small", Version: "26.1", Location: string(apiclient.UsWest)})
	if err != nil || cl.Location != "us-west" {
		t.Fatalf("CreateCluster = %+v, %v; want location us-west", cl, err)
	}
	if created["location"] != "us-west" {
		t.Errorf("create sent location %v, want us-west", created["location"])
	}

	locs, err := c.ListClusterLocations(ctx)
	if err != nil {
		t.Fatalf("ListClusterLocations: %v", err)
	}
	if len(locs) != 2 || locs[0].Location != "us" || locs[1].Location != "us-west" || locs[1].Available {
		t.Fatalf("ListClusterLocations = %+v, want distinct us and unavailable us-west", locs)
	}
}

// A workspace without access to us-west gets the same 400 as any other closed
// region, and the caller must see the API's own reason.
func TestCreateClusterUSWestWithoutAccessSurfacesThe400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"title":"Bad Request","status":400,"detail":"location not available"}`))
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).CreateCluster(context.Background(), CreateClusterRequest{Name: "west", Size: "small", Version: "26.1", Location: "us-west"})
	apiErr, ok := AsAPIError(err)
	if !ok {
		t.Fatalf("want *APIError, got %T (%v)", err, err)
	}
	if apiErr.StatusCode != http.StatusBadRequest || apiErr.Problem.Detail != "location not available" {
		t.Fatalf("APIError = %+v, want 400 location not available", apiErr)
	}
}

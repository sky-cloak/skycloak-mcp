package tools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// Fleet questions ("which realms still allow self-registration") were answerable
// only by listing clusters and then calling per cluster, stitching the results
// by hand. A caller that forgets a cluster under-reports, and for a security
// posture question that is the dangerous direction to fail in.

func fleetAPI() stubAPI {
	return stubAPI{
		clusters: []skycloak.Cluster{
			{ID: "c1", Name: "prod-us", Status: "available"},
			{ID: "c2", Name: "dev", Status: "available"},
		},
		realms: []skycloak.Realm{{Name: "master", Enabled: true}},
	}
}

func TestListRealmsWithoutClusterCoversEveryCluster(t *testing.T) {
	_, out, err := listRealmsHandler(fleetAPI())(context.Background(), nil, ListRealmsInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Realms) != 2 {
		t.Fatalf("omitting cluster_id must cover every cluster, got %d rows", len(out.Realms))
	}
	seen := map[string]bool{}
	for _, r := range out.Realms {
		seen[r.ClusterID] = true
		if r.ClusterName == "" {
			t.Errorf("a fleet row must name its cluster, or the rows cannot be told apart: %+v", r)
		}
	}
	if !seen["c1"] || !seen["c2"] {
		t.Errorf("rows must carry the cluster they came from: %+v", out.Realms)
	}
}

// A single-cluster call keeps working exactly as before.
func TestListRealmsWithClusterIsUnchanged(t *testing.T) {
	_, out, err := listRealmsHandler(fleetAPI())(context.Background(), nil,
		ListRealmsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Realms) != 1 {
		t.Fatalf("scoped call returned %d rows, want 1", len(out.Realms))
	}
}

// The whole point of fanning out is a complete answer. A cluster that fails
// must be named, not dropped: a silently partial fleet answer is exactly the
// under-report this feature exists to prevent.
func TestFleetListNamesClustersItCouldNotRead(t *testing.T) {
	api := fleetAPI()
	api.realmErrFor = map[string]error{"c2": errors.New("boom")}

	res, out, err := listRealmsHandler(api)(context.Background(), nil, ListRealmsInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Realms) != 1 {
		t.Fatalf("the readable cluster should still be reported, got %d rows", len(out.Realms))
	}
	if len(out.Unreachable) != 1 || out.Unreachable[0].ClusterID != "c2" {
		t.Fatalf("the failed cluster must be reported, not dropped: %+v", out.Unreachable)
	}
	text := renderedText(res)
	if !strings.Contains(text, "dev") || !strings.Contains(strings.ToLower(text), "could not") {
		t.Errorf("rendered text must say the answer is incomplete and which cluster is missing: %q", text)
	}
}

// If nothing could be read, that is a failure, not an empty fleet. Returning
// "no realms" would read as "nobody has self-registration on".
func TestFleetListFailsWhenNoClusterCouldBeRead(t *testing.T) {
	api := fleetAPI()
	api.realmErrFor = map[string]error{"c1": errors.New("boom"), "c2": errors.New("boom")}

	res, _, err := listRealmsHandler(api)(context.Background(), nil, ListRealmsInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("a fleet call that read nothing must be an error, not an empty result")
	}
}

func TestListIdentityProvidersWithoutClusterCoversEveryCluster(t *testing.T) {
	api := fleetAPI()
	api.idps = []skycloak.IdentityProvider{{ProviderID: "google", Type: "oidc", Enabled: true}}

	_, out, err := listIdentityProvidersHandler(api)(context.Background(), nil,
		ListIdentityProvidersInput{Realm: "master"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.IdentityProviders) != 2 {
		t.Fatalf("omitting cluster_id must cover every cluster, got %d", len(out.IdentityProviders))
	}
	for _, p := range out.IdentityProviders {
		if p.ClusterID == "" || p.ClusterName == "" {
			t.Errorf("a fleet row must name its cluster: %+v", p)
		}
	}
}

// Listing the clusters is itself a call that can fail, and failing it means we
// do not know the fleet at all.
func TestFleetListFailsIfClustersCannotBeListed(t *testing.T) {
	api := stubAPI{err: errors.New("no clusters for you")}
	res, _, err := listRealmsHandler(api)(context.Background(), nil, ListRealmsInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("an unlistable fleet must be an error, not an empty answer")
	}
}

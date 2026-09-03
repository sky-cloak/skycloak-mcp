package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// The handler already fanned out across clusters, but the schema marked
// cluster_id required, so a client never offered the fleet call. And realm was
// genuinely required, so "which SSO connections exist across the fleet" still
// cost one call per realm per cluster.
func TestListIdentityProvidersSchemaMakesScopeOptional(t *testing.T) {
	for _, tool := range advertisedTools(t) {
		if tool.Name != "skycloak_list_identity_providers" {
			continue
		}
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var schema struct {
			Required []string `json:"required"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(schema.Required) != 0 {
			t.Fatalf("required = %v, want none: both cluster_id and realm narrow the search", schema.Required)
		}
		return
	}
	t.Fatal("skycloak_list_identity_providers is not registered")
}

func TestListIdentityProvidersSpansEveryRealmWhenRealmOmitted(t *testing.T) {
	api := fleetStub{
		clusters: []string{"c1", "c2"},
		realms:   map[string][]string{"c1": {"master", "alfred"}, "c2": {"master"}},
		idps:     map[string][]string{"c1/master": {"okta"}, "c1/alfred": {"azure"}, "c2/master": {"google"}},
	}
	_, out, err := listIdentityProvidersHandler(api)(context.Background(), nil, ListIdentityProvidersInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Count != 3 {
		t.Fatalf("count = %d, want 3 across both clusters and every realm", out.Count)
	}
	seen := map[string]string{}
	for _, p := range out.IdentityProviders {
		seen[p.ProviderID] = p.ClusterID + "/" + p.Realm
	}
	for id, want := range map[string]string{"okta": "c1/master", "azure": "c1/alfred", "google": "c2/master"} {
		if seen[id] != want {
			t.Errorf("%s came back as %q, want %q", id, seen[id], want)
		}
	}
}

// Narrowing must still work, and must not fan out.
func TestListIdentityProvidersHonoursAnExplicitScope(t *testing.T) {
	api := fleetStub{
		clusters: []string{"c1", "c2"},
		realms:   map[string][]string{"c1": {"master", "alfred"}, "c2": {"master"}},
		idps:     map[string][]string{"c1/master": {"okta"}, "c1/alfred": {"azure"}, "c2/master": {"google"}},
	}
	_, out, err := listIdentityProvidersHandler(api)(context.Background(), nil,
		ListIdentityProvidersInput{ClusterID: "c1", Realm: "alfred"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Count != 1 || out.IdentityProviders[0].ProviderID != "azure" {
		t.Fatalf("got %+v, want only azure", out.IdentityProviders)
	}
}

// A realm that cannot be read must be reported, not silently dropped: a partial
// fleet answer that looks complete is worse than an error.
func TestListIdentityProvidersReportsUnreadableRealms(t *testing.T) {
	api := fleetStub{
		clusters: []string{"c1"},
		realms:   map[string][]string{"c1": {"master", "broken"}},
		idps:     map[string][]string{"c1/master": {"okta"}},
		failIDPs: map[string]bool{"c1/broken": true},
	}
	res, out, err := listIdentityProvidersHandler(api)(context.Background(), nil, ListIdentityProvidersInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Unreachable) != 1 || out.Unreachable[0].ClusterID != "c1" {
		t.Fatalf("unreachable = %+v, want the failing realm reported", out.Unreachable)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "Incomplete") {
		t.Errorf("text does not warn the answer is partial: %q", txt)
	}
}

// fleetStub answers the three calls a fleet-wide identity provider listing
// makes, keyed so a test can tell which cluster and realm each row came from.
type fleetStub struct {
	stubAPI
	clusters []string
	realms   map[string][]string
	idps     map[string][]string
	failIDPs map[string]bool
}

func (f fleetStub) ListClusters(context.Context, skycloak.ListClustersParams) ([]skycloak.Cluster, error) {
	out := make([]skycloak.Cluster, 0, len(f.clusters))
	for _, id := range f.clusters {
		out = append(out, skycloak.Cluster{ID: id, Name: id, Status: "available"})
	}
	return out, nil
}

func (f fleetStub) ListRealms(_ context.Context, clusterID string) ([]skycloak.Realm, error) {
	out := make([]skycloak.Realm, 0)
	for _, r := range f.realms[clusterID] {
		out = append(out, skycloak.Realm{Name: r, Enabled: true})
	}
	return out, nil
}

func (f fleetStub) ListIdentityProviders(_ context.Context, clusterID, realm string) ([]skycloak.IdentityProvider, error) {
	key := clusterID + "/" + realm
	if f.failIDPs[key] {
		return nil, errors.New("boom")
	}
	out := make([]skycloak.IdentityProvider, 0)
	for _, id := range f.idps[key] {
		out = append(out, skycloak.IdentityProvider{ProviderID: id, Enabled: true})
	}
	return out, nil
}

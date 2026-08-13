package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestReads2Handlers(t *testing.T) {
	api := stubAPI{
		upPath: []skycloak.UpgradePathStep{{Version: "26.1", Required: true}},
		rusers: []skycloak.RealmUser{{ID: "u1", Username: "jdoe", Email: "j@x.com"}},
	}
	if res, out, err := getClusterCredentialsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"}); err != nil || res.IsError || out.ClientID != "skycloak-automation" {
		t.Fatalf("credentials: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getClusterMaintenanceWindowHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"}); err != nil || res.IsError || out.Timezone != "Europe/Berlin" {
		t.Fatalf("maintenance window: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if _, out, err := getClusterUpgradePathHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"}); err != nil || len(out.Steps) != 1 {
		t.Fatalf("upgrade path: %+v %v", out, err)
	}
	if res, out, err := getClusterInsightsHandler(api)(context.Background(), nil, InsightsInput{ClusterID: "c1", Type: "overview"}); err != nil || res.IsError || out.JSON == "" {
		t.Fatalf("insights: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getRealmRoleHandler(api)(context.Background(), nil, RealmRoleRef{ClusterID: "c1", Realm: "app", Name: "admin"}); err != nil || res.IsError || out.Name != "admin" {
		t.Fatalf("get role: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getRealmGroupHandler(api)(context.Background(), nil, RealmGroupRef{ClusterID: "c1", Realm: "app", GroupID: "g1"}); err != nil || res.IsError || out.Name != "eng" {
		t.Fatalf("get group: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if _, out, err := listRealmGroupMembersHandler(api)(context.Background(), nil, RealmGroupRef{ClusterID: "c1", Realm: "app", GroupID: "g1"}); err != nil || out.Count != 1 {
		t.Fatalf("members: %+v %v", out, err)
	}
}

// The credentials scope is opt-in, so the one tool it gates must say how to get
// it. A bare "forbidden" leaves a signed-in user with no idea what to do.
func TestGetClusterCredentialsExplainsTheOptInScope(t *testing.T) {
	api := stubAPI{err: &skycloak.APIError{StatusCode: 403}}
	res, _, err := getClusterCredentialsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || !res.IsError {
		t.Fatal("expected an error result for a 403")
	}
	txt, _ := res.Content[0].(*mcp.TextContent)
	if txt == nil || !strings.Contains(txt.Text, "--allow-credentials") {
		t.Fatalf("403 message does not say how to get the scope: %+v", txt)
	}
}

// Other failures must not be mislabelled as a missing scope.
func TestGetClusterCredentialsDoesNotBlameScopeForOtherErrors(t *testing.T) {
	api := stubAPI{err: &skycloak.APIError{StatusCode: 404}}
	res, _, _ := getClusterCredentialsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	txt, _ := res.Content[0].(*mcp.TextContent)
	if txt != nil && strings.Contains(txt.Text, "--allow-credentials") {
		t.Fatalf("404 wrongly blamed on the credentials scope: %q", txt.Text)
	}
}

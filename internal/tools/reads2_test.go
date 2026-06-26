package tools

import (
	"context"
	"testing"

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

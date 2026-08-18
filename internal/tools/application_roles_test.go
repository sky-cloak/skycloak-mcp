package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListApplicationRolesHandler(t *testing.T) {
	api := stubAPI{appRoles: []skycloak.ApplicationRole{{Name: "manage-users", ClientRole: true}}}
	res, out, err := listApplicationRolesHandler(api)(context.Background(), nil, ApplicationRef{ClusterID: "c1", Realm: "app", ClientID: "web"})
	if err != nil || res.IsError || out.Count != 1 {
		t.Fatalf("listApplicationRoles: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestListApplicationSessionsHandler(t *testing.T) {
	api := stubAPI{appSess: []skycloak.ApplicationSession{{ID: "s1", Username: "jdoe"}}}
	res, out, err := listApplicationSessionsHandler(api)(context.Background(), nil, ApplicationRef{ClusterID: "c1", Realm: "app", ClientID: "web"})
	if err != nil || res.IsError || out.Count != 1 {
		t.Fatalf("listApplicationSessions: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestAssignApplicationRoleHandler(t *testing.T) {
	res, _, err := assignApplicationRoleHandler(stubAPI{})(context.Background(), nil, AppRoleInput{ClusterID: "c1", Realm: "app", ClientID: "web", RoleName: "manage-users", RoleClientID: "realm-management"})
	if err != nil || res.IsError {
		t.Fatalf("assignApplicationRole: err=%v res=%v", err, res.IsError)
	}
}

func TestAssignApplicationRoleRequiresFields(t *testing.T) {
	res, _, err := assignApplicationRoleHandler(stubAPI{})(context.Background(), nil, AppRoleInput{ClusterID: "c1", Realm: "app"})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result for missing fields")
	}
}

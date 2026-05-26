package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListRealmRolesHandler(t *testing.T) {
	api := stubAPI{rroles: []skycloak.RealmRole{{Name: "admin", Description: "Admins"}}}
	res, out, err := listRealmRolesHandler(api)(context.Background(), nil, RealmScopeInput{ClusterID: "c1", Realm: "app"})
	if err != nil || res.IsError || out.Count != 1 || out.Roles[0].Name != "admin" {
		t.Fatalf("listRealmRoles: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateRealmRoleHandler(t *testing.T) {
	res, out, err := createRealmRoleHandler(stubAPI{})(context.Background(), nil, CreateRealmRoleInput{ClusterID: "c1", Realm: "app", Name: "admin"})
	if err != nil || res.IsError || out.Name != "admin" {
		t.Fatalf("createRealmRole: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestDeleteRealmRoleRequiresConfirm(t *testing.T) {
	res, _, err := deleteRealmRoleHandler(stubAPI{})(context.Background(), nil, DeleteRealmRoleInput{ClusterID: "c1", Realm: "app", Name: "admin"})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result without confirm")
	}
}

func TestCreateRealmUserHandler(t *testing.T) {
	res, out, err := createRealmUserHandler(stubAPI{})(context.Background(), nil, CreateRealmUserInput{
		ClusterID: "c1", Realm: "app", Username: "jdoe", Email: "jdoe@example.com", TemporaryPassword: "password1",
	})
	if err != nil || res.IsError || out.Username != "jdoe" {
		t.Fatalf("createRealmUser: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateRealmUserRequiresPassword(t *testing.T) {
	res, _, err := createRealmUserHandler(stubAPI{})(context.Background(), nil, CreateRealmUserInput{ClusterID: "c1", Realm: "app", Username: "jdoe", Email: "jdoe@example.com"})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result without temporary_password")
	}
}

func TestAssignAndGroupHandlers(t *testing.T) {
	res, _, err := assignRealmUserRoleHandler(stubAPI{})(context.Background(), nil, UserRoleInput{ClusterID: "c1", Realm: "app", UserID: "u1", RoleName: "admin"})
	if err != nil || res.IsError {
		t.Fatalf("assignRealmUserRole: err=%v res=%v", err, res.IsError)
	}
	res, _, err = addRealmUserToGroupHandler(stubAPI{})(context.Background(), nil, UserGroupInput{ClusterID: "c1", Realm: "app", UserID: "u1", GroupID: "g1"})
	if err != nil || res.IsError {
		t.Fatalf("addRealmUserToGroup: err=%v res=%v", err, res.IsError)
	}
}

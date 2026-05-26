package tools

import (
	"context"
	"testing"
)

func TestWrites2Handlers(t *testing.T) {
	api := stubAPI{}
	if res, out, err := updateRealmRoleHandler(api)(context.Background(), nil, UpdateRealmRoleInput{ClusterID: "c1", Realm: "app", Name: "admin", NewName: "administrators"}); err != nil || res.IsError || out.Name != "administrators" {
		t.Fatalf("update role: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, _, err := updateRealmGroupHandler(api)(context.Background(), nil, UpdateRealmGroupInput{ClusterID: "c1", Realm: "app", GroupID: "g1", Name: "eng"}); err != nil || res.IsError {
		t.Fatalf("update group: err=%v res=%v", err, res.IsError)
	}
	if res, out, err := updateRealmUserHandler(api)(context.Background(), nil, UpdateRealmUserInput{ClusterID: "c1", Realm: "app", UserID: "u1", Email: "j@x.com"}); err != nil || res.IsError || out.Email != "j@x.com" {
		t.Fatalf("update user: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, _, err := updateClusterHandler(api)(context.Background(), nil, UpdateClusterInput{ClusterID: "c1", Version: "26.1"}); err != nil || res.IsError {
		t.Fatalf("update cluster: err=%v res=%v", err, res.IsError)
	}
	if res, out, err := upsertSMTPHandler(api)(context.Background(), nil, UpsertSMTPInput{ClusterID: "c1", Realm: "app", Host: "smtp.x.com", Port: 587, FromEmail: "a@x.com"}); err != nil || res.IsError || out.Port != 587 {
		t.Fatalf("upsert smtp: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, _, err := upsertLoginBrandingHandler(api)(context.Background(), nil, UpsertLoginBrandingInput{ClusterID: "c1", Realm: "app", PrimaryColor: "#0ea5e9"}); err != nil || res.IsError {
		t.Fatalf("upsert login branding: err=%v res=%v", err, res.IsError)
	}
	if res, _, err := upsertEmailBrandingHandler(api)(context.Background(), nil, UpsertEmailBrandingInput{ClusterID: "c1", Realm: "app", PrimaryColor: "#111"}); err != nil || res.IsError {
		t.Fatalf("upsert email branding: err=%v res=%v", err, res.IsError)
	}
	if res, _, err := exportClusterEventsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"}); err != nil || res.IsError {
		t.Fatalf("export events: err=%v res=%v", err, res.IsError)
	}
}

func TestDeleteBrandingRequiresConfirm(t *testing.T) {
	if res, _, _ := deleteLoginBrandingHandler(stubAPI{})(context.Background(), nil, RealmConfirmInput{ClusterID: "c1", Realm: "app"}); !res.IsError {
		t.Fatalf("delete login branding should require confirm")
	}
	if res, _, err := deleteEmailBrandingHandler(stubAPI{})(context.Background(), nil, RealmConfirmInput{ClusterID: "c1", Realm: "app", Confirm: true}); err != nil || res.IsError {
		t.Fatalf("delete email branding confirmed should succeed: res=%v err=%v", res.IsError, err)
	}
}

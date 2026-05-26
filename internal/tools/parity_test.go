package tools

import (
	"context"
	"testing"
)

func TestParityReadHandlers(t *testing.T) {
	api := stubAPI{}
	if res, out, err := getSMTPHandler(api)(context.Background(), nil, RealmScopeInput{ClusterID: "c1", Realm: "app"}); err != nil || res.IsError || out.Port != 587 {
		t.Fatalf("getSMTP: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getThemeHandler(api)(context.Background(), nil, ThemeRef{ClusterID: "c1", ThemeID: "t1"}); err != nil || res.IsError || out.Name != "corp" {
		t.Fatalf("getTheme: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getDomainRouteHandler(api)(context.Background(), nil, RouteRef{ClusterID: "c1", DomainID: "d1", RouteID: "r1"}); err != nil || res.IsError || out.Realm != "app" {
		t.Fatalf("getDomainRoute: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestRotateApplicationSecretHandler(t *testing.T) {
	res, out, err := rotateApplicationSecretHandler(stubAPI{})(context.Background(), nil, AppRef{ClusterID: "c1", Realm: "app", ClientID: "web"})
	if err != nil || res.IsError || out.ClientSecret != "rotated-secret" {
		t.Fatalf("rotate: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateDomainRouteHandler(t *testing.T) {
	res, out, err := createDomainRouteHandler(stubAPI{})(context.Background(), nil, CreateDomainRouteInput{ClusterID: "c1", DomainID: "d1", Realm: "app", HideRealmPath: true})
	if err != nil || res.IsError || !out.HideRealmPath {
		t.Fatalf("createDomainRoute: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestUpdateRealmHandler(t *testing.T) {
	res, out, err := updateRealmHandler(stubAPI{})(context.Background(), nil, UpdateRealmInput{ClusterID: "c1", Realm: "app", DisplayName: "App", Enabled: true})
	if err != nil || res.IsError || out.DisplayName != "App" {
		t.Fatalf("updateRealm: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestParityDeletesRequireConfirm(t *testing.T) {
	if res, _, _ := deleteSMTPHandler(stubAPI{})(context.Background(), nil, RealmConfirmInput{ClusterID: "c1", Realm: "app"}); !res.IsError {
		t.Fatalf("delete_smtp should require confirm")
	}
	if res, _, _ := deleteThemeHandler(stubAPI{})(context.Background(), nil, ThemeConfirmInput{ClusterID: "c1", ThemeID: "t1"}); !res.IsError {
		t.Fatalf("delete_theme should require confirm")
	}
	if res, _, _ := deleteExportHandler(stubAPI{})(context.Background(), nil, ExportConfirmInput{ClusterID: "c1", ExportID: "x1"}); !res.IsError {
		t.Fatalf("delete_export should require confirm")
	}
	if res, _, _ := deleteExportHandler(stubAPI{})(context.Background(), nil, ExportConfirmInput{ClusterID: "c1", ExportID: "x1", Confirm: true}); res.IsError {
		t.Fatalf("delete_export confirmed should succeed")
	}
}

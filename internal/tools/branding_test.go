package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListThemesHandler(t *testing.T) {
	api := stubAPI{themes: []skycloak.Theme{
		{ID: "44444444-4444-4444-4444-444444444444", Name: "corporate", Status: "deployed", ThemeTypes: []string{"login", "email"}},
	}}
	res, out, err := listThemesHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Count != 1 || out.Themes[0].Name != "corporate" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestGetThemeAssignmentHandler(t *testing.T) {
	api := stubAPI{assign: &skycloak.ThemeAssignment{Login: "tid"}}
	res, out, err := getThemeAssignmentHandler(api)(context.Background(), nil, RealmRef{ClusterID: "c1", Realm: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Login != "tid" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestSetThemeAssignmentHandler(t *testing.T) {
	res, out, err := setThemeAssignmentHandler(stubAPI{})(context.Background(), nil, SetThemeAssignmentInput{ClusterID: "c1", Realm: "app", Login: "tid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Login != "tid" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestSetThemeAssignmentRequiresRealm(t *testing.T) {
	res, _, err := setThemeAssignmentHandler(stubAPI{})(context.Background(), nil, SetThemeAssignmentInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result for missing realm")
	}
}

func TestGetBrandingHandlers(t *testing.T) {
	api := stubAPI{login: &skycloak.LoginBranding{PrimaryColor: "#0ea5e9", Status: "applied"}, email: &skycloak.EmailBranding{PrimaryColor: "#111827", Status: "applied"}}
	resL, outL, err := getLoginBrandingHandler(api)(context.Background(), nil, RealmRef{ClusterID: "c1", Realm: "app"})
	if err != nil || resL.IsError || outL.PrimaryColor != "#0ea5e9" {
		t.Fatalf("login branding: err=%v res=%v out=%+v", err, resL.IsError, outL)
	}
	resE, outE, err := getEmailBrandingHandler(api)(context.Background(), nil, RealmRef{ClusterID: "c1", Realm: "app"})
	if err != nil || resE.IsError || outE.PrimaryColor != "#111827" {
		t.Fatalf("email branding: err=%v res=%v out=%+v", err, resE.IsError, outE)
	}
}

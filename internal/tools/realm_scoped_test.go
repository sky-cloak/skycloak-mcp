package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListApplicationsHandler(t *testing.T) {
	api := stubAPI{apps: []skycloak.Application{{ClientID: "web", Name: "Web", Type: "confidential", Protocol: "openid-connect"}}}

	res, out, err := listApplicationsHandler(api)(context.Background(), nil, ListApplicationsInput{ClusterID: "c1", Realm: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Count != 1 || out.Applications[0].ClientID != "web" {
		t.Fatalf("unexpected result: err=%v out=%+v", res.IsError, out)
	}
}

func TestListApplicationsHandler_MissingArgs(t *testing.T) {
	res, _, err := listApplicationsHandler(stubAPI{})(context.Background(), nil, ListApplicationsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError when realm is empty")
	}
}

func TestListIdentityProvidersHandler(t *testing.T) {
	api := stubAPI{idps: []skycloak.IdentityProvider{{ProviderID: "google", Type: "oidc", DisplayName: "Google", Enabled: true}}}

	res, out, err := listIdentityProvidersHandler(api)(context.Background(), nil, ListIdentityProvidersInput{ClusterID: "c1", Realm: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Count != 1 || out.IdentityProviders[0].ProviderID != "google" {
		t.Fatalf("unexpected result: err=%v out=%+v", res.IsError, out)
	}
}

// Neither argument is required any more: each one narrows the search, and
// omitting both asks the whole workspace. Fleet coverage is in idp_fleet_test.go.
func TestListIdentityProvidersHandler_MissingArgs(t *testing.T) {
	res, _, err := listIdentityProvidersHandler(stubAPI{})(context.Background(), nil, ListIdentityProvidersInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("omitting both cluster_id and realm must search the workspace, not fail")
	}

	res, _, err = listIdentityProvidersHandler(stubAPI{})(context.Background(), nil, ListIdentityProvidersInput{Realm: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("omitting cluster_id must fan out, not fail")
	}
}

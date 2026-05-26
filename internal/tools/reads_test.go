package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestGetEntityHandlers(t *testing.T) {
	api := stubAPI{}
	if res, out, err := getRealmHandler(api)(context.Background(), nil, RealmScopeInput{ClusterID: "c1", Realm: "app"}); err != nil || res.IsError || out.Name != "app" {
		t.Fatalf("getRealm: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getApplicationHandler(api)(context.Background(), nil, AppRef{ClusterID: "c1", Realm: "app", ClientID: "web"}); err != nil || res.IsError || out.ClientID != "web" {
		t.Fatalf("getApplication: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if res, out, err := getIdentityProviderHandler(api)(context.Background(), nil, IDPRef{ClusterID: "c1", Realm: "app", ProviderID: "google"}); err != nil || res.IsError || out.ProviderID != "google" {
		t.Fatalf("getIdentityProvider: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestClusterMetadataHandlers(t *testing.T) {
	api := stubAPI{
		locations: []skycloak.ClusterLocationInfo{{Location: "eu", Name: "Europe", Available: true}},
		ctypes:    []skycloak.ClusterTypeInfo{{Type: "keycloak", Name: "Keycloak", Available: true}},
		features:  []skycloak.ClusterFeatureInfo{{Name: "token-exchange", DisplayName: "Token Exchange"}},
		versions:  []string{"26.1", "26.0"},
	}
	if _, out, err := listClusterLocationsHandler(api)(context.Background(), nil, NoInput{}); err != nil || len(out.Locations) != 1 {
		t.Fatalf("locations: %+v %v", out, err)
	}
	if _, out, err := listClusterTypesHandler(api)(context.Background(), nil, NoInput{}); err != nil || len(out.Types) != 1 {
		t.Fatalf("types: %+v %v", out, err)
	}
	if _, out, err := listClusterFeaturesHandler(api)(context.Background(), nil, NoInput{}); err != nil || len(out.Features) != 1 {
		t.Fatalf("features: %+v %v", out, err)
	}
	if res, out, err := listClusterVersionsHandler(api)(context.Background(), nil, ClusterTypeInput{Type: "keycloak"}); err != nil || res.IsError || len(out.Versions) != 2 {
		t.Fatalf("versions: %+v %v", out, err)
	}
}

func TestListDomainRoutesHandler(t *testing.T) {
	api := stubAPI{routes: []skycloak.DomainRoute{{ID: "r1", Realm: "app", HideRealmPath: true}}}
	res, out, err := listDomainRoutesHandler(api)(context.Background(), nil, DomainRoutesInput{ClusterID: "c1", DomainID: "d1"})
	if err != nil || res.IsError || len(out.Routes) != 1 {
		t.Fatalf("domainRoutes: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

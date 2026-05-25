package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListExtensionsHandler(t *testing.T) {
	api := stubAPI{catalog: []skycloak.ExtensionInfo{
		{ID: "55555555-5555-5555-5555-555555555555", Name: "Magic Link", Source: "marketplace", KeycloakVersions: []string{"26"}},
	}}
	res, out, err := listExtensionsHandler(api)(context.Background(), nil, ListExtensionsInput{})
	if err != nil || res.IsError || out.Count != 1 || out.Extensions[0].Name != "Magic Link" {
		t.Fatalf("listExtensions: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestListClusterExtensionsHandler(t *testing.T) {
	api := stubAPI{clusExts: []skycloak.ClusterExtension{
		{ExtensionID: "e1", ExtensionName: "Magic Link", InstalledVersion: "1.0.0", Status: "active"},
	}}
	res, out, err := listClusterExtensionsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.Count != 1 {
		t.Fatalf("listClusterExtensions: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestInstallExtensionHandler(t *testing.T) {
	res, out, err := installExtensionHandler(stubAPI{})(context.Background(), nil, InstallExtensionInput{ClusterID: "c1", ExtensionID: "e1"})
	if err != nil || res.IsError || out.Status != "installing" {
		t.Fatalf("installExtension: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestInstallExtensionRequiresIDs(t *testing.T) {
	res, _, err := installExtensionHandler(stubAPI{})(context.Background(), nil, InstallExtensionInput{ClusterID: "c1"})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result for missing extension_id")
	}
}

func TestUninstallExtensionRequiresConfirm(t *testing.T) {
	res, _, err := uninstallExtensionHandler(stubAPI{})(context.Background(), nil, UninstallExtensionInput{ClusterID: "c1", ExtensionID: "e1"})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result without confirm")
	}
}

func TestUninstallExtensionConfirmed(t *testing.T) {
	res, _, err := uninstallExtensionHandler(stubAPI{})(context.Background(), nil, UninstallExtensionInput{ClusterID: "c1", ExtensionID: "e1", Confirm: true})
	if err != nil || res.IsError {
		t.Fatalf("uninstall confirmed: err=%v res=%v", err, res.IsError)
	}
}

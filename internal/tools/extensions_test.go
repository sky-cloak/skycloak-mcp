package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

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

// The catalog line states the version the catalog ships, and a version the
// catalog already prefixes with "v" is not prefixed twice.
func TestListExtensionsLinePrintsVersion(t *testing.T) {
	api := stubAPI{catalog: []skycloak.ExtensionInfo{
		{ID: "e1", Name: "Email OTP", Source: "platform", Version: "1.5.0", KeycloakVersions: []string{"25", "26"}},
		{ID: "e2", Name: "PII Encryption", Source: "platform", Version: "v2.7", KeycloakVersions: []string{"26"}},
		{ID: "e3", Name: "Phone Provider", Source: "platform", KeycloakVersions: []string{"26"}},
	}}
	res, _, _ := listExtensionsHandler(api)(context.Background(), nil, ListExtensionsInput{})
	txt := res.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{
		"- Email OTP (e1): version=v1.5.0 source=platform keycloak=25,26\n",
		"- PII Encryption (e2): version=v2.7 source=platform keycloak=26\n",
		"- Phone Provider (e3): version=unknown source=platform keycloak=26\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("catalog text missing %q in:\n%s", want, txt)
		}
	}
	assertNoDashes(t, txt)
}

// The installed line puts the installed and available versions side by side,
// so a caller sees what an upgrade would move to without a second call.
func TestListClusterExtensionsLinePrintsAvailableVersion(t *testing.T) {
	api := stubAPI{clusExts: []skycloak.ClusterExtension{
		{ExtensionID: "e1", ExtensionName: "Email OTP", InstalledVersion: "1.3.5", AvailableVersion: "1.5.0", Status: "active", UpgradeAvailable: true},
		{ExtensionID: "e2", ExtensionName: "SCIM", InstalledVersion: "1.4.1-SNAPSHOT", AvailableVersion: "1.4.1-SNAPSHOT", Status: "active"},
		{ExtensionID: "e3", ExtensionName: "Magic Link", InstalledVersion: "unknown", Status: "active"},
	}}
	res, _, _ := listClusterExtensionsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	txt := res.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{
		"- Email OTP (e1): installed=v1.3.5 available=v1.5.0 status=active upgrade_available=true\n",
		"- SCIM (e2): installed=v1.4.1-SNAPSHOT available=v1.4.1-SNAPSHOT status=active upgrade_available=false\n",
		"- Magic Link (e3): installed=unknown available=unknown status=active upgrade_available=false\n",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("installed text missing %q in:\n%s", want, txt)
		}
	}
	assertNoDashes(t, txt)
}

func assertNoDashes(t *testing.T, txt string) {
	t.Helper()
	if strings.ContainsAny(txt, "\u2014\u2013") {
		t.Errorf("output contains an em-dash or en-dash:\n%s", txt)
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

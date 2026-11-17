package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerActionReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_discover_oidc",
		Description: "Fetch an external OIDC issuer's discovery document and return its authorization, token and userinfo endpoints with the scopes it supports. " +
			"Reaches the issuer over the network and changes nothing in Skycloak. Use the result to fill skycloak_create_identity_provider.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true), ReadOnlyHint: true, Title: "Discover OIDC endpoints"},
	}, discoverOIDCHandler(api))
}

func registerActionWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_test_smtp",
		Description: "Send a test email through one realm's configured SMTP server to the address given, and report success with the server's message. " +
			"It really sends mail, but changes no configuration; skycloak_upsert_smtp is what edits the settings.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Test SMTP"},
	}, testSMTPHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_test_identity_provider",
		Description: "Check connectivity from one realm to one of its identity providers and report success with the message. " +
			"client_id and client_secret, when given, are used for this test only and are not saved; skycloak_update_identity_provider is what changes the stored provider.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Test identity provider"},
	}, testIdentityProviderHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_cancel_cluster_upgrade",
		Description: "Cancel the Keycloak version upgrade currently running on one cluster. Stopping an upgrade part-way can leave the cluster mid-migration, so check skycloak_get_cluster for the version it ended on and skycloak_list_cluster_upgrades for the recorded phase. " +
			"Set confirm=true to proceed. There is nothing to cancel when no upgrade is in flight.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Cancel cluster upgrade"},
	}, cancelClusterUpgradeHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_restart_cluster_instances",
		Description: "Restart one cluster's Keycloak instances, disrupting live traffic on that cluster. " +
			"Mainly needed after skycloak_update_theme_settings turns exact_theme_names on: a theme replaced under its exact name serves its new content only once Keycloak restarts, which is what restart_required on skycloak_get_theme and skycloak_list_themes reports. " +
			"Applies immediately unless the workspace defers disruptive changes to the maintenance window, reported as deferred=true with next_window (RFC3339) when known. " +
			"Conflicts when the cluster is already busy with a restart or update, is not in an available state, or its operator has no environment variable slot left. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Restart cluster instances"},
	}, restartClusterInstancesHandler(api))
}

// DiscoverOIDCInput is the input for skycloak_discover_oidc.
type DiscoverOIDCInput struct {
	IssuerURL string `json:"issuer_url" jsonschema:"the OIDC issuer URL"`
}

func discoverOIDCHandler(api API) mcp.ToolHandlerFor[DiscoverOIDCInput, skycloak.OIDCDiscovery] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DiscoverOIDCInput) (*mcp.CallToolResult, skycloak.OIDCDiscovery, error) {
		if in.IssuerURL == "" {
			return errResult("issuer_url is required"), skycloak.OIDCDiscovery{}, nil
		}
		doc, err := api.DiscoverOIDC(ctx, in.IssuerURL)
		if err != nil {
			return toolError(err), skycloak.OIDCDiscovery{}, nil
		}
		txt := fmt.Sprintf("issuer=%s\nauthorization_endpoint=%s\ntoken_endpoint=%s\nuserinfo_endpoint=%s\nscopes=%s",
			doc.Issuer, doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.UserinfoEndpoint, strings.Join(doc.ScopesSupported, " "))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *doc, nil
	}
}

// TestSMTPInput is the input for skycloak_test_smtp.
type TestSMTPInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	Email     string `json:"email" jsonschema:"recipient email address for the test message"`
}

func testSMTPHandler(api API) mcp.ToolHandlerFor[TestSMTPInput, skycloak.TestResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in TestSMTPInput) (*mcp.CallToolResult, skycloak.TestResult, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Email == "" {
			return errResult("cluster_id, realm and email are required"), skycloak.TestResult{}, nil
		}
		res, err := api.TestSMTP(ctx, in.ClusterID, in.Realm, in.Email)
		if err != nil {
			return toolError(err), skycloak.TestResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: testResultText(res)}}}, *res, nil
	}
}

// TestIDPInput is the input for skycloak_test_identity_provider.
type TestIDPInput struct {
	ClusterID    string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm        string `json:"realm" jsonschema:"the Keycloak realm name"`
	ProviderID   string `json:"provider_id" jsonschema:"the identity provider alias, exactly as skycloak_list_identity_providers reports it (case-sensitive)"`
	ClientID     string `json:"client_id,omitempty" jsonschema:"override client ID for this test only"`
	ClientSecret string `json:"client_secret,omitempty" jsonschema:"override client secret for this test only"`
}

func testIdentityProviderHandler(api API) mcp.ToolHandlerFor[TestIDPInput, skycloak.TestResult] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in TestIDPInput) (*mcp.CallToolResult, skycloak.TestResult, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ProviderID == "" {
			return errResult("cluster_id, realm and provider_id are required"), skycloak.TestResult{}, nil
		}
		res, err := api.TestIdentityProviderConnection(ctx, in.ClusterID, in.Realm, in.ProviderID, in.ClientID, in.ClientSecret)
		if err != nil {
			return toolError(err), skycloak.TestResult{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: testResultText(res)}}}, *res, nil
	}
}

// CancelUpgradeInput is the input for skycloak_cancel_cluster_upgrade.
type CancelUpgradeInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm cancellation"`
}

func cancelClusterUpgradeHandler(api API) mcp.ToolHandlerFor[CancelUpgradeInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CancelUpgradeInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to cancel the upgrade: set confirm=true."), struct{}{}, nil
		}
		if err := api.CancelClusterUpgrade(ctx, in.ClusterID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Cancelled the in-progress upgrade for cluster " + in.ClusterID}}}, struct{}{}, nil
	}
}

// RestartClusterInstancesInput is the input for skycloak_restart_cluster_instances.
type RestartClusterInstancesInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm the restart, which disrupts live traffic on the cluster"`
}

func restartClusterInstancesHandler(api API) mcp.ToolHandlerFor[RestartClusterInstancesInput, skycloak.ClusterRestartOutcome] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RestartClusterInstancesInput) (*mcp.CallToolResult, skycloak.ClusterRestartOutcome, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.ClusterRestartOutcome{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to restart cluster instances: set confirm=true. This disrupts live traffic on the cluster."), skycloak.ClusterRestartOutcome{}, nil
		}
		out, err := api.RestartClusterInstances(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.ClusterRestartOutcome{}, nil
		}
		text := fmt.Sprintf("Restarting instances for cluster %s. %s", in.ClusterID, out.Impact)
		if out.Deferred {
			text = fmt.Sprintf("Restart for cluster %s is deferred to its maintenance window.", in.ClusterID)
			if out.NextWindow != "" {
				text += " Next window: " + out.NextWindow + "."
			}
			text += " " + out.Impact
		}
		return okResult(text), *out, nil
	}
}

func testResultText(r *skycloak.TestResult) string {
	if r.Success {
		return "success: " + r.Message
	}
	return "failed: " + r.Message
}

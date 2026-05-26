package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerActionReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_discover_oidc",
		Description: "Resolve an OIDC issuer's discovery document to obtain its authorization, token, and userinfo endpoints. Use the result when creating an identity provider.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Discover OIDC endpoints"},
	}, discoverOIDCHandler(api))
}

func registerActionWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_test_smtp",
		Description: "Send a test email through a realm's configured SMTP server to verify delivery.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Test SMTP"},
	}, testSMTPHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_test_identity_provider",
		Description: "Test connectivity to an identity provider, optionally overriding the client credentials for this test only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Test identity provider"},
	}, testIdentityProviderHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_cancel_cluster_upgrade",
		Description: "Cancel an in-progress cluster version upgrade. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Cancel cluster upgrade"},
	}, cancelClusterUpgradeHandler(api))
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
	ProviderID   string `json:"provider_id" jsonschema:"the identity provider ID"`
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

func testResultText(r *skycloak.TestResult) string {
	if r.Success {
		return "success: " + r.Message
	}
	return "failed: " + r.Message
}

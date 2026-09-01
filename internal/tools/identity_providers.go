package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListIdentityProvidersInput is the input schema for skycloak_list_identity_providers.
type ListIdentityProvidersInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the ID of the cluster"`
	Realm     string `json:"realm" jsonschema:"the realm name whose identity providers to list"`
}

// IdentityProviderSummary is one row of the list output.
type IdentityProviderSummary struct {
	ProviderID  string `json:"provider_id"`
	Type        string `json:"type,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ListIdentityProvidersOutput is the structured result.
type ListIdentityProvidersOutput struct {
	IdentityProviders []IdentityProviderSummary `json:"identity_providers"`
	Count             int                       `json:"count"`
}

func registerIdentityProviderReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_identity_providers",
		Description: "List the identity providers (SSO connections) in a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List identity providers"},
	}, listIdentityProvidersHandler(api))
}

func listIdentityProvidersHandler(api API) mcp.ToolHandlerFor[ListIdentityProvidersInput, ListIdentityProvidersOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListIdentityProvidersInput) (*mcp.CallToolResult, ListIdentityProvidersOutput, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id and realm are required"}}}, ListIdentityProvidersOutput{}, nil
		}
		idps, err := api.ListIdentityProviders(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), ListIdentityProvidersOutput{}, nil
		}
		out := ListIdentityProvidersOutput{Count: len(idps), IdentityProviders: []IdentityProviderSummary{}}
		var b strings.Builder
		for _, p := range idps {
			out.IdentityProviders = append(out.IdentityProviders, IdentityProviderSummary{ProviderID: p.ProviderID, Type: p.Type, DisplayName: p.DisplayName, Enabled: p.Enabled})
			fmt.Fprintf(&b, "- %s (%s) — %s · enabled=%t\n", p.ProviderID, p.DisplayName, p.Type, p.Enabled)
		}
		if len(idps) == 0 {
			b.WriteString("No identity providers found in this realm.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
	}
}

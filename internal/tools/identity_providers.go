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
	// Which cluster the provider lives in, so fleet rows are never ambiguous.
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name,omitempty"`

	ProviderID  string `json:"provider_id"`
	Type        string `json:"type,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ListIdentityProvidersOutput is the structured result.
type ListIdentityProvidersOutput struct {
	IdentityProviders []IdentityProviderSummary `json:"identity_providers"`
	Count             int                       `json:"count"`

	// Clusters a fleet-wide call could not read; non-empty means partial.
	Unreachable []UnreachableCluster `json:"unreachable,omitempty"`
}

func registerIdentityProviderReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_identity_providers",
		Description: "List the identity providers (SSO connections) in a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List identity providers"},
	}, listIdentityProvidersHandler(api))
}

func listIdentityProvidersHandler(api API) mcp.ToolHandlerFor[ListIdentityProvidersInput, ListIdentityProvidersOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListIdentityProvidersInput) (*mcp.CallToolResult, ListIdentityProvidersOutput, error) {
		if in.Realm == "" {
			return errResult("realm is required"), ListIdentityProvidersOutput{}, nil
		}
		targets, err := fleetTargets(ctx, api, in.ClusterID)
		if err != nil {
			return toolError(err), ListIdentityProvidersOutput{}, nil
		}
		multi := len(targets) > 1 || in.ClusterID == ""

		out := ListIdentityProvidersOutput{IdentityProviders: []IdentityProviderSummary{}}
		var b strings.Builder
		for _, t := range targets {
			idps, err := api.ListIdentityProviders(ctx, t.id, in.Realm)
			if err != nil {
				out.Unreachable = append(out.Unreachable, UnreachableCluster{
					ClusterID: t.id, ClusterName: t.name, Error: err.Error(),
				})
				continue
			}
			for _, p := range idps {
				out.IdentityProviders = append(out.IdentityProviders, IdentityProviderSummary{
					ProviderID: p.ProviderID, Type: p.Type, DisplayName: p.DisplayName,
					Enabled: p.Enabled, ClusterID: t.id, ClusterName: t.name,
				})
				fmt.Fprintf(&b, "- %s%s (%s) — %s · enabled=%t\n",
					fleetHeader(t, multi), p.ProviderID, p.DisplayName, p.Type, p.Enabled)
			}
		}
		out.Count = len(out.IdentityProviders)

		if len(out.IdentityProviders) == 0 && len(out.Unreachable) > 0 {
			return errResult("no cluster could be read." + fleetNote(out.Unreachable)), out, nil
		}
		if len(out.IdentityProviders) == 0 {
			b.WriteString("No identity providers found.")
		}
		b.WriteString(fleetNote(out.Unreachable))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
	}
}

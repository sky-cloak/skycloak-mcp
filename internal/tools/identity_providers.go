package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListIdentityProvidersInput is the input schema for skycloak_list_identity_providers.
type ListIdentityProvidersInput struct {
	ClusterID string `json:"cluster_id,omitempty" jsonschema:"the ID of the cluster. Omit to search every cluster in the workspace"`
	Realm     string `json:"realm,omitempty" jsonschema:"the realm name whose identity providers to list. Omit to search every realm"`
}

// IdentityProviderSummary is one row of the list output.
type IdentityProviderSummary struct {
	// Which cluster the provider lives in, so fleet rows are never ambiguous.
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name,omitempty"`

	// Which realm the provider lives in, for the same reason.
	Realm string `json:"realm"`

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
		Description: "List the identity providers (SSO connections) in a realm. Omit realm to cover every realm, and cluster_id to cover every cluster, so one call can answer an SSO question across the whole fleet.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List identity providers"},
	}, listIdentityProvidersHandler(api))
}

func listIdentityProvidersHandler(api API) mcp.ToolHandlerFor[ListIdentityProvidersInput, ListIdentityProvidersOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListIdentityProvidersInput) (*mcp.CallToolResult, ListIdentityProvidersOutput, error) {
		targets, err := fleetTargets(ctx, api, in.ClusterID)
		if err != nil {
			return toolError(err), ListIdentityProvidersOutput{}, nil
		}
		// Only the cluster needs a prefix, and only when more than one is in play.
		// The realm is printed on every row regardless, so naming one cluster and
		// searching all its realms stays unambiguous without repeating the cluster
		// the caller just named.
		multi := len(targets) > 1 || in.ClusterID == ""

		out := ListIdentityProvidersOutput{IdentityProviders: []IdentityProviderSummary{}}
		var b strings.Builder
		for _, t := range targets {
			realms, err := realmTargets(ctx, api, t, in.Realm)
			if err != nil {
				out.Unreachable = append(out.Unreachable, UnreachableCluster{
					ClusterID: t.id, ClusterName: t.name, Error: err.Error(),
				})
				continue
			}
			for _, realm := range realms {
				idps, err := api.ListIdentityProviders(ctx, t.id, realm)
				if err != nil {
					out.Unreachable = append(out.Unreachable, UnreachableCluster{
						ClusterID: t.id, ClusterName: t.name, Realm: realm, Error: err.Error(),
					})
					continue
				}
				for _, p := range idps {
					out.IdentityProviders = append(out.IdentityProviders, IdentityProviderSummary{
						ProviderID: p.ProviderID, Type: p.Type, DisplayName: p.DisplayName,
						Enabled: p.Enabled, ClusterID: t.id, ClusterName: t.name, Realm: realm,
					})
					fmt.Fprintf(&b, "- %s%s/%s (%s) — %s · enabled=%t\n",
						fleetHeader(t, multi), realm, p.ProviderID, p.DisplayName, p.Type, p.Enabled)
				}
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

// realmTargets resolves which realms to search on one cluster. A named realm is
// taken as given rather than verified against the list, so narrowing stays a
// single call.
func realmTargets(ctx context.Context, api API, t fleetTarget, realm string) ([]string, error) {
	if realm != "" {
		return []string{realm}, nil
	}
	realms, err := api.ListRealms(ctx, t.id)
	if err != nil {
		return nil, fmt.Errorf("realm was omitted, so every realm had to be listed, and that failed: %w", err)
	}
	out := make([]string, 0, len(realms))
	for _, r := range realms {
		out = append(out, r.Name)
	}
	return out, nil
}

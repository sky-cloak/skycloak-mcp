package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerPublicAccessReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_public_access",
		Description: "Get whether one cluster's public hostname is served (enabled true) or the cluster is reachable only through its private link hostname (enabled false). Needs cluster_id from skycloak_list_clusters. To change it use skycloak_set_cluster_public_access; for the private hostname itself see skycloak_get_cluster_private_link.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster public access"},
	}, getClusterPublicAccessHandler(api))
}

func registerPublicAccessWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_set_cluster_public_access",
		Description: "Turn one cluster's public hostname on or off and return the new state. Turning it off serves the cluster only on its private link hostname, so everyone who signs in through the public hostname loses access: set confirm=true to proceed. Turning it on needs no confirmation. The API refuses turning it off with 403 when the plan has no private networking, 422 when the cluster's site has no Azure private link, and 409 unless private link is enabled and ready on the cluster; the tool returns the refusal as it is. Check skycloak_get_cluster_private_link first.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), IdempotentHint: true, Title: "Set cluster public access"},
	}, setClusterPublicAccessHandler(api))
}

func getClusterPublicAccessHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, skycloak.PublicAccess] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, skycloak.PublicAccess, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.PublicAccess{}, nil
		}
		pa, err := api.GetClusterPublicAccess(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.PublicAccess{}, nil
		}
		return okResult(publicAccessText(pa)), *pa, nil
	}
}

// SetClusterPublicAccessInput is the input for skycloak_set_cluster_public_access.
type SetClusterPublicAccessInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Enabled   bool   `json:"enabled" jsonschema:"true serves the public hostname, false serves the cluster only on its private link hostname"`
	Confirm   bool   `json:"confirm,omitempty" jsonschema:"must be true to turn public access off"`
}

func setClusterPublicAccessHandler(api API) mcp.ToolHandlerFor[SetClusterPublicAccessInput, skycloak.PublicAccess] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SetClusterPublicAccessInput) (*mcp.CallToolResult, skycloak.PublicAccess, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.PublicAccess{}, nil
		}
		if !in.Enabled && !in.Confirm {
			return errResult("Refusing to turn public access off: the cluster is then reachable only through its private link hostname. Set confirm=true."), skycloak.PublicAccess{}, nil
		}
		pa, err := api.SetClusterPublicAccess(ctx, in.ClusterID, in.Enabled)
		if err != nil {
			return toolError(err), skycloak.PublicAccess{}, nil
		}
		return okResult("Updated public access. " + publicAccessText(pa)), *pa, nil
	}
}

func publicAccessText(p *skycloak.PublicAccess) string {
	return fmt.Sprintf("Public access enabled=%t.", p.Enabled)
}

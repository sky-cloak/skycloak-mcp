package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerPrivateLinkReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_private_link",
		Description: "Get one cluster's Azure private link: whether it is on, the Azure subscription IDs allowed to connect, the Private Link Service alias to use when creating the private endpoint, the dns_name to create in your private DNS zone, the status (disabled, waiting or connected) and the connection state per subscription. Needs cluster_id from skycloak_list_clusters. Only clusters on a site with Azure private link have one; the API answers 422 for the others.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster private link"},
	}, getClusterPrivateLinkHandler(api))
}

func registerPrivateLinkWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_update_cluster_private_link",
		Description: "Set the Azure subscription IDs allowed to connect a private endpoint to one cluster, and return the new private link. azure_subscription_ids replaces the stored list: an empty list clears it and leaving it out keeps it, and at least one is needed to turn private link on. enabled turns private link on or off and is left as it is when omitted. The API refuses with 403 when the plan has no private networking, 422 when the site has no Azure private link or an ID is not a valid GUID, and 409 when turning it off while public access is off. Removing a subscription or turning private link off cuts the connections it carried. Read the current state first with skycloak_get_cluster_private_link.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Update cluster private link"},
	}, updateClusterPrivateLinkHandler(api))
}

func getClusterPrivateLinkHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, skycloak.PrivateLink] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, skycloak.PrivateLink, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.PrivateLink{}, nil
		}
		pl, err := api.GetClusterPrivateLink(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.PrivateLink{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: privateLinkText(pl)}}}, *pl, nil
	}
}

// UpdateClusterPrivateLinkInput is the input for skycloak_update_cluster_private_link.
type UpdateClusterPrivateLinkInput struct {
	ClusterID            string    `json:"cluster_id" jsonschema:"the cluster ID"`
	AzureSubscriptionIDs *[]string `json:"azure_subscription_ids,omitempty" jsonschema:"Azure subscription IDs (GUIDs, at most 20) allowed to connect; replaces the stored list, an empty list clears it, omit to keep it"`
	Enabled              *bool     `json:"enabled,omitempty" jsonschema:"turn private link on or off; omit to leave it as it is"`
}

func updateClusterPrivateLinkHandler(api API) mcp.ToolHandlerFor[UpdateClusterPrivateLinkInput, skycloak.PrivateLink] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateClusterPrivateLinkInput) (*mcp.CallToolResult, skycloak.PrivateLink, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.PrivateLink{}, nil
		}
		if in.AzureSubscriptionIDs == nil && in.Enabled == nil {
			return errResult("send azure_subscription_ids, enabled or both"), skycloak.PrivateLink{}, nil
		}
		pl, err := api.UpdateClusterPrivateLink(ctx, in.ClusterID, in.AzureSubscriptionIDs, in.Enabled)
		if err != nil {
			return toolError(err), skycloak.PrivateLink{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated private link. " + privateLinkText(pl)}}}, *pl, nil
	}
}

func privateLinkText(p *skycloak.PrivateLink) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Private link enabled=%t status=%s.", p.Enabled, p.Status)
	if len(p.AzureSubscriptionIDs) == 0 {
		b.WriteString(" No Azure subscriptions allowed.")
	} else {
		fmt.Fprintf(&b, " Allowed subscriptions: %s.", strings.Join(p.AzureSubscriptionIDs, ", "))
	}
	if p.Alias != "" {
		fmt.Fprintf(&b, " Alias: %s.", p.Alias)
	}
	if p.DNSName != "" {
		fmt.Fprintf(&b, " DNS name: %s.", p.DNSName)
	}
	return b.String()
}

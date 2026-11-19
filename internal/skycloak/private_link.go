package skycloak

import (
	"context"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

// PrivateLinkConnection is the private endpoint connection of one Azure
// subscription.
type PrivateLinkConnection struct {
	SubscriptionID string `json:"subscription_id"`
	Status         string `json:"status"`
}

// PrivateLink is a cluster's Azure private link. Alias and DNSName are present
// only while private link is enabled.
type PrivateLink struct {
	Enabled              bool                    `json:"enabled"`
	AzureSubscriptionIDs []string                `json:"azure_subscription_ids"`
	Alias                string                  `json:"alias,omitempty"`
	DNSName              string                  `json:"dns_name,omitempty"`
	Status               string                  `json:"status"`
	Connections          []PrivateLinkConnection `json:"connections,omitempty"`
}

func privateLinkFromAPI(p *apiclient.ClusterPrivateLink) *PrivateLink {
	out := &PrivateLink{
		Enabled:              p.Enabled,
		AzureSubscriptionIDs: p.AzureSubscriptionIds,
		Alias:                strDeref(p.Alias),
		DNSName:              strDeref(p.DnsName),
		Status:               string(p.Status),
	}
	if out.AzureSubscriptionIDs == nil {
		out.AzureSubscriptionIDs = []string{}
	}
	if p.Connections != nil {
		for _, c := range *p.Connections {
			out.Connections = append(out.Connections, PrivateLinkConnection{SubscriptionID: c.SubscriptionId, Status: string(c.Status)})
		}
	}
	return out
}

// GetClusterPrivateLink returns a cluster's Azure private link.
func (c *Client) GetClusterPrivateLink(ctx context.Context, clusterID string) (*PrivateLink, error) {
	resp, err := c.gen.GetClusterPrivateLinkWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return privateLinkFromAPI(resp.JSON200), nil
}

// UpdateClusterPrivateLink sets a cluster's allowed Azure subscription IDs and
// returns the new state. A nil subscriptionIDs keeps the stored list and an
// empty one clears it. A nil enabled keeps the current on or off state: the
// API requires the flag on every update, so it is read first rather than
// guessed, and a failed read stops the update instead of switching private
// link off by default.
func (c *Client) UpdateClusterPrivateLink(ctx context.Context, clusterID string, subscriptionIDs *[]string, enabled *bool) (*PrivateLink, error) {
	on := false
	if enabled != nil {
		on = *enabled
	} else {
		cur, err := c.gen.GetClusterPrivateLinkWithResponse(ctx, cid(clusterID), nil)
		if err != nil {
			return nil, err
		}
		if cur.JSON200 == nil {
			return nil, statusError(cur.HTTPResponse, cur.Body)
		}
		on = cur.JSON200.Enabled
	}
	resp, err := c.gen.UpdateClusterPrivateLinkWithResponse(ctx, cid(clusterID), nil, apiclient.UpdateClusterPrivateLinkJSONRequestBody{
		Enabled:              on,
		AzureSubscriptionIds: subscriptionIDs,
	})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return privateLinkFromAPI(resp.JSON200), nil
}

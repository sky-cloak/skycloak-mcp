package skycloak

import (
	"context"
	"errors"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

// PublicAccess says whether a cluster's public hostname is served. When it is
// off the cluster is reachable only through its private link hostname.
type PublicAccess struct {
	Enabled bool `json:"enabled"`
}

// errNoPublicAccess is returned when the API answers a cluster without the
// public_access field. Reporting that as "on" or "off" would be a guess about
// a setting that can lock users out, so it is surfaced instead.
var errNoPublicAccess = errors.New("the API did not report public access for this cluster")

func publicAccessFromAPI(cl *apiclient.Cluster) (*PublicAccess, error) {
	if cl.PublicAccess == nil {
		return nil, errNoPublicAccess
	}
	return &PublicAccess{Enabled: *cl.PublicAccess}, nil
}

// GetClusterPublicAccess returns whether a cluster's public hostname is served.
func (c *Client) GetClusterPublicAccess(ctx context.Context, clusterID string) (*PublicAccess, error) {
	resp, err := c.gen.GetClusterWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return publicAccessFromAPI(resp.JSON200)
}

// SetClusterPublicAccess turns a cluster's public hostname on or off and
// returns the new state. Only public_access is sent, so the cluster's other
// settings are left as they are. The API refuses turning it off with 403, 409
// or 422; those come back as the API's own error.
func (c *Client) SetClusterPublicAccess(ctx context.Context, clusterID string, enabled bool) (*PublicAccess, error) {
	resp, err := c.gen.UpdateClusterWithResponse(ctx, cid(clusterID), nil, apiclient.UpdateClusterJSONRequestBody{PublicAccess: &enabled})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return publicAccessFromAPI(resp.JSON200)
}

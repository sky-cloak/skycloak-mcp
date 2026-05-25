// Package tools registers Skycloak MCP tools on a server.
package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// API is the subset of the Skycloak client the tools depend on. It is an
// interface so tool handlers can be unit-tested against a stub.
type API interface {
	ListClusters(ctx context.Context, p skycloak.ListClustersParams) ([]skycloak.Cluster, error)
	GetCluster(ctx context.Context, id string) (*skycloak.Cluster, error)
	ListRealms(ctx context.Context, clusterID string) ([]skycloak.Realm, error)
	ListApplications(ctx context.Context, clusterID, realm string) ([]skycloak.Application, error)
	ListIdentityProviders(ctx context.Context, clusterID, realm string) ([]skycloak.IdentityProvider, error)
	CreateRealm(ctx context.Context, clusterID string, r skycloak.Realm) (*skycloak.Realm, error)
	DeleteRealm(ctx context.Context, clusterID, name string) error
	CreateCluster(ctx context.Context, req skycloak.CreateClusterRequest) (*skycloak.Cluster, error)
	DeleteCluster(ctx context.Context, id string) error
}

// Register adds all tools to the server.
//
// Read-only tools are always registered. Mutating tools are registered only
// when allowWrites is true and the API key carries the matching write scope.
func Register(s *mcp.Server, api API, allowWrites bool) {
	registerClusterReadTools(s, api)
	registerRealmReadTools(s, api)
	registerApplicationReadTools(s, api)
	registerIdentityProviderReadTools(s, api)
	if allowWrites {
		registerWriteTools(s, api)
	}
}

// ptr returns a pointer to v. Used for optional *bool tool annotations.
func ptr[T any](v T) *T { return &v }

// toolError converts an error into a tool-call error result the model can read
// and act on. Transport-level failures are returned as Go errors; API-level
// failures (4xx/5xx) are surfaced as IsError results with actionable hints.
func toolError(err error) *mcp.CallToolResult {
	msg := err.Error()
	if apiErr, ok := skycloak.AsAPIError(err); ok {
		switch apiErr.StatusCode {
		case 401:
			msg = "Unauthorized — check that SKYCLOAK_API_KEY is set and valid. " + msg
		case 403:
			msg = "Forbidden — your API key lacks the required scope for this action. " + msg
		case 429:
			msg = "Rate limited by the Skycloak gateway — wait and retry. " + msg
		}
	}
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

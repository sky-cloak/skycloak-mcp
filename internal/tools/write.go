package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// registerWriteTools registers mutating tools. These are gated behind
// --allow-writes and (once the public scopes endpoint ships) the API key's
// write scopes. Destructive tools set DestructiveHint and require a typed
// confirmation argument.
func registerWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_create_realm",
		Description: "Create a new Keycloak realm in a cluster. Requires the server to be started with --allow-writes and a write-scoped API key.",
		Annotations: &mcp.ToolAnnotations{Title: "Create realm", ReadOnlyHint: false, DestructiveHint: ptr(false)},
	}, createRealmHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_delete_realm",
		Description: "Permanently delete a realm and all of its users, clients and configuration. This is irreversible. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{Title: "Delete realm", ReadOnlyHint: false, DestructiveHint: ptr(true)},
	}, deleteRealmHandler(api))
}

// CreateRealmInput is the input schema for skycloak_create_realm.
type CreateRealmInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster to create the realm in"`
	Name        string `json:"name" jsonschema:"the realm name (unique within the cluster)"`
	DisplayName string `json:"display_name,omitempty" jsonschema:"optional human-readable display name"`
}

func createRealmHandler(api API) mcp.ToolHandlerFor[CreateRealmInput, RealmSummary] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRealmInput) (*mcp.CallToolResult, RealmSummary, error) {
		if in.ClusterID == "" || in.Name == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id and name are required"}}}, RealmSummary{}, nil
		}
		realm, err := api.CreateRealm(ctx, in.ClusterID, skycloak.Realm{Name: in.Name, DisplayName: in.DisplayName, Enabled: true})
		if err != nil {
			return toolError(err), RealmSummary{}, nil
		}
		out := RealmSummary{Name: realm.Name, DisplayName: realm.DisplayName, Enabled: realm.Enabled}
		text := fmt.Sprintf("Created realm %q in cluster %s.", realm.Name, in.ClusterID)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
	}
}

// DeleteRealmInput is the input schema for skycloak_delete_realm.
type DeleteRealmInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster the realm belongs to"`
	Name      string `json:"name" jsonschema:"the realm name to delete"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm permanent, irreversible deletion of the realm and all its data"`
}

func deleteRealmHandler(api API) mcp.ToolHandlerFor[DeleteRealmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteRealmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Name == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id and name are required"}}}, struct{}{}, nil
		}
		if !in.Confirm {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Refusing to delete realm %q: set confirm=true to proceed. This is irreversible.", in.Name)}}}, struct{}{}, nil
		}
		if err := api.DeleteRealm(ctx, in.ClusterID, in.Name); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleted realm %q from cluster %s.", in.Name, in.ClusterID)}}}, struct{}{}, nil
	}
}

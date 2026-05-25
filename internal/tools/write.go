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
		Name:        "skycloak_create_cluster",
		Description: "Provision a new Keycloak cluster. Asynchronous: the returned cluster starts in a provisioning state — poll skycloak_get_cluster until its status is 'available'. Requires --allow-writes.",
		Annotations: &mcp.ToolAnnotations{Title: "Create cluster", ReadOnlyHint: false, DestructiveHint: ptr(false)},
	}, createClusterHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_delete_cluster",
		Description: "Permanently delete a Keycloak cluster and all of its realms and data. Irreversible. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{Title: "Delete cluster", ReadOnlyHint: false, DestructiveHint: ptr(true)},
	}, deleteClusterHandler(api))

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

// CreateClusterInput is the input schema for skycloak_create_cluster.
type CreateClusterInput struct {
	Name     string `json:"name" jsonschema:"human-readable cluster name"`
	Type     string `json:"type,omitempty" jsonschema:"cluster type (keycloak or tidecloak); defaults to keycloak"`
	Size     string `json:"size" jsonschema:"instance size: small, medium, or large"`
	Version  string `json:"version" jsonschema:"Keycloak version, e.g. 26.1"`
	Location string `json:"location" jsonschema:"region: us, ca, eu, or au"`
}

func createClusterHandler(api API) mcp.ToolHandlerFor[CreateClusterInput, ClusterDetail] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateClusterInput) (*mcp.CallToolResult, ClusterDetail, error) {
		if in.Name == "" || in.Size == "" || in.Version == "" || in.Location == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "name, size, version and location are required"}}}, ClusterDetail{}, nil
		}
		cl, err := api.CreateCluster(ctx, skycloak.CreateClusterRequest{Name: in.Name, Type: in.Type, Size: in.Size, Version: in.Version, Location: in.Location})
		if err != nil {
			return toolError(err), ClusterDetail{}, nil
		}
		detail := ClusterDetail{ID: cl.ID, Name: cl.Name, Status: cl.Status, Type: cl.Type, Size: cl.Size, Version: cl.Version, Location: cl.Location, URL: cl.URL, CreatedAt: cl.CreatedAt, UpdatedAt: cl.UpdatedAt}
		text := fmt.Sprintf("Provisioning cluster %q (%s), status %q. Poll skycloak_get_cluster with id=%s until status is 'available'.", cl.Name, cl.ID, cl.Status, cl.ID)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, detail, nil
	}
}

// DeleteClusterInput is the input schema for skycloak_delete_cluster.
type DeleteClusterInput struct {
	ID      string `json:"id" jsonschema:"the cluster ID to delete"`
	Confirm bool   `json:"confirm" jsonschema:"must be true to confirm permanent, irreversible deletion of the cluster and all its data"`
}

func deleteClusterHandler(api API) mcp.ToolHandlerFor[DeleteClusterInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteClusterInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ID == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "id is required"}}}, struct{}{}, nil
		}
		if !in.Confirm {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Refusing to delete cluster %s: set confirm=true. This is irreversible.", in.ID)}}}, struct{}{}, nil
		}
		if err := api.DeleteCluster(ctx, in.ID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleting cluster %s.", in.ID)}}}, struct{}{}, nil
	}
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

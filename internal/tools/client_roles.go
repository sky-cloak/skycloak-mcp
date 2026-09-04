package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// ClientRoleRef identifies one role on an application.
type ClientRoleRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID  string `json:"client_id" jsonschema:"the application's OAuth client ID"`
	RoleName  string `json:"role_name" jsonschema:"the role name"`
}

// CreateClientRoleInput is the input for skycloak_create_application_role.
type CreateClientRoleInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm       string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID    string `json:"client_id" jsonschema:"the application's OAuth client ID"`
	Name        string `json:"name" jsonschema:"the role name"`
	Description string `json:"description,omitempty" jsonschema:"what the role is for"`
}

// UpdateClientRoleInput is the input for skycloak_update_application_role.
type UpdateClientRoleInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm       string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID    string `json:"client_id" jsonschema:"the application's OAuth client ID"`
	RoleName    string `json:"role_name" jsonschema:"the role to change"`
	NewName     string `json:"new_name,omitempty" jsonschema:"rename the role to this"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
}

func registerClientRoleReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_application_role",
		Description: "Get one role defined on an application, with its description and Keycloak identifiers.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get application role"},
	}, getClientRoleHandler(api))
}

func registerClientRoleWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_create_application_role",
		Description: "Define a new role on an application. This creates the role itself; use skycloak_assign_application_role to grant it to a user.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: false, DestructiveHint: ptr(false), Title: "Create application role"},
	}, createClientRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_update_application_role",
		Description: "Rename an application role or change its description. Fields you omit keep their current value.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update application role"},
	}, updateClientRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_delete_application_role",
		Description: "Delete a role from an application. Every user and group holding it loses it. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete application role"},
	}, deleteClientRoleHandler(api))
}

func getClientRoleHandler(api API) mcp.ToolHandlerFor[ClientRoleRef, skycloak.ClientRole] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ClientRoleRef) (*mcp.CallToolResult, skycloak.ClientRole, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, client_id and role_name are required"), skycloak.ClientRole{}, nil
		}
		r, err := api.GetClientRole(ctx, in.ClusterID, in.Realm, in.ClientID, in.RoleName)
		if err != nil {
			return toolError(err), skycloak.ClientRole{}, nil
		}
		return okResult(fmt.Sprintf("%s on %s%s", r.Name, r.ClientID, descSuffix(r.Description))), *r, nil
	}
}

func createClientRoleHandler(api API) mcp.ToolHandlerFor[CreateClientRoleInput, skycloak.ClientRole] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateClientRoleInput) (*mcp.CallToolResult, skycloak.ClientRole, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" || in.Name == "" {
			return errResult("cluster_id, realm, client_id and name are required"), skycloak.ClientRole{}, nil
		}
		r, err := api.CreateClientRole(ctx, in.ClusterID, in.Realm, in.ClientID, skycloak.ClientRoleRequest{Name: in.Name, Description: in.Description})
		if err != nil {
			return toolError(err), skycloak.ClientRole{}, nil
		}
		return okResult(fmt.Sprintf("Created role %q on %s.", r.Name, r.ClientID)), *r, nil
	}
}

func updateClientRoleHandler(api API) mcp.ToolHandlerFor[UpdateClientRoleInput, skycloak.ClientRole] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateClientRoleInput) (*mcp.CallToolResult, skycloak.ClientRole, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, client_id and role_name are required"), skycloak.ClientRole{}, nil
		}
		if in.NewName == "" && in.Description == "" {
			return errResult("pass new_name or description: an update with neither would change nothing"), skycloak.ClientRole{}, nil
		}
		r, err := api.UpdateClientRole(ctx, in.ClusterID, in.Realm, in.ClientID, in.RoleName,
			skycloak.ClientRoleRequest{Name: in.NewName, Description: in.Description})
		if err != nil {
			return toolError(err), skycloak.ClientRole{}, nil
		}
		return okResult(fmt.Sprintf("Updated role %q on %s.", r.Name, r.ClientID)), *r, nil
	}
}

// ClientRoleDeleteInput is the input for skycloak_delete_application_role.
type ClientRoleDeleteInput struct {
	ClientRoleRef
	Confirm bool `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteClientRoleHandler(api API) mcp.ToolHandlerFor[ClientRoleDeleteInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ClientRoleDeleteInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, client_id and role_name are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete role %q on %s: set confirm=true.", in.RoleName, in.ClientID)), struct{}{}, nil
		}
		if err := api.DeleteClientRole(ctx, in.ClusterID, in.Realm, in.ClientID, in.RoleName); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return okResult(fmt.Sprintf("Deleted role %q on %s.", in.RoleName, in.ClientID)), struct{}{}, nil
	}
}

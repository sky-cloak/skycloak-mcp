package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerApplicationRoleReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_application_roles",
		Description: "List the roles assigned to an application's service account.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List application roles"},
	}, listApplicationRolesHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_application_sessions",
		Description: "List active user sessions for an application.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List application sessions"},
	}, listApplicationSessionsHandler(api))
}

func registerApplicationRoleWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_assign_application_role",
		Description: "Grant a role to an application's service account. Provide role_client_id for a client role, or omit it for a realm role.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Assign application role"},
	}, assignApplicationRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_remove_application_role",
		Description: "Remove a role from an application's service account.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), IdempotentHint: true, Title: "Remove application role"},
	}, removeApplicationRoleHandler(api))
}

// ApplicationRef identifies an application client in a realm.
type ApplicationRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID  string `json:"client_id" jsonschema:"the application client ID"`
}

// AppRolesOutput is the structured application-role result.
type AppRolesOutput struct {
	Roles []skycloak.ApplicationRole `json:"roles"`
	Count int                        `json:"count"`
}

func listApplicationRolesHandler(api API) mcp.ToolHandlerFor[ApplicationRef, AppRolesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ApplicationRef) (*mcp.CallToolResult, AppRolesOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), AppRolesOutput{}, nil
		}
		roles, err := api.ListApplicationRoles(ctx, in.ClusterID, in.Realm, in.ClientID)
		if err != nil {
			return toolError(err), AppRolesOutput{}, nil
		}
		var b strings.Builder
		for _, r := range roles {
			fmt.Fprintf(&b, "- %s (client_role=%t)%s\n", r.Name, r.ClientRole, descSuffix(r.Description))
		}
		if len(roles) == 0 {
			b.WriteString("No roles assigned to this application.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, AppRolesOutput{Roles: roles, Count: len(roles)}, nil
	}
}

// AppSessionsOutput is the structured application-session result.
type AppSessionsOutput struct {
	Sessions []skycloak.ApplicationSession `json:"sessions"`
	Count    int                           `json:"count"`
}

func listApplicationSessionsHandler(api API) mcp.ToolHandlerFor[ApplicationRef, AppSessionsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ApplicationRef) (*mcp.CallToolResult, AppSessionsOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), AppSessionsOutput{}, nil
		}
		sessions, err := api.ListApplicationSessions(ctx, in.ClusterID, in.Realm, in.ClientID)
		if err != nil {
			return toolError(err), AppSessionsOutput{}, nil
		}
		var b strings.Builder
		for _, s := range sessions {
			fmt.Fprintf(&b, "- %s — user=%s ip=%s last_access=%s\n", s.ID, s.Username, s.IPAddress, s.LastAccessAt)
		}
		if len(sessions) == 0 {
			b.WriteString("No active sessions for this application.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, AppSessionsOutput{Sessions: sessions, Count: len(sessions)}, nil
	}
}

// AppRoleInput targets a role on an application's service account.
type AppRoleInput struct {
	ClusterID    string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm        string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID     string `json:"client_id" jsonschema:"the application client ID receiving the role"`
	RoleName     string `json:"role_name" jsonschema:"the role name"`
	RoleClientID string `json:"role_client_id,omitempty" jsonschema:"client ID owning the role for a client role; omit for a realm role"`
}

func assignApplicationRoleHandler(api API) mcp.ToolHandlerFor[AppRoleInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in AppRoleInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, client_id and role_name are required"), struct{}{}, nil
		}
		if err := api.AssignApplicationRole(ctx, in.ClusterID, in.Realm, in.ClientID, in.RoleName, in.RoleClientID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Assigned role %s to %s", in.RoleName, in.ClientID)}}}, struct{}{}, nil
	}
}

func removeApplicationRoleHandler(api API) mcp.ToolHandlerFor[AppRoleInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in AppRoleInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, client_id and role_name are required"), struct{}{}, nil
		}
		if err := api.RemoveApplicationRole(ctx, in.ClusterID, in.Realm, in.ClientID, in.RoleName, in.RoleClientID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Removed role %s from %s", in.RoleName, in.ClientID)}}}, struct{}{}, nil
	}
}

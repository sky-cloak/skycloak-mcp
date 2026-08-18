package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerRBACReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_realm_roles",
		Description: "List the realm-scoped roles in a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realm roles"},
	}, listRealmRolesHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_realm_groups",
		Description: "List the top-level groups in a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realm groups"},
	}, listRealmGroupsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_realm_users",
		Description: "List the users in a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realm users"},
	}, listRealmUsersHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_realm_user",
		Description: "Get a realm user by ID.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get realm user"},
	}, getRealmUserHandler(api))
}

func registerRBACWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_create_realm_role",
		Description: "Create a realm-scoped role.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create realm role"},
	}, createRealmRoleHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_delete_realm_role",
		Description: "Delete a realm role. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete realm role"},
	}, deleteRealmRoleHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_create_realm_group",
		Description: "Create a realm group, optionally nested under a parent group.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create realm group"},
	}, createRealmGroupHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_delete_realm_group",
		Description: "Delete a realm group. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete realm group"},
	}, deleteRealmGroupHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_create_realm_user",
		Description: "Create a realm user with an initial temporary password.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create realm user"},
	}, createRealmUserHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_delete_realm_user",
		Description: "Delete a realm user. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete realm user"},
	}, deleteRealmUserHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_assign_realm_user_role",
		Description: "Assign a realm role to a user.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Assign user role"},
	}, assignRealmUserRoleHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_remove_realm_user_role",
		Description: "Remove a realm role from a user.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), IdempotentHint: true, Title: "Remove user role"},
	}, removeRealmUserRoleHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_add_realm_user_to_group",
		Description: "Add a user to a realm group.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Add user to group"},
	}, addRealmUserToGroupHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_remove_realm_user_from_group",
		Description: "Remove a user from a realm group.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), IdempotentHint: true, Title: "Remove user from group"},
	}, removeRealmUserFromGroupHandler(api))
}

// RealmScopeInput targets a realm on a cluster.
type RealmScopeInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
}

// RolesOutput is the structured role-list result.
type RolesOutput struct {
	Roles []skycloak.RealmRole `json:"roles"`
	Count int                  `json:"count"`
}

func listRealmRolesHandler(api API) mcp.ToolHandlerFor[RealmScopeInput, RolesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmScopeInput) (*mcp.CallToolResult, RolesOutput, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), RolesOutput{}, nil
		}
		roles, err := api.ListRealmRoles(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), RolesOutput{}, nil
		}
		var b strings.Builder
		for _, r := range roles {
			fmt.Fprintf(&b, "- %s%s\n", r.Name, descSuffix(r.Description))
		}
		if len(roles) == 0 {
			b.WriteString("No roles in this realm.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, RolesOutput{Roles: roles, Count: len(roles)}, nil
	}
}

// GroupsOutput is the structured group-list result.
type GroupsOutput struct {
	Groups []skycloak.RealmGroup `json:"groups"`
	Count  int                   `json:"count"`
}

func listRealmGroupsHandler(api API) mcp.ToolHandlerFor[RealmScopeInput, GroupsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmScopeInput) (*mcp.CallToolResult, GroupsOutput, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), GroupsOutput{}, nil
		}
		groups, err := api.ListRealmGroups(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), GroupsOutput{}, nil
		}
		var b strings.Builder
		for _, g := range groups {
			fmt.Fprintf(&b, "- %s (%s) path=%s\n", g.Name, g.ID, g.Path)
		}
		if len(groups) == 0 {
			b.WriteString("No groups in this realm.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, GroupsOutput{Groups: groups, Count: len(groups)}, nil
	}
}

// UsersOutput is the structured user-list result.
type UsersOutput struct {
	Users []skycloak.RealmUser `json:"users"`
	Count int                  `json:"count"`
}

func listRealmUsersHandler(api API) mcp.ToolHandlerFor[RealmScopeInput, UsersOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmScopeInput) (*mcp.CallToolResult, UsersOutput, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), UsersOutput{}, nil
		}
		users, err := api.ListRealmUsers(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), UsersOutput{}, nil
		}
		var b strings.Builder
		for _, u := range users {
			fmt.Fprintf(&b, "- %s (%s) <%s> enabled=%t\n", u.Username, u.ID, u.Email, u.Enabled)
		}
		if len(users) == 0 {
			b.WriteString("No users in this realm.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, UsersOutput{Users: users, Count: len(users)}, nil
	}
}

// RealmUserRef identifies a user in a realm.
type RealmUserRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	UserID    string `json:"user_id" jsonschema:"the user ID"`
}

func getRealmUserHandler(api API) mcp.ToolHandlerFor[RealmUserRef, skycloak.RealmUser] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmUserRef) (*mcp.CallToolResult, skycloak.RealmUser, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" {
			return errResult("cluster_id, realm and user_id are required"), skycloak.RealmUser{}, nil
		}
		u, err := api.GetRealmUser(ctx, in.ClusterID, in.Realm, in.UserID)
		if err != nil {
			return toolError(err), skycloak.RealmUser{}, nil
		}
		txt := fmt.Sprintf("%s (%s) <%s> enabled=%t email_verified=%t", u.Username, u.ID, u.Email, u.Enabled, u.EmailVerified)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *u, nil
	}
}

// CreateRealmRoleInput is the input for skycloak_create_realm_role.
type CreateRealmRoleInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm       string `json:"realm" jsonschema:"the Keycloak realm name"`
	Name        string `json:"name" jsonschema:"the role name"`
	Description string `json:"description,omitempty" jsonschema:"optional role description"`
}

func createRealmRoleHandler(api API) mcp.ToolHandlerFor[CreateRealmRoleInput, skycloak.RealmRole] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRealmRoleInput) (*mcp.CallToolResult, skycloak.RealmRole, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Name == "" {
			return errResult("cluster_id, realm and name are required"), skycloak.RealmRole{}, nil
		}
		role, err := api.CreateRealmRole(ctx, in.ClusterID, in.Realm, in.Name, in.Description)
		if err != nil {
			return toolError(err), skycloak.RealmRole{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Created role " + role.Name}}}, *role, nil
	}
}

// DeleteRealmRoleInput is the input for skycloak_delete_realm_role.
type DeleteRealmRoleInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	Name      string `json:"name" jsonschema:"the role name"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteRealmRoleHandler(api API) mcp.ToolHandlerFor[DeleteRealmRoleInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteRealmRoleInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Name == "" {
			return errResult("cluster_id, realm and name are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete role %s: set confirm=true.", in.Name)), struct{}{}, nil
		}
		if err := api.DeleteRealmRole(ctx, in.ClusterID, in.Realm, in.Name); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted role " + in.Name}}}, struct{}{}, nil
	}
}

// CreateRealmGroupInput is the input for skycloak_create_realm_group.
type CreateRealmGroupInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	Name      string `json:"name" jsonschema:"the group name"`
	ParentID  string `json:"parent_id,omitempty" jsonschema:"optional parent group ID for a nested group"`
}

func createRealmGroupHandler(api API) mcp.ToolHandlerFor[CreateRealmGroupInput, skycloak.RealmGroup] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRealmGroupInput) (*mcp.CallToolResult, skycloak.RealmGroup, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Name == "" {
			return errResult("cluster_id, realm and name are required"), skycloak.RealmGroup{}, nil
		}
		g, err := api.CreateRealmGroup(ctx, in.ClusterID, in.Realm, in.Name, in.ParentID)
		if err != nil {
			return toolError(err), skycloak.RealmGroup{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Created group %s (%s) at %s", g.Name, g.ID, g.Path)}}}, *g, nil
	}
}

// GroupRef identifies a group in a realm.
type GroupRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	GroupID   string `json:"group_id" jsonschema:"the group ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteRealmGroupHandler(api API) mcp.ToolHandlerFor[GroupRef, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GroupRef) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.GroupID == "" {
			return errResult("cluster_id, realm and group_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete group %s: set confirm=true.", in.GroupID)), struct{}{}, nil
		}
		if err := api.DeleteRealmGroup(ctx, in.ClusterID, in.Realm, in.GroupID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted group " + in.GroupID}}}, struct{}{}, nil
	}
}

// CreateRealmUserInput is the input for skycloak_create_realm_user.
type CreateRealmUserInput struct {
	ClusterID         string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm             string `json:"realm" jsonschema:"the Keycloak realm name"`
	Username          string `json:"username" jsonschema:"the username"`
	Email             string `json:"email" jsonschema:"the email address"`
	FirstName         string `json:"first_name,omitempty" jsonschema:"optional first name"`
	LastName          string `json:"last_name,omitempty" jsonschema:"optional last name"`
	TemporaryPassword string `json:"temporary_password" jsonschema:"initial password (min 8 characters)"`
	Enabled           bool   `json:"enabled,omitempty" jsonschema:"whether the user can sign in (defaults to true when omitted)"`
}

func createRealmUserHandler(api API) mcp.ToolHandlerFor[CreateRealmUserInput, skycloak.RealmUser] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRealmUserInput) (*mcp.CallToolResult, skycloak.RealmUser, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Username == "" || in.Email == "" || in.TemporaryPassword == "" {
			return errResult("cluster_id, realm, username, email and temporary_password are required"), skycloak.RealmUser{}, nil
		}
		u, err := api.CreateRealmUser(ctx, in.ClusterID, in.Realm, in.Username, in.Email, in.FirstName, in.LastName, in.TemporaryPassword, true)
		if err != nil {
			return toolError(err), skycloak.RealmUser{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Created user %s (%s)", u.Username, u.ID)}}}, *u, nil
	}
}

// DeleteRealmUserInput is the input for skycloak_delete_realm_user.
type DeleteRealmUserInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	UserID    string `json:"user_id" jsonschema:"the user ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteRealmUserHandler(api API) mcp.ToolHandlerFor[DeleteRealmUserInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteRealmUserInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" {
			return errResult("cluster_id, realm and user_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete user %s: set confirm=true.", in.UserID)), struct{}{}, nil
		}
		if err := api.DeleteRealmUser(ctx, in.ClusterID, in.Realm, in.UserID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted user " + in.UserID}}}, struct{}{}, nil
	}
}

// UserRoleInput targets a (user, role) edge.
type UserRoleInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	UserID    string `json:"user_id" jsonschema:"the user ID"`
	RoleName  string `json:"role_name" jsonschema:"the realm role name"`
}

func assignRealmUserRoleHandler(api API) mcp.ToolHandlerFor[UserRoleInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UserRoleInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, user_id and role_name are required"), struct{}{}, nil
		}
		if err := api.AssignRealmUserRole(ctx, in.ClusterID, in.Realm, in.UserID, in.RoleName); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Assigned role %s to user %s", in.RoleName, in.UserID)}}}, struct{}{}, nil
	}
}

func removeRealmUserRoleHandler(api API) mcp.ToolHandlerFor[UserRoleInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UserRoleInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" || in.RoleName == "" {
			return errResult("cluster_id, realm, user_id and role_name are required"), struct{}{}, nil
		}
		if err := api.RemoveRealmUserRole(ctx, in.ClusterID, in.Realm, in.UserID, in.RoleName); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Removed role %s from user %s", in.RoleName, in.UserID)}}}, struct{}{}, nil
	}
}

// UserGroupInput targets a (user, group) edge.
type UserGroupInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	UserID    string `json:"user_id" jsonschema:"the user ID"`
	GroupID   string `json:"group_id" jsonschema:"the group ID"`
}

func addRealmUserToGroupHandler(api API) mcp.ToolHandlerFor[UserGroupInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UserGroupInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" || in.GroupID == "" {
			return errResult("cluster_id, realm, user_id and group_id are required"), struct{}{}, nil
		}
		if err := api.AddRealmUserToGroup(ctx, in.ClusterID, in.Realm, in.UserID, in.GroupID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Added user %s to group %s", in.UserID, in.GroupID)}}}, struct{}{}, nil
	}
}

func removeRealmUserFromGroupHandler(api API) mcp.ToolHandlerFor[UserGroupInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UserGroupInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" || in.GroupID == "" {
			return errResult("cluster_id, realm, user_id and group_id are required"), struct{}{}, nil
		}
		if err := api.RemoveRealmUserFromGroup(ctx, in.ClusterID, in.Realm, in.UserID, in.GroupID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Removed user %s from group %s", in.UserID, in.GroupID)}}}, struct{}{}, nil
	}
}

func descSuffix(d string) string {
	if d == "" {
		return ""
	}
	return " — " + d
}

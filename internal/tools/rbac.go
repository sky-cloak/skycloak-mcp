package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerRBACReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_list_realm_roles",
		Description: "List every realm-scoped role defined in one realm, with each role's name and description. " +
			"These are definitions, not assignments: use skycloak_list_user_roles for the roles one user holds and skycloak_list_application_roles for what a service account holds. Roles defined on a client are separate; see skycloak_get_application_role.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realm roles"},
	}, listRealmRolesHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_realm_groups",
		Description: "List the top-level groups of one realm, each with its group_id, name and path; child groups are not expanded. " +
			"This is where group_id comes from. For a group's users use skycloak_list_realm_group_members, and for one user's groups use skycloak_list_user_groups.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realm groups"},
	}, listRealmGroupsHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_realm_users",
		Description: "List the users of one realm, each with username, user_id, email and enabled state. " +
			"Needs cluster_id from skycloak_list_clusters and a realm from skycloak_list_realms, and it is where the user_id the user tools take comes from.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realm users"},
	}, listRealmUsersHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_realm_user",
		Description: "Get one realm user by user_id, with username, email, enabled and email_verified. " +
			"Needs user_id from skycloak_list_realm_users. It carries no roles or groups; use skycloak_list_user_roles and skycloak_list_user_groups for those.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get realm user"},
	}, getRealmUserHandler(api))
}

func registerRBACWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_create_realm_role",
		Description: "Create a realm-scoped role in one realm, with an optional description. " +
			"The role is defined but held by nobody until skycloak_assign_realm_user_role grants it to a user. For a role that belongs to one application, use skycloak_create_application_role.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create realm role"},
	}, createRealmRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_realm_role",
		Description: "Delete one realm role by name. Every user and group holding it loses it, and the role cannot be recovered. " +
			"Set confirm=true to proceed. To revoke it from a single user instead, use skycloak_remove_realm_user_role.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete realm role"},
	}, deleteRealmRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_create_realm_group",
		Description: "Create a group in one realm, nested under parent_id when given, and return its new group_id and path. " +
			"The group starts empty; add users with skycloak_add_realm_user_to_group.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create realm group"},
	}, createRealmGroupHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_realm_group",
		Description: "Delete one realm group by group_id. Its members lose the membership and anything they inherited through it, and the group cannot be recovered. " +
			"Set confirm=true to proceed. To remove one user instead, use skycloak_remove_realm_user_from_group.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete realm group"},
	}, deleteRealmGroupHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_create_realm_user",
		Description: "Create a user in one realm. temporary_password is the required initial password, at least 8 characters and also subject to the realm's Keycloak password policy. " +
			"Despite the field name the API documents it as the initial password and does not mark the credential temporary, so do not promise the user a forced reset at first sign-in. " +
			"The user is always created enabled, whatever the enabled argument says; use skycloak_update_realm_user to disable one. Returns the new user_id. Roles and group membership are separate calls.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create realm user"},
	}, createRealmUserHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_realm_user",
		Description: "Delete one user from a realm, with their credentials and role and group memberships. This cannot be undone. " +
			"Set confirm=true to proceed. To block sign-in reversibly instead, call skycloak_update_realm_user with enabled=false.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete realm user"},
	}, deleteRealmUserHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_assign_realm_user_role",
		Description: "Grant a realm role to a realm user, identified by user_id from skycloak_list_realm_users. " +
			"The principal is a user and the role is realm-scoped: a client role cannot be granted here, and for an application's service account use skycloak_assign_application_role. Granting an existing role again changes nothing.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Assign user role"},
	}, assignRealmUserRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_remove_realm_user_role",
		Description: "Revoke a realm role from a realm user, who loses whatever that role granted. The role itself stays defined in the realm. " +
			"For an application's service account use skycloak_remove_application_role; to delete the role everywhere use skycloak_delete_realm_role.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), IdempotentHint: true, Title: "Remove user role"},
	}, removeRealmUserRoleHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_add_realm_user_to_group",
		Description: "Add one realm user to one realm group, so the user picks up whatever the group carries. " +
			"Needs user_id from skycloak_list_realm_users and group_id from skycloak_list_realm_groups. Adding an existing member changes nothing.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Add user to group"},
	}, addRealmUserToGroupHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_remove_realm_user_from_group",
		Description: "Remove one realm user from one realm group, so the user loses what the group carried. Both the user and the group remain. " +
			"To delete the group itself use skycloak_delete_realm_group.",
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
	TemporaryPassword string `json:"temporary_password" jsonschema:"initial password (min 8 characters); the API does not mark the credential temporary"`
	Enabled           bool   `json:"enabled,omitempty" jsonschema:"accepted but ignored: the user is always created enabled, so enabled=false does not work; use skycloak_update_realm_user to disable one"`
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

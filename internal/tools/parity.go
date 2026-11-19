package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerParityReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_get_smtp",
		Description: "Get one realm's SMTP configuration: host, port, from address, auth type and status. Passwords are never returned. " +
			"Needs cluster_id from skycloak_list_clusters and a realm name. Use skycloak_test_smtp to check that it actually delivers.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get SMTP config"},
	}, getSMTPHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_theme",
		Description: "Get one custom theme of a cluster by theme_id, with its name, status, theme types and restart_required. " +
			"restart_required is true when the theme's content was replaced under its exact name (see skycloak_get_theme_settings) and Keycloak has not restarted since, so the previous content may still be live; skycloak_restart_cluster_instances applies it. " +
			"Needs theme_id from skycloak_list_themes. This reads metadata, not the files, which skycloak_download_theme_content returns.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get theme"},
	}, getThemeHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_domain_route",
		Description: "Get one realm route on a custom domain by route_id, with the realm it serves and its admin-access setting. " +
			"Needs cluster_id, domain_id and route_id from skycloak_list_domain_routes.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get domain route"},
	}, getDomainRouteHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_client_theme_assignment",
		Description: "Get one application's login-theme override in a realm; an empty login means the client follows the realm's assignment. " +
			"Covers this client and the login page only. For the realm-wide themes across login, account, admin and email, use skycloak_get_theme_assignment.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get client theme"},
	}, getClientThemeHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_user_roles",
		Description: "List the realm roles one user currently holds, by user_id from skycloak_list_realm_users. " +
			"These are that user's grants, not the realm's catalogue of roles (skycloak_list_realm_roles) and not an application service account's roles (skycloak_list_application_roles).",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List user roles"},
	}, listUserRolesHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_user_groups",
		Description: "List the groups one user belongs to, each with its name and path. Needs user_id from skycloak_list_realm_users. " +
			"For the other direction, the users in a group, use skycloak_list_realm_group_members.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List user groups"},
	}, listUserGroupsHandler(api))
}

func registerParityWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_rotate_application_secret",
		Description: "Generate a new client secret for one confidential application and return it. " +
			"The previous secret stops working at once, so every integration using it fails until updated, and the new value is not retrievable later. Needs client_id from skycloak_list_applications.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Rotate application secret"},
	}, rotateApplicationSecretHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_update_realm",
		Description: "Update one realm's display name and enabled state. enabled is always sent, so omitting it disables the realm and stops every sign-in to it. " +
			"Only these two fields are editable here; a realm cannot be renamed, and skycloak_create_realm and skycloak_delete_realm handle the rest.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Update realm"},
	}, updateRealmHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_smtp",
		Description: "Remove one realm's SMTP configuration, after which Keycloak cannot send email for that realm. " +
			"Set confirm=true to proceed. To change the settings instead of removing them, use skycloak_upsert_smtp.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete SMTP config"},
	}, deleteSMTPHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_create_domain_route",
		Description: "Route one realm of a cluster onto a custom domain, optionally allowing admin-console access and hiding the /realms/{name} path segment. " +
			"Never use the master realm; it is reserved for cluster management and the API rejects it. Needs domain_id from skycloak_list_domains, and returns the new route_id.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create domain route"},
	}, createDomainRouteHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_domain_route",
		Description: "Remove one realm route from a custom domain, so that hostname stops serving that realm. The domain itself stays. " +
			"Set confirm=true to proceed, and use skycloak_delete_domain to remove the domain with all of its routes.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete domain route"},
	}, deleteDomainRouteHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_set_client_theme_assignment",
		Description: "Set or clear one application's login-theme override in a realm. Pass a theme ID from skycloak_list_themes, or an empty string to fall back to the realm's assignment. " +
			"Affects this client's login page only; skycloak_set_theme_assignment sets the realm-wide themes.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Set client theme"},
	}, setClientThemeHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_theme",
		Description: "Delete one custom theme from a cluster, discarding its archive for good. Set confirm=true to proceed. " +
			"To change an existing theme's files, use skycloak_update_theme_content instead: deleting a theme that is still assigned returns 409, and re-uploading gives a new ID.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete theme"},
	}, deleteThemeHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_extension",
		Description: "Delete a custom extension from the workspace catalog, so it can no longer be installed anywhere. Set confirm=true to proceed. " +
			"This is the catalog entry; to remove an extension from one cluster use skycloak_uninstall_extension.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete extension"},
	}, deleteExtensionHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_export",
		Description: "Delete one whole-cluster database export archive, after which its download URL stops working. " +
			"Set confirm=true to proceed, and take export_id from skycloak_list_exports. It covers the exports skycloak_create_export makes, not realm exports.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete export"},
	}, deleteExportHandler(api))
}

func getSMTPHandler(api API) mcp.ToolHandlerFor[RealmScopeInput, skycloak.SMTPConfig] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmScopeInput) (*mcp.CallToolResult, skycloak.SMTPConfig, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.SMTPConfig{}, nil
		}
		cfg, err := api.GetSMTP(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), skycloak.SMTPConfig{}, nil
		}
		txt := fmt.Sprintf("%s:%d from=%s auth=%s status=%s", cfg.Host, cfg.Port, cfg.FromEmail, cfg.AuthType, cfg.Status)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *cfg, nil
	}
}

func getThemeHandler(api API) mcp.ToolHandlerFor[ThemeRef, skycloak.Theme] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ThemeRef) (*mcp.CallToolResult, skycloak.Theme, error) {
		if in.ClusterID == "" || in.ThemeID == "" {
			return errResult("cluster_id and theme_id are required"), skycloak.Theme{}, nil
		}
		t, err := api.GetTheme(ctx, in.ClusterID, in.ThemeID)
		if err != nil {
			return toolError(err), skycloak.Theme{}, nil
		}
		text := fmt.Sprintf("%s (%s) status=%s%s", t.Name, t.ID, t.Status, restartRequiredSuffix(t.RestartRequired))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *t, nil
	}
}

func getDomainRouteHandler(api API) mcp.ToolHandlerFor[RouteRef, skycloak.DomainRoute] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RouteRef) (*mcp.CallToolResult, skycloak.DomainRoute, error) {
		if in.ClusterID == "" || in.DomainID == "" || in.RouteID == "" {
			return errResult("cluster_id, domain_id and route_id are required"), skycloak.DomainRoute{}, nil
		}
		r, err := api.GetDomainRoute(ctx, in.ClusterID, in.DomainID, in.RouteID)
		if err != nil {
			return toolError(err), skycloak.DomainRoute{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s realm=%s", r.ID, r.Realm)}}}, *r, nil
	}
}

func getClientThemeHandler(api API) mcp.ToolHandlerFor[AppRef, ClientThemeOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in AppRef) (*mcp.CallToolResult, ClientThemeOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), ClientThemeOutput{}, nil
		}
		login, err := api.GetClientThemeAssignment(ctx, in.ClusterID, in.Realm, in.ClientID)
		if err != nil {
			return toolError(err), ClientThemeOutput{}, nil
		}
		txt := "login=default"
		if login != "" {
			txt = "login=" + login
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, ClientThemeOutput{Login: login}, nil
	}
}

func listUserRolesHandler(api API) mcp.ToolHandlerFor[RealmUserRef, RolesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmUserRef) (*mcp.CallToolResult, RolesOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" {
			return errResult("cluster_id, realm and user_id are required"), RolesOutput{}, nil
		}
		roles, err := api.ListRealmUserRoles(ctx, in.ClusterID, in.Realm, in.UserID)
		if err != nil {
			return toolError(err), RolesOutput{}, nil
		}
		var b strings.Builder
		for _, r := range roles {
			fmt.Fprintf(&b, "- %s\n", r.Name)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, RolesOutput{Roles: roles, Count: len(roles)}, nil
	}
}

func listUserGroupsHandler(api API) mcp.ToolHandlerFor[RealmUserRef, GroupsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmUserRef) (*mcp.CallToolResult, GroupsOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" {
			return errResult("cluster_id, realm and user_id are required"), GroupsOutput{}, nil
		}
		groups, err := api.ListRealmUserGroups(ctx, in.ClusterID, in.Realm, in.UserID)
		if err != nil {
			return toolError(err), GroupsOutput{}, nil
		}
		var b strings.Builder
		for _, g := range groups {
			fmt.Fprintf(&b, "- %s (%s)\n", g.Name, g.Path)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, GroupsOutput{Groups: groups, Count: len(groups)}, nil
	}
}

func rotateApplicationSecretHandler(api API) mcp.ToolHandlerFor[AppRef, RotateSecretOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in AppRef) (*mcp.CallToolResult, RotateSecretOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), RotateSecretOutput{}, nil
		}
		secret, err := api.RotateApplicationSecret(ctx, in.ClusterID, in.Realm, in.ClientID)
		if err != nil {
			return toolError(err), RotateSecretOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Rotated. New client secret: " + secret}}}, RotateSecretOutput{ClientSecret: secret}, nil
	}
}

func updateRealmHandler(api API) mcp.ToolHandlerFor[UpdateRealmInput, skycloak.Realm] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateRealmInput) (*mcp.CallToolResult, skycloak.Realm, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.Realm{}, nil
		}
		r, err := api.UpdateRealm(ctx, in.ClusterID, in.Realm, in.DisplayName, in.Enabled)
		if err != nil {
			return toolError(err), skycloak.Realm{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated realm " + r.Name}}}, *r, nil
	}
}

func deleteSMTPHandler(api API) mcp.ToolHandlerFor[RealmConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to delete SMTP config: set confirm=true."), struct{}{}, nil
		}
		if err := api.DeleteSMTP(ctx, in.ClusterID, in.Realm); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted SMTP config for " + in.Realm}}}, struct{}{}, nil
	}
}

func createDomainRouteHandler(api API) mcp.ToolHandlerFor[CreateDomainRouteInput, skycloak.DomainRoute] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateDomainRouteInput) (*mcp.CallToolResult, skycloak.DomainRoute, error) {
		if in.ClusterID == "" || in.DomainID == "" || in.Realm == "" {
			return errResult("cluster_id, domain_id and realm are required"), skycloak.DomainRoute{}, nil
		}
		r, err := api.CreateDomainRoute(ctx, in.ClusterID, in.DomainID, in.Realm, in.AllowAdminAccess, in.HideRealmPath)
		if err != nil {
			return toolError(err), skycloak.DomainRoute{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Created route %s for realm %s", r.ID, r.Realm)}}}, *r, nil
	}
}

func deleteDomainRouteHandler(api API) mcp.ToolHandlerFor[RouteConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RouteConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.DomainID == "" || in.RouteID == "" {
			return errResult("cluster_id, domain_id and route_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to delete route: set confirm=true."), struct{}{}, nil
		}
		if err := api.DeleteDomainRoute(ctx, in.ClusterID, in.DomainID, in.RouteID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted route " + in.RouteID}}}, struct{}{}, nil
	}
}

func setClientThemeHandler(api API) mcp.ToolHandlerFor[SetClientThemeInput, ClientThemeOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SetClientThemeInput) (*mcp.CallToolResult, ClientThemeOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), ClientThemeOutput{}, nil
		}
		login, err := api.SetClientThemeAssignment(ctx, in.ClusterID, in.Realm, in.ClientID, in.Login)
		if err != nil {
			return toolError(err), ClientThemeOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated client login theme."}}}, ClientThemeOutput{Login: login}, nil
	}
}

func deleteThemeHandler(api API) mcp.ToolHandlerFor[ThemeConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ThemeConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.ThemeID == "" {
			return errResult("cluster_id and theme_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete theme %s: set confirm=true.", in.ThemeID)), struct{}{}, nil
		}
		if err := api.DeleteTheme(ctx, in.ClusterID, in.ThemeID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted theme " + in.ThemeID}}}, struct{}{}, nil
	}
}

func deleteExtensionHandler(api API) mcp.ToolHandlerFor[ExtensionConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ExtensionConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ExtensionID == "" {
			return errResult("extension_id is required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete extension %s: set confirm=true.", in.ExtensionID)), struct{}{}, nil
		}
		if err := api.DeleteExtension(ctx, in.ExtensionID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted extension " + in.ExtensionID}}}, struct{}{}, nil
	}
}

func deleteExportHandler(api API) mcp.ToolHandlerFor[ExportConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ExportConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.ExportID == "" {
			return errResult("cluster_id and export_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete export %s: set confirm=true.", in.ExportID)), struct{}{}, nil
		}
		if err := api.DeleteExport(ctx, in.ClusterID, in.ExportID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Deleted export " + in.ExportID}}}, struct{}{}, nil
	}
}

// Input/output types for parity tools.

// ThemeRef identifies a theme.
type ThemeRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	ThemeID   string `json:"theme_id" jsonschema:"the theme ID"`
}

// ThemeConfirmInput is a theme reference plus a deletion confirmation.
type ThemeConfirmInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	ThemeID   string `json:"theme_id" jsonschema:"the theme ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

// RouteRef identifies a domain route.
type RouteRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID  string `json:"domain_id" jsonschema:"the domain ID"`
	RouteID   string `json:"route_id" jsonschema:"the route ID"`
}

// RouteConfirmInput is a route reference plus a deletion confirmation.
type RouteConfirmInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID  string `json:"domain_id" jsonschema:"the domain ID"`
	RouteID   string `json:"route_id" jsonschema:"the route ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

// CreateDomainRouteInput is the input for skycloak_create_domain_route.
type CreateDomainRouteInput struct {
	ClusterID        string `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID         string `json:"domain_id" jsonschema:"the domain ID"`
	Realm            string `json:"realm" jsonschema:"the realm to route to this domain"`
	AllowAdminAccess bool   `json:"allow_admin_access,omitempty" jsonschema:"whether the admin console is reachable via this domain"`
	HideRealmPath    bool   `json:"hide_realm_path,omitempty" jsonschema:"whether to omit the /realms/{name} path segment"`
}

// ClientThemeOutput is the structured client-theme result.
type ClientThemeOutput struct {
	Login string `json:"login"`
}

// SetClientThemeInput is the input for skycloak_set_client_theme_assignment.
type SetClientThemeInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID  string `json:"client_id" jsonschema:"the application client ID"`
	Login     string `json:"login,omitempty" jsonschema:"theme ID for the client login page; empty resets to the realm default"`
}

// RotateSecretOutput carries a freshly rotated client secret.
type RotateSecretOutput struct {
	ClientSecret string `json:"client_secret"`
}

// UpdateRealmInput is the input for skycloak_update_realm.
type UpdateRealmInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm       string `json:"realm" jsonschema:"the Keycloak realm name"`
	DisplayName string `json:"display_name,omitempty" jsonschema:"new display name"`
	Enabled     bool   `json:"enabled,omitempty" jsonschema:"whether users can sign in to the realm"`
}

// RealmConfirmInput is a realm reference plus a deletion confirmation.
type RealmConfirmInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

// ExtensionConfirmInput is an extension reference plus a deletion confirmation.
type ExtensionConfirmInput struct {
	ExtensionID string `json:"extension_id" jsonschema:"the extension ID"`
	Confirm     bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

// ExportConfirmInput is an export reference plus a deletion confirmation.
type ExportConfirmInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	ExportID  string `json:"export_id" jsonschema:"the export ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

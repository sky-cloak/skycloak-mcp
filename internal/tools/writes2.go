package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerWrites2Tools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_realm_role", Description: "Rename a realm role or change its description.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update realm role"}}, updateRealmRoleHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_realm_group", Description: "Rename a realm group.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update realm group"}}, updateRealmGroupHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_realm_user", Description: "Update a realm user's profile (email, name, enabled, email_verified).", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update realm user"}}, updateRealmUserHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_domain_route", Description: "Update a domain route's admin access and CORS origins.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update domain route"}}, updateDomainRouteHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_application", Description: "Update an application's name, description, or redirect URIs.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update application"}}, updateApplicationHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_identity_provider", Description: "Update an identity provider's display name and enabled state.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update identity provider"}}, updateIdentityProviderHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_cluster", Description: "Update a cluster's version (to trigger an upgrade) or size.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update cluster"}}, updateClusterHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_extension", Description: "Update a custom extension's name or description.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update extension"}}, updateExtensionHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_update_theme", Description: "Update a theme's name, description, or version.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Update theme"}}, updateThemeHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_upsert_smtp", Description: "Create or update a realm's SMTP configuration (basic auth).", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Upsert SMTP"}}, upsertSMTPHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_upsert_login_branding", Description: "Create or update login-page branding (colors, logo, registration toggle).", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Upsert login branding"}}, upsertLoginBrandingHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_upsert_email_branding", Description: "Create or update email-template branding (color, logo, footer).", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Upsert email branding"}}, upsertEmailBrandingHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_delete_login_branding", Description: "Revert login branding to defaults. Set confirm=true to proceed.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete login branding"}}, deleteLoginBrandingHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_delete_email_branding", Description: "Revert email branding to defaults. Set confirm=true to proceed.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete email branding"}}, deleteEmailBrandingHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_export_cluster_events", Description: "Export a cluster's events as a document and return its contents.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Export cluster events"}}, exportClusterEventsHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_set_cluster_maintenance_window", Description: "Create or replace a cluster-specific maintenance window.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(false), Title: "Set maintenance window"}}, setClusterMaintenanceWindowHandler(api))
	mcp.AddTool(s, &mcp.Tool{Name: "skycloak_delete_cluster_maintenance_window", Description: "Delete a cluster-specific maintenance window so the cluster follows the workspace default. Set confirm=true to proceed.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete maintenance window"}}, deleteClusterMaintenanceWindowHandler(api))
}

// UpdateRealmRoleInput is the input for skycloak_update_realm_role.
type UpdateRealmRoleInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm       string `json:"realm" jsonschema:"the Keycloak realm name"`
	Name        string `json:"name" jsonschema:"the current role name"`
	NewName     string `json:"new_name,omitempty" jsonschema:"rename the role to this"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
}

func updateRealmRoleHandler(api API) mcp.ToolHandlerFor[UpdateRealmRoleInput, skycloak.RealmRole] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateRealmRoleInput) (*mcp.CallToolResult, skycloak.RealmRole, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Name == "" {
			return errResult("cluster_id, realm and name are required"), skycloak.RealmRole{}, nil
		}
		r, err := api.UpdateRealmRole(ctx, in.ClusterID, in.Realm, in.Name, in.NewName, in.Description)
		if err != nil {
			return toolError(err), skycloak.RealmRole{}, nil
		}
		return okResult("Updated role " + r.Name), *r, nil
	}
}

// UpdateRealmGroupInput is the input for skycloak_update_realm_group.
type UpdateRealmGroupInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	GroupID   string `json:"group_id" jsonschema:"the group ID"`
	Name      string `json:"name" jsonschema:"the new group name"`
}

func updateRealmGroupHandler(api API) mcp.ToolHandlerFor[UpdateRealmGroupInput, skycloak.RealmGroup] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateRealmGroupInput) (*mcp.CallToolResult, skycloak.RealmGroup, error) {
		if in.ClusterID == "" || in.Realm == "" || in.GroupID == "" || in.Name == "" {
			return errResult("cluster_id, realm, group_id and name are required"), skycloak.RealmGroup{}, nil
		}
		g, err := api.UpdateRealmGroup(ctx, in.ClusterID, in.Realm, in.GroupID, in.Name)
		if err != nil {
			return toolError(err), skycloak.RealmGroup{}, nil
		}
		return okResult("Updated group " + g.Name), *g, nil
	}
}

// UpdateRealmUserInput is the input for skycloak_update_realm_user.
type UpdateRealmUserInput struct {
	ClusterID     string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm         string `json:"realm" jsonschema:"the Keycloak realm name"`
	UserID        string `json:"user_id" jsonschema:"the user ID"`
	Email         string `json:"email,omitempty" jsonschema:"new email address"`
	FirstName     string `json:"first_name,omitempty" jsonschema:"new first name"`
	LastName      string `json:"last_name,omitempty" jsonschema:"new last name"`
	Enabled       bool   `json:"enabled,omitempty" jsonschema:"whether the user can sign in"`
	EmailVerified bool   `json:"email_verified,omitempty" jsonschema:"whether the email is verified"`
}

func updateRealmUserHandler(api API) mcp.ToolHandlerFor[UpdateRealmUserInput, skycloak.RealmUser] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateRealmUserInput) (*mcp.CallToolResult, skycloak.RealmUser, error) {
		if in.ClusterID == "" || in.Realm == "" || in.UserID == "" {
			return errResult("cluster_id, realm and user_id are required"), skycloak.RealmUser{}, nil
		}
		u, err := api.UpdateRealmUser(ctx, in.ClusterID, in.Realm, in.UserID, in.Email, in.FirstName, in.LastName, in.Enabled, in.EmailVerified)
		if err != nil {
			return toolError(err), skycloak.RealmUser{}, nil
		}
		return okResult("Updated user " + u.Username), *u, nil
	}
}

// UpdateDomainRouteInput is the input for skycloak_update_domain_route.
type UpdateDomainRouteInput struct {
	ClusterID          string   `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID           string   `json:"domain_id" jsonschema:"the domain ID"`
	RouteID            string   `json:"route_id" jsonschema:"the route ID"`
	AllowAdminAccess   bool     `json:"allow_admin_access,omitempty" jsonschema:"whether the admin console is reachable"`
	CorsAllowedOrigins []string `json:"cors_allowed_origins,omitempty" jsonschema:"CORS origins allowed via this domain"`
}

func updateDomainRouteHandler(api API) mcp.ToolHandlerFor[UpdateDomainRouteInput, skycloak.DomainRoute] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateDomainRouteInput) (*mcp.CallToolResult, skycloak.DomainRoute, error) {
		if in.ClusterID == "" || in.DomainID == "" || in.RouteID == "" {
			return errResult("cluster_id, domain_id and route_id are required"), skycloak.DomainRoute{}, nil
		}
		r, err := api.UpdateDomainRoute(ctx, in.ClusterID, in.DomainID, in.RouteID, in.AllowAdminAccess, in.CorsAllowedOrigins)
		if err != nil {
			return toolError(err), skycloak.DomainRoute{}, nil
		}
		return okResult("Updated route " + r.ID), *r, nil
	}
}

// UpdateApplicationInput is the input for skycloak_update_application.
type UpdateApplicationInput struct {
	ClusterID    string   `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm        string   `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID     string   `json:"client_id" jsonschema:"the application client ID"`
	Name         string   `json:"name,omitempty" jsonschema:"new display name"`
	Description  string   `json:"description,omitempty" jsonschema:"new description"`
	RedirectURIs []string `json:"redirect_uris,omitempty" jsonschema:"replace the full set of redirect URIs"`
}

func updateApplicationHandler(api API) mcp.ToolHandlerFor[UpdateApplicationInput, skycloak.Application] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateApplicationInput) (*mcp.CallToolResult, skycloak.Application, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), skycloak.Application{}, nil
		}
		a, err := api.UpdateApplication(ctx, in.ClusterID, in.Realm, in.ClientID, in.Name, in.Description, in.RedirectURIs)
		if err != nil {
			return toolError(err), skycloak.Application{}, nil
		}
		return okResult("Updated application " + a.ClientID), *a, nil
	}
}

// UpdateIdentityProviderInput is the input for skycloak_update_identity_provider.
type UpdateIdentityProviderInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm       string `json:"realm" jsonschema:"the Keycloak realm name"`
	ProviderID  string `json:"provider_id" jsonschema:"the identity provider alias, exactly as skycloak_list_identity_providers reports it (case-sensitive)"`
	DisplayName string `json:"display_name,omitempty" jsonschema:"new display name"`
	Enabled     bool   `json:"enabled,omitempty" jsonschema:"whether the provider is enabled"`
}

func updateIdentityProviderHandler(api API) mcp.ToolHandlerFor[UpdateIdentityProviderInput, skycloak.IdentityProvider] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateIdentityProviderInput) (*mcp.CallToolResult, skycloak.IdentityProvider, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ProviderID == "" {
			return errResult("cluster_id, realm and provider_id are required"), skycloak.IdentityProvider{}, nil
		}
		p, err := api.UpdateIdentityProvider(ctx, in.ClusterID, in.Realm, in.ProviderID, in.DisplayName, in.Enabled)
		if err != nil {
			return toolError(err), skycloak.IdentityProvider{}, nil
		}
		return okResult("Updated identity provider " + p.ProviderID), *p, nil
	}
}

// UpdateClusterInput is the input for skycloak_update_cluster.
type UpdateClusterInput struct {
	ClusterID          string `json:"cluster_id" jsonschema:"the cluster ID"`
	Version            string `json:"version,omitempty" jsonschema:"target Keycloak version (triggers an upgrade)"`
	Size               string `json:"size,omitempty" jsonschema:"new instance size: small, medium, or large (case-insensitive)"`
	AutoUpgradeEnabled *bool  `json:"auto_upgrade_enabled,omitempty" jsonschema:"enable or disable automatic patch upgrades"`
}

func updateClusterHandler(api API) mcp.ToolHandlerFor[UpdateClusterInput, skycloak.Cluster] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateClusterInput) (*mcp.CallToolResult, skycloak.Cluster, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.Cluster{}, nil
		}
		cl, err := api.UpdateCluster(ctx, in.ClusterID, in.Version, enumClusterSize.canonical(in.Size), in.AutoUpgradeEnabled)
		if err != nil {
			return toolError(err), skycloak.Cluster{}, nil
		}
		return okResult("Updated cluster " + cl.Name), *cl, nil
	}
}

// MaintenanceWindowInput is the input for skycloak_set_cluster_maintenance_window.
type MaintenanceWindowInput struct {
	ClusterID  string  `json:"cluster_id" jsonschema:"the cluster ID"`
	Enabled    bool    `json:"enabled" jsonschema:"whether the window is active"`
	DaysOfWeek []int32 `json:"days_of_week" jsonschema:"days of week, 0=Sunday through 6=Saturday"`
	StartLocal string  `json:"start_local" jsonschema:"local start time in HH:MM format"`
	EndLocal   string  `json:"end_local" jsonschema:"local end time in HH:MM format"`
	Timezone   string  `json:"timezone" jsonschema:"IANA timezone, e.g. Europe/Berlin"`
}

func setClusterMaintenanceWindowHandler(api API) mcp.ToolHandlerFor[MaintenanceWindowInput, skycloak.MaintenanceWindow] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in MaintenanceWindowInput) (*mcp.CallToolResult, skycloak.MaintenanceWindow, error) {
		if in.ClusterID == "" || in.StartLocal == "" || in.EndLocal == "" || in.Timezone == "" || len(in.DaysOfWeek) == 0 {
			return errResult("cluster_id, days_of_week, start_local, end_local and timezone are required"), skycloak.MaintenanceWindow{}, nil
		}
		window := skycloak.MaintenanceWindow{
			Enabled: in.Enabled, DaysOfWeek: in.DaysOfWeek,
			StartLocal: in.StartLocal, EndLocal: in.EndLocal, Timezone: in.Timezone,
		}
		out, err := api.SetClusterMaintenanceWindow(ctx, in.ClusterID, window)
		if err != nil {
			return toolError(err), skycloak.MaintenanceWindow{}, nil
		}
		return okResult("Updated maintenance window: " + formatMaintenanceWindow(*out)), *out, nil
	}
}

// DeleteMaintenanceWindowInput is the input for skycloak_delete_cluster_maintenance_window.
type DeleteMaintenanceWindowInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteClusterMaintenanceWindowHandler(api API) mcp.ToolHandlerFor[DeleteMaintenanceWindowInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteMaintenanceWindowInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to delete maintenance window: set confirm=true."), struct{}{}, nil
		}
		if err := api.DeleteClusterMaintenanceWindow(ctx, in.ClusterID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return okResult("Deleted maintenance window for cluster " + in.ClusterID), struct{}{}, nil
	}
}

// UpdateExtensionInput is the input for skycloak_update_extension.
type UpdateExtensionInput struct {
	ExtensionID string `json:"extension_id" jsonschema:"the extension ID"`
	Name        string `json:"name,omitempty" jsonschema:"new name"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
}

func updateExtensionHandler(api API) mcp.ToolHandlerFor[UpdateExtensionInput, skycloak.ExtensionInfo] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateExtensionInput) (*mcp.CallToolResult, skycloak.ExtensionInfo, error) {
		if in.ExtensionID == "" {
			return errResult("extension_id is required"), skycloak.ExtensionInfo{}, nil
		}
		e, err := api.UpdateExtension(ctx, in.ExtensionID, in.Name, in.Description)
		if err != nil {
			return toolError(err), skycloak.ExtensionInfo{}, nil
		}
		return okResult("Updated extension " + e.Name), *e, nil
	}
}

// UpdateThemeInput is the input for skycloak_update_theme.
type UpdateThemeInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	ThemeID     string `json:"theme_id" jsonschema:"the theme ID"`
	Name        string `json:"name,omitempty" jsonschema:"new name"`
	Description string `json:"description,omitempty" jsonschema:"new description"`
	Version     string `json:"version,omitempty" jsonschema:"new version"`
}

func updateThemeHandler(api API) mcp.ToolHandlerFor[UpdateThemeInput, skycloak.Theme] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateThemeInput) (*mcp.CallToolResult, skycloak.Theme, error) {
		if in.ClusterID == "" || in.ThemeID == "" {
			return errResult("cluster_id and theme_id are required"), skycloak.Theme{}, nil
		}
		t, err := api.UpdateTheme(ctx, in.ClusterID, in.ThemeID, in.Name, in.Description, in.Version)
		if err != nil {
			return toolError(err), skycloak.Theme{}, nil
		}
		return okResult("Updated theme " + t.Name), *t, nil
	}
}

// UpsertSMTPInput is the input for skycloak_upsert_smtp.
type UpsertSMTPInput struct {
	ClusterID  string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm      string `json:"realm" jsonschema:"the Keycloak realm name"`
	Host       string `json:"host" jsonschema:"SMTP server hostname"`
	Port       int64  `json:"port" jsonschema:"SMTP server port (e.g. 587)"`
	FromEmail  string `json:"from_email" jsonschema:"sender email address"`
	FromName   string `json:"from_name,omitempty" jsonschema:"sender display name"`
	Encryption string `json:"encryption,omitempty" jsonschema:"encryption mode: none, ssl, or starttls (case-insensitive)"`
	Username   string `json:"username,omitempty" jsonschema:"SMTP username (basic auth)"`
	Password   string `json:"password,omitempty" jsonschema:"SMTP password (basic auth); omit to retain the stored value"`
}

func upsertSMTPHandler(api API) mcp.ToolHandlerFor[UpsertSMTPInput, skycloak.SMTPConfig] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpsertSMTPInput) (*mcp.CallToolResult, skycloak.SMTPConfig, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Host == "" || in.FromEmail == "" {
			return errResult("cluster_id, realm, host and from_email are required"), skycloak.SMTPConfig{}, nil
		}
		cfg, err := api.UpsertSMTP(ctx, in.ClusterID, in.Realm, skycloak.UpsertSMTPRequest{
			Host: in.Host, Port: in.Port, Encryption: enumSMTPEncryption.canonical(in.Encryption),
			FromEmail: in.FromEmail, FromName: in.FromName,
			AuthType: "basic", Username: in.Username, Password: in.Password,
		})
		if err != nil {
			return toolError(err), skycloak.SMTPConfig{}, nil
		}
		return okResult(fmt.Sprintf("Configured SMTP %s:%d", cfg.Host, cfg.Port)), *cfg, nil
	}
}

// UpsertLoginBrandingInput is the input for skycloak_upsert_login_branding.
type UpsertLoginBrandingInput struct {
	ClusterID           string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm               string `json:"realm" jsonschema:"the Keycloak realm name"`
	PrimaryColor        string `json:"primary_color,omitempty" jsonschema:"primary accent color (hex)"`
	BackgroundColor     string `json:"background_color,omitempty" jsonschema:"background color (hex)"`
	LogoURL             string `json:"logo_url,omitempty" jsonschema:"logo URL"`
	RegistrationEnabled *bool  `json:"registration_enabled,omitempty" jsonschema:"show the self-registration link"`
}

func upsertLoginBrandingHandler(api API) mcp.ToolHandlerFor[UpsertLoginBrandingInput, skycloak.LoginBranding] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpsertLoginBrandingInput) (*mcp.CallToolResult, skycloak.LoginBranding, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.LoginBranding{}, nil
		}
		b, err := api.UpsertLoginBranding(ctx, in.ClusterID, in.Realm, skycloak.UpsertLoginBrandingRequest{
			PrimaryColor: in.PrimaryColor, BackgroundColor: in.BackgroundColor, LogoURL: in.LogoURL, RegistrationEnabled: in.RegistrationEnabled,
		})
		if err != nil {
			return toolError(err), skycloak.LoginBranding{}, nil
		}
		return okResult("Updated login branding."), *b, nil
	}
}

// UpsertEmailBrandingInput is the input for skycloak_upsert_email_branding.
type UpsertEmailBrandingInput struct {
	ClusterID          string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm              string `json:"realm" jsonschema:"the Keycloak realm name"`
	PrimaryColor       string `json:"primary_color,omitempty" jsonschema:"primary accent color (hex)"`
	HeaderLogoLightURL string `json:"header_logo_light_url,omitempty" jsonschema:"logo URL for light email clients"`
	FooterCompanyName  string `json:"footer_company_name,omitempty" jsonschema:"company name in the footer"`
}

func upsertEmailBrandingHandler(api API) mcp.ToolHandlerFor[UpsertEmailBrandingInput, skycloak.EmailBranding] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpsertEmailBrandingInput) (*mcp.CallToolResult, skycloak.EmailBranding, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.EmailBranding{}, nil
		}
		b, err := api.UpsertEmailBranding(ctx, in.ClusterID, in.Realm, skycloak.UpsertEmailBrandingRequest{
			PrimaryColor: in.PrimaryColor, HeaderLogoLightURL: in.HeaderLogoLightURL, FooterCompanyName: in.FooterCompanyName,
		})
		if err != nil {
			return toolError(err), skycloak.EmailBranding{}, nil
		}
		return okResult("Updated email branding."), *b, nil
	}
}

func deleteLoginBrandingHandler(api API) mcp.ToolHandlerFor[RealmConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to reset login branding: set confirm=true."), struct{}{}, nil
		}
		if err := api.DeleteLoginBranding(ctx, in.ClusterID, in.Realm); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return okResult("Reset login branding to defaults."), struct{}{}, nil
	}
}

func deleteEmailBrandingHandler(api API) mcp.ToolHandlerFor[RealmConfirmInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmConfirmInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult("Refusing to reset email branding: set confirm=true."), struct{}{}, nil
		}
		if err := api.DeleteEmailBranding(ctx, in.ClusterID, in.Realm); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return okResult("Reset email branding to defaults."), struct{}{}, nil
	}
}

// ExportEventsOutput carries the exported document.
type ExportEventsOutput struct {
	Document string `json:"document"`
}

func exportClusterEventsHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, ExportEventsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, ExportEventsOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), ExportEventsOutput{}, nil
		}
		raw, err := api.ExportClusterEvents(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), ExportEventsOutput{}, nil
		}
		return okResult(string(raw)), ExportEventsOutput{Document: string(raw)}, nil
	}
}

func okResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

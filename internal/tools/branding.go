package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerBrandingReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_themes",
		Description: "List the custom themes uploaded to a cluster, with their IDs, status, and theme types.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List themes"},
	}, listThemesHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_theme_assignment",
		Description: "Get the active custom theme per Keycloak theme type (login, account, admin, email) for a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get theme assignment"},
	}, getThemeAssignmentHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_login_branding",
		Description: "Get the login-page branding (colors, logo, toggles) for a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get login branding"},
	}, getLoginBrandingHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_email_branding",
		Description: "Get the email-template branding (colors, logo, footer) for a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get email branding"},
	}, getEmailBrandingHandler(api))
}

func registerBrandingWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_set_theme_assignment",
		Description: "Assign custom themes to a realm per Keycloak theme type. Pass a theme ID to activate it, or an empty string to reset that type to Keycloak's built-in default. Only the provided fields are changed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Set theme assignment"},
	}, setThemeAssignmentHandler(api))
}

// RealmRef identifies a realm on a cluster.
type RealmRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
}

// ThemesOutput is the structured result of a theme list.
type ThemesOutput struct {
	Themes []skycloak.Theme `json:"themes"`
	Count  int              `json:"count"`
}

func listThemesHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, ThemesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, ThemesOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), ThemesOutput{}, nil
		}
		themes, err := api.ListThemes(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), ThemesOutput{}, nil
		}
		var b strings.Builder
		for _, t := range themes {
			fmt.Fprintf(&b, "- %s (%s) — status=%s types=%s\n", t.Name, t.ID, t.Status, strings.Join(t.ThemeTypes, ","))
		}
		if len(themes) == 0 {
			b.WriteString("No custom themes on this cluster.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, ThemesOutput{Themes: themes, Count: len(themes)}, nil
	}
}

func getThemeAssignmentHandler(api API) mcp.ToolHandlerFor[RealmRef, skycloak.ThemeAssignment] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmRef) (*mcp.CallToolResult, skycloak.ThemeAssignment, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.ThemeAssignment{}, nil
		}
		a, err := api.GetThemeAssignment(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), skycloak.ThemeAssignment{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: themeAssignmentText(a)}}}, *a, nil
	}
}

func getLoginBrandingHandler(api API) mcp.ToolHandlerFor[RealmRef, skycloak.LoginBranding] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmRef) (*mcp.CallToolResult, skycloak.LoginBranding, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.LoginBranding{}, nil
		}
		b, err := api.GetLoginBranding(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), skycloak.LoginBranding{}, nil
		}
		txt := fmt.Sprintf("login branding: status=%s primary=%s background=%s logo=%s registration=%t forgot_password=%t",
			b.Status, b.PrimaryColor, b.BackgroundColor, b.LogoURL, b.RegistrationEnabled, b.ForgotPasswordEnabled)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *b, nil
	}
}

func getEmailBrandingHandler(api API) mcp.ToolHandlerFor[RealmRef, skycloak.EmailBranding] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmRef) (*mcp.CallToolResult, skycloak.EmailBranding, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.EmailBranding{}, nil
		}
		b, err := api.GetEmailBranding(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), skycloak.EmailBranding{}, nil
		}
		txt := fmt.Sprintf("email branding: status=%s primary=%s logo=%s footer_company=%s", b.Status, b.PrimaryColor, b.HeaderLogoLightURL, b.FooterCompanyName)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *b, nil
	}
}

// SetThemeAssignmentInput is the input for skycloak_set_theme_assignment.
type SetThemeAssignmentInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	Login     string `json:"login,omitempty" jsonschema:"theme ID for the login page; empty string resets to the Keycloak default"`
	Account   string `json:"account,omitempty" jsonschema:"theme ID for the account console; empty string resets to the Keycloak default"`
	Admin     string `json:"admin,omitempty" jsonschema:"theme ID for the admin console; empty string resets to the Keycloak default"`
	Email     string `json:"email,omitempty" jsonschema:"theme ID for email templates; empty string resets to the Keycloak default"`
}

func setThemeAssignmentHandler(api API) mcp.ToolHandlerFor[SetThemeAssignmentInput, skycloak.ThemeAssignment] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SetThemeAssignmentInput) (*mcp.CallToolResult, skycloak.ThemeAssignment, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.ThemeAssignment{}, nil
		}
		a, err := api.SetThemeAssignment(ctx, in.ClusterID, in.Realm, skycloak.ThemeAssignment{
			Login: in.Login, Account: in.Account, Admin: in.Admin, Email: in.Email,
		})
		if err != nil {
			return toolError(err), skycloak.ThemeAssignment{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated theme assignment. " + themeAssignmentText(a)}}}, *a, nil
	}
}

func themeAssignmentText(a *skycloak.ThemeAssignment) string {
	field := func(name, id string) string {
		if id == "" {
			return name + "=default"
		}
		return name + "=" + id
	}
	return strings.Join([]string{
		field("login", a.Login), field("account", a.Account), field("admin", a.Admin), field("email", a.Email),
	}, " ")
}

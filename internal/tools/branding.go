package tools

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerBrandingReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_themes",
		Description: "List the custom themes uploaded to a cluster, with their IDs, status, and theme types.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List themes"},
	}, listThemesHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_theme_assignment",
		Description: "Get the active custom theme per Keycloak theme type (login, account, admin, email) for a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get theme assignment"},
	}, getThemeAssignmentHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_login_branding",
		Description: "Get the login-page branding (colors, logo, toggles) for a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get login branding"},
	}, getLoginBrandingHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_email_branding",
		Description: "Get the email-template branding (colors, logo, footer) for a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get email branding"},
	}, getEmailBrandingHandler(api))
}

func registerBrandingWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_set_theme_assignment",
		Description: "Assign custom themes to a realm per Keycloak theme type. Pass a theme ID to activate it, or an empty string to reset that type to Keycloak's built-in default. Only the provided fields are changed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Set theme assignment"},
	}, setThemeAssignmentHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_update_theme_content",
		Description: "Replace an existing theme's archive with a new one, in place. The theme keeps its ID, its name and every realm and application assignment, and the new content deploys immediately, so this is the way to edit a theme: deleting and re-uploading detaches it and leaves the sign-in page unbranded in between. " +
			"Pass the ZIP or Keycloakify JAR base64-encoded in content_base64. Set confirm=true to proceed: the archive being replaced is not recoverable afterwards. The replacement must still contain every theme type the theme provides today, or the API rejects it; a theme created by a platform migration has pinned content and answers 409.",
		// Destructive because the archive it overwrites is not recoverable
		// afterwards, the way rotate_application_secret discards the old secret.
		// The theme's identity and assignments survive, which is the point.
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), IdempotentHint: true, Title: "Update theme content"},
	}, updateThemeContentHandler(api))
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

// maxThemeArchive caps the archive this tool will send. The endpoint's body
// limit is 50 MB; refusing here turns a spent upload and an opaque rejection
// into an answer the caller can act on.
const maxThemeArchive = 50 << 20

// defaultThemeFilename names an archive the caller did not name. The API reads
// the media type from the filename, so an unnamed archive has to default to
// something, and ZIP is what a theme package is unless it says otherwise.
const defaultThemeFilename = "theme.zip"

// UpdateThemeContentInput is the input for skycloak_update_theme_content.
type UpdateThemeContentInput struct {
	ClusterID     string `json:"cluster_id" jsonschema:"the cluster ID"`
	ThemeID       string `json:"theme_id" jsonschema:"the ID of the theme whose content is replaced"`
	ContentBase64 string `json:"content_base64" jsonschema:"the replacement theme archive (ZIP or Keycloakify JAR) base64-encoded"`
	Filename      string `json:"filename,omitempty" jsonschema:"archive filename; a .jar name is sent as a Keycloakify JAR, anything else as a ZIP (default theme.zip)"`
	Version       string `json:"version,omitempty" jsonschema:"new version label to record once the content is live, e.g. v2.4; omit to keep the current one"`
	Confirm       bool   `json:"confirm" jsonschema:"must be true to confirm the current archive is overwritten, which cannot be undone"`
}

// decodeThemeArchive turns a caller's base64 into archive bytes, refusing what
// the endpoint would refuse anyway. Whitespace is tolerated because base64 from
// a shell pipeline or a model arrives wrapped, and a line break is not a reason
// to send the caller round a retry.
func decodeThemeArchive(content string, limit int) ([]byte, error) {
	stripped := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, content)

	// Check before decoding: a base64 string this long cannot decode to
	// anything within the limit, and decoding it first would allocate it.
	if base64.StdEncoding.DecodedLen(len(stripped)) > limit {
		return nil, fmt.Errorf("theme archive is larger than the %d byte limit", limit)
	}
	raw, err := base64.StdEncoding.DecodeString(stripped)
	if err != nil {
		return nil, fmt.Errorf("content_base64 is not valid base64: %w", err)
	}
	if len(raw) > limit {
		return nil, fmt.Errorf("theme archive is larger than the %d byte limit", limit)
	}
	// A JAR is a ZIP, so reading the central directory is what tells both apart
	// from a payload that merely looks like one: it walks the real structure
	// rather than a two-byte prefix. Catching a mis-encoded or truncated body
	// here beats uploading it to be told.
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("content_base64 does not decode to a valid ZIP or JAR archive: %w", err)
	}
	if len(zr.File) == 0 {
		return nil, errors.New("content_base64 decodes to an empty ZIP or JAR archive, which carries no theme")
	}
	return raw, nil
}

func updateThemeContentHandler(api API) mcp.ToolHandlerFor[UpdateThemeContentInput, skycloak.Theme] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateThemeContentInput) (*mcp.CallToolResult, skycloak.Theme, error) {
		if in.ClusterID == "" || in.ThemeID == "" {
			return errResult("cluster_id and theme_id are required"), skycloak.Theme{}, nil
		}
		if in.ContentBase64 == "" {
			return errResult("content_base64 is required: it carries the replacement theme archive"), skycloak.Theme{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to replace the content of theme %s: set confirm=true. The archive it overwrites is not recoverable.", in.ThemeID)), skycloak.Theme{}, nil
		}
		archive, err := decodeThemeArchive(in.ContentBase64, maxThemeArchive)
		if err != nil {
			return errResult(err.Error()), skycloak.Theme{}, nil
		}
		filename := in.Filename
		if filename == "" {
			filename = defaultThemeFilename
		}

		t, err := api.UpdateThemeContent(ctx, in.ClusterID, in.ThemeID, filename, archive, in.Version)
		if err != nil {
			return toolError(err), skycloak.Theme{}, nil
		}
		text := fmt.Sprintf("Replaced the content of theme %s (%s): status=%s types=%s. Its realm and application assignments are unchanged.",
			t.Name, t.ID, t.Status, strings.Join(t.ThemeTypes, ","))
		return okResult(text), *t, nil
	}
}

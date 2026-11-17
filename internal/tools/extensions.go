package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerExtensionReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_list_extensions",
		Description: "List the workspace's extension catalog: the extensions available to install, with each one's extension_id, version, source and supported Keycloak versions. " +
			"Workspace-wide and takes no arguments. Not what a cluster is running; use skycloak_list_cluster_extensions for that.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List extension catalog"},
	}, listExtensionsHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_cluster_extensions",
		Description: "List the extensions installed on one cluster, each with its installed version, the version available for that cluster's Keycloak, its status and upgrade_available. " +
			"This is the installed set, while skycloak_list_extensions is the catalog to install from. Poll it after installing, upgrading or uninstalling, since those are asynchronous.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List installed extensions"},
	}, listClusterExtensionsHandler(api))
}

func registerExtensionWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_install_extension",
		Description: "Install one catalog extension on a cluster, passing any required parameters keyed by parameter name. " +
			"Asynchronous: poll skycloak_list_cluster_extensions until the status settles. extension_id comes from skycloak_list_extensions.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Install extension"},
	}, installExtensionHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_upgrade_extension",
		Description: "Upgrade an extension already installed on a cluster to the version available for that cluster's Keycloak, replacing the running artifact. " +
			"Asynchronous: poll skycloak_list_cluster_extensions. Not for catalog metadata, which skycloak_update_extension edits without touching any cluster.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Upgrade extension"},
	}, upgradeExtensionHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_uninstall_extension",
		Description: "Remove one installed extension from a cluster, so that cluster stops loading it. Set confirm=true to proceed. " +
			"The extension stays in the workspace catalog and can be installed again; skycloak_delete_extension is what removes it from the catalog.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Uninstall extension"},
	}, uninstallExtensionHandler(api))
}

// ListExtensionsInput is the input for skycloak_list_extensions (no parameters).
type ListExtensionsInput struct{}

// ExtensionsOutput is the structured catalog result.
type ExtensionsOutput struct {
	Extensions []skycloak.ExtensionInfo `json:"extensions"`
	Count      int                      `json:"count"`
}

func listExtensionsHandler(api API) mcp.ToolHandlerFor[ListExtensionsInput, ExtensionsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ ListExtensionsInput) (*mcp.CallToolResult, ExtensionsOutput, error) {
		exts, err := api.ListExtensions(ctx)
		if err != nil {
			return toolError(err), ExtensionsOutput{}, nil
		}
		var b strings.Builder
		for _, e := range exts {
			fmt.Fprintf(&b, "- %s (%s): version=%s source=%s keycloak=%s\n", e.Name, e.ID, versionLabel(e.Version), e.Source, strings.Join(e.KeycloakVersions, ","))
		}
		if len(exts) == 0 {
			b.WriteString("No extensions in the catalog.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, ExtensionsOutput{Extensions: exts, Count: len(exts)}, nil
	}
}

// ClusterExtensionsOutput is the structured installed-extensions result.
type ClusterExtensionsOutput struct {
	Extensions []skycloak.ClusterExtension `json:"extensions"`
	Count      int                         `json:"count"`
}

func listClusterExtensionsHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, ClusterExtensionsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, ClusterExtensionsOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), ClusterExtensionsOutput{}, nil
		}
		exts, err := api.ListClusterExtensions(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), ClusterExtensionsOutput{}, nil
		}
		var b strings.Builder
		for _, e := range exts {
			fmt.Fprintf(&b, "- %s (%s): installed=%s available=%s status=%s upgrade_available=%t\n",
				e.ExtensionName, e.ExtensionID, versionLabel(e.InstalledVersion), versionLabel(e.AvailableVersion), e.Status, e.UpgradeAvailable)
		}
		if len(exts) == 0 {
			b.WriteString("No extensions installed on this cluster.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, ClusterExtensionsOutput{Extensions: exts, Count: len(exts)}, nil
	}
}

// versionLabel renders an extension version for the text summary. Versions are
// free-form upstream strings (1.5.0, v2.7, 1.4.1-SNAPSHOT) and are shown
// verbatim; a missing version reads "unknown", the same word the API uses for
// an artifact it cannot identify.
func versionLabel(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// InstallExtensionInput is the input for skycloak_install_extension.
type InstallExtensionInput struct {
	ClusterID   string            `json:"cluster_id" jsonschema:"the cluster ID"`
	ExtensionID string            `json:"extension_id" jsonschema:"the catalog extension ID to install"`
	Parameters  map[string]string `json:"parameters,omitempty" jsonschema:"parameter values keyed by parameter name; required parameters must be provided"`
}

func installExtensionHandler(api API) mcp.ToolHandlerFor[InstallExtensionInput, skycloak.ClusterExtension] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in InstallExtensionInput) (*mcp.CallToolResult, skycloak.ClusterExtension, error) {
		if in.ClusterID == "" || in.ExtensionID == "" {
			return errResult("cluster_id and extension_id are required"), skycloak.ClusterExtension{}, nil
		}
		e, err := api.InstallExtension(ctx, in.ClusterID, in.ExtensionID, in.Parameters)
		if err != nil {
			return toolError(err), skycloak.ClusterExtension{}, nil
		}
		txt := fmt.Sprintf("Installing %s (status=%s). Poll skycloak_list_cluster_extensions for progress.", e.ExtensionName, e.Status)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *e, nil
	}
}

// ExtensionRef identifies an installed extension on a cluster.
type ExtensionRef struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	ExtensionID string `json:"extension_id" jsonschema:"the extension ID"`
}

func upgradeExtensionHandler(api API) mcp.ToolHandlerFor[ExtensionRef, skycloak.ClusterExtension] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ExtensionRef) (*mcp.CallToolResult, skycloak.ClusterExtension, error) {
		if in.ClusterID == "" || in.ExtensionID == "" {
			return errResult("cluster_id and extension_id are required"), skycloak.ClusterExtension{}, nil
		}
		e, err := api.UpgradeExtension(ctx, in.ClusterID, in.ExtensionID)
		if err != nil {
			return toolError(err), skycloak.ClusterExtension{}, nil
		}
		txt := fmt.Sprintf("Upgrading %s (status=%s).", e.ExtensionName, e.Status)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *e, nil
	}
}

// UninstallExtensionInput is the input for skycloak_uninstall_extension.
type UninstallExtensionInput struct {
	ClusterID   string `json:"cluster_id" jsonschema:"the cluster ID"`
	ExtensionID string `json:"extension_id" jsonschema:"the extension ID to uninstall"`
	Confirm     bool   `json:"confirm" jsonschema:"must be true to confirm uninstall"`
}

func uninstallExtensionHandler(api API) mcp.ToolHandlerFor[UninstallExtensionInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UninstallExtensionInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.ExtensionID == "" {
			return errResult("cluster_id and extension_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to uninstall extension %s: set confirm=true.", in.ExtensionID)), struct{}{}, nil
		}
		if err := api.UninstallExtension(ctx, in.ClusterID, in.ExtensionID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Uninstalled extension %s.", in.ExtensionID)}}}, struct{}{}, nil
	}
}

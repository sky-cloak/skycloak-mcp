package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerExportReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_exports",
		Description: "List the database export jobs for a cluster, with their status and expiry.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List exports"},
	}, listExportsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_export",
		Description: "Get a database export job by ID, including its status, progress, and (once completed) the time-limited download URL.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get export"},
	}, getExportHandler(api))
}

func registerExportWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_create_export",
		Description: "Start a database export for a cluster. Asynchronous: poll skycloak_get_export until the status is 'completed' to obtain the download URL. Including credentials requires an encryption_password.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create export"},
	}, createExportHandler(api))
}

// ExportsOutput is the structured result of an export list.
type ExportsOutput struct {
	Exports []skycloak.Export `json:"exports"`
	Count   int               `json:"count"`
}

func listExportsHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, ExportsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, ExportsOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), ExportsOutput{}, nil
		}
		exports, err := api.ListExports(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), ExportsOutput{}, nil
		}
		var b strings.Builder
		for _, e := range exports {
			fmt.Fprintf(&b, "- %s — format=%s status=%s expires=%s\n", e.ID, e.Format, e.Status, e.ExpiresAt)
		}
		if len(exports) == 0 {
			b.WriteString("No exports for this cluster.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, ExportsOutput{Exports: exports, Count: len(exports)}, nil
	}
}

// ExportRef identifies an export job.
type ExportRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	ExportID  string `json:"export_id" jsonschema:"the export job ID"`
}

func getExportHandler(api API) mcp.ToolHandlerFor[ExportRef, skycloak.Export] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ExportRef) (*mcp.CallToolResult, skycloak.Export, error) {
		if in.ClusterID == "" || in.ExportID == "" {
			return errResult("cluster_id and export_id are required"), skycloak.Export{}, nil
		}
		e, err := api.GetExport(ctx, in.ClusterID, in.ExportID)
		if err != nil {
			return toolError(err), skycloak.Export{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: exportText(e)}}}, *e, nil
	}
}

// CreateExportInput is the input for skycloak_create_export.
type CreateExportInput struct {
	ClusterID          string `json:"cluster_id" jsonschema:"the cluster ID"`
	Format             string `json:"format" jsonschema:"export format: sql or pgdump (case-insensitive)"`
	IncludeCredentials bool   `json:"include_credentials,omitempty" jsonschema:"include the Keycloak credential tables; requires encryption_password"`
	EncryptionPassword string `json:"encryption_password,omitempty" jsonschema:"password to encrypt the archive (AES-256-CBC); required when include_credentials is true"`
}

func createExportHandler(api API) mcp.ToolHandlerFor[CreateExportInput, skycloak.Export] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateExportInput) (*mcp.CallToolResult, skycloak.Export, error) {
		format := enumExportFormat.canonical(in.Format)
		if in.ClusterID == "" || format == "" {
			return errResult("cluster_id and format are required"), skycloak.Export{}, nil
		}
		if in.IncludeCredentials && in.EncryptionPassword == "" {
			return errResult("encryption_password is required when include_credentials is true"), skycloak.Export{}, nil
		}
		e, err := api.CreateExport(ctx, in.ClusterID, format, in.IncludeCredentials, in.EncryptionPassword)
		if err != nil {
			return toolError(err), skycloak.Export{}, nil
		}
		txt := fmt.Sprintf("Started export %s (status=%s). Poll skycloak_get_export for the download URL.", e.ID, e.Status)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *e, nil
	}
}

func exportText(e *skycloak.Export) string {
	s := fmt.Sprintf("export %s — format=%s status=%s progress=%d%%", e.ID, e.Format, e.Status, e.Progress)
	if e.DownloadURL != "" {
		s += "\ndownload_url: " + e.DownloadURL
	}
	if e.ErrorMessage != "" {
		s += "\nerror: " + e.ErrorMessage
	}
	return s
}

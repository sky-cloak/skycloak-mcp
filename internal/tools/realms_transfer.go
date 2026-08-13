package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// maxInlineThemeArchive caps what the theme download will inline. Beyond it the
// tool reports size and checksum only: a bigger archive costs more context than
// it is worth, and base64 inflates it by a third on the way.
const maxInlineThemeArchive = 1 << 20

func registerRealmTransferReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_realm_export",
		Description: "Get a realm export job by ID. Poll this after skycloak_create_realm_export until status is 'completed'; the download URL only appears then and expires 24 hours later.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get realm export"},
	}, getRealmExportHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_realm_import",
		Description: "Get a realm import job by ID. Poll this after skycloak_create_realm_import until status is 'completed' or 'failed'.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get realm import"},
	}, getRealmImportHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_download_theme_content",
		Description: "Download a custom theme's content archive. Returns size and SHA-256 always, and the archive itself only when it is small enough to inline.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Download theme content"},
	}, downloadThemeContentHandler(api))
}

func registerRealmTransferWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "skycloak_create_realm_export",
		Description: "Export a Keycloak realm to an encrypted archive. Asynchronous: poll skycloak_get_realm_export until status is 'completed'. " +
			"The archive is always encrypted, so encryption_password is required, and the same password is needed to import it again. " +
			"This is a realm export (one realm's configuration); skycloak_create_export is the separate whole-cluster database export.",
		Annotations: &mcp.ToolAnnotations{Title: "Export realm", ReadOnlyHint: false, DestructiveHint: ptr(false)},
	}, createRealmExportHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name: "skycloak_create_realm_import_upload_url",
		Description: "Get a presigned URL to upload a realm archive to. PUT the archive to upload_url, then pass the returned s3_key to skycloak_create_realm_import as upload_s3_key. " +
			"Not needed when importing an existing export: pass that export's ID as source_export_id instead.",
		Annotations: &mcp.ToolAnnotations{Title: "Get realm import upload URL", ReadOnlyHint: false, DestructiveHint: ptr(false)},
	}, createRealmImportUploadHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name: "skycloak_create_realm_import",
		Description: "Import a Keycloak realm into a cluster from an uploaded archive or an existing realm export. Asynchronous: poll skycloak_get_realm_import. " +
			"This overwrites the target realm's configuration and cannot be undone, so set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{Title: "Import realm", ReadOnlyHint: false, DestructiveHint: ptr(true)},
	}, createRealmImportHandler(api))
}

// CreateRealmExportInput is the input schema for skycloak_create_realm_export.
type CreateRealmExportInput struct {
	ClusterID          string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm              string `json:"realm" jsonschema:"the realm to export"`
	EncryptionPassword string `json:"encryption_password" jsonschema:"password used to encrypt the archive; required, and needed again to import it"`
}

func createRealmExportHandler(api API) mcp.ToolHandlerFor[CreateRealmExportInput, skycloak.RealmExport] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRealmExportInput) (*mcp.CallToolResult, skycloak.RealmExport, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.RealmExport{}, nil
		}
		if in.EncryptionPassword == "" {
			return errResult("encryption_password is required: realm archives are always encrypted"), skycloak.RealmExport{}, nil
		}
		e, err := api.CreateRealmExport(ctx, in.ClusterID, in.Realm, in.EncryptionPassword)
		if err != nil {
			return toolError(err), skycloak.RealmExport{}, nil
		}
		text := fmt.Sprintf("Started export of realm %s (id %s, status %s). Poll skycloak_get_realm_export until it is completed.", e.Realm, e.ID, e.Status)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *e, nil
	}
}

// RealmExportRef identifies a realm export job.
type RealmExportRef struct {
	ExportID string `json:"export_id" jsonschema:"the realm export ID"`
}

func getRealmExportHandler(api API) mcp.ToolHandlerFor[RealmExportRef, skycloak.RealmExport] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmExportRef) (*mcp.CallToolResult, skycloak.RealmExport, error) {
		if in.ExportID == "" {
			return errResult("export_id is required"), skycloak.RealmExport{}, nil
		}
		e, err := api.GetRealmExport(ctx, in.ExportID)
		if err != nil {
			return toolError(err), skycloak.RealmExport{}, nil
		}
		text := fmt.Sprintf("realm %s: %s (%d%%)", e.Realm, e.Status, e.Progress)
		if e.ErrorMessage != "" {
			text += " - " + e.ErrorMessage
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *e, nil
	}
}

// ClusterRefInput identifies a cluster.
type ClusterRefInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
}

func createRealmImportUploadHandler(api API) mcp.ToolHandlerFor[ClusterRefInput, skycloak.RealmImportUpload] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ClusterRefInput) (*mcp.CallToolResult, skycloak.RealmImportUpload, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.RealmImportUpload{}, nil
		}
		u, err := api.CreateRealmImportUpload(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.RealmImportUpload{}, nil
		}
		text := fmt.Sprintf("PUT the realm archive to the returned upload_url, then call skycloak_create_realm_import with upload_s3_key=%s.", u.S3Key)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *u, nil
	}
}

// CreateRealmImportInput is the input schema for skycloak_create_realm_import.
type CreateRealmImportInput struct {
	ClusterID      string `json:"cluster_id" jsonschema:"the cluster ID to import into"`
	UploadS3Key    string `json:"upload_s3_key,omitempty" jsonschema:"s3_key from skycloak_create_realm_import_upload_url, after uploading the archive"`
	SourceExportID string `json:"source_export_id,omitempty" jsonschema:"ID of an existing realm export to import instead of an upload"`
	Password       string `json:"password,omitempty" jsonschema:"password that decrypts the archive; required for an encrypted one"`
	Confirm        bool   `json:"confirm" jsonschema:"must be true: importing overwrites the target realm's configuration"`
}

func createRealmImportHandler(api API) mcp.ToolHandlerFor[CreateRealmImportInput, skycloak.RealmImport] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateRealmImportInput) (*mcp.CallToolResult, skycloak.RealmImport, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.RealmImport{}, nil
		}
		if !in.Confirm {
			return errResult("refusing to import without confirm=true: this overwrites the target realm's configuration"), skycloak.RealmImport{}, nil
		}
		switch {
		case in.UploadS3Key != "" && in.SourceExportID != "":
			return errResult("pass either upload_s3_key or source_export_id, not both"), skycloak.RealmImport{}, nil
		case in.UploadS3Key == "" && in.SourceExportID == "":
			return errResult("one of upload_s3_key or source_export_id is required"), skycloak.RealmImport{}, nil
		}

		req := skycloak.CreateRealmImportRequest{
			UploadS3Key: in.UploadS3Key, SourceExportID: in.SourceExportID, Password: in.Password,
		}
		req.SourceKind = "upload"
		if in.SourceExportID != "" {
			req.SourceKind = "stored_export"
		}
		i, err := api.CreateRealmImport(ctx, in.ClusterID, req)
		if err != nil {
			return toolError(err), skycloak.RealmImport{}, nil
		}
		text := fmt.Sprintf("Started import into cluster %s (id %s, status %s). Poll skycloak_get_realm_import.", in.ClusterID, i.ID, i.Status)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *i, nil
	}
}

// RealmImportRef identifies a realm import job.
type RealmImportRef struct {
	ImportID string `json:"import_id" jsonschema:"the realm import ID"`
}

func getRealmImportHandler(api API) mcp.ToolHandlerFor[RealmImportRef, skycloak.RealmImport] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmImportRef) (*mcp.CallToolResult, skycloak.RealmImport, error) {
		if in.ImportID == "" {
			return errResult("import_id is required"), skycloak.RealmImport{}, nil
		}
		i, err := api.GetRealmImport(ctx, in.ImportID)
		if err != nil {
			return toolError(err), skycloak.RealmImport{}, nil
		}
		text := fmt.Sprintf("realm %s: %s (%d%%)", i.Realm, i.Status, i.Progress)
		if i.ErrorMessage != "" {
			text += " - " + i.ErrorMessage
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *i, nil
	}
}

// ThemeContentInput identifies a theme.
type ThemeContentInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	ThemeID   string `json:"theme_id" jsonschema:"the theme ID"`
}

// ThemeContentOutput describes the archive, and carries it when small enough.
type ThemeContentOutput struct {
	SizeBytes int    `json:"size_bytes"`
	SHA256    string `json:"sha256"`
	Inlined   bool   `json:"inlined"`
}

func downloadThemeContentHandler(api API) mcp.ToolHandlerFor[ThemeContentInput, ThemeContentOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ThemeContentInput) (*mcp.CallToolResult, ThemeContentOutput, error) {
		if in.ClusterID == "" || in.ThemeID == "" {
			return errResult("cluster_id and theme_id are required"), ThemeContentOutput{}, nil
		}
		raw, err := api.DownloadThemeContent(ctx, in.ClusterID, in.ThemeID)
		if err != nil {
			return toolError(err), ThemeContentOutput{}, nil
		}
		sum := sha256.Sum256(raw)
		out := ThemeContentOutput{SizeBytes: len(raw), SHA256: hex.EncodeToString(sum[:])}

		if len(raw) > maxInlineThemeArchive {
			text := fmt.Sprintf("Theme archive is %d bytes, too large to inline (limit %d). SHA-256 %s.", len(raw), maxInlineThemeArchive, out.SHA256)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, out, nil
		}

		out.Inlined = true
		return &mcp.CallToolResult{Content: []mcp.Content{
			&mcp.TextContent{Text: fmt.Sprintf("Theme archive: %d bytes, SHA-256 %s.", len(raw), out.SHA256)},
			&mcp.EmbeddedResource{Resource: &mcp.ResourceContents{
				URI:      fmt.Sprintf("skycloak://clusters/%s/themes/%s/content", in.ClusterID, in.ThemeID),
				MIMEType: "application/octet-stream",
				Blob:     raw,
			}},
		}}, out, nil
	}
}

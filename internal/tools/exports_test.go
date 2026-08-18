package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListExportsHandler(t *testing.T) {
	api := stubAPI{exports: []skycloak.Export{{ID: "x1", Format: "pgdump", Status: "completed"}}}
	res, out, err := listExportsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.Count != 1 {
		t.Fatalf("listExports: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestGetExportHandler(t *testing.T) {
	res, out, err := getExportHandler(stubAPI{})(context.Background(), nil, ExportRef{ClusterID: "c1", ExportID: "x1"})
	if err != nil || res.IsError || out.DownloadURL == "" {
		t.Fatalf("getExport: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateExportHandler(t *testing.T) {
	res, out, err := createExportHandler(stubAPI{})(context.Background(), nil, CreateExportInput{ClusterID: "c1", Format: "pgdump"})
	if err != nil || res.IsError || out.Status != "pending" {
		t.Fatalf("createExport: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateExportRequiresPasswordForCredentials(t *testing.T) {
	res, _, err := createExportHandler(stubAPI{})(context.Background(), nil, CreateExportInput{ClusterID: "c1", Format: "pgdump", IncludeCredentials: true})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result when include_credentials lacks a password")
	}
}

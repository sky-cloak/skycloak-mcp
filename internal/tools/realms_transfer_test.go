package tools

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCreateRealmExportHandler(t *testing.T) {
	api := stubAPI{}
	res, out, err := createRealmExportHandler(api)(context.Background(), nil,
		CreateRealmExportInput{ClusterID: "c1", Realm: "app", EncryptionPassword: "pw"})
	if err != nil || res.IsError || out.ID != "rex_1" || out.Realm != "app" {
		t.Fatalf("createRealmExport: err=%v isErr=%v out=%+v", err, res.IsError, out)
	}
}

// The archive is always encrypted, so a caller that omits the password gets a
// usable message rather than a 400 from the API.
func TestCreateRealmExportRequiresEncryptionPassword(t *testing.T) {
	res, _, err := createRealmExportHandler(stubAPI{})(context.Background(), nil,
		CreateRealmExportInput{ClusterID: "c1", Realm: "app"})
	if err != nil || !res.IsError {
		t.Fatal("expected an error result when encryption_password is missing")
	}
}

func TestCreateRealmExportSurfacesAPIError(t *testing.T) {
	api := stubAPI{err: errors.New("boom")}
	res, _, err := createRealmExportHandler(api)(context.Background(), nil,
		CreateRealmExportInput{ClusterID: "c1", Realm: "app", EncryptionPassword: "pw"})
	if err != nil || !res.IsError {
		t.Fatal("expected an API failure to surface as an error result")
	}
}

func TestGetRealmExportHandler(t *testing.T) {
	res, out, err := getRealmExportHandler(stubAPI{})(context.Background(), nil, RealmExportRef{ExportID: "rex_1"})
	if err != nil || res.IsError || out.Status != "completed" || out.DownloadURL == "" {
		t.Fatalf("getRealmExport: err=%v isErr=%v out=%+v", err, res.IsError, out)
	}
	if res, _, _ := getRealmExportHandler(stubAPI{})(context.Background(), nil, RealmExportRef{}); !res.IsError {
		t.Fatal("expected an error result when export_id is missing")
	}
}

func TestCreateRealmImportUploadHandler(t *testing.T) {
	res, out, err := createRealmImportUploadHandler(stubAPI{})(context.Background(), nil, ClusterRefInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.UploadURL == "" || out.S3Key == "" {
		t.Fatalf("createRealmImportUpload: err=%v isErr=%v out=%+v", err, res.IsError, out)
	}
}

// Import overwrites a realm, so it must refuse without an explicit confirm.
func TestCreateRealmImportRequiresConfirm(t *testing.T) {
	res, _, err := createRealmImportHandler(stubAPI{})(context.Background(), nil,
		CreateRealmImportInput{ClusterID: "c1", UploadS3Key: "k"})
	if err != nil || !res.IsError {
		t.Fatal("expected an error result without confirm=true")
	}
}

// The two sources are alternatives; taking both would leave which one wins up
// to the server.
func TestCreateRealmImportRejectsAmbiguousSource(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   CreateRealmImportInput
	}{
		{"both sources", CreateRealmImportInput{ClusterID: "c1", UploadS3Key: "k", SourceExportID: "rex_1", Confirm: true}},
		{"neither source", CreateRealmImportInput{ClusterID: "c1", Confirm: true}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res, _, err := createRealmImportHandler(stubAPI{})(context.Background(), nil, tt.in)
			if err != nil || !res.IsError {
				t.Fatal("expected an error result")
			}
		})
	}
}

// source_kind is derived, not asked for: the caller picks a source and the tool
// tells the API which kind it is.
func TestCreateRealmImportDerivesSourceKind(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   CreateRealmImportInput
		want string
	}{
		{"upload", CreateRealmImportInput{ClusterID: "c1", UploadS3Key: "k", Confirm: true}, "upload"},
		{"stored export", CreateRealmImportInput{ClusterID: "c1", SourceExportID: "rex_1", Confirm: true}, "stored_export"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			res, out, err := createRealmImportHandler(stubAPI{})(context.Background(), nil, tt.in)
			if err != nil || res.IsError {
				t.Fatalf("err=%v isErr=%v", err, res.IsError)
			}
			if out.SourceKind != tt.want {
				t.Fatalf("source_kind = %q, want %q", out.SourceKind, tt.want)
			}
		})
	}
}

func TestGetRealmImportHandler(t *testing.T) {
	res, out, err := getRealmImportHandler(stubAPI{})(context.Background(), nil, RealmImportRef{ImportID: "rim_1"})
	if err != nil || res.IsError || out.Status != "completed" {
		t.Fatalf("getRealmImport: err=%v isErr=%v out=%+v", err, res.IsError, out)
	}
	if res, _, _ := getRealmImportHandler(stubAPI{})(context.Background(), nil, RealmImportRef{}); !res.IsError {
		t.Fatal("expected an error result when import_id is missing")
	}
}

// A small archive comes back as a blob the client can actually use.
func TestDownloadThemeContentInlinesSmallArchive(t *testing.T) {
	archive := []byte("PK\x03\x04 small")
	api := stubAPI{themeArchive: archive}
	res, out, err := downloadThemeContentHandler(api)(context.Background(), nil,
		ThemeContentInput{ClusterID: "c1", ThemeID: "t1"})
	if err != nil || res.IsError {
		t.Fatalf("err=%v isErr=%v", err, res.IsError)
	}
	if !out.Inlined || out.SizeBytes != len(archive) || out.SHA256 == "" {
		t.Fatalf("out=%+v", out)
	}
	var blob []byte
	for _, c := range res.Content {
		if er, ok := c.(*mcp.EmbeddedResource); ok && er.Resource != nil {
			blob = er.Resource.Blob
		}
	}
	if !bytes.Equal(blob, archive) {
		t.Fatalf("blob = %q, want the archive bytes", blob)
	}
}

// A large archive must not be inlined: base64 would inflate it by a third and
// it would crowd out the rest of the conversation.
func TestDownloadThemeContentSkipsLargeArchive(t *testing.T) {
	api := stubAPI{themeArchive: bytes.Repeat([]byte("x"), maxInlineThemeArchive+1)}
	res, out, err := downloadThemeContentHandler(api)(context.Background(), nil,
		ThemeContentInput{ClusterID: "c1", ThemeID: "t1"})
	if err != nil || res.IsError {
		t.Fatalf("err=%v isErr=%v", err, res.IsError)
	}
	if out.Inlined {
		t.Fatal("archive over the limit was inlined")
	}
	if out.SHA256 == "" || out.SizeBytes != maxInlineThemeArchive+1 {
		t.Fatalf("size and checksum must still be reported: %+v", out)
	}
	for _, c := range res.Content {
		if _, ok := c.(*mcp.EmbeddedResource); ok {
			t.Fatal("large archive was embedded anyway")
		}
	}
	txt, _ := res.Content[0].(*mcp.TextContent)
	if txt == nil || !strings.Contains(txt.Text, "too large") {
		t.Fatal("expected the message to say why the archive was not inlined")
	}
}

func TestDownloadThemeContentValidatesInput(t *testing.T) {
	if res, _, _ := downloadThemeContentHandler(stubAPI{})(context.Background(), nil, ThemeContentInput{}); !res.IsError {
		t.Fatal("expected an error result when cluster_id and theme_id are missing")
	}
}

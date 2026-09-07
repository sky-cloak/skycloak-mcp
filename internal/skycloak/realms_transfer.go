package skycloak

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

// RealmExport is a Keycloak realm export job. Distinct from Export, which is a
// database-level dump of a whole cluster.
type RealmExport struct {
	ID             string `json:"id"`
	ClusterID      string `json:"cluster_id"`
	Realm          string `json:"realm"`
	Scope          string `json:"scope"`
	Status         string `json:"status"`
	Progress       int64  `json:"progress"`
	SourceVersion  string `json:"source_version,omitempty"`
	SHA256Checksum string `json:"sha256_checksum,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
	CreatedAt      string `json:"created_at,omitempty"`
	CompletedAt    string `json:"completed_at,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
}

// RealmImport is a Keycloak realm import job.
type RealmImport struct {
	ID            string `json:"id"`
	ClusterID     string `json:"cluster_id"`
	Realm         string `json:"realm"`
	SourceKind    string `json:"source_kind"`
	Status        string `json:"status"`
	Progress      int64  `json:"progress"`
	SourceVersion string `json:"source_version,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
	CreatedAt     string `json:"created_at,omitempty"`
	CompletedAt   string `json:"completed_at,omitempty"`
}

// RealmImportUpload is a presigned destination for a realm artifact.
type RealmImportUpload struct {
	UploadURL string `json:"upload_url"`
	S3Key     string `json:"s3_key"`
}

// Realm import sources. Defined from the generated enum, so a spec change to
// these values fails the build here rather than 400ing at runtime.
const (
	RealmImportSourceUpload = string(apiclient.Upload)
	RealmImportSourceStored = string(apiclient.Stored)
)

// CreateRealmImportRequest starts an import. Exactly one source is used:
// UploadS3Key for an artifact uploaded via CreateRealmImportUpload, or
// SourceExportID to reuse a realm export that already exists.
type CreateRealmImportRequest struct {
	SourceKind     string
	UploadS3Key    string
	SourceExportID string
	Password       string
}

func realmExportFromAPI(e *apiclient.RealmExport) RealmExport {
	return RealmExport{
		ID: uuidString(e.Id), ClusterID: uuidString(e.ClusterId), Realm: e.Realm,
		Scope: string(e.Scope), Status: string(e.Status), Progress: int64(e.Progress),
		SourceVersion: nstrN(e.SourceVersion), SHA256Checksum: nstrN(e.Sha256Checksum),
		DownloadURL: nstrN(e.DownloadUrl), ErrorMessage: nstrN(e.ErrorMessage),
		CreatedAt: fmtTime(e.CreatedAt), CompletedAt: ntimeN(e.CompletedAt), ExpiresAt: ntimeN(e.ExpiresAt),
	}
}

func realmImportFromAPI(i *apiclient.RealmImport) RealmImport {
	return RealmImport{
		ID: uuidString(i.Id), ClusterID: uuidString(i.ClusterId), Realm: i.Realm,
		SourceKind: string(i.SourceKind), Status: string(i.Status), Progress: int64(i.Progress),
		SourceVersion: nstrN(i.SourceVersion), TargetVersion: nstrN(i.TargetVersion),
		ErrorMessage: nstrN(i.ErrorMessage),
		CreatedAt:    fmtTime(i.CreatedAt), CompletedAt: ntimeN(i.CompletedAt),
	}
}

// CreateRealmExport starts a realm export (asynchronous). The archive is always
// encrypted, so encryptionPassword is required; the same password is needed to
// import it again.
func (c *Client) CreateRealmExport(ctx context.Context, clusterID, realm, encryptionPassword string) (*RealmExport, error) {
	body := apiclient.CreateRealmExportJSONRequestBody{EncryptionPassword: encryptionPassword}
	resp, err := c.gen.CreateRealmExportWithResponse(ctx, cid(clusterID), realm, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON202 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := realmExportFromAPI(resp.JSON202)
	return &e, nil
}

// GetRealmExport returns a realm export job. Poll until status is completed;
// download_url only appears then, and expires 24h after.
func (c *Client) GetRealmExport(ctx context.Context, exportID string) (*RealmExport, error) {
	resp, err := c.gen.GetRealmExportWithResponse(ctx, uid(exportID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := realmExportFromAPI(resp.JSON200)
	return &e, nil
}

// CreateRealmImportUpload returns a presigned URL to PUT a realm artifact to,
// plus the key to hand back to CreateRealmImport.
func (c *Client) CreateRealmImportUpload(ctx context.Context, clusterID string) (*RealmImportUpload, error) {
	resp, err := c.gen.PresignRealmImportUploadWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return &RealmImportUpload{UploadURL: resp.JSON200.UploadUrl, S3Key: resp.JSON200.S3Key}, nil
}

// CreateRealmImport starts a realm import (asynchronous).
func (c *Client) CreateRealmImport(ctx context.Context, clusterID string, req CreateRealmImportRequest) (*RealmImport, error) {
	body := apiclient.CreateRealmImportJSONRequestBody{}
	if req.SourceKind != "" {
		k := apiclient.RealmImportSourceKind(req.SourceKind)
		body.SourceKind = &k
	}
	if req.UploadS3Key != "" {
		body.UploadS3Key = &req.UploadS3Key
	}
	if req.SourceExportID != "" {
		body.SourceExportId = &req.SourceExportID
	}
	if req.Password != "" {
		body.Password = &req.Password
	}
	resp, err := c.gen.CreateRealmImportWithResponse(ctx, cid(clusterID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON202 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	i := realmImportFromAPI(resp.JSON202)
	return &i, nil
}

// GetRealmImport returns a realm import job. Poll until status settles.
func (c *Client) GetRealmImport(ctx context.Context, importID string) (*RealmImport, error) {
	resp, err := c.gen.GetRealmImportWithResponse(ctx, uid(importID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	i := realmImportFromAPI(resp.JSON200)
	return &i, nil
}

// DownloadThemeContent returns a theme's content archive. Raw bytes, like
// ClusterInsights, because the response is an archive rather than JSON.
func (c *Client) DownloadThemeContent(ctx context.Context, clusterID, themeID string) ([]byte, error) {
	resp, err := c.gen.DownloadThemeContentWithResponse(ctx, cid(clusterID), uid(themeID), nil)
	if err != nil {
		return nil, err
	}
	if resp.HTTPResponse == nil || resp.HTTPResponse.StatusCode != 200 {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return resp.Body, nil
}

// themeArchiveMediaType is what the theme_file part declares. The endpoint
// accepts only these two, and a Keycloakify JAR is a ZIP by format, so the
// filename is the only thing that can tell them apart.
func themeArchiveMediaType(filename string) string {
	if strings.HasSuffix(strings.ToLower(filename), ".jar") {
		return "application/java-archive"
	}
	return "application/zip"
}

// quoteMIMEValue escapes a value for a quoted MIME parameter, as
// mime/multipart does for the filenames it writes itself.
var quoteMIMEValue = strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace

// UpdateThemeContent replaces a theme's archive in place, keeping the theme's
// ID, name and every realm and application assignment pointing at it. It is the
// path that avoids delete-then-re-upload, which detaches the theme and leaves
// the sign-in page unbranded in between.
//
// version is optional: an empty one leaves the recorded label alone rather than
// blanking it, so the part is omitted rather than sent empty.
//
// The multipart body is buffered rather than streamed on purpose. http.Request
// derives GetBody from a *bytes.Reader, and without it the retry transport
// would replay a PUT 503 with an empty body.
func (c *Client) UpdateThemeContent(ctx context.Context, clusterID, themeID, filename string, archive []byte, version string) (*Theme, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="theme_file"; filename="%s"`, quoteMIMEValue(filename)))
	h.Set("Content-Type", themeArchiveMediaType(filename))
	part, err := w.CreatePart(h)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(archive); err != nil {
		return nil, err
	}
	if version != "" {
		if err := w.WriteField("version", version); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	resp, err := c.gen.UpdateThemeContentWithBodyWithResponse(ctx, cid(clusterID), uid(themeID), nil,
		w.FormDataContentType(), bytes.NewReader(body.Bytes()))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	t := themeFromAPI(resp.JSON200)
	return &t, nil
}

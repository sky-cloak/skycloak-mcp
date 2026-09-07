package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListThemesHandler(t *testing.T) {
	api := stubAPI{themes: []skycloak.Theme{
		{ID: "44444444-4444-4444-4444-444444444444", Name: "corporate", Status: "deployed", ThemeTypes: []string{"login", "email"}},
	}}
	res, out, err := listThemesHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Count != 1 || out.Themes[0].Name != "corporate" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestGetThemeAssignmentHandler(t *testing.T) {
	api := stubAPI{assign: &skycloak.ThemeAssignment{Login: "tid"}}
	res, out, err := getThemeAssignmentHandler(api)(context.Background(), nil, RealmRef{ClusterID: "c1", Realm: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Login != "tid" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestSetThemeAssignmentHandler(t *testing.T) {
	res, out, err := setThemeAssignmentHandler(stubAPI{})(context.Background(), nil, SetThemeAssignmentInput{ClusterID: "c1", Realm: "app", Login: "tid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Login != "tid" {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestSetThemeAssignmentRequiresRealm(t *testing.T) {
	res, _, err := setThemeAssignmentHandler(stubAPI{})(context.Background(), nil, SetThemeAssignmentInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result for missing realm")
	}
}

func TestGetBrandingHandlers(t *testing.T) {
	api := stubAPI{login: &skycloak.LoginBranding{PrimaryColor: "#0ea5e9", Status: "applied"}, email: &skycloak.EmailBranding{PrimaryColor: "#111827", Status: "applied"}}
	resL, outL, err := getLoginBrandingHandler(api)(context.Background(), nil, RealmRef{ClusterID: "c1", Realm: "app"})
	if err != nil || resL.IsError || outL.PrimaryColor != "#0ea5e9" {
		t.Fatalf("login branding: err=%v res=%v out=%+v", err, resL.IsError, outL)
	}
	resE, outE, err := getEmailBrandingHandler(api)(context.Background(), nil, RealmRef{ClusterID: "c1", Realm: "app"})
	if err != nil || resE.IsError || outE.PrimaryColor != "#111827" {
		t.Fatalf("email branding: err=%v res=%v out=%+v", err, resE.IsError, outE)
	}
}

// themeContentStub records the calls a content update makes, so a test can
// assert what the tool did NOT do as well as what it did.
type themeContentStub struct {
	stubAPI
	calls    *[]string
	filename *string
	archive  *[]byte
	version  *string
}

func (s themeContentStub) UpdateThemeContent(_ context.Context, clusterID, themeID, filename string, archive []byte, version string) (*skycloak.Theme, error) {
	if s.err != nil {
		return nil, s.err
	}
	*s.calls = append(*s.calls, "UpdateThemeContent "+clusterID+"/"+themeID)
	*s.filename, *s.archive, *s.version = filename, archive, version
	return &skycloak.Theme{ID: themeID, Name: "corporate", Status: "deploying", ThemeTypes: []string{"login", "email"}, Version: version}, nil
}

func (s themeContentStub) DeleteTheme(_ context.Context, _, _ string) error {
	*s.calls = append(*s.calls, "DeleteTheme")
	return nil
}

func (s themeContentStub) UpdateTheme(_ context.Context, _, _, _, _, _ string) (*skycloak.Theme, error) {
	*s.calls = append(*s.calls, "UpdateTheme")
	return &skycloak.Theme{}, nil
}

func (s themeContentStub) SetThemeAssignment(_ context.Context, _, _ string, a skycloak.ThemeAssignment) (*skycloak.ThemeAssignment, error) {
	*s.calls = append(*s.calls, "SetThemeAssignment")
	return &a, nil
}

func newThemeContentStub() (themeContentStub, *[]string, *string, *[]byte, *string) {
	calls, filename, archive, version := &[]string{}, new(string), new([]byte), new(string)
	return themeContentStub{calls: calls, filename: filename, archive: archive, version: version}, calls, filename, archive, version
}

// The point of the content endpoint is that one call replaces the archive: no
// delete, no rename, no reassignment. A tool that reached for any of those
// would take the realm's sign-in page unbranded in between, which is the bug
// this path exists to fix, so assert the absence as well as the update.
func TestUpdateThemeContentReplacesInPlace(t *testing.T) {
	api, calls, filename, archive, version := newThemeContentStub()

	res, out, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID:     "c1",
		ThemeID:       "t1",
		ContentBase64: base64.StdEncoding.EncodeToString([]byte("PK\x03\x04new archive")),
		Filename:      "corporate.zip",
		Version:       "v2.4",
	})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if got := *calls; len(got) != 1 || got[0] != "UpdateThemeContent c1/t1" {
		t.Fatalf("calls = %v, want the content update alone", got)
	}
	if *filename != "corporate.zip" || string(*archive) != "PK\x03\x04new archive" || *version != "v2.4" {
		t.Fatalf("sent filename=%q archive=%q version=%q", *filename, *archive, *version)
	}
	if out.ID != "t1" || out.Status != "deploying" {
		t.Fatalf("out = %+v, want the theme with its ID kept", out)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "assignments") {
		t.Errorf("text does not say the assignments survived: %q", txt)
	}
}

// Callers that pass only the bytes still need a filename, and the media type
// the API demands is derived from it, so the default has to be a ZIP one.
func TestUpdateThemeContentDefaultsTheFilename(t *testing.T) {
	api, _, filename, _, _ := newThemeContentStub()

	res, _, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString([]byte("PK\x03\x04")),
	})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !strings.HasSuffix(*filename, ".zip") {
		t.Fatalf("filename = %q, want a .zip default", *filename)
	}
}

func TestUpdateThemeContentValidatesInput(t *testing.T) {
	zip := base64.StdEncoding.EncodeToString([]byte("PK\x03\x04"))
	cases := []struct {
		name string
		in   UpdateThemeContentInput
		want string
	}{
		{"no cluster", UpdateThemeContentInput{ThemeID: "t1", ContentBase64: zip}, "cluster_id"},
		{"no theme", UpdateThemeContentInput{ClusterID: "c1", ContentBase64: zip}, "theme_id"},
		{"no content", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1"}, "content_base64"},
		{"not base64", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: "not base64!"}, "base64"},
		{"not an archive", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString([]byte("<html>"))}, "ZIP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api, calls, _, _, _ := newThemeContentStub()
			res, _, err := updateThemeContentHandler(api)(context.Background(), nil, tc.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !res.IsError {
				t.Fatalf("expected an error result")
			}
			if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, tc.want) {
				t.Errorf("message %q does not name %q", txt, tc.want)
			}
			if len(*calls) != 0 {
				t.Errorf("calls = %v, want nothing sent for invalid input", *calls)
			}
		})
	}
}

// Base64 from a model or a shell pipeline routinely arrives wrapped, and a
// rejected line break would send the caller round a pointless retry.
func TestUpdateThemeContentAcceptsWrappedBase64(t *testing.T) {
	api, _, _, archive, _ := newThemeContentStub()
	raw := []byte("PK\x03\x04a slightly longer archive body")
	wrapped := base64.StdEncoding.EncodeToString(raw)
	wrapped = wrapped[:8] + "\n" + wrapped[8:16] + "\r\n " + wrapped[16:]

	res, _, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID: "c1", ThemeID: "t1", ContentBase64: wrapped,
	})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !bytes.Equal(*archive, raw) {
		t.Fatalf("archive = %q, want the unwrapped bytes", *archive)
	}
}

// The endpoint caps the body at 50 MB. Refusing locally beats spending the
// upload to be told, and the message has to say the limit so the caller can
// act. Tested through the helper so the case costs no 50 MB allocation.
func TestDecodeThemeArchiveRefusesAnOversizedArchive(t *testing.T) {
	content := base64.StdEncoding.EncodeToString([]byte("PK\x03\x04 padding padding"))
	if _, err := decodeThemeArchive(content, 8); err == nil {
		t.Fatal("expected an error for an archive over the limit")
	} else if !strings.Contains(err.Error(), "8") {
		t.Errorf("error %q does not state the limit", err)
	}
}

func TestUpdateThemeContentSurfacesAPIErrors(t *testing.T) {
	api, _, _, _, _ := newThemeContentStub()
	api.stubAPI = stubAPI{err: errors.New("theme content is pinned")}

	res, _, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString([]byte("PK\x03\x04")),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "pinned") {
		t.Fatalf("res = %+v, want the API's reason surfaced", res)
	}
}

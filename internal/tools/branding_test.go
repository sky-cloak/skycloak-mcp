package tools

import (
	"archive/zip"
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

// themeZIP builds a real archive, because the tool now reads the central
// directory rather than trusting a "PK" prefix. Padding makes the bytes long
// enough for the tests that slice the encoded form.
func themeZIP(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("theme/login/theme.properties")
	if err != nil {
		t.Fatalf("creating the zip entry: %v", err)
	}
	if _, err := w.Write([]byte("parent=keycloak\n")); err != nil {
		t.Fatalf("writing the zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("closing the zip: %v", err)
	}
	return buf.Bytes()
}

// The point of the content endpoint is that one call replaces the archive: no
// delete, no rename, no reassignment. A tool that reached for any of those
// would take the realm's sign-in page unbranded in between, which is the bug
// this path exists to fix, so assert the absence as well as the update.
func TestUpdateThemeContentReplacesInPlace(t *testing.T) {
	api, calls, filename, archive, version := newThemeContentStub()
	raw := themeZIP(t)

	res, out, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID:     "c1",
		ThemeID:       "t1",
		ContentBase64: base64.StdEncoding.EncodeToString(raw),
		Filename:      "corporate.zip",
		Version:       "v2.4",
		Confirm:       true,
	})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if got := *calls; len(got) != 1 || got[0] != "UpdateThemeContent c1/t1" {
		t.Fatalf("calls = %v, want the content update alone", got)
	}
	if *filename != "corporate.zip" || !bytes.Equal(*archive, raw) || *version != "v2.4" {
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
		ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString(themeZIP(t)), Confirm: true,
	})
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	if !strings.HasSuffix(*filename, ".zip") {
		t.Fatalf("filename = %q, want a .zip default", *filename)
	}
}

// Replacing the archive discards the current one for good, so the tool obeys
// the same confirm=true contract as the other destructive tools: without it,
// nothing reaches the API.
func TestUpdateThemeContentRequiresConfirmation(t *testing.T) {
	api, calls, _, _, _ := newThemeContentStub()

	res, _, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString(themeZIP(t)),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result without confirm=true")
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "confirm=true") {
		t.Errorf("message %q does not say how to confirm", txt)
	}
	if len(*calls) != 0 {
		t.Errorf("calls = %v, want nothing sent without confirmation", *calls)
	}
}

func TestUpdateThemeContentValidatesInput(t *testing.T) {
	archive := base64.StdEncoding.EncodeToString(themeZIP(t))
	var empty bytes.Buffer
	if err := zip.NewWriter(&empty).Close(); err != nil {
		t.Fatalf("building the empty zip: %v", err)
	}
	cases := []struct {
		name string
		in   UpdateThemeContentInput
		want string
	}{
		{"no cluster", UpdateThemeContentInput{ThemeID: "t1", ContentBase64: archive, Confirm: true}, "cluster_id"},
		{"no theme", UpdateThemeContentInput{ClusterID: "c1", ContentBase64: archive, Confirm: true}, "theme_id"},
		{"no content", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", Confirm: true}, "content_base64"},
		{"not base64", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: "not base64!", Confirm: true}, "base64"},
		{"not an archive", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString([]byte("<html>")), Confirm: true}, "ZIP"},
		// A "PK" prefix is what a two-byte check would have accepted.
		{"only looks like an archive", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString([]byte("PKnot-a-zip")), Confirm: true}, "ZIP"},
		{"truncated archive", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString(themeZIP(t)[:20]), Confirm: true}, "ZIP"},
		{"empty archive", UpdateThemeContentInput{ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString(empty.Bytes()), Confirm: true}, "empty"},
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
	raw := themeZIP(t)
	wrapped := base64.StdEncoding.EncodeToString(raw)
	wrapped = wrapped[:8] + "\n" + wrapped[8:16] + "\r\n " + wrapped[16:]

	res, _, err := updateThemeContentHandler(api)(context.Background(), nil, UpdateThemeContentInput{
		ClusterID: "c1", ThemeID: "t1", ContentBase64: wrapped, Confirm: true,
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
	content := base64.StdEncoding.EncodeToString(themeZIP(t))
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
		ClusterID: "c1", ThemeID: "t1", ContentBase64: base64.StdEncoding.EncodeToString(themeZIP(t)), Confirm: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "pinned") {
		t.Fatalf("res = %+v, want the API's reason surfaced", res)
	}
}

func TestGetThemeSettingsHandler(t *testing.T) {
	api := stubAPI{themeSettings: &skycloak.ThemeSettings{ExactThemeNames: true}}
	res, out, err := getThemeSettingsHandler(api)(context.Background(), nil, NoInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || !out.ExactThemeNames {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
}

func TestUpdateThemeSettingsHandler(t *testing.T) {
	res, out, err := updateThemeSettingsHandler(stubAPI{})(context.Background(), nil, UpdateThemeSettingsInput{ExactThemeNames: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || !out.ExactThemeNames {
		t.Fatalf("unexpected: err=%v out=%+v", res.IsError, out)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "restart_required") {
		t.Errorf("turning exact_theme_names on should mention restart_required, got %q", txt)
	}
}

func TestUpdateThemeSettingsHandlerSurfacesForbidden(t *testing.T) {
	api := stubAPI{err: errors.New("key has no user, or user is not a workspace owner or admin")}
	res, _, err := updateThemeSettingsHandler(api)(context.Background(), nil, UpdateThemeSettingsInput{ExactThemeNames: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "workspace owner or admin") {
		t.Fatalf("res = %+v, want the API's reason surfaced", res)
	}
}

// list_themes and get_theme are curated structs, not passthrough, so
// restart_required has to be mapped through explicitly or it silently drops.
func TestListAndGetThemeSurfaceRestartRequired(t *testing.T) {
	api := stubAPI{
		themes: []skycloak.Theme{{ID: "t1", Name: "corporate", Status: "deployed", RestartRequired: true}},
		theme:  &skycloak.Theme{ID: "t1", Name: "corporate", Status: "deployed", RestartRequired: true},
	}
	_, listOut, err := listThemesHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listOut.Themes[0].RestartRequired {
		t.Fatalf("list_themes dropped restart_required: %+v", listOut.Themes[0])
	}
	getRes, getOut, err := getThemeHandler(api)(context.Background(), nil, ThemeRef{ClusterID: "c1", ThemeID: "t1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !getOut.RestartRequired {
		t.Fatalf("get_theme dropped restart_required: %+v", getOut)
	}
	if txt := getRes.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "restart_required=true") {
		t.Errorf("get_theme text should flag restart_required, got %q", txt)
	}
}

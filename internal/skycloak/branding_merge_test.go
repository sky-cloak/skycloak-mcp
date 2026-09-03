package skycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The branding endpoints are PUT, and the API resets any field the body omits
// back to its own default rather than leaving it alone. A tool that can only
// send a few fields therefore erases the rest: change one colour and the realm
// loses its favicon, its policy links and its "powered by" choice. These cover
// the read-merge-write that keeps a partial update partial.

const fullLoginBranding = `{
	"cluster_id":"11111111-1111-1111-1111-111111111111","realm":"app",
	"primary_color":"#111111","background_color":"#222222",
	"logo_url":"https://x/logo.png","favicon_url":"https://x/fav.ico","font_url":"https://x/f.woff2",
	"registration_enabled":false,"remember_me_enabled":false,"forgot_password_enabled":false,
	"terms_of_service_url":"https://x/tos","privacy_policy_url":"https://x/privacy",
	"show_powered_by":false,
	"sso":{"enabled":false,"layout":"horizontal","display_style":"logo_only","button_size":"large"},
	"internationalization":{"enabled":true,"default_locale":"fr","supported_locales":["fr","en"],
		"language_selection_mode":"manual","language_selector_position":"top-left","language_selector_style":"list"},
	"status":"applied","created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z"
}`

// brandingServer answers the GET with getStatus/getBody and records the PUT.
func brandingServer(t *testing.T, getStatus int, getBody string) (*httptest.Server, *map[string]any, *bool) {
	t.Helper()
	var put map[string]any
	sawPut := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			writeJSON(w, getStatus, getBody)
			return
		}
		sawPut = true
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &put)
		writeJSON(w, 200, `{"cluster_id":"11111111-1111-1111-1111-111111111111","realm":"app","status":"pending","created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z"}`)
	}))
	t.Cleanup(srv.Close)
	return srv, &put, &sawPut
}

func TestUpsertLoginBrandingKeepsFieldsTheCallerDidNotSend(t *testing.T) {
	srv, put, _ := brandingServer(t, 200, fullLoginBranding)
	newColor := "#ff0000"
	if _, err := newTestClient(srv.URL).UpsertLoginBranding(context.Background(), cuid, "app",
		UpsertLoginBrandingRequest{PrimaryColor: &newColor}); err != nil {
		t.Fatalf("UpsertLoginBranding: %v", err)
	}
	body := *put
	if body["primary_color"] != "#ff0000" {
		t.Fatalf("primary_color = %v, want the new value", body["primary_color"])
	}
	for k, want := range map[string]any{
		"background_color": "#222222", "logo_url": "https://x/logo.png",
		"favicon_url": "https://x/fav.ico", "font_url": "https://x/f.woff2",
		"registration_enabled": false, "remember_me_enabled": false, "forgot_password_enabled": false,
		"terms_of_service_url": "https://x/tos", "privacy_policy_url": "https://x/privacy",
		"show_powered_by": false,
	} {
		if body[k] != want {
			t.Errorf("%s = %v, want %v (it was not sent, so it must survive)", k, body[k], want)
		}
	}
	sso, _ := body["sso"].(map[string]any)
	if sso == nil || sso["enabled"] != false || sso["layout"] != "horizontal" {
		t.Errorf("sso = %v, want the existing config carried through", body["sso"])
	}
	i18n, _ := body["internationalization"].(map[string]any)
	if i18n == nil || i18n["default_locale"] != "fr" {
		t.Errorf("internationalization = %v, want the existing config carried through", body["internationalization"])
	}
}

// A realm with no branding yet has nothing to merge, so the call still has to
// work as a plain create.
func TestUpsertLoginBrandingCreatesWhenNoneExists(t *testing.T) {
	srv, put, sawPut := brandingServer(t, 404, `{"title":"not found"}`)
	color := "#ff0000"
	if _, err := newTestClient(srv.URL).UpsertLoginBranding(context.Background(), cuid, "app",
		UpsertLoginBrandingRequest{PrimaryColor: &color}); err != nil {
		t.Fatalf("UpsertLoginBranding: %v", err)
	}
	if !*sawPut {
		t.Fatalf("expected the create to be attempted")
	}
	if (*put)["primary_color"] != "#ff0000" {
		t.Fatalf("primary_color = %v", (*put)["primary_color"])
	}
}

// If the current config cannot be read, writing anyway would erase whatever is
// there. Failing is the only safe answer.
func TestUpsertLoginBrandingDoesNotWriteWhenCurrentIsUnreadable(t *testing.T) {
	srv, _, sawPut := brandingServer(t, 500, `{"title":"boom"}`)
	color := "#ff0000"
	_, err := newTestClient(srv.URL).UpsertLoginBranding(context.Background(), cuid, "app",
		UpsertLoginBrandingRequest{PrimaryColor: &color})
	if err == nil {
		t.Fatalf("expected an error when the existing branding cannot be read")
	}
	if *sawPut {
		t.Fatalf("a failed read must not be followed by a write: it would erase the realm's branding")
	}
}

const fullEmailBranding = `{
	"cluster_id":"11111111-1111-1111-1111-111111111111","realm":"app",
	"primary_color":"#111111","header_logo_light_url":"https://x/l.png","header_logo_dark_url":"https://x/d.png",
	"company_url":"https://x","footer_company_name":"Acme","footer_text":"All rights reserved",
	"internationalization":{"enabled":true,"default_locale":"fr","supported_locales":["fr","en"]},
	"status":"applied","created_at":"2026-09-01T00:00:00Z","updated_at":"2026-09-01T00:00:00Z"
}`

func TestUpsertEmailBrandingKeepsFieldsTheCallerDidNotSend(t *testing.T) {
	srv, put, _ := brandingServer(t, 200, fullEmailBranding)
	name := "Acme Inc"
	if _, err := newTestClient(srv.URL).UpsertEmailBranding(context.Background(), cuid, "app",
		UpsertEmailBrandingRequest{FooterCompanyName: &name}); err != nil {
		t.Fatalf("UpsertEmailBranding: %v", err)
	}
	body := *put
	if body["footer_company_name"] != "Acme Inc" {
		t.Fatalf("footer_company_name = %v", body["footer_company_name"])
	}
	for k, want := range map[string]any{
		"primary_color": "#111111", "header_logo_light_url": "https://x/l.png",
		"header_logo_dark_url": "https://x/d.png", "company_url": "https://x",
		"footer_text": "All rights reserved",
	} {
		if body[k] != want {
			t.Errorf("%s = %v, want %v", k, body[k], want)
		}
	}
	if i18n, _ := body["internationalization"].(map[string]any); i18n == nil || i18n["default_locale"] != "fr" {
		t.Errorf("internationalization = %v", body["internationalization"])
	}
}

func TestUpsertEmailBrandingDoesNotWriteWhenCurrentIsUnreadable(t *testing.T) {
	// 500 rather than 503: the latter is retryable, so the client would spend the
	// whole backoff budget before failing. retry_test.go covers that path.
	srv, _, sawPut := brandingServer(t, 500, `{"title":"boom"}`)
	name := "Acme"
	if _, err := newTestClient(srv.URL).UpsertEmailBranding(context.Background(), cuid, "app",
		UpsertEmailBrandingRequest{FooterCompanyName: &name}); err == nil {
		t.Fatalf("expected an error")
	}
	if *sawPut {
		t.Fatalf("a failed read must not be followed by a write")
	}
}

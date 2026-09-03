package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

type brandingRecorder struct {
	stubAPI
	login skycloak.UpsertLoginBrandingRequest
	email skycloak.UpsertEmailBrandingRequest
}

func (r *brandingRecorder) UpsertLoginBranding(_ context.Context, _, _ string, req skycloak.UpsertLoginBrandingRequest) (*skycloak.LoginBranding, error) {
	r.login = req
	return &skycloak.LoginBranding{Status: "pending"}, nil
}

func (r *brandingRecorder) UpsertEmailBranding(_ context.Context, _, _ string, req skycloak.UpsertEmailBrandingRequest) (*skycloak.EmailBranding, error) {
	r.email = req
	return &skycloak.EmailBranding{Status: "pending"}, nil
}

func str(v *string) string {
	if v == nil {
		return "<nil>"
	}
	return *v
}

func boolp(v *bool) string {
	if v == nil {
		return "<nil>"
	}
	if *v {
		return "true"
	}
	return "false"
}

// Every field the API accepts has to be reachable, otherwise a caller who wants
// one of them has no way to set it and the merge quietly keeps the old value.
func TestUpsertLoginBrandingForwardsEveryField(t *testing.T) {
	rec := &brandingRecorder{}
	no := false
	in := UpsertLoginBrandingInput{
		ClusterID: "c1", Realm: "app",
		PrimaryColor: "#111", BackgroundColor: "#222", LogoURL: "https://x/l.png",
		FaviconURL: "https://x/f.ico", FontURL: "https://x/f.woff2",
		TermsOfServiceURL: "https://x/tos", PrivacyPolicyURL: "https://x/p",
		RegistrationEnabled: &no, RememberMeEnabled: &no, ForgotPasswordEnabled: &no, ShowPoweredBy: &no,
	}
	if res, _, err := upsertLoginBrandingHandler(rec)(context.Background(), nil, in); err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v isErr=%v", err, res.IsError)
	}
	got := rec.login
	for name, pair := range map[string][2]string{
		"primary_color":        {str(got.PrimaryColor), "#111"},
		"background_color":     {str(got.BackgroundColor), "#222"},
		"logo_url":             {str(got.LogoURL), "https://x/l.png"},
		"favicon_url":          {str(got.FaviconURL), "https://x/f.ico"},
		"font_url":             {str(got.FontURL), "https://x/f.woff2"},
		"terms_of_service_url": {str(got.TermsOfServiceURL), "https://x/tos"},
		"privacy_policy_url":   {str(got.PrivacyPolicyURL), "https://x/p"},
		"registration_enabled": {boolp(got.RegistrationEnabled), "false"},
		"remember_me_enabled":  {boolp(got.RememberMeEnabled), "false"},
		"forgot_password":      {boolp(got.ForgotPasswordEnabled), "false"},
		"show_powered_by":      {boolp(got.ShowPoweredBy), "false"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %s, want %s", name, pair[0], pair[1])
		}
	}
}

// An omitted string must stay nil rather than becoming "", which the merge
// would write over the realm's existing value.
func TestUpsertLoginBrandingLeavesOmittedFieldsNil(t *testing.T) {
	rec := &brandingRecorder{}
	in := UpsertLoginBrandingInput{ClusterID: "c1", Realm: "app", PrimaryColor: "#111"}
	if _, _, err := upsertLoginBrandingHandler(rec)(context.Background(), nil, in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := rec.login
	for name, p := range map[string]*string{
		"background_color": got.BackgroundColor, "logo_url": got.LogoURL, "favicon_url": got.FaviconURL,
		"font_url": got.FontURL, "terms_of_service_url": got.TermsOfServiceURL, "privacy_policy_url": got.PrivacyPolicyURL,
	} {
		if p != nil {
			t.Errorf("%s = %q, want nil so the merge keeps the current value", name, *p)
		}
	}
	for name, p := range map[string]*bool{
		"registration_enabled": got.RegistrationEnabled, "remember_me_enabled": got.RememberMeEnabled,
		"forgot_password_enabled": got.ForgotPasswordEnabled, "show_powered_by": got.ShowPoweredBy,
	} {
		if p != nil {
			t.Errorf("%s = %v, want nil", name, *p)
		}
	}
}

func TestUpsertEmailBrandingForwardsEveryField(t *testing.T) {
	rec := &brandingRecorder{}
	in := UpsertEmailBrandingInput{
		ClusterID: "c1", Realm: "app",
		PrimaryColor: "#111", HeaderLogoLightURL: "https://x/l.png", HeaderLogoDarkURL: "https://x/d.png",
		CompanyURL: "https://x", FooterCompanyName: "Acme", FooterText: "hi",
	}
	if res, _, err := upsertEmailBrandingHandler(rec)(context.Background(), nil, in); err != nil || res.IsError {
		t.Fatalf("unexpected failure: err=%v isErr=%v", err, res.IsError)
	}
	got := rec.email
	for name, pair := range map[string][2]string{
		"primary_color":         {str(got.PrimaryColor), "#111"},
		"header_logo_light_url": {str(got.HeaderLogoLightURL), "https://x/l.png"},
		"header_logo_dark_url":  {str(got.HeaderLogoDarkURL), "https://x/d.png"},
		"company_url":           {str(got.CompanyURL), "https://x"},
		"footer_company_name":   {str(got.FooterCompanyName), "Acme"},
		"footer_text":           {str(got.FooterText), "hi"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %s, want %s", name, pair[0], pair[1])
		}
	}
}

func TestUpsertEmailBrandingLeavesOmittedFieldsNil(t *testing.T) {
	rec := &brandingRecorder{}
	in := UpsertEmailBrandingInput{ClusterID: "c1", Realm: "app", FooterCompanyName: "Acme"}
	if _, _, err := upsertEmailBrandingHandler(rec)(context.Background(), nil, in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := rec.email
	for name, p := range map[string]*string{
		"primary_color": got.PrimaryColor, "header_logo_light_url": got.HeaderLogoLightURL,
		"header_logo_dark_url": got.HeaderLogoDarkURL, "company_url": got.CompanyURL, "footer_text": got.FooterText,
	} {
		if p != nil {
			t.Errorf("%s = %q, want nil", name, *p)
		}
	}
}

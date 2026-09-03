package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// appRecorder keeps the request the handler built, so a test can assert on what
// would reach the API rather than on the handler's own return value.
type appRecorder struct {
	stubAPI
	got    skycloak.CreateApplicationRequest
	called bool
}

func (r *appRecorder) CreateApplication(_ context.Context, _, _ string, req skycloak.CreateApplicationRequest) (string, string, error) {
	r.got = req
	r.called = true
	return req.ClientID, "s3cret", nil
}

func createApp(t *testing.T, in CreateApplicationInput) (*appRecorder, bool) {
	t.Helper()
	rec := &appRecorder{}
	res, _, err := createApplicationHandler(rec)(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return rec, res.IsError
}

func base(in CreateApplicationInput) CreateApplicationInput {
	in.ClusterID, in.Realm, in.ClientID = "c1", "app", "web"
	return in
}

// The API rejects an OIDC client with no grant types, so omitting the parameter
// has to mean the common flow rather than an empty list.
func TestCreateApplicationDefaultsToAuthorizationCode(t *testing.T) {
	rec, isErr := createApp(t, base(CreateApplicationInput{RedirectURIs: []string{"https://a/cb"}}))
	if isErr {
		t.Fatalf("expected success")
	}
	if got := rec.got.GrantTypes; len(got) != 1 || got[0] != "authorization_code" {
		t.Fatalf("grant types = %v, want [authorization_code]", got)
	}
}

func TestCreateApplicationForwardsAndCanonicalisesGrantTypes(t *testing.T) {
	rec, isErr := createApp(t, base(CreateApplicationInput{GrantTypes: []string{"Client_Credentials", "REFRESH_TOKEN"}}))
	if isErr {
		t.Fatalf("expected success: client_credentials needs no redirect URI")
	}
	want := []string{"client_credentials", "refresh_token"}
	if got := rec.got.GrantTypes; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("grant types = %v, want %v", got, want)
	}
}

// The default grant makes redirect URIs mandatory, so a caller who supplied
// neither would otherwise get an API error about a parameter they never sent.
func TestCreateApplicationRejectsCodeFlowWithoutRedirectURIs(t *testing.T) {
	for _, grants := range [][]string{nil, {"authorization_code"}, {"implicit"}, {"refresh_token", "Implicit"}} {
		rec, isErr := createApp(t, base(CreateApplicationInput{GrantTypes: grants}))
		if !isErr {
			t.Fatalf("grants %v: expected an error without redirect URIs", grants)
		}
		if rec.called {
			t.Fatalf("grants %v: request should not reach the API", grants)
		}
	}
}

func TestCreateApplicationRedirectErrorNamesTheParameter(t *testing.T) {
	rec := &appRecorder{}
	res, _, err := createApplicationHandler(rec)(context.Background(), nil, base(CreateApplicationInput{}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	for _, want := range []string{"redirect_uris", "authorization_code"} {
		if !strings.Contains(text, want) {
			t.Fatalf("message %q does not mention %q", text, want)
		}
	}
}

// SAML clients carry no grant types at all; defaulting one in would send a
// field the protocol has no use for.
func TestCreateApplicationSAMLSendsNoGrantTypes(t *testing.T) {
	rec, isErr := createApp(t, base(CreateApplicationInput{Protocol: "SAML"}))
	if isErr {
		t.Fatalf("expected success for SAML without redirect URIs")
	}
	if len(rec.got.GrantTypes) != 0 {
		t.Fatalf("grant types = %v, want none for SAML", rec.got.GrantTypes)
	}
}

package skycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The tool-level tests stop at CreateApplicationRequest. This one reads the
// body actually put on the wire, which is where the grant types were being
// dropped: the field was built as an empty slice regardless of the request.
func TestCreateApplicationSendsGrantTypes(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 201, `{"client_id":"web","client_secret":"s3cret"}`)
	}))
	defer srv.Close()

	_, _, err := newTestClient(srv.URL).CreateApplication(context.Background(), cuid, "app", CreateApplicationRequest{
		ClientID:     "web",
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		RedirectURIs: []string{"https://a/cb"},
	})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	got, _ := body["grant_types"].([]any)
	if len(got) != 2 || got[0] != "authorization_code" || got[1] != "refresh_token" {
		t.Fatalf("grant_types on the wire = %v, want [authorization_code refresh_token]", body["grant_types"])
	}
}

// The field is not omitempty in the generated client, so a SAML app still sends
// the key; it has to be an empty list rather than null, which the API rejects.
func TestCreateApplicationSendsEmptyGrantTypesWhenNoneGiven(t *testing.T) {
	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		writeJSON(w, 201, `{"client_id":"web"}`)
	}))
	defer srv.Close()

	if _, _, err := newTestClient(srv.URL).CreateApplication(context.Background(), cuid, "app", CreateApplicationRequest{ClientID: "web"}); err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatalf("body: %v", err)
	}
	if string(body["grant_types"]) != "[]" {
		t.Fatalf("grant_types = %s, want []", body["grant_types"])
	}
}

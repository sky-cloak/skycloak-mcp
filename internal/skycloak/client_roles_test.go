package skycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const clientRoleBody = `{"name":"invoices-read","client_id":"web","client_uuid":"9a1f0f0e-1b2c-4d3e-8f5a-6b7c8d9e0f11","description":"Read invoices","id":"r1","composite":false}`

func roleServer(t *testing.T, status int, body string) (*httptest.Server, *string, *map[string]any) {
	t.Helper()
	method := ""
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method + " " + r.URL.Path
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &sent)
		}
		writeJSON(w, status, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &method, &sent
}

func TestCreateClientRoleSendsNameAndDescription(t *testing.T) {
	srv, method, sent := roleServer(t, 201, clientRoleBody)
	role, err := newTestClient(srv.URL).CreateClientRole(context.Background(), cuid, "app", "web",
		ClientRoleRequest{Name: "invoices-read", Description: "Read invoices"})
	if err != nil {
		t.Fatalf("CreateClientRole: %v", err)
	}
	if (*sent)["name"] != "invoices-read" || (*sent)["description"] != "Read invoices" {
		t.Fatalf("body = %v", *sent)
	}
	if role.Name != "invoices-read" || role.ClientID != "web" || role.Description != "Read invoices" {
		t.Fatalf("mapped role = %+v", role)
	}
	// The role's own Keycloak id is what a caller needs to act on it later.
	if role.ID != "r1" || role.ClientUUID != "9a1f0f0e-1b2c-4d3e-8f5a-6b7c8d9e0f11" {
		t.Errorf("identifiers dropped: %+v", role)
	}
	if *method != "POST /clusters/"+cuid+"/realms/app/clients/web/roles" {
		t.Errorf("unexpected request: %s", *method)
	}
}

// An omitted field must not be sent as an empty string: the update is a patch,
// and blanking a description the caller never mentioned loses it.
func TestUpdateClientRoleOmitsFieldsTheCallerLeftOut(t *testing.T) {
	srv, _, sent := roleServer(t, 200, clientRoleBody)
	if _, err := newTestClient(srv.URL).UpdateClientRole(context.Background(), cuid, "app", "web", "invoices-read",
		ClientRoleRequest{Name: "invoices-reader"}); err != nil {
		t.Fatalf("UpdateClientRole: %v", err)
	}
	if (*sent)["name"] != "invoices-reader" {
		t.Fatalf("name not sent: %v", *sent)
	}
	if _, present := (*sent)["description"]; present {
		t.Fatalf("description was sent though the caller omitted it: %v", *sent)
	}
}

func TestGetClientRoleMapsTheRole(t *testing.T) {
	srv, method, _ := roleServer(t, 200, clientRoleBody)
	role, err := newTestClient(srv.URL).GetClientRole(context.Background(), cuid, "app", "web", "invoices-read")
	if err != nil {
		t.Fatalf("GetClientRole: %v", err)
	}
	if role.Name != "invoices-read" || role.Description != "Read invoices" {
		t.Fatalf("mapped role = %+v", role)
	}
	if *method != "GET /clusters/"+cuid+"/realms/app/clients/web/roles/invoices-read" {
		t.Errorf("unexpected request: %s", *method)
	}
}

func TestDeleteClientRoleReportsFailure(t *testing.T) {
	srv, _, _ := roleServer(t, 404, `{"title":"not found"}`)
	if err := newTestClient(srv.URL).DeleteClientRole(context.Background(), cuid, "app", "web", "gone"); err == nil {
		t.Fatal("expected an error on 404")
	}
	srv2, method, _ := roleServer(t, 204, ``)
	if err := newTestClient(srv2.URL).DeleteClientRole(context.Background(), cuid, "app", "web", "invoices-read"); err != nil {
		t.Fatalf("DeleteClientRole: %v", err)
	}
	if *method != "DELETE /clusters/"+cuid+"/realms/app/clients/web/roles/invoices-read" {
		t.Errorf("unexpected request: %s", *method)
	}
}

// Creation is the only call that reports whether default branding landed, so a
// realm that was merely read must not claim it was skipped.
func TestCreateRealmReportsWhetherDefaultBrandingApplied(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *bool
	}{
		{"applied", `{"name":"r","display_name":"R","enabled":true,"ssl_required":"external","registration_allowed":false,"registration_email_as_username":false,"login_with_email_allowed":true,"duplicate_emails_allowed":false,"default_branding_applied":true}`, boolPtr(true)},
		{"skipped", `{"name":"r","display_name":"R","enabled":true,"ssl_required":"external","registration_allowed":false,"registration_email_as_username":false,"login_with_email_allowed":true,"duplicate_emails_allowed":false,"default_branding_applied":false}`, boolPtr(false)},
		{"absent", `{"name":"r","display_name":"R","enabled":true,"ssl_required":"external","registration_allowed":false,"registration_email_as_username":false,"login_with_email_allowed":true,"duplicate_emails_allowed":false}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := roleServer(t, 201, tc.body)
			r, err := newTestClient(srv.URL).CreateRealm(context.Background(), cuid, Realm{Name: "r"})
			if err != nil {
				t.Fatalf("CreateRealm: %v", err)
			}
			switch {
			case tc.want == nil && r.DefaultBrandingApplied != nil:
				t.Fatalf("got %v, want nil when the API says nothing", *r.DefaultBrandingApplied)
			case tc.want != nil && r.DefaultBrandingApplied == nil:
				t.Fatalf("got nil, want %v", *tc.want)
			case tc.want != nil && *r.DefaultBrandingApplied != *tc.want:
				t.Fatalf("got %v, want %v", *r.DefaultBrandingApplied, *tc.want)
			}
			if r.Name != "r" {
				t.Errorf("name = %q", r.Name)
			}
		})
	}
}

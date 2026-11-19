package skycloak

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// These three endpoints are PATCH with every property optional, so an omitted
// field keeps its stored value and the client must not invent one. Sending
// enabled or allow_admin_access unasked is what disabled a user, a realm or the
// admin console on a partial update. Asserted at the wire, because a pointer
// that is dereferenced into the body too early still type-checks.

// patchRecorder answers a PATCH with resp and records the decoded body.
func patchRecorder(t *testing.T, resp string) (*httptest.Server, *map[string]any) {
	t.Helper()
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		writeJSON(w, 200, resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &body
}

// checkPatchedBool asserts a key is absent for a nil want and carries the exact
// value otherwise.
func checkPatchedBool(t *testing.T, body map[string]any, key string, want *bool) {
	t.Helper()
	got, present := body[key]
	switch {
	case want == nil && present:
		t.Errorf("%s = %v was sent; an omitted field must stay out of the PATCH so the stored value survives", key, got)
	case want != nil && !present:
		t.Errorf("%s was not sent, want %v", key, *want)
	case want != nil && present && got != any(*want):
		t.Errorf("%s = %v, want %v", key, got, *want)
	}
}

const realmUserResponse = `{"id":"u1","username":"jdoe","email":"j@x.com","enabled":true,"email_verified":true}`

func TestUpdateRealmUserSendsOnlyTheBooleansGiven(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		enabled, emailVerified *bool
	}{
		{name: "omitted"},
		{name: "explicit false", enabled: ptrTo(false), emailVerified: ptrTo(false)},
		{name: "explicit true", enabled: ptrTo(true), emailVerified: ptrTo(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, body := patchRecorder(t, realmUserResponse)
			if _, err := newTestClient(srv.URL).UpdateRealmUser(context.Background(), cuid, "app", "u1",
				"j@x.com", "", "", tc.enabled, tc.emailVerified); err != nil {
				t.Fatalf("UpdateRealmUser: %v", err)
			}
			checkPatchedBool(t, *body, "enabled", tc.enabled)
			checkPatchedBool(t, *body, "email_verified", tc.emailVerified)
		})
	}
}

const realmResponse = `{"id":"44444444-4444-4444-4444-444444444444","name":"app","display_name":"App","enabled":true}`

func TestUpdateRealmSendsOnlyTheBooleanGiven(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled *bool
	}{
		{name: "omitted"},
		{name: "explicit false", enabled: ptrTo(false)},
		{name: "explicit true", enabled: ptrTo(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, body := patchRecorder(t, realmResponse)
			if _, err := newTestClient(srv.URL).UpdateRealm(context.Background(), cuid, "app", "App", tc.enabled); err != nil {
				t.Fatalf("UpdateRealm: %v", err)
			}
			checkPatchedBool(t, *body, "enabled", tc.enabled)
		})
	}
}

const domainRouteResponse = `{"id":"55555555-5555-5555-5555-555555555555","realm":"app","allow_admin_access":true,"hide_realm_path":false}`

func TestUpdateDomainRouteSendsOnlyTheBooleanGiven(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin *bool
	}{
		{name: "omitted"},
		{name: "explicit false", admin: ptrTo(false)},
		{name: "explicit true", admin: ptrTo(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, body := patchRecorder(t, domainRouteResponse)
			if _, err := newTestClient(srv.URL).UpdateDomainRoute(context.Background(), cuid,
				"66666666-6666-6666-6666-666666666666", "55555555-5555-5555-5555-555555555555", tc.admin, nil); err != nil {
				t.Fatalf("UpdateDomainRoute: %v", err)
			}
			checkPatchedBool(t, *body, "allow_admin_access", tc.admin)
		})
	}
}

func ptrTo[T any](v T) *T { return &v }

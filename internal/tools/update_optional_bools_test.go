package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// The three update tools below can lock people out: a user, a whole realm or
// the admin console behind a custom domain. Their booleans are pointers so the
// handler can tell "the caller left this out" apart from "the caller sent
// false"; only the latter may reach the API. recordingAPI captures what each
// handler forwards, which the shared stub cannot show because it collapses a
// nil pointer into a plain bool.
type recordingAPI struct {
	stubAPI
	userEnabled       *bool
	userEmailVerified *bool
	realmEnabled      *bool
	realmFrontendURL  *string
	routeAdminAccess  *bool
}

func (r *recordingAPI) UpdateRealmUser(ctx context.Context, clusterID, realm, userID, email, firstName, lastName string, enabled, emailVerified *bool) (*skycloak.RealmUser, error) {
	r.userEnabled, r.userEmailVerified = enabled, emailVerified
	return r.stubAPI.UpdateRealmUser(ctx, clusterID, realm, userID, email, firstName, lastName, enabled, emailVerified)
}

func (r *recordingAPI) UpdateRealm(ctx context.Context, clusterID, realm, displayName string, enabled *bool, frontendURL *string) (*skycloak.Realm, error) {
	r.realmEnabled, r.realmFrontendURL = enabled, frontendURL
	return r.stubAPI.UpdateRealm(ctx, clusterID, realm, displayName, enabled, frontendURL)
}

func (r *recordingAPI) UpdateDomainRoute(ctx context.Context, clusterID, domainID, routeID string, allowAdminAccess *bool, cors []string) (*skycloak.DomainRoute, error) {
	r.routeAdminAccess = allowAdminAccess
	return r.stubAPI.UpdateDomainRoute(ctx, clusterID, domainID, routeID, allowAdminAccess, cors)
}

// checkBool reads the expectation the same way for all three tools: a nil want
// means the field must not travel at all.
func checkBool(t *testing.T, field string, got, want *bool) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s = %v, want it left out so the current value survives", field, *got)
	case want != nil && got == nil:
		t.Errorf("%s was left out, want %v forwarded", field, *want)
	case want != nil && got != nil && *got != *want:
		t.Errorf("%s = %v, want %v", field, *got, *want)
	}
}

func TestUpdateRealmUserForwardsOnlyTheBooleansTheCallerSent(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		enabled, emailVerified    *bool
		wantEnabled, wantVerified *bool
	}{
		{name: "omitted"},
		{name: "explicit false", enabled: ptr(false), emailVerified: ptr(false), wantEnabled: ptr(false), wantVerified: ptr(false)},
		{name: "explicit true", enabled: ptr(true), emailVerified: ptr(true), wantEnabled: ptr(true), wantVerified: ptr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &recordingAPI{}
			in := UpdateRealmUserInput{ClusterID: "c1", Realm: "app", UserID: "u1", Email: "j@x.com", Enabled: tc.enabled, EmailVerified: tc.emailVerified}
			res, _, err := updateRealmUserHandler(api)(context.Background(), nil, in)
			if err != nil || res.IsError {
				t.Fatalf("update user: err=%v res=%v", err, res.IsError)
			}
			checkBool(t, "enabled", api.userEnabled, tc.wantEnabled)
			checkBool(t, "email_verified", api.userEmailVerified, tc.wantVerified)
		})
	}
}

func TestUpdateRealmForwardsOnlyTheBooleanTheCallerSent(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enabled, wantArg *bool
	}{
		{name: "omitted"},
		{name: "explicit false", enabled: ptr(false), wantArg: ptr(false)},
		{name: "explicit true", enabled: ptr(true), wantArg: ptr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &recordingAPI{}
			in := UpdateRealmInput{ClusterID: "c1", Realm: "app", DisplayName: "App", Enabled: tc.enabled}
			res, _, err := updateRealmHandler(api)(context.Background(), nil, in)
			if err != nil || res.IsError {
				t.Fatalf("update realm: err=%v res=%v", err, res.IsError)
			}
			checkBool(t, "enabled", api.realmEnabled, tc.wantArg)
		})
	}
}

func TestUpdateDomainRouteForwardsOnlyTheBooleanTheCallerSent(t *testing.T) {
	for _, tc := range []struct {
		name           string
		admin, wantArg *bool
	}{
		{name: "omitted"},
		{name: "explicit false", admin: ptr(false), wantArg: ptr(false)},
		{name: "explicit true", admin: ptr(true), wantArg: ptr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &recordingAPI{}
			in := UpdateDomainRouteInput{ClusterID: "c1", DomainID: "d1", RouteID: "r1", AllowAdminAccess: tc.admin}
			res, _, err := updateDomainRouteHandler(api)(context.Background(), nil, in)
			if err != nil || res.IsError {
				t.Fatalf("update route: err=%v res=%v", err, res.IsError)
			}
			checkBool(t, "allow_admin_access", api.routeAdminAccess, tc.wantArg)
		})
	}
}

func TestUpdateRealmForwardsFrontendURLStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  *string
	}{
		{name: "omitted"},
		{name: "set", url: ptr("https://login.example.com")},
		{name: "cleared", url: ptr("")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &recordingAPI{}
			in := UpdateRealmInput{ClusterID: "c1", Realm: "app", FrontendURL: tc.url}
			res, out, err := updateRealmHandler(api)(context.Background(), nil, in)
			if err != nil || res.IsError {
				t.Fatalf("update realm: err=%v res=%v", err, res.IsError)
			}
			if (api.realmFrontendURL == nil) != (tc.url == nil) || (tc.url != nil && *api.realmFrontendURL != *tc.url) {
				t.Errorf("forwarded frontend_url = %v, want %v", api.realmFrontendURL, tc.url)
			}
			if tc.url != nil && *tc.url != "" && (out.FrontendURL == nil || *out.FrontendURL != *tc.url) {
				t.Errorf("returned frontend_url = %v, want %v", out.FrontendURL, *tc.url)
			}
		})
	}
}

func TestUpdateRealmPassesFrontendURLRefusalsThrough(t *testing.T) {
	for _, status := range []int{403, 409, 422} {
		api := stubAPI{err: &skycloak.APIError{StatusCode: status, Problem: skycloak.Problem{Detail: "frontend_url refused"}}}
		res, _, err := updateRealmHandler(api)(context.Background(), nil, UpdateRealmInput{ClusterID: "c1", Realm: "app", FrontendURL: ptr("https://x.example.com")})
		if err != nil || !res.IsError {
			t.Fatalf("status %d: err=%v isError=%v, want a tool error", status, err, res != nil && res.IsError)
		}
	}
}

func TestGetRealmShowsFrontendURL(t *testing.T) {
	u := "https://login.example.com"
	res, out, err := getRealmHandler(stubAPI{realm: &skycloak.Realm{Name: "app", Enabled: true, FrontendURL: &u}})(context.Background(), nil, RealmScopeInput{ClusterID: "c1", Realm: "app"})
	if err != nil || res.IsError || out.FrontendURL == nil || *out.FrontendURL != u {
		t.Fatalf("get realm: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if text := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(text, "frontend_url="+u) {
		t.Errorf("text %q does not show the frontend URL", text)
	}
}

package skycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// These exercise the API-to-EventEntry mapping itself. The tool-level tests use
// a stub that hands back an already-populated EventEntry, so they keep passing
// even if this mapping drops every field the API sends — which is precisely the
// bug being fixed here, admin events arriving without their resource.

func TestQueryEventsMapsAdminResourceFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `[{
			"id":"11111111-1111-1111-1111-111111111111",
			"timestamp":"2026-08-31T18:45:00Z",
			"category":"admin",
			"realm_id":"r1","realm_name":"alfred",
			"operation_type":"UPDATE",
			"resource_type":"REALM",
			"resource_path":"realms/alfred",
			"ip_address":"203.0.113.7"
		}]`)
	}))
	defer srv.Close()

	events, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events", len(events))
	}
	e := events[0]
	if e.ResourceType != "REALM" {
		t.Errorf("resource_type dropped: %+v", e)
	}
	if e.ResourcePath != "realms/alfred" {
		t.Errorf("resource_path dropped: %+v", e)
	}
	if e.OperationType != "UPDATE" {
		t.Errorf("operation_type dropped: %+v", e)
	}
}

func TestQueryEventsMapsUserEventFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `[{
			"id":"22222222-2222-2222-2222-222222222222",
			"timestamp":"2026-08-31T18:45:00Z",
			"category":"user",
			"realm_id":"r1","realm_name":"alfred",
			"type":"LOGIN_ERROR",
			"user_id":"33333333-3333-3333-3333-333333333333",
			"username":"someone",
			"session_id":"sess-1",
			"auth_method":"openid-connect",
			"identity_provider":"google",
			"grant_type":"authorization_code",
			"is_m2m":true,
			"error":"invalid_user_credentials"
		}]`)
	}))
	defer srv.Close()

	events, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	// Exact values, not merely non-empty: the fixture gives every field a
	// distinct value so a cross-wired mapping (auth_method into grant_type, say)
	// fails here instead of passing because both happen to be populated.
	e := events[0]
	for name, pair := range map[string][2]string{
		"user_id":           {e.UserID, "33333333-3333-3333-3333-333333333333"},
		"session_id":        {e.SessionID, "sess-1"},
		"auth_method":       {e.AuthMethod, "openid-connect"},
		"identity_provider": {e.IdentityProvider, "google"},
		"grant_type":        {e.GrantType, "authorization_code"},
		"username":          {e.Username, "someone"},
		"error":             {e.Error, "invalid_user_credentials"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q (mapping dropped or cross-wired): %+v", name, pair[0], pair[1], e)
		}
	}
	if e.IsM2M == nil || !*e.IsM2M {
		t.Errorf("is_m2m dropped: %+v", e)
	}
}

// is_m2m is three-valued on the wire and has to stay that way: admin events have
// no machine-to-machine notion, so a bare false would assert one. Hardcoding it
// either way passed before, because only the true case had a fixture.
func TestQueryEventsPreservesIsM2MAbsenceAndFalse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want *bool
	}{
		{"absent", `{"id":"22222222-2222-2222-2222-222222222222","timestamp":"2026-08-31T18:45:00Z","category":"admin","realm_id":"r1","realm_name":"alfred"}`, nil},
		{"false", `{"id":"22222222-2222-2222-2222-222222222222","timestamp":"2026-08-31T18:45:00Z","category":"user","realm_id":"r1","realm_name":"alfred","is_m2m":false}`, boolPtr(false)},
		{"true", `{"id":"22222222-2222-2222-2222-222222222222","timestamp":"2026-08-31T18:45:00Z","category":"user","realm_id":"r1","realm_name":"alfred","is_m2m":true}`, boolPtr(true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, 200, "["+tc.body+"]")
			}))
			defer srv.Close()

			events, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{})
			if err != nil {
				t.Fatalf("QueryEvents: %v", err)
			}
			got := events[0].IsM2M
			switch {
			case tc.want == nil && got != nil:
				t.Errorf("absent is_m2m became %v, asserting something the event never said", *got)
			case tc.want != nil && got == nil:
				t.Errorf("is_m2m %v was dropped", *tc.want)
			case tc.want != nil && got != nil && *tc.want != *got:
				t.Errorf("is_m2m = %v, want %v", *got, *tc.want)
			}
		})
	}
}

func boolPtr(b bool) *bool { return &b }

// A filter that cannot apply to the requested category is refused, not dropped.
// Dropping it returns the whole category unfiltered while the caller believes it
// narrowed the query, which is the failure this change exists to remove.
func TestQueryEventsRejectsFilterThatCannotApplyToCategory(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	for _, tc := range []struct {
		name string
		q    EventQuery
	}{
		{"user types on an admin query", EventQuery{Category: "admin", Types: []string{"LOGIN_ERROR"}}},
		{"admin operations on a user query", EventQuery{Category: "user", OperationTypes: []string{"UPDATE"}}},
		{"both with a category", EventQuery{Category: "user", Types: []string{"LOGIN_ERROR"}, OperationTypes: []string{"UPDATE"}}},
		{"both with an unrecognised category", EventQuery{Category: "login", Types: []string{"LOGIN_ERROR"}, OperationTypes: []string{"UPDATE"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			if _, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, tc.q); err == nil {
				t.Fatal("an inapplicable filter was accepted; the query would return the category unfiltered")
			}
			if called {
				t.Error("request was sent despite a filter that cannot apply")
			}
		})
	}
}

// The happy path for admin filtering. Replacing the old mismatch test with
// error-only cases removed the sole wire assertion for operation_types, so
// deleting the forwarding block entirely passed the suite — the exact symptom
// (admin events silently unfiltered) that this change exists to prevent.
func TestQueryEventsSendsOperationTypesOnTheWire(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	if _, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{
		Category: "admin", OperationTypes: []string{"UPDATE", "DELETE"},
	}); err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if vs := got["operation_types"]; len(vs) == 0 {
		t.Fatalf("operation_types never reached the query string: %v", got)
	}
	joined := strings.Join(got["operation_types"], ",")
	for _, want := range []string{"UPDATE", "DELETE"} {
		if !strings.Contains(joined, want) {
			t.Errorf("operation_types missing %q: %v", want, got)
		}
	}
	if got.Get("category") != "admin" {
		t.Errorf("category = %q, want admin", got.Get("category"))
	}
}

// A negative offset is a caller mistake. Clamping it to zero hands back page one
// while the caller believes they paged past it.
func TestQueryEventsRejectsNegativeOffset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request sent with a negative offset")
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	if _, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid,
		EventQuery{Offset: -1}); err == nil {
		t.Fatal("negative offset accepted")
	}
}

// The filters have to reach the wire, not just the struct. Asserting on the
// query string is what proves the request the API actually receives.
func TestQueryEventsSendsFiltersOnTheWire(t *testing.T) {
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{
		Limit: 100, Offset: 200, Category: "user",
		StartTime: "2026-08-31T00:00:00Z", EndTime: "2026-09-01T00:00:00Z",
		Types: []string{"LOGIN_ERROR"}, Error: "invalid_user_credentials", Order: "asc",
	})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	// Every value asserted exactly. Checking start_time and end_time for mere
	// presence let a swap of the two pass, which would silently invert the
	// window a caller asked for.
	for k, want := range map[string]string{
		"offset":     "200",
		"types":      "LOGIN_ERROR",
		"error":      "invalid_user_credentials",
		"order":      "asc",
		"start_time": "2026-08-31T00:00:00Z",
		"end_time":   "2026-09-01T00:00:00Z",
	} {
		if g := got.Get(k); g != want {
			t.Errorf("%s = %q, want %q (full query: %v)", k, g, want, got)
		}
	}
}

// An unparseable timestamp must fail the call, not vanish. Silently dropping it
// leaves the API to apply its default 24-hour window while the caller believes
// its own range applied, so a question about last week is answered from
// yesterday and reads as "nothing happened" — the exact failure this change
// exists to remove.
func TestQueryEventsRejectsUnparseableTime(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	for _, tc := range []struct{ name, start, end string }{
		{"date only", "2026-08-25", ""},
		{"no timezone", "2026-08-25T00:00:00", ""},
		{"prose", "last tuesday", ""},
		{"bad end only", "2026-08-25T00:00:00Z", "not a time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			_, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid,
				EventQuery{StartTime: tc.start, EndTime: tc.end})
			if err == nil {
				t.Fatalf("unparseable time accepted, the range would be silently ignored")
			}
			if called {
				t.Errorf("request was sent despite an unusable time filter")
			}
		})
	}
}

// With no category there is no way to pick between the two filter lists, and the
// spec calls them mutually exclusive without encoding it, so the server's
// behaviour is undefined. Refuse rather than send both and hope.
func TestQueryEventsRejectsBothFilterListsWithoutCategory(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{
		Types: []string{"LOGIN_ERROR"}, OperationTypes: []string{"UPDATE"},
	})
	if err == nil {
		t.Fatal("both filter lists accepted with no category to disambiguate them")
	}
	if called {
		t.Error("request was sent with two mutually exclusive filters")
	}
}

// get_realm and list_realms go through one converter, so the same entity cannot
// serialise two ways depending on which call produced it.
func TestGetRealmMapsSecuritySettings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `{
			"id":"44444444-4444-4444-4444-444444444444",
			"name":"alfred","display_name":"Alfred","enabled":true,
			"ssl_required":"external",
			"registration_allowed":true,
			"registration_email_as_username":false,
			"login_with_email_allowed":true,
			"duplicate_emails_allowed":false
		}`)
	}))
	defer srv.Close()

	r, err := newTestClient(srv.URL).GetRealm(context.Background(), cuid, "alfred")
	if err != nil {
		t.Fatalf("GetRealm: %v", err)
	}
	if !r.RegistrationAllowed {
		t.Errorf("registration_allowed dropped: %+v", r)
	}
	if !r.LoginWithEmailAllowed {
		t.Errorf("login_with_email_allowed dropped: %+v", r)
	}
	if r.SSLRequired != "external" {
		t.Errorf("ssl_required dropped: %+v", r)
	}
	if r.ID == "" {
		t.Errorf("id dropped: %+v", r)
	}
}

// Every path that builds a Realm must go through realmFromAPI. The security
// fields are plain bools, so a path that builds one inline reports registration
// and email login as off regardless of what the API said — fabricating a
// security posture rather than merely omitting one. Keycloak enables
// login_with_email by default, so an inline build is wrong on most realms.
func TestRealmWritesReturnTheServersSettings(t *testing.T) {
	body := `{
		"id":"44444444-4444-4444-4444-444444444444",
		"name":"alfred","display_name":"Alfred","enabled":true,
		"ssl_required":"external",
		"registration_allowed":true,
		"registration_email_as_username":true,
		"login_with_email_allowed":true,
		"duplicate_emails_allowed":true
	}`

	for _, tc := range []struct {
		name   string
		status int
		call   func(c *Client) (*Realm, error)
	}{
		{"create", 201, func(c *Client) (*Realm, error) {
			return c.CreateRealm(context.Background(), cuid, Realm{Name: "alfred"})
		}},
		{"update", 200, func(c *Client) (*Realm, error) {
			return c.UpdateRealm(context.Background(), cuid, "alfred", "Alfred", true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, tc.status, body)
			}))
			defer srv.Close()

			r, err := tc.call(newTestClient(srv.URL))
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !r.RegistrationAllowed {
				t.Errorf("%s reported registration_allowed=false while the API said true: %+v", tc.name, r)
			}
			if !r.LoginWithEmailAllowed {
				t.Errorf("%s reported login_with_email_allowed=false while the API said true: %+v", tc.name, r)
			}
			if r.SSLRequired != "external" {
				t.Errorf("%s dropped ssl_required: %+v", tc.name, r)
			}
			if r.ID == "" {
				t.Errorf("%s dropped id: %+v", tc.name, r)
			}
		})
	}
}

// The tool tests drive a stub, so they pass even if this mapping hardcodes
// every field — the third time that gap has appeared in this change. Asserted
// here against a real response instead.
func TestClusterTypeVersionsMapsEveryField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `[
			{"version":"27.0.0","active":true,"is_major_change":true,"breaking_change_count":3},
			{"version":"26.6.3","active":false,"is_major_change":false,"breaking_change_count":0}
		]`)
	}))
	defer srv.Close()

	vs, err := newTestClient(srv.URL).ClusterTypeVersions(context.Background(), "keycloak")
	if err != nil {
		t.Fatalf("ClusterTypeVersions: %v", err)
	}
	if len(vs) != 2 {
		t.Fatalf("got %d versions, want 2 (a recognised version must not be filtered out)", len(vs))
	}
	if vs[0].Version != "27.0.0" || !vs[0].Active || !vs[0].IsMajorChange || vs[0].BreakingChangeCount != 3 {
		t.Errorf("offered version mismapped: %+v", vs[0])
	}
	if vs[1].Version != "26.6.3" || vs[1].Active || vs[1].IsMajorChange || vs[1].BreakingChangeCount != 0 {
		t.Errorf("retired version mismapped, active=false must survive: %+v", vs[1])
	}
}

// An absent realm id must be omitted, not rendered as the zero UUID. RealmId is
// a value type, so a missing id stringifies to a well-formed
// 00000000-0000-0000-0000-000000000000 that omitempty cannot catch — a caller
// could paste it into a lookup believing it identifies the realm. Observed live
// against prod, where get_realm returned exactly that.
func TestRealmOmitsAbsentID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `{"name":"alfred","display_name":"Alfred","enabled":true,
			"ssl_required":"external","registration_allowed":true,
			"registration_email_as_username":false,"login_with_email_allowed":true,
			"duplicate_emails_allowed":false}`)
	}))
	defer srv.Close()

	r, err := newTestClient(srv.URL).GetRealm(context.Background(), cuid, "alfred")
	if err != nil {
		t.Fatalf("GetRealm: %v", err)
	}
	if r.ID != "" {
		t.Errorf("absent id became %q, a fabricated identifier", r.ID)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "00000000-0000-0000-0000-000000000000") {
		t.Errorf("zero UUID reached the payload: %s", b)
	}
	if strings.Contains(string(b), `"id"`) {
		t.Errorf("id must be omitted entirely when absent: %s", b)
	}
}

// A real id still comes through.
func TestRealmKeepsPresentID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `{"id":"44444444-4444-4444-4444-444444444444","name":"alfred",
			"display_name":"Alfred","enabled":true,"ssl_required":"external",
			"registration_allowed":true,"registration_email_as_username":false,
			"login_with_email_allowed":true,"duplicate_emails_allowed":false}`)
	}))
	defer srv.Close()

	r, err := newTestClient(srv.URL).GetRealm(context.Background(), cuid, "alfred")
	if err != nil {
		t.Fatalf("GetRealm: %v", err)
	}
	if r.ID != "44444444-4444-4444-4444-444444444444" {
		t.Errorf("id dropped or mangled: %q", r.ID)
	}
}

// The API names the administrator behind an admin change; the MCP dropped it,
// so "who changed this realm" stopped one layer short of the caller. The whole
// chain, SPI to enricher to ClickHouse to API, exists to answer that.
func TestQueryEventsMapsTheAdminActor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `[{
			"id":"11111111-1111-1111-1111-111111111111",
			"timestamp":"2026-09-02T20:42:43Z",
			"category":"admin",
			"realm_id":"r1","realm_name":"master",
			"operation_type":"DELETE",
			"resource_type":"IDENTITY_PROVIDER",
			"resource_path":"identity-provider/instances/skycloak",
			"auth_user_id":"93d8b074-0000-4000-8000-000000000001",
			"username":"service-account-skycloak-service-f49a5d72"
		}]`)
	}))
	defer srv.Close()

	events, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	e := events[0]
	if e.AuthUserID != "93d8b074-0000-4000-8000-000000000001" {
		t.Errorf("admin actor id dropped: %+v", e)
	}
	if e.Username != "service-account-skycloak-service-f49a5d72" {
		t.Errorf("admin actor name dropped: %+v", e)
	}
}

// A federated administrator has no UUID id, so the API sends a name and no
// auth_user_id. Requiring both would make federated admins invisible.
func TestQueryEventsMapsActorNameWithoutID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, `[{
			"id":"11111111-1111-1111-1111-111111111111",
			"timestamp":"2026-09-02T20:42:43Z","category":"admin",
			"realm_id":"r1","realm_name":"master",
			"operation_type":"UPDATE","username":"alice@example.com"
		}]`)
	}))
	defer srv.Close()

	events, err := newTestClient(srv.URL).QueryEvents(context.Background(), cuid, EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if events[0].Username != "alice@example.com" {
		t.Errorf("actor name dropped when no id was sent: %+v", events[0])
	}
	if events[0].AuthUserID != "" {
		t.Errorf("invented an actor id: %q", events[0].AuthUserID)
	}
}

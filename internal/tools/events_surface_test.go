package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// renderedText pulls the human-readable half of a tool result, which is what a
// model actually reads.
func renderedText(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	t, _ := res.Content[0].(*mcp.TextContent)
	if t == nil {
		return ""
	}
	return t.Text
}

// The API has offered these filters all along; the tool simply never passed
// them on. Without them a caller cannot express "failed logins this week" and
// has to pull the newest N events and hope the window covers the period, which
// is how an incomplete answer gets reported as a complete one.

func TestQueryEventsPassesTimeRangeThrough(t *testing.T) {
	var got skycloak.EventQuery
	api := stubAPI{gotEventQuery: &got}

	in := QueryEventsInput{
		ClusterID: "c1",
		StartTime: "2026-08-31T00:00:00Z",
		EndTime:   "2026-09-01T00:00:00Z",
	}
	if _, _, err := queryEventsHandler(api)(context.Background(), nil, in); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.StartTime != in.StartTime || got.EndTime != in.EndTime {
		t.Fatalf("time range dropped: got start=%q end=%q", got.StartTime, got.EndTime)
	}
}

func TestQueryEventsPassesOffsetThrough(t *testing.T) {
	var got skycloak.EventQuery
	api := stubAPI{gotEventQuery: &got}

	if _, _, err := queryEventsHandler(api)(context.Background(), nil,
		QueryEventsInput{ClusterID: "c1", Offset: 100}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Offset != 100 {
		t.Fatalf("offset dropped: got %d", got.Offset)
	}
}

// Without a type filter the caller burns the whole page budget on noise: in the
// reported session 90+ of 100 events were one health check firing every 15
// minutes, so the single failed login being looked for was unreachable.
func TestQueryEventsPassesTypeFiltersThrough(t *testing.T) {
	var got skycloak.EventQuery
	api := stubAPI{gotEventQuery: &got}

	in := QueryEventsInput{
		ClusterID: "c1",
		Category:  "user",
		Types:     []string{"LOGIN_ERROR", "CLIENT_LOGIN_ERROR"},
		Error:     "invalid_user_credentials",
	}
	if _, _, err := queryEventsHandler(api)(context.Background(), nil, in); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got.Types) != 2 || got.Types[0] != "LOGIN_ERROR" {
		t.Fatalf("types dropped: %v", got.Types)
	}
	if got.Error != "invalid_user_credentials" {
		t.Fatalf("error filter dropped: %q", got.Error)
	}
}

func TestQueryEventsPassesOperationTypesThrough(t *testing.T) {
	var got skycloak.EventQuery
	api := stubAPI{gotEventQuery: &got}

	in := QueryEventsInput{ClusterID: "c1", Category: "admin", OperationTypes: []string{"UPDATE"}}
	if _, _, err := queryEventsHandler(api)(context.Background(), nil, in); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got.OperationTypes) != 1 || got.OperationTypes[0] != "UPDATE" {
		t.Fatalf("operation_types dropped: %v", got.OperationTypes)
	}
}

// Event types are enum-backed upstream, so they get the same case folding every
// other enum parameter in this server gets.
func TestQueryEventsNormalisesTypeCase(t *testing.T) {
	var got skycloak.EventQuery
	api := stubAPI{gotEventQuery: &got}

	in := QueryEventsInput{
		ClusterID:      "c1",
		Types:          []string{"login_error"},
		OperationTypes: []string{"update"},
	}
	if _, _, err := queryEventsHandler(api)(context.Background(), nil, in); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Types[0] != "LOGIN_ERROR" {
		t.Fatalf("type not folded: %q", got.Types[0])
	}
	if got.OperationTypes[0] != "UPDATE" {
		t.Fatalf("operation type not folded: %q", got.OperationTypes[0])
	}
}

// An admin UPDATE with no resource is unclassifiable: realm settings, a user
// edit and a client edit all render identically. The API returns the resource;
// dropping it is what made "did anyone change the login settings" unanswerable.
func TestQueryEventsSurfacesAdminResource(t *testing.T) {
	api := stubAPI{events: []skycloak.EventEntry{{
		Timestamp: "2026-08-31T18:45:00Z", Category: "admin", Type: "UPDATE",
		RealmName: "alfred", OperationType: "UPDATE",
		ResourceType: "REALM", ResourcePath: "realms/alfred",
	}}}

	res, out, err := queryEventsHandler(api)(context.Background(), nil,
		QueryEventsInput{ClusterID: "c1", Category: "admin"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Events[0].ResourceType != "REALM" || out.Events[0].ResourcePath != "realms/alfred" {
		t.Fatalf("resource dropped from structured output: %+v", out.Events[0])
	}
	text := renderedText(res)
	if !strings.Contains(text, "REALM") || !strings.Contains(text, "realms/alfred") {
		t.Fatalf("resource missing from rendered text, an UPDATE is unclassifiable without it: %q", text)
	}
}

// resourceSuffix has three shapes and only the both-present one was covered, so
// dropping either partial branch rendered an admin event bare and passed.
func TestResourceSuffixRendersPartialResources(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry skycloak.EventEntry
		want  []string
	}{
		{"type and path", skycloak.EventEntry{ResourceType: "REALM", ResourcePath: "realms/alfred"}, []string{"REALM", "realms/alfred"}},
		{"type only", skycloak.EventEntry{ResourceType: "REALM"}, []string{"REALM"}},
		{"path only", skycloak.EventEntry{ResourcePath: "realms/alfred"}, []string{"realms/alfred"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resourceSuffix(tc.entry)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("suffix %q missing %q", got, w)
				}
			}
		})
	}
	if got := resourceSuffix(skycloak.EventEntry{}); got != "" {
		t.Errorf("no resource should render nothing, got %q", got)
	}
}

// The cap is inclusive: 100 is what the API accepts, so refusing it would reject
// a legitimate request. Only the boundary catches an off-by-one here.
func TestQueryEventsAcceptsExactlyTheCap(t *testing.T) {
	var got skycloak.EventQuery
	res, _, err := queryEventsHandler(stubAPI{gotEventQuery: &got})(context.Background(), nil,
		QueryEventsInput{ClusterID: "c1", Limit: maxEventLimit})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.IsError {
		t.Fatalf("limit=%d is the documented maximum and must be accepted: %q", maxEventLimit, renderedText(res))
	}
	if got.Limit != maxEventLimit {
		t.Errorf("limit = %d, want %d", got.Limit, maxEventLimit)
	}
}

// canonicalEach drops blanks so a stray empty entry cannot become an empty
// filter value the API rejects; nothing pinned that before.
func TestQueryEventsDropsBlankTypeEntries(t *testing.T) {
	var got skycloak.EventQuery
	if _, _, err := queryEventsHandler(stubAPI{gotEventQuery: &got})(context.Background(), nil,
		QueryEventsInput{ClusterID: "c1", Types: []string{"", "  ", "LOGIN_ERROR"}}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got.Types) != 1 || got.Types[0] != "LOGIN_ERROR" {
		t.Fatalf("blank entries survived: %v", got.Types)
	}

	got = skycloak.EventQuery{}
	if _, _, err := queryEventsHandler(stubAPI{gotEventQuery: &got})(context.Background(), nil,
		QueryEventsInput{ClusterID: "c1", Types: []string{"", " "}}); err != nil {
		t.Fatalf("err: %v", err)
	}
	if got.Types != nil {
		t.Fatalf("an all-blank list must become no filter, got %v", got.Types)
	}
}

// The tool description is the only place a caller learns what search covers.
// Describing it as "free-text search" invites the assumption that it matches
// the event type, which it never has.
func TestQueryEventsDescriptionStatesSearchScopeAndLimit(t *testing.T) {
	d := queryEventsDescription
	for _, want := range []string{"username", "ip_address", "does not match", "100"} {
		if !strings.Contains(d, want) {
			t.Errorf("description must mention %q so the caller is not misled: %q", want, d)
		}
	}
}

// get_realm returned the bare Go struct, so it serialised as PascalCase while
// list_realms returned snake_case for the same entity.
func TestGetRealmOutputIsSnakeCase(t *testing.T) {
	api := stubAPI{realm: &skycloak.Realm{Name: "alfred", DisplayName: "Alfred", Enabled: true}}
	_, out, err := getRealmHandler(api)(context.Background(), nil,
		RealmScopeInput{ClusterID: "c1", Realm: "alfred"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"name"`, `"display_name"`, `"enabled"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.Contains(s, `"Name"`) || strings.Contains(s, `"DisplayName"`) {
		t.Errorf("PascalCase leaked, get_realm and list_realms disagree on the same entity: %s", s)
	}
}

// "Which realms still have self-registration enabled" is a security-posture
// question the API can answer; the tool was dropping the fields.
func TestGetRealmSurfacesSecuritySettings(t *testing.T) {
	api := stubAPI{realm: &skycloak.Realm{
		Name: "alfred", Enabled: true,
		RegistrationAllowed:   true,
		LoginWithEmailAllowed: true,
		SSLRequired:           "external",
	}}
	_, out, err := getRealmHandler(api)(context.Background(), nil,
		RealmScopeInput{ClusterID: "c1", Realm: "alfred"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !out.RegistrationAllowed {
		t.Fatalf("registration_allowed dropped: %+v", out)
	}
	if out.SSLRequired != "external" {
		t.Fatalf("ssl_required dropped: %+v", out)
	}
}

// The API marks every realm security setting required, so they map as plain
// bools. If one ever becomes optional upstream this test is the tripwire: an
// omitted value would then read as "registration is off", answering a security
// question wrongly rather than declining to answer it.
func TestRealmSecuritySettingsAreRequiredBySpec(t *testing.T) {
	doc := specDoc(t)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)
	realm := schemas["Realm"].(map[string]any)

	required := map[string]bool{}
	for _, r := range realm["required"].([]any) {
		required[r.(string)] = true
	}
	for _, f := range []string{
		"registration_allowed", "login_with_email_allowed",
		"registration_email_as_username", "duplicate_emails_allowed", "ssl_required",
	} {
		if !required[f] {
			t.Errorf("%s is no longer required by the spec; it must become a pointer here or an absent value reads as false", f)
		}
	}
}

// The rendered line is what a model reads before the structured payload, so the
// security settings have to appear in it. Gutting this rendering passed every
// test before, while making the fleet question unanswerable from what is read.
func TestGetRealmRendersSecuritySettings(t *testing.T) {
	api := stubAPI{realm: &skycloak.Realm{
		Name: "alfred", DisplayName: "Alfred", Enabled: true,
		RegistrationAllowed: true, LoginWithEmailAllowed: true, SSLRequired: "external",
	}}
	res, _, err := getRealmHandler(api)(context.Background(), nil,
		RealmScopeInput{ClusterID: "c1", Realm: "alfred"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	text := renderedText(res)
	for _, want := range []string{"registration_allowed=true", "login_with_email=true", "ssl_required=external"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered realm text missing %q: %q", want, text)
		}
	}
}

// The false case matters as much as the true one: hardcoding the rendered value
// passed every test while reporting registration as on for every realm.
func TestGetRealmRendersRegistrationDisabled(t *testing.T) {
	api := stubAPI{realm: &skycloak.Realm{Name: "locked", Enabled: true}}
	res, _, err := getRealmHandler(api)(context.Background(), nil,
		RealmScopeInput{ClusterID: "c1", Realm: "locked"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if text := renderedText(res); !strings.Contains(text, "registration_allowed=false") {
		t.Errorf("a realm with registration off must say so: %q", text)
	}
}

// Same for the list rows: answering "which realms allow self-registration"
// across a fleet is the point, and it is read from this line.
func TestListRealmsRendersRegistrationState(t *testing.T) {
	api := stubAPI{realms: []skycloak.Realm{
		{Name: "alfred", Enabled: true, RegistrationAllowed: true},
		{Name: "locked", Enabled: true},
	}}
	res, out, err := listRealmsHandler(api)(context.Background(), nil, ListRealmsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	text := renderedText(res)
	if !strings.Contains(text, "registration_allowed=true") || !strings.Contains(text, "registration_allowed=false") {
		t.Errorf("list rows must state registration state: %q", text)
	}
	if !out.Realms[0].RegistrationAllowed || out.Realms[1].RegistrationAllowed {
		t.Errorf("registration state dropped from list payload: %+v", out.Realms)
	}
}

// A limit the API cannot serve is refused here with the bound named. Forwarding
// it returns "Invalid parameter: limit" with no maximum, which is what made
// callers bisect to find it.
func TestQueryEventsRefusesOverLimitAndNamesTheCap(t *testing.T) {
	res, _, err := queryEventsHandler(stubAPI{})(context.Background(), nil,
		QueryEventsInput{ClusterID: "c1", Limit: 200})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.IsError {
		t.Fatal("an over-limit request must be refused, not forwarded")
	}
	if !strings.Contains(renderedText(res), "100") {
		t.Errorf("refusal must name the cap: %q", renderedText(res))
	}
}

// A nil slice marshals to null, which naive clients iterate straight into a
// crash. Every list output should be [] when empty.
func TestEmptyListsMarshalAsArrays(t *testing.T) {
	api := stubAPI{}

	_, idps, err := listIdentityProvidersHandler(api)(context.Background(), nil,
		ListIdentityProvidersInput{ClusterID: "c1", Realm: "alfred"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if b, _ := json.Marshal(idps); strings.Contains(string(b), "null") {
		t.Errorf("identity_providers is null, want []: %s", b)
	}

	_, evs, err := queryEventsHandler(api)(context.Background(), nil, QueryEventsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if b, _ := json.Marshal(evs); strings.Contains(string(b), "null") {
		t.Errorf("events is null, want []: %s", b)
	}

	_, realms, err := listRealmsHandler(api)(context.Background(), nil, ListRealmsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if b, _ := json.Marshal(realms); strings.Contains(string(b), "null") {
		t.Errorf("realms is null, want []: %s", b)
	}

	_, clusters, err := listClustersHandler(api)(context.Background(), nil, ListClustersInput{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if b, _ := json.Marshal(clusters); strings.Contains(string(b), "null") {
		t.Errorf("clusters is null, want []: %s", b)
	}

	_, apps, err := listApplicationsHandler(api)(context.Background(), nil,
		ListApplicationsInput{ClusterID: "c1", Realm: "alfred"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if b, _ := json.Marshal(apps); strings.Contains(string(b), "null") {
		t.Errorf("applications is null, want []: %s", b)
	}
}

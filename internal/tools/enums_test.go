package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// recAPI records the enum-ish values that reached the API layer, keyed exactly
// as enumParams identifies them, so a probe can assert the handler folded the
// case instead of forwarding whatever the model spelled.
type recAPI struct {
	stubAPI
	seen map[string]string
}

func (r recAPI) GetLogs(_ context.Context, _ string, q skycloak.LogQuery) ([]skycloak.LogEntry, error) {
	r.seen["skycloak_get_logs.level"] = q.Level
	return nil, nil
}

func (r recAPI) QueryEvents(_ context.Context, _ string, q skycloak.EventQuery) ([]skycloak.EventEntry, error) {
	r.seen["skycloak_query_events.category"] = q.Category
	r.seen["skycloak_query_events.order"] = q.Order
	if len(q.Types) > 0 {
		r.seen["skycloak_query_events.types"] = q.Types[0]
	}
	if len(q.OperationTypes) > 0 {
		r.seen["skycloak_query_events.operation_types"] = q.OperationTypes[0]
	}
	return nil, nil
}

func (r recAPI) CreateExport(_ context.Context, _, format string, _ bool, _ string) (*skycloak.Export, error) {
	r.seen["skycloak_create_export.format"] = format
	return &skycloak.Export{ID: "e1"}, nil
}

func (r recAPI) CreateApplication(_ context.Context, _, _ string, req skycloak.CreateApplicationRequest) (string, string, error) {
	r.seen["skycloak_create_application.type"] = req.Type
	r.seen["skycloak_create_application.protocol"] = req.Protocol
	if len(req.GrantTypes) > 0 {
		r.seen["skycloak_create_application.grant_types"] = req.GrantTypes[0]
	}
	return req.ClientID, "", nil
}

func (r recAPI) CreateCluster(_ context.Context, req skycloak.CreateClusterRequest) (*skycloak.Cluster, error) {
	r.seen["skycloak_create_cluster.type"] = req.Type
	r.seen["skycloak_create_cluster.size"] = req.Size
	r.seen["skycloak_create_cluster.location"] = req.Location
	return &skycloak.Cluster{ID: "new", Name: req.Name}, nil
}

func (r recAPI) UpdateCluster(_ context.Context, _, _, size string, _ *bool) (*skycloak.Cluster, error) {
	r.seen["skycloak_update_cluster.size"] = size
	return &skycloak.Cluster{ID: "c1"}, nil
}

func (r recAPI) UpsertSMTP(_ context.Context, _, _ string, req skycloak.UpsertSMTPRequest) (*skycloak.SMTPConfig, error) {
	r.seen["skycloak_upsert_smtp.encryption"] = req.Encryption
	return &skycloak.SMTPConfig{Host: req.Host}, nil
}

func (r recAPI) ClusterTypeVersions(_ context.Context, clusterType string) ([]skycloak.ClusterTypeVersion, error) {
	r.seen["skycloak_list_cluster_versions.type"] = clusterType
	return nil, nil
}

func (r recAPI) ClusterInsights(_ context.Context, _, kind string) ([]byte, error) {
	r.seen["skycloak_get_cluster_insights.type"] = kind
	return []byte("{}"), nil
}

func (r recAPI) ListWebhookEventTypes(_ context.Context, source string) ([]skycloak.WebhookEventType, error) {
	r.seen["skycloak_list_webhook_event_types.source"] = source
	return nil, nil
}

func (r recAPI) ListWebhookSubscriptions(_ context.Context, f skycloak.ListWebhookSubscriptionsFilter) ([]skycloak.WebhookSubscription, error) {
	r.seen["skycloak_list_webhook_subscriptions.source"] = f.Source
	return nil, nil
}

func (r recAPI) CreateWebhookSubscription(_ context.Context, req skycloak.CreateWebhookSubscriptionRequest) (*skycloak.WebhookSubscription, error) {
	r.seen["skycloak_create_webhook_subscription.source"] = req.Source
	return &skycloak.WebhookSubscription{ID: "w1", Name: req.Name}, nil
}

func (r recAPI) UpdateWebhookSubscription(_ context.Context, _ string, req skycloak.UpdateWebhookSubscriptionRequest) (*skycloak.WebhookSubscription, error) {
	if req.Source != nil {
		r.seen["skycloak_update_webhook_subscription.source"] = *req.Source
	}
	return &skycloak.WebhookSubscription{ID: "w1"}, nil
}

func (r recAPI) CreateSIEMDestination(_ context.Context, req skycloak.CreateSIEMDestinationRequest) (*skycloak.SIEMDestination, error) {
	r.seen["skycloak_create_siem_destination.type"] = req.Type
	r.seen["skycloak_create_siem_destination.source.type"] = req.Source.Type
	if req.Syslog != nil {
		r.seen["skycloak_create_siem_destination.syslog.protocol"] = req.Syslog.Protocol
		r.seen["skycloak_create_siem_destination.syslog.format"] = req.Syslog.Format
	}
	if req.HTTP != nil {
		r.seen["skycloak_create_siem_destination.http.auth_type"] = req.HTTP.AuthType
	}
	if req.S3 != nil {
		r.seen["skycloak_create_siem_destination.s3.auth_type"] = req.S3.AuthType
	}
	return &skycloak.SIEMDestination{ID: "d1", Name: req.Name}, nil
}

func (r recAPI) UpdateSIEMDestination(_ context.Context, _ string, req skycloak.UpdateSIEMDestinationRequest) (*skycloak.SIEMDestination, error) {
	if req.Source != nil {
		r.seen["skycloak_update_siem_destination.source.type"] = req.Source.Type
	}
	if req.Syslog != nil {
		r.seen["skycloak_update_siem_destination.syslog.protocol"] = req.Syslog.Protocol
		r.seen["skycloak_update_siem_destination.syslog.format"] = req.Syslog.Format
	}
	if req.HTTP != nil {
		r.seen["skycloak_update_siem_destination.http.auth_type"] = req.HTTP.AuthType
	}
	if req.S3 != nil {
		r.seen["skycloak_update_siem_destination.s3.auth_type"] = req.S3.AuthType
	}
	return &skycloak.SIEMDestination{ID: "d1"}, nil
}

func (r recAPI) UpdateClusterSecurity(_ context.Context, _ string, sec *skycloak.ClusterSecurity) (*skycloak.ClusterSecurity, error) {
	if sec.WAF != nil {
		r.seen["skycloak_update_cluster_security.waf.mode"] = sec.WAF.Mode
		r.seen["skycloak_update_cluster_security.waf.preset"] = sec.WAF.Preset
	}
	if sec.GeoBlocking != nil {
		r.seen["skycloak_update_cluster_security.geo_blocking.mode"] = sec.GeoBlocking.Mode
	}
	if sec.BotManagement != nil {
		r.seen["skycloak_update_cluster_security.bot_management.mode"] = sec.BotManagement.Mode
		r.seen["skycloak_update_cluster_security.bot_management.challenge_mode"] = sec.BotManagement.ChallengeMode
	}
	return sec, nil
}

func (r recAPI) CreateOIDCIdentityProvider(_ context.Context, _, _ string, req skycloak.CreateOIDCIdentityProviderRequest) error {
	r.seen["skycloak_create_identity_provider.provider_id"] = req.ProviderID
	return nil
}

// The four alias lookups record under one key: what matters is that the alias
// arrives exactly as the caller wrote it, whichever tool carried it.
func (r recAPI) GetIdentityProvider(_ context.Context, _, _, alias string) (*skycloak.IdentityProvider, error) {
	r.seen["alias"] = alias
	return &skycloak.IdentityProvider{ProviderID: alias}, nil
}

func (r recAPI) UpdateIdentityProvider(_ context.Context, _, _, alias, _ string, _ bool) (*skycloak.IdentityProvider, error) {
	r.seen["alias"] = alias
	return &skycloak.IdentityProvider{ProviderID: alias}, nil
}

func (r recAPI) DeleteIdentityProvider(_ context.Context, _, _, alias string) error {
	r.seen["alias"] = alias
	return nil
}

func (r recAPI) TestIdentityProviderConnection(_ context.Context, _, _, alias, _, _ string) (*skycloak.TestResult, error) {
	r.seen["alias"] = alias
	return &skycloak.TestResult{Success: true}, nil
}

// enumProbes builds the arguments for one tool call with v in the parameter
// named by the key. Hand-written per parameter: every tool input is its own
// shape, so there is no mechanical way to set "the field called size" across
// all of them. TestEveryEnumParamHasAProbe keeps the set complete.
//
// The call goes through the registered tool by name, not through a handler
// constructor, so a tool wired to a different function than the one a probe
// names cannot pass while shipping the unnormalised value.
var enumProbes = map[string]func(v string) map[string]any{
	"skycloak_get_logs.level": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "level": v}
	},
	"skycloak_query_events.category": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "category": v}
	},
	"skycloak_query_events.types": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "types": []any{v}}
	},
	"skycloak_query_events.operation_types": func(v string) map[string]any {
		// category=admin, or the client drops operation_types as inapplicable.
		return map[string]any{"cluster_id": "c1", "category": "admin", "operation_types": []any{v}}
	},
	"skycloak_query_events.order": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "order": v}
	},
	"skycloak_create_export.format": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "format": v}
	},
	"skycloak_create_application.type": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "realm": "r", "client_id": "app", "name": "App", "redirect_uris": []string{"https://a/cb"}, "type": v}
	},
	"skycloak_create_application.protocol": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "realm": "r", "client_id": "app", "name": "App", "redirect_uris": []string{"https://a/cb"}, "protocol": v}
	},
	"skycloak_create_application.grant_types": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "realm": "r", "client_id": "app", "name": "App", "redirect_uris": []string{"https://a/cb"}, "grant_types": []string{v}}
	},
	"skycloak_create_cluster.type": func(v string) map[string]any {
		return map[string]any{"name": "n", "size": "small", "version": "26.1", "location": "eu", "type": v}
	},
	"skycloak_create_cluster.size": func(v string) map[string]any {
		return map[string]any{"name": "n", "version": "26.1", "location": "eu", "size": v}
	},
	"skycloak_create_cluster.location": func(v string) map[string]any {
		return map[string]any{"name": "n", "size": "small", "version": "26.1", "location": v}
	},
	"skycloak_update_cluster.size": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "size": v}
	},
	"skycloak_upsert_smtp.encryption": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "realm": "r", "host": "smtp.example.com", "port": 587, "from_email": "a@b.c", "encryption": v}
	},
	"skycloak_list_cluster_versions.type": func(v string) map[string]any {
		return map[string]any{"type": v}
	},
	"skycloak_get_cluster_insights.type": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "type": v}
	},
	"skycloak_list_webhook_event_types.source": func(v string) map[string]any {
		return map[string]any{"source": v}
	},
	"skycloak_list_webhook_subscriptions.source": func(v string) map[string]any {
		return map[string]any{"source": v}
	},
	"skycloak_create_webhook_subscription.source": func(v string) map[string]any {
		return map[string]any{
			"name": "w", "url": "https://example.com", "signing_secret": "s",
			"event_types": []any{"LOGIN"}, "source": v,
		}
	},
	"skycloak_update_webhook_subscription.source": func(v string) map[string]any {
		return map[string]any{"webhook_id": "w1", "source": v}
	},
	"skycloak_create_siem_destination.type": func(v string) map[string]any {
		return siemCreateArgs(func(a map[string]any) { a["type"] = v })
	},
	"skycloak_create_siem_destination.source.type": func(v string) map[string]any {
		return siemCreateArgs(func(a map[string]any) { a["source"].(map[string]any)["type"] = v })
	},
	"skycloak_create_siem_destination.syslog.protocol": func(v string) map[string]any {
		return siemCreateArgs(func(a map[string]any) { a["syslog"].(map[string]any)["protocol"] = v })
	},
	"skycloak_create_siem_destination.syslog.format": func(v string) map[string]any {
		return siemCreateArgs(func(a map[string]any) { a["syslog"].(map[string]any)["format"] = v })
	},
	"skycloak_create_siem_destination.http.auth_type": func(v string) map[string]any {
		return siemCreateArgs(func(a map[string]any) { a["http"].(map[string]any)["auth_type"] = v })
	},
	"skycloak_create_siem_destination.s3.auth_type": func(v string) map[string]any {
		return siemCreateArgs(func(a map[string]any) { a["s3"].(map[string]any)["auth_type"] = v })
	},
	"skycloak_update_siem_destination.source.type": func(v string) map[string]any {
		return siemUpdateArgs(func(a map[string]any) { a["source"].(map[string]any)["type"] = v })
	},
	"skycloak_update_siem_destination.syslog.protocol": func(v string) map[string]any {
		return siemUpdateArgs(func(a map[string]any) { a["syslog"].(map[string]any)["protocol"] = v })
	},
	"skycloak_update_siem_destination.syslog.format": func(v string) map[string]any {
		return siemUpdateArgs(func(a map[string]any) { a["syslog"].(map[string]any)["format"] = v })
	},
	"skycloak_update_siem_destination.http.auth_type": func(v string) map[string]any {
		return siemUpdateArgs(func(a map[string]any) { a["http"].(map[string]any)["auth_type"] = v })
	},
	"skycloak_update_siem_destination.s3.auth_type": func(v string) map[string]any {
		return siemUpdateArgs(func(a map[string]any) { a["s3"].(map[string]any)["auth_type"] = v })
	},
	"skycloak_update_cluster_security.waf.mode": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "waf": map[string]any{"enabled": true, "mode": v, "preset": "custom", "paranoia_level": 1}}
	},
	"skycloak_update_cluster_security.waf.preset": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "waf": map[string]any{"enabled": true, "mode": "detect", "preset": v, "paranoia_level": 1}}
	},
	"skycloak_update_cluster_security.geo_blocking.mode": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "geo_blocking": map[string]any{"enabled": true, "mode": v, "countries": []any{"FR"}}}
	},
	"skycloak_update_cluster_security.bot_management.mode": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "bot_management": map[string]any{"enabled": true, "mode": v, "challenge_mode": "captcha"}}
	},
	"skycloak_update_cluster_security.bot_management.challenge_mode": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "bot_management": map[string]any{"enabled": true, "mode": "detect", "challenge_mode": v}}
	},
	"skycloak_create_identity_provider.provider_id": func(v string) map[string]any {
		return map[string]any{"cluster_id": "c1", "realm": "r", "provider_id": v, "display_name": "d"}
	},
}

func siemCreateArgs(set func(map[string]any)) map[string]any {
	a := map[string]any{
		"name":   "d",
		"type":   "syslog",
		"source": map[string]any{"type": "keycloak_events"},
		"syslog": map[string]any{"host": "h", "port": 514, "protocol": "tcp", "format": "json"},
		"s3":     map[string]any{"auth_type": "iam_role", "bucket": "b", "region": "us-east-1"},
		"http":   map[string]any{"url": "https://example.com", "auth_type": "none"},
	}
	set(a)
	return a
}

func siemUpdateArgs(set func(map[string]any)) map[string]any {
	a := siemCreateArgs(func(map[string]any) {})
	delete(a, "name")
	delete(a, "type")
	a["destination_id"] = "d1"
	set(a)
	return a
}

// probeSession registers the real tool surface against a recording API and
// returns a client session plus the map the handlers write into.
func probeSession(t *testing.T) (*mcp.ClientSession, map[string]string) {
	t.Helper()
	seen := map[string]string{}
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(s, recAPI{seen: seen}, true, nil)

	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, seen
}

func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// Every value the API accepts must survive a round trip through the tool in any
// case the model might have written it in.
func TestEnumParamsAreNormalisedByTheirHandlers(t *testing.T) {
	cs, seen := probeSession(t)
	for _, p := range enumParams {
		probe, ok := enumProbes[p.key()]
		if !ok {
			continue // TestEveryEnumParamHasAProbe reports this
		}
		for _, want := range p.enum.values {
			for _, spelling := range []string{strings.ToUpper(want), capitalise(want), " " + want + " "} {
				clear(seen)
				if res := callTool(t, cs, p.tool, probe(spelling)); res.IsError {
					t.Fatalf("%s refused %q: %v", p.tool, spelling, res.Content)
				}
				if got := seen[p.key()]; got != want {
					t.Errorf("%s: %q reached the API as %q, want %q", p.key(), spelling, got, want)
				}
			}
		}
	}
}

func capitalise(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// A value the enum does not list must reach the API untouched, so a value the
// API grew after this build still works and its error is the API's own. That
// only applies to values we forward, not to the ones we resolve ourselves.
func TestUnknownEnumValuesArePassedThrough(t *testing.T) {
	cs, seen := probeSession(t)
	for _, p := range enumParams {
		probe, ok := enumProbes[p.key()]
		if !ok || p.enum.closed {
			continue
		}
		clear(seen)
		if res := callTool(t, cs, p.tool, probe("SomethingElse")); res.IsError {
			t.Fatalf("%s refused an unknown value outright: %v", p.tool, res.Content)
		}
		if got := seen[p.key()]; got != "SomethingElse" {
			t.Errorf("%s: unknown value reached the API as %q, want it untouched", p.key(), got)
		}
	}
}

// A closed enum picks which request the client makes, so an unrecognised value
// never reaches the API to be rejected. get_cluster_insights used to answer such
// a call with the overview document, which is a different question, not an error.
func TestClosedEnumsRejectUnknownValues(t *testing.T) {
	cs, seen := probeSession(t)
	checked := 0
	for _, p := range enumParams {
		probe, ok := enumProbes[p.key()]
		if !ok || !p.enum.closed {
			continue
		}
		checked++
		clear(seen)
		res := callTool(t, cs, p.tool, probe("SomethingElse"))
		if !res.IsError {
			t.Errorf("%s accepted %q instead of refusing it; it reached the API as %q", p.key(), "SomethingElse", seen[p.key()])
		}
	}
	if checked == 0 {
		t.Fatal("no closed enums were checked")
	}
}

// A registry entry with no probe is an entry nothing checks: it would claim a
// parameter is normalised while the handler still forwards the raw value.
func TestEveryEnumParamHasAProbe(t *testing.T) {
	keys := map[string]bool{}
	for _, p := range enumParams {
		keys[p.key()] = true
		if _, ok := enumProbes[p.key()]; !ok {
			t.Errorf("%s is in enumParams but has no probe, so nothing proves its tool normalises it", p.key())
		}
	}
	for k := range enumProbes {
		if !keys[k] {
			t.Errorf("probe %q has no matching enumParams entry", k)
		}
	}
}

// Folding must stay confined to the enum parameters: realm names, usernames and
// client IDs are case-sensitive everywhere in Keycloak.
func TestCaseSensitiveSiblingsAreNotFolded(t *testing.T) {
	var got skycloak.EventQuery
	api := stubAPI{gotEventQuery: &got}
	if _, _, err := queryEventsHandler(api)(t.Context(), nil, QueryEventsInput{
		ClusterID: "c1", Category: "USER", Realm: "MyRealm", Username: "Alice",
	}); err != nil {
		t.Fatalf("query events: %v", err)
	}
	if got.Realm != "MyRealm" || got.Username != "Alice" {
		t.Errorf("realm/username were folded: realm=%q username=%q", got.Realm, got.Username)
	}
}

// The identity-provider path parameter is the provider's alias, which the spec
// types as a free-form string, not as the SkycloakProviderId enum. Folding it
// would point a lookup, or a delete, at a different provider.
func TestIdentityProviderAliasIsNotFolded(t *testing.T) {
	cs, seen := probeSession(t)
	for _, tool := range []string{
		"skycloak_get_identity_provider", "skycloak_update_identity_provider",
		"skycloak_test_identity_provider", "skycloak_delete_identity_provider",
	} {
		clear(seen)
		args := map[string]any{"cluster_id": "c1", "realm": "r", "provider_id": "Google"}
		if tool == "skycloak_delete_identity_provider" {
			args["confirm"] = true
		}
		if res := callTool(t, cs, tool, args); res.IsError {
			t.Fatalf("%s refused the call: %v", tool, res.Content)
		}
		if got := seen["alias"]; got != "Google" {
			t.Errorf("%s sent alias %q, want %q untouched", tool, got, "Google")
		}
	}
}

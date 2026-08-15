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
	return nil, nil
}

func (r recAPI) CreateExport(_ context.Context, _, format string, _ bool, _ string) (*skycloak.Export, error) {
	r.seen["skycloak_create_export.format"] = format
	return &skycloak.Export{ID: "e1"}, nil
}

func (r recAPI) CreateApplication(_ context.Context, _, _ string, req skycloak.CreateApplicationRequest) (string, string, error) {
	r.seen["skycloak_create_application.type"] = req.Type
	r.seen["skycloak_create_application.protocol"] = req.Protocol
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

func (r recAPI) ClusterTypeVersions(_ context.Context, clusterType string) ([]string, error) {
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

func (r recAPI) GetIdentityProvider(_ context.Context, _, _, providerID string) (*skycloak.IdentityProvider, error) {
	r.seen["skycloak_get_identity_provider.provider_id"] = providerID
	return &skycloak.IdentityProvider{ProviderID: providerID}, nil
}

func (r recAPI) UpdateIdentityProvider(_ context.Context, _, _, providerID, _ string, _ bool) (*skycloak.IdentityProvider, error) {
	r.seen["skycloak_update_identity_provider.provider_id"] = providerID
	return &skycloak.IdentityProvider{ProviderID: providerID}, nil
}

func (r recAPI) DeleteIdentityProvider(_ context.Context, _, _, providerID string) error {
	r.seen["skycloak_delete_identity_provider.provider_id"] = providerID
	return nil
}

func (r recAPI) TestIdentityProviderConnection(_ context.Context, _, _, providerID, _, _ string) (*skycloak.TestResult, error) {
	r.seen["skycloak_test_identity_provider.provider_id"] = providerID
	return &skycloak.TestResult{Success: true}, nil
}

// enumProbes drives the real handler for one normalised parameter with v in
// that field. Hand-written per parameter: every tool input is its own Go
// struct, so there is no mechanical way to set "the field called size" across
// all of them. TestEveryEnumParamHasAProbe keeps the set complete.
var enumProbes = map[string]func(t *testing.T, api API, v string){
	"skycloak_get_logs.level": func(t *testing.T, api API, v string) {
		call(t, getLogsHandler(api), GetLogsInput{ClusterID: "c1", Level: v})
	},
	"skycloak_query_events.category": func(t *testing.T, api API, v string) {
		call(t, queryEventsHandler(api), QueryEventsInput{ClusterID: "c1", Category: v})
	},
	"skycloak_create_export.format": func(t *testing.T, api API, v string) {
		call(t, createExportHandler(api), CreateExportInput{ClusterID: "c1", Format: v})
	},
	"skycloak_create_application.type": func(t *testing.T, api API, v string) {
		call(t, createApplicationHandler(api), CreateApplicationInput{ClusterID: "c1", Realm: "r", ClientID: "app", Type: v})
	},
	"skycloak_create_application.protocol": func(t *testing.T, api API, v string) {
		call(t, createApplicationHandler(api), CreateApplicationInput{ClusterID: "c1", Realm: "r", ClientID: "app", Protocol: v})
	},
	"skycloak_create_cluster.type": func(t *testing.T, api API, v string) {
		call(t, createClusterHandler(api), CreateClusterInput{Name: "n", Size: "small", Version: "26.1", Location: "eu", Type: v})
	},
	"skycloak_create_cluster.size": func(t *testing.T, api API, v string) {
		call(t, createClusterHandler(api), CreateClusterInput{Name: "n", Version: "26.1", Location: "eu", Size: v})
	},
	"skycloak_create_cluster.location": func(t *testing.T, api API, v string) {
		call(t, createClusterHandler(api), CreateClusterInput{Name: "n", Size: "small", Version: "26.1", Location: v})
	},
	"skycloak_update_cluster.size": func(t *testing.T, api API, v string) {
		call(t, updateClusterHandler(api), UpdateClusterInput{ClusterID: "c1", Size: v})
	},
	"skycloak_upsert_smtp.encryption": func(t *testing.T, api API, v string) {
		call(t, upsertSMTPHandler(api), UpsertSMTPInput{ClusterID: "c1", Realm: "r", Host: "smtp.example.com", FromEmail: "a@b.c", Encryption: v})
	},
	"skycloak_list_cluster_versions.type": func(t *testing.T, api API, v string) {
		call(t, listClusterVersionsHandler(api), ClusterTypeInput{Type: v})
	},
	"skycloak_get_cluster_insights.type": func(t *testing.T, api API, v string) {
		call(t, getClusterInsightsHandler(api), InsightsInput{ClusterID: "c1", Type: v})
	},
	"skycloak_list_webhook_event_types.source": func(t *testing.T, api API, v string) {
		call(t, listWebhookEventTypesHandler(api), WebhookEventTypesInput{Source: v})
	},
	"skycloak_list_webhook_subscriptions.source": func(t *testing.T, api API, v string) {
		call(t, listWebhookSubscriptionsHandler(api), skycloak.ListWebhookSubscriptionsFilter{Source: v})
	},
	"skycloak_create_webhook_subscription.source": func(t *testing.T, api API, v string) {
		call(t, createWebhookSubscriptionHandler(api), skycloak.CreateWebhookSubscriptionRequest{
			Name: "w", URL: "https://example.com", Source: v, SigningSecret: "s", EventTypes: []string{"LOGIN"},
		})
	},
	"skycloak_update_webhook_subscription.source": func(t *testing.T, api API, v string) {
		call(t, updateWebhookSubscriptionHandler(api), UpdateWebhookSubscriptionInput{
			WebhookID: "w1", UpdateWebhookSubscriptionRequest: skycloak.UpdateWebhookSubscriptionRequest{Source: &v},
		})
	},
	"skycloak_create_siem_destination.type": func(t *testing.T, api API, v string) {
		call(t, createSIEMDestinationHandler(api), newSIEMCreate(func(r *skycloak.CreateSIEMDestinationRequest) { r.Type = v }))
	},
	"skycloak_create_siem_destination.source.type": func(t *testing.T, api API, v string) {
		call(t, createSIEMDestinationHandler(api), newSIEMCreate(func(r *skycloak.CreateSIEMDestinationRequest) { r.Source.Type = v }))
	},
	"skycloak_create_siem_destination.syslog.protocol": func(t *testing.T, api API, v string) {
		call(t, createSIEMDestinationHandler(api), newSIEMCreate(func(r *skycloak.CreateSIEMDestinationRequest) { r.Syslog.Protocol = v }))
	},
	"skycloak_create_siem_destination.syslog.format": func(t *testing.T, api API, v string) {
		call(t, createSIEMDestinationHandler(api), newSIEMCreate(func(r *skycloak.CreateSIEMDestinationRequest) { r.Syslog.Format = v }))
	},
	"skycloak_create_siem_destination.http.auth_type": func(t *testing.T, api API, v string) {
		call(t, createSIEMDestinationHandler(api), newSIEMCreate(func(r *skycloak.CreateSIEMDestinationRequest) { r.HTTP.AuthType = v }))
	},
	"skycloak_create_siem_destination.s3.auth_type": func(t *testing.T, api API, v string) {
		call(t, createSIEMDestinationHandler(api), newSIEMCreate(func(r *skycloak.CreateSIEMDestinationRequest) { r.S3.AuthType = v }))
	},
	"skycloak_update_siem_destination.source.type": func(t *testing.T, api API, v string) {
		call(t, updateSIEMDestinationHandler(api), newSIEMUpdate(func(r *skycloak.UpdateSIEMDestinationRequest) { r.Source.Type = v }))
	},
	"skycloak_update_siem_destination.syslog.protocol": func(t *testing.T, api API, v string) {
		call(t, updateSIEMDestinationHandler(api), newSIEMUpdate(func(r *skycloak.UpdateSIEMDestinationRequest) { r.Syslog.Protocol = v }))
	},
	"skycloak_update_siem_destination.syslog.format": func(t *testing.T, api API, v string) {
		call(t, updateSIEMDestinationHandler(api), newSIEMUpdate(func(r *skycloak.UpdateSIEMDestinationRequest) { r.Syslog.Format = v }))
	},
	"skycloak_update_siem_destination.http.auth_type": func(t *testing.T, api API, v string) {
		call(t, updateSIEMDestinationHandler(api), newSIEMUpdate(func(r *skycloak.UpdateSIEMDestinationRequest) { r.HTTP.AuthType = v }))
	},
	"skycloak_update_siem_destination.s3.auth_type": func(t *testing.T, api API, v string) {
		call(t, updateSIEMDestinationHandler(api), newSIEMUpdate(func(r *skycloak.UpdateSIEMDestinationRequest) { r.S3.AuthType = v }))
	},
	"skycloak_update_cluster_security.waf.mode": func(t *testing.T, api API, v string) {
		call(t, updateClusterSecurityHandler(api), UpdateClusterSecurityInput{ClusterID: "c1", WAF: &skycloak.WAF{Mode: v}})
	},
	"skycloak_update_cluster_security.waf.preset": func(t *testing.T, api API, v string) {
		call(t, updateClusterSecurityHandler(api), UpdateClusterSecurityInput{ClusterID: "c1", WAF: &skycloak.WAF{Preset: v}})
	},
	"skycloak_update_cluster_security.geo_blocking.mode": func(t *testing.T, api API, v string) {
		call(t, updateClusterSecurityHandler(api), UpdateClusterSecurityInput{ClusterID: "c1", GeoBlocking: &skycloak.GeoBlocking{Mode: v}})
	},
	"skycloak_update_cluster_security.bot_management.mode": func(t *testing.T, api API, v string) {
		call(t, updateClusterSecurityHandler(api), UpdateClusterSecurityInput{ClusterID: "c1", BotManagement: &skycloak.BotManagement{Mode: v}})
	},
	"skycloak_update_cluster_security.bot_management.challenge_mode": func(t *testing.T, api API, v string) {
		call(t, updateClusterSecurityHandler(api), UpdateClusterSecurityInput{ClusterID: "c1", BotManagement: &skycloak.BotManagement{ChallengeMode: v}})
	},
	"skycloak_create_identity_provider.provider_id": func(t *testing.T, api API, v string) {
		call(t, createIdentityProviderHandler(api), CreateIdentityProviderInput{ClusterID: "c1", Realm: "r", ProviderID: v, DisplayName: "d"})
	},
	"skycloak_get_identity_provider.provider_id": func(t *testing.T, api API, v string) {
		call(t, getIdentityProviderHandler(api), IDPRef{ClusterID: "c1", Realm: "r", ProviderID: v})
	},
	"skycloak_update_identity_provider.provider_id": func(t *testing.T, api API, v string) {
		call(t, updateIdentityProviderHandler(api), UpdateIdentityProviderInput{ClusterID: "c1", Realm: "r", ProviderID: v})
	},
	"skycloak_delete_identity_provider.provider_id": func(t *testing.T, api API, v string) {
		call(t, deleteIdentityProviderHandler(api), DeleteIdentityProviderInput{ClusterID: "c1", Realm: "r", ProviderID: v, Confirm: true})
	},
	"skycloak_test_identity_provider.provider_id": func(t *testing.T, api API, v string) {
		call(t, testIdentityProviderHandler(api), TestIDPInput{ClusterID: "c1", Realm: "r", ProviderID: v})
	},
}

func newSIEMCreate(set func(*skycloak.CreateSIEMDestinationRequest)) skycloak.CreateSIEMDestinationRequest {
	r := skycloak.CreateSIEMDestinationRequest{
		Name:   "d",
		Type:   "syslog",
		Source: skycloak.SIEMSourceConfig{Type: "keycloak_events"},
		Syslog: &skycloak.SIEMSyslogConfig{Host: "h", Port: 514, Protocol: "tcp", Format: "json"},
		S3:     &skycloak.SIEMS3Config{AuthType: "iam_role", Bucket: "b", Region: "us-east-1"},
		HTTP:   &skycloak.SIEMHTTPConfig{URL: "https://example.com", AuthType: "none"},
	}
	set(&r)
	return r
}

func newSIEMUpdate(set func(*skycloak.UpdateSIEMDestinationRequest)) UpdateSIEMDestinationInput {
	r := skycloak.UpdateSIEMDestinationRequest{
		Source: &skycloak.SIEMSourceConfig{Type: "keycloak_events"},
		Syslog: &skycloak.SIEMSyslogConfig{Host: "h", Port: 514, Protocol: "tcp", Format: "json"},
		S3:     &skycloak.SIEMS3Config{AuthType: "iam_role", Bucket: "b", Region: "us-east-1"},
		HTTP:   &skycloak.SIEMHTTPConfig{URL: "https://example.com", AuthType: "none"},
	}
	set(&r)
	return UpdateSIEMDestinationInput{DestinationID: "d1", UpdateSIEMDestinationRequest: r}
}

// call runs a tool handler and fails the test if it errors or refuses, so a
// probe that stops reaching the API layer cannot pass silently.
func call[In, Out any](t *testing.T, h mcp.ToolHandlerFor[In, Out], in In) {
	t.Helper()
	res, _, err := h(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("handler returned an error: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("handler refused the input: %v", res.Content)
	}
}

func capitalise(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// Every value the API accepts must survive a round trip through the handler in
// any case the model might have written it in.
func TestEnumParamsAreNormalisedByTheirHandlers(t *testing.T) {
	for _, p := range enumParams {
		probe, ok := enumProbes[p.key()]
		if !ok {
			continue // TestEveryEnumParamHasAProbe reports this
		}
		for _, want := range p.enum.values {
			for _, spelling := range []string{strings.ToUpper(want), capitalise(want), " " + want + " "} {
				seen := map[string]string{}
				probe(t, recAPI{seen: seen}, spelling)
				if got := seen[p.key()]; got != want {
					t.Errorf("%s: %q reached the API as %q, want %q", p.key(), spelling, got, want)
				}
			}
		}
	}
}

// A value the enum does not list must reach the API untouched, so a value the
// API grew after this build still works and its error is the API's own.
func TestUnknownEnumValuesArePassedThrough(t *testing.T) {
	for _, p := range enumParams {
		probe, ok := enumProbes[p.key()]
		if !ok {
			continue
		}
		seen := map[string]string{}
		probe(t, recAPI{seen: seen}, "SomethingElse")
		if got := seen[p.key()]; got != "SomethingElse" {
			t.Errorf("%s: unknown value reached the API as %q, want it untouched", p.key(), got)
		}
	}
}

// A registry entry with no probe is an entry nothing checks: it would claim a
// parameter is normalised while the handler still forwards the raw value.
func TestEveryEnumParamHasAProbe(t *testing.T) {
	for _, p := range enumParams {
		if _, ok := enumProbes[p.key()]; !ok {
			t.Errorf("%s is in enumParams but has no probe, so nothing proves its handler normalises it", p.key())
		}
	}
	keys := map[string]bool{}
	for _, p := range enumParams {
		keys[p.key()] = true
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

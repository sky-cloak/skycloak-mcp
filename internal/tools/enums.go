package tools

import (
	"strings"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// apiEnum is one closed value set the Skycloak API accepts, spelled exactly as
// internal/apiclient/openapi.yaml declares it. A wrong case is a 422
// "Invalid parameter" (or, where the value picks a path, a wrong or missing
// document) that never says the case was the problem, and a model has no way
// to know which enums are lowercase: UserEventType, AdminOperationType and
// DnsRecordType are uppercase, so nothing here may assume a blanket casing.
//
// enums_spec_test.go re-reads the spec and fails if these drift from it.
type apiEnum struct {
	// schema is the component schema in openapi.yaml that declares the values,
	// or "" when they come from the paths rather than a named schema.
	schema string
	values []string
}

// canonical folds v to the casing its own enum uses. A value that matches
// nothing is returned trimmed but otherwise untouched, so a value the API has
// grown since this build still reaches it and the API's own error is what the
// caller sees.
func (e apiEnum) canonical(v string) string {
	t := strings.TrimSpace(v)
	for _, want := range e.values {
		if strings.EqualFold(t, want) {
			return want
		}
	}
	return t
}

// canonicalPtr normalises through a pointer, leaving an absent value absent.
func (e apiEnum) canonicalPtr(v *string) *string {
	if v == nil {
		return nil
	}
	c := e.canonical(*v)
	return &c
}

var (
	enumLogLevel            = apiEnum{"LogLevel", []string{"info", "warn", "error", "debug"}}
	enumEventCategory       = apiEnum{"EventCategory", []string{"user", "admin"}}
	enumExportFormat        = apiEnum{"ExportFormat", []string{"sql", "pgdump"}}
	enumApplicationType     = apiEnum{"ApplicationType", []string{"confidential", "public"}}
	enumApplicationProtocol = apiEnum{"ApplicationProtocol", []string{"openid-connect", "saml"}}
	enumClusterType         = apiEnum{"ClusterType", []string{"keycloak", "tidecloak"}}
	enumClusterSize         = apiEnum{"ClusterSize", []string{"small", "medium", "large"}}
	enumClusterLocation     = apiEnum{"ClusterLocation", []string{"us", "ca", "au", "eu"}}
	enumSMTPEncryption      = apiEnum{"SmtpEncryption", []string{"none", "ssl", "starttls"}}
	enumWebhookSource       = apiEnum{"WebhookSource", []string{"keycloak", "platform"}}
	enumSIEMDestinationType = apiEnum{"SIEMDestinationType", []string{"syslog", "s3", "http"}}
	enumSIEMSourceType      = apiEnum{"SIEMSourceType", []string{"keycloak_events", "application_logs", "security_logs", "skycloak_audit"}}
	enumSyslogProtocol      = apiEnum{"SyslogProtocol", []string{"udp", "tcp", "tls"}}
	enumSyslogFormat        = apiEnum{"SyslogFormat", []string{"cef", "leef", "rfc5424", "json"}}
	enumHTTPAuthType        = apiEnum{"HTTPAuthType", []string{"none", "bearer", "basic"}}
	enumS3AuthType          = apiEnum{"S3AuthType", []string{"access_key", "iam_role", "assume_role", "irsa"}}
	enumSecurityMode        = apiEnum{"SecurityMode", []string{"detect", "block"}}
	enumWAFPreset           = apiEnum{"WAFPreset", []string{"full_crs", "owasp_top_10", "custom"}}
	enumBotChallengeMode    = apiEnum{"BotChallengeMode", []string{"none", "javascript", "captcha"}}
	enumGeoBlockingMode     = apiEnum{"GeoBlockingMode", []string{"allowlist", "blocklist"}}

	enumProviderID = apiEnum{"SkycloakProviderId", []string{
		"oidc", "saml", "keycloak-oidc", "google", "github", "microsoft", "facebook",
		"gitlab", "bitbucket", "linkedin-openid-connect", "twitter", "instagram",
		"paypal", "stackoverflow", "openshift-v4", "google-workspace", "okta-oidc",
		"onelogin-oidc", "jumpcloud-oidc", "pingone-oidc", "auth0", "salesforce",
		"slack", "discord", "atlassian", "twitch", "custom-oidc",
		"google-workspace-saml", "okta-saml", "azure-ad-saml", "onelogin-saml",
		"jumpcloud-saml", "pingfederate-saml", "pingone-saml", "duo-saml",
		"cloudflare-saml", "cyberark-saml", "custom-saml",
	}}

	// The insight kinds are separate endpoints rather than one enum, so the
	// values come from the /insights/… paths. Getting the case wrong here used
	// to fall through to the overview document, which answers the wrong
	// question without erroring.
	enumInsightType = apiEnum{"", []string{"overview", "authentication", "events", "performance", "security"}}
)

// enumParam is one tool input field that maps to an API enum. field is the
// dotted path into the tool's input schema.
type enumParam struct {
	tool  string
	field string
	enum  apiEnum
}

func (p enumParam) key() string { return p.tool + "." + p.field }

// enumParams is the inventory of every enum-backed tool parameter this package
// normalises. enums_spec_test.go checks it both ways: no entry may claim a
// value set the spec does not declare, and no enum-backed parameter may be
// missing from it.
var enumParams = []enumParam{
	{"skycloak_get_logs", "level", enumLogLevel},
	{"skycloak_query_events", "category", enumEventCategory},
	{"skycloak_create_export", "format", enumExportFormat},
	{"skycloak_create_application", "type", enumApplicationType},
	{"skycloak_create_application", "protocol", enumApplicationProtocol},
	{"skycloak_create_cluster", "type", enumClusterType},
	{"skycloak_create_cluster", "size", enumClusterSize},
	{"skycloak_create_cluster", "location", enumClusterLocation},
	{"skycloak_update_cluster", "size", enumClusterSize},
	{"skycloak_upsert_smtp", "encryption", enumSMTPEncryption},
	{"skycloak_list_cluster_versions", "type", enumClusterType},
	{"skycloak_get_cluster_insights", "type", enumInsightType},
	{"skycloak_list_webhook_event_types", "source", enumWebhookSource},
	{"skycloak_list_webhook_subscriptions", "source", enumWebhookSource},
	{"skycloak_create_webhook_subscription", "source", enumWebhookSource},
	{"skycloak_update_webhook_subscription", "source", enumWebhookSource},
	{"skycloak_create_siem_destination", "type", enumSIEMDestinationType},
	{"skycloak_create_siem_destination", "source.type", enumSIEMSourceType},
	{"skycloak_create_siem_destination", "syslog.protocol", enumSyslogProtocol},
	{"skycloak_create_siem_destination", "syslog.format", enumSyslogFormat},
	{"skycloak_create_siem_destination", "http.auth_type", enumHTTPAuthType},
	{"skycloak_create_siem_destination", "s3.auth_type", enumS3AuthType},
	{"skycloak_update_siem_destination", "source.type", enumSIEMSourceType},
	{"skycloak_update_siem_destination", "syslog.protocol", enumSyslogProtocol},
	{"skycloak_update_siem_destination", "syslog.format", enumSyslogFormat},
	{"skycloak_update_siem_destination", "http.auth_type", enumHTTPAuthType},
	{"skycloak_update_siem_destination", "s3.auth_type", enumS3AuthType},
	{"skycloak_update_cluster_security", "waf.mode", enumSecurityMode},
	{"skycloak_update_cluster_security", "waf.preset", enumWAFPreset},
	{"skycloak_update_cluster_security", "geo_blocking.mode", enumGeoBlockingMode},
	{"skycloak_update_cluster_security", "bot_management.mode", enumSecurityMode},
	{"skycloak_update_cluster_security", "bot_management.challenge_mode", enumBotChallengeMode},
	// The alias of a provider instance is always the SkycloakProviderId it was
	// created with, so the same folding is right on the path parameter too.
	{"skycloak_create_identity_provider", "provider_id", enumProviderID},
	{"skycloak_get_identity_provider", "provider_id", enumProviderID},
	{"skycloak_update_identity_provider", "provider_id", enumProviderID},
	{"skycloak_delete_identity_provider", "provider_id", enumProviderID},
	{"skycloak_test_identity_provider", "provider_id", enumProviderID},
}

// normaliseSIEMSource folds the enum field of a SIEM source selector in place.
func normaliseSIEMSource(s *skycloak.SIEMSourceConfig) {
	if s != nil {
		s.Type = enumSIEMSourceType.canonical(s.Type)
	}
}

// normaliseSIEMTransport folds the enum fields of the transport-specific SIEM
// configs, which the create and update inputs share.
func normaliseSIEMTransport(syslog *skycloak.SIEMSyslogConfig, s3 *skycloak.SIEMS3Config, httpCfg *skycloak.SIEMHTTPConfig) {
	if syslog != nil {
		syslog.Protocol = enumSyslogProtocol.canonical(syslog.Protocol)
		syslog.Format = enumSyslogFormat.canonical(syslog.Format)
	}
	if s3 != nil {
		s3.AuthType = enumS3AuthType.canonical(s3.AuthType)
	}
	if httpCfg != nil {
		httpCfg.AuthType = enumHTTPAuthType.canonical(httpCfg.AuthType)
	}
}

// normaliseClusterSecurity folds the mode and preset fields of the edge-security
// sections in place.
func normaliseClusterSecurity(sec *skycloak.ClusterSecurity) {
	if sec.WAF != nil {
		sec.WAF.Mode = enumSecurityMode.canonical(sec.WAF.Mode)
		sec.WAF.Preset = enumWAFPreset.canonical(sec.WAF.Preset)
	}
	if sec.GeoBlocking != nil {
		sec.GeoBlocking.Mode = enumGeoBlockingMode.canonical(sec.GeoBlocking.Mode)
	}
	if sec.BotManagement != nil {
		sec.BotManagement.Mode = enumSecurityMode.canonical(sec.BotManagement.Mode)
		sec.BotManagement.ChallengeMode = enumBotChallengeMode.canonical(sec.BotManagement.ChallengeMode)
	}
}

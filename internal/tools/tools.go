// Package tools registers Skycloak MCP tools and prompts on a server.
package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// API is the subset of the Skycloak client the tools depend on. It is an
// interface so tool handlers can be unit-tested against a stub.
type API interface {
	ListClusters(ctx context.Context, p skycloak.ListClustersParams) ([]skycloak.Cluster, error)
	GetCluster(ctx context.Context, id string) (*skycloak.Cluster, error)
	ListRealms(ctx context.Context, clusterID string) ([]skycloak.Realm, error)
	ListApplications(ctx context.Context, clusterID, realm string) ([]skycloak.Application, error)
	ListIdentityProviders(ctx context.Context, clusterID, realm string) ([]skycloak.IdentityProvider, error)
	CreateRealm(ctx context.Context, clusterID string, r skycloak.Realm) (*skycloak.Realm, error)
	DeleteRealm(ctx context.Context, clusterID, name string) error
	CreateCluster(ctx context.Context, req skycloak.CreateClusterRequest) (*skycloak.Cluster, error)
	DeleteCluster(ctx context.Context, id string) error
	CreateApplication(ctx context.Context, clusterID, realm string, req skycloak.CreateApplicationRequest) (clientID, clientSecret string, err error)
	DeleteApplication(ctx context.Context, clusterID, realm, clientID string) error
	CreateOIDCIdentityProvider(ctx context.Context, clusterID, realm string, req skycloak.CreateOIDCIdentityProviderRequest) error
	DeleteIdentityProvider(ctx context.Context, clusterID, realm, providerID string) error
	GetLogs(ctx context.Context, clusterID string, q skycloak.LogQuery) ([]skycloak.LogEntry, error)
	GetSecurityLogs(ctx context.Context, clusterID string, q skycloak.SecurityLogQuery) ([]skycloak.SecurityLogEntry, error)
	QueryEvents(ctx context.Context, clusterID string, q skycloak.EventQuery) ([]skycloak.EventEntry, error)
	ListDomains(ctx context.Context, clusterID string) ([]skycloak.Domain, error)
	GetDomain(ctx context.Context, clusterID, domainID string) (*skycloak.Domain, error)
	CreateDomain(ctx context.Context, clusterID, domain, subdomain string) (*skycloak.Domain, error)
	VerifyDomain(ctx context.Context, clusterID, domainID string) (*skycloak.Domain, error)
	DeleteDomain(ctx context.Context, clusterID, domainID string) error
	ListThemes(ctx context.Context, clusterID string) ([]skycloak.Theme, error)
	GetThemeAssignment(ctx context.Context, clusterID, realm string) (*skycloak.ThemeAssignment, error)
	SetThemeAssignment(ctx context.Context, clusterID, realm string, a skycloak.ThemeAssignment) (*skycloak.ThemeAssignment, error)
	GetLoginBranding(ctx context.Context, clusterID, realm string) (*skycloak.LoginBranding, error)
	GetEmailBranding(ctx context.Context, clusterID, realm string) (*skycloak.EmailBranding, error)
	ListExtensions(ctx context.Context) ([]skycloak.ExtensionInfo, error)
	ListClusterExtensions(ctx context.Context, clusterID string) ([]skycloak.ClusterExtension, error)
	InstallExtension(ctx context.Context, clusterID, extensionID string, params map[string]string) (*skycloak.ClusterExtension, error)
	UpgradeExtension(ctx context.Context, clusterID, extensionID string) (*skycloak.ClusterExtension, error)
	UninstallExtension(ctx context.Context, clusterID, extensionID string) error
	ListExports(ctx context.Context, clusterID string) ([]skycloak.Export, error)
	GetExport(ctx context.Context, clusterID, exportID string) (*skycloak.Export, error)
	CreateExport(ctx context.Context, clusterID, format string, includeCredentials bool, encryptionPassword string) (*skycloak.Export, error)
	ListRealmRoles(ctx context.Context, clusterID, realm string) ([]skycloak.RealmRole, error)
	CreateRealmRole(ctx context.Context, clusterID, realm, name, description string) (*skycloak.RealmRole, error)
	DeleteRealmRole(ctx context.Context, clusterID, realm, name string) error
	ListRealmGroups(ctx context.Context, clusterID, realm string) ([]skycloak.RealmGroup, error)
	CreateRealmGroup(ctx context.Context, clusterID, realm, name, parentID string) (*skycloak.RealmGroup, error)
	DeleteRealmGroup(ctx context.Context, clusterID, realm, groupID string) error
	ListRealmUsers(ctx context.Context, clusterID, realm string) ([]skycloak.RealmUser, error)
	GetRealmUser(ctx context.Context, clusterID, realm, userID string) (*skycloak.RealmUser, error)
	CreateRealmUser(ctx context.Context, clusterID, realm, username, email, firstName, lastName, temporaryPassword string, enabled bool) (*skycloak.RealmUser, error)
	DeleteRealmUser(ctx context.Context, clusterID, realm, userID string) error
	AssignRealmUserRole(ctx context.Context, clusterID, realm, userID, roleName string) error
	RemoveRealmUserRole(ctx context.Context, clusterID, realm, userID, roleName string) error
	AddRealmUserToGroup(ctx context.Context, clusterID, realm, userID, groupID string) error
	RemoveRealmUserFromGroup(ctx context.Context, clusterID, realm, userID, groupID string) error
	ListApplicationRoles(ctx context.Context, clusterID, realm, clientID string) ([]skycloak.ApplicationRole, error)
	AssignApplicationRole(ctx context.Context, clusterID, realm, clientID, roleName, roleClientID string) error
	RemoveApplicationRole(ctx context.Context, clusterID, realm, clientID, roleName, roleClientID string) error
	ListApplicationSessions(ctx context.Context, clusterID, realm, clientID string) ([]skycloak.ApplicationSession, error)
	GetRealm(ctx context.Context, clusterID, realm string) (*skycloak.Realm, error)
	GetApplication(ctx context.Context, clusterID, realm, clientID string) (*skycloak.Application, error)
	GetIdentityProvider(ctx context.Context, clusterID, realm, providerID string) (*skycloak.IdentityProvider, error)
	ListClusterLocations(ctx context.Context) ([]skycloak.ClusterLocationInfo, error)
	ListClusterTypes(ctx context.Context) ([]skycloak.ClusterTypeInfo, error)
	ListClusterFeatures(ctx context.Context) ([]skycloak.ClusterFeatureInfo, error)
	ClusterTypeVersions(ctx context.Context, clusterType string) ([]string, error)
	ListClusterUpgrades(ctx context.Context, clusterID string) ([]skycloak.ClusterUpgrade, error)
	ListIdentityProviderTemplates(ctx context.Context) ([]skycloak.ProviderTemplate, error)
	ListDomainRoutes(ctx context.Context, clusterID, domainID string) ([]skycloak.DomainRoute, error)
	GetSMTP(ctx context.Context, clusterID, realm string) (*skycloak.SMTPConfig, error)
	DeleteSMTP(ctx context.Context, clusterID, realm string) error
	RotateApplicationSecret(ctx context.Context, clusterID, realm, clientID string) (string, error)
	GetTheme(ctx context.Context, clusterID, themeID string) (*skycloak.Theme, error)
	DeleteTheme(ctx context.Context, clusterID, themeID string) error
	DeleteExtension(ctx context.Context, extensionID string) error
	DeleteExport(ctx context.Context, clusterID, exportID string) error
	GetDomainRoute(ctx context.Context, clusterID, domainID, routeID string) (*skycloak.DomainRoute, error)
	CreateDomainRoute(ctx context.Context, clusterID, domainID, realm string, allowAdminAccess, hideRealmPath bool) (*skycloak.DomainRoute, error)
	DeleteDomainRoute(ctx context.Context, clusterID, domainID, routeID string) error
	GetClientThemeAssignment(ctx context.Context, clusterID, realm, clientID string) (string, error)
	SetClientThemeAssignment(ctx context.Context, clusterID, realm, clientID, login string) (string, error)
	ListRealmUserRoles(ctx context.Context, clusterID, realm, userID string) ([]skycloak.RealmRole, error)
	ListRealmUserGroups(ctx context.Context, clusterID, realm, userID string) ([]skycloak.RealmGroup, error)
	UpdateRealm(ctx context.Context, clusterID, realm, displayName string, enabled bool) (*skycloak.Realm, error)
	DiscoverOIDC(ctx context.Context, issuerURL string) (*skycloak.OIDCDiscovery, error)
	TestSMTP(ctx context.Context, clusterID, realm, email string) (*skycloak.TestResult, error)
	TestIdentityProviderConnection(ctx context.Context, clusterID, realm, providerID, clientID, clientSecret string) (*skycloak.TestResult, error)
	CancelClusterUpgrade(ctx context.Context, clusterID string) error
	GetClusterSecurity(ctx context.Context, clusterID string) (*skycloak.ClusterSecurity, error)
	UpdateClusterSecurity(ctx context.Context, clusterID string, sec *skycloak.ClusterSecurity) (*skycloak.ClusterSecurity, error)
	ListClusterCAPTCHADomains(ctx context.Context, clusterID string) (*skycloak.CAPTCHADomainsInfo, error)
	AddClusterCAPTCHADomain(ctx context.Context, clusterID, hostname string) (*skycloak.CAPTCHADomain, error)
	RemoveClusterCAPTCHADomain(ctx context.Context, clusterID, hostname string) error
	GetClusterCredentials(ctx context.Context, clusterID string) (*skycloak.ClusterCredentials, error)
	GetClusterUpgradePath(ctx context.Context, clusterID string) ([]skycloak.UpgradePathStep, error)
	ClusterInsights(ctx context.Context, clusterID, kind string) ([]byte, error)
	GetRealmRole(ctx context.Context, clusterID, realm, name string) (*skycloak.RealmRole, error)
	GetRealmGroup(ctx context.Context, clusterID, realm, groupID string) (*skycloak.RealmGroup, error)
	ListRealmGroupMembers(ctx context.Context, clusterID, realm, groupID string) ([]skycloak.RealmUser, error)
	UpdateRealmRole(ctx context.Context, clusterID, realm, name, newName, description string) (*skycloak.RealmRole, error)
	UpdateRealmGroup(ctx context.Context, clusterID, realm, groupID, name string) (*skycloak.RealmGroup, error)
	UpdateRealmUser(ctx context.Context, clusterID, realm, userID, email, firstName, lastName string, enabled, emailVerified bool) (*skycloak.RealmUser, error)
	UpdateDomainRoute(ctx context.Context, clusterID, domainID, routeID string, allowAdminAccess bool, cors []string) (*skycloak.DomainRoute, error)
	UpdateApplication(ctx context.Context, clusterID, realm, clientID, name, description string, redirectURIs []string) (*skycloak.Application, error)
	UpdateIdentityProvider(ctx context.Context, clusterID, realm, providerID, displayName string, enabled bool) (*skycloak.IdentityProvider, error)
	UpdateCluster(ctx context.Context, clusterID, version, size string, autoUpgradeEnabled *bool) (*skycloak.Cluster, error)
	UpdateExtension(ctx context.Context, extensionID, name, description string) (*skycloak.ExtensionInfo, error)
	UpdateTheme(ctx context.Context, clusterID, themeID, name, description, version string) (*skycloak.Theme, error)
	UpsertSMTP(ctx context.Context, clusterID, realm string, req skycloak.UpsertSMTPRequest) (*skycloak.SMTPConfig, error)
	UpsertLoginBranding(ctx context.Context, clusterID, realm string, req skycloak.UpsertLoginBrandingRequest) (*skycloak.LoginBranding, error)
	UpsertEmailBranding(ctx context.Context, clusterID, realm string, req skycloak.UpsertEmailBrandingRequest) (*skycloak.EmailBranding, error)
	DeleteLoginBranding(ctx context.Context, clusterID, realm string) error
	DeleteEmailBranding(ctx context.Context, clusterID, realm string) error
	ExportClusterEvents(ctx context.Context, clusterID string) ([]byte, error)
	GetClusterMaintenanceWindow(ctx context.Context, clusterID string) (*skycloak.MaintenanceWindow, error)
	SetClusterMaintenanceWindow(ctx context.Context, clusterID string, window skycloak.MaintenanceWindow) (*skycloak.MaintenanceWindow, error)
	DeleteClusterMaintenanceWindow(ctx context.Context, clusterID string) error
	ListSIEMDestinations(ctx context.Context) ([]skycloak.SIEMDestination, error)
	CreateSIEMDestination(ctx context.Context, req skycloak.CreateSIEMDestinationRequest) (*skycloak.SIEMDestination, error)
	GetSIEMDestination(ctx context.Context, destinationID string) (*skycloak.SIEMDestination, error)
	UpdateSIEMDestination(ctx context.Context, destinationID string, req skycloak.UpdateSIEMDestinationRequest) (*skycloak.SIEMDestination, error)
	DeleteSIEMDestination(ctx context.Context, destinationID string) error
	TestSIEMDestination(ctx context.Context, destinationID string) (*skycloak.SIEMDestinationTestResult, error)
	ListWebhookEventTypes(ctx context.Context, source string) ([]skycloak.WebhookEventType, error)
	ListWebhookSubscriptions(ctx context.Context, filter skycloak.ListWebhookSubscriptionsFilter) ([]skycloak.WebhookSubscription, error)
	CreateWebhookSubscription(ctx context.Context, req skycloak.CreateWebhookSubscriptionRequest) (*skycloak.WebhookSubscription, error)
	GetWebhookSubscription(ctx context.Context, webhookID string) (*skycloak.WebhookSubscription, error)
	UpdateWebhookSubscription(ctx context.Context, webhookID string, req skycloak.UpdateWebhookSubscriptionRequest) (*skycloak.WebhookSubscription, error)
	DeleteWebhookSubscription(ctx context.Context, webhookID string) error
	TestWebhookSubscription(ctx context.Context, webhookID string, req skycloak.TestWebhookSubscriptionRequest) (*skycloak.WebhookTestResult, error)
	CreateRealmExport(ctx context.Context, clusterID, realm, encryptionPassword string) (*skycloak.RealmExport, error)
	GetRealmExport(ctx context.Context, exportID string) (*skycloak.RealmExport, error)
	CreateRealmImportUpload(ctx context.Context, clusterID string) (*skycloak.RealmImportUpload, error)
	CreateRealmImport(ctx context.Context, clusterID string, req skycloak.CreateRealmImportRequest) (*skycloak.RealmImport, error)
	GetRealmImport(ctx context.Context, importID string) (*skycloak.RealmImport, error)
	DownloadThemeContent(ctx context.Context, clusterID, themeID string) ([]byte, error)
}

// clusterCredentialsScope reads a cluster's Keycloak admin credentials. It is
// never part of an OAuth session's grant, so the tool behind it is registered
// only for a credential that explicitly carries the scope.
const clusterCredentialsScope = "clusters:credentials:read"

// Scopes is the set of API scopes the caller's credential carries.
//
// A nil Scopes means "unknown", and allows everything. Stdio and the API-key
// HTTP path are in that position: the key's scopes are not enumerable from
// here, and the Skycloak API is the authority anyway, so an over-broad tool
// list costs a 403 rather than access. A non-nil but empty set means the
// opposite: the caller is known to hold nothing.
type Scopes map[string]bool

// NewScopes builds a known scope set. The result is never nil, so an empty
// grant is not mistaken for an unknown one.
func NewScopes(list []string) Scopes {
	sc := make(Scopes, len(list))
	for _, s := range list {
		sc[s] = true
	}
	return sc
}

// grants reports whether every listed scope is held. Unknown scopes allow all.
//
// Requiring all of them rests on the dashboard issuing whole read or write
// sets, which is what the roles behind a session key do today. Were it ever to
// issue a partial set, this would drop tools with nothing said: a caller with
// `realms:read` but no `clusters:read` would lose every area naming both, and
// the tests would stay green because they assume the same whole sets. Granular
// roles would mean gating per tool rather than per area.
func (sc Scopes) grants(want ...string) bool {
	if sc == nil {
		return true
	}
	for _, w := range want {
		if !sc[w] {
			return false
		}
	}
	return true
}

// toolArea is one group of tools and the scopes a caller needs to be shown it.
//
// An area that spans several API areas lists all of their scopes, and is
// registered only when the caller holds the lot. That errs toward hiding a tool
// the caller could have used rather than advertising one that would 403, and it
// costs nothing in practice: a session key's scopes come from the caller's role
// as a whole read-only or read-write set, never a partial mix.
type toolArea struct {
	name     string
	write    bool
	scopes   []string
	register func(*mcp.Server, API)
}

// toolAreas maps every group of tools to the scopes it needs. Adding a tool to
// an area whose scope it does not have makes that tool 403 for scoped callers,
// so a new area belongs here with its own entry.
var toolAreas = []toolArea{
	{name: "clusters", scopes: []string{"clusters:read"}, register: registerClusterReadTools},
	{name: "realms", scopes: []string{"realms:read"}, register: registerRealmReadTools},
	{name: "applications", scopes: []string{"applications:read"}, register: registerApplicationReadTools},
	{name: "identity providers", scopes: []string{"identity-providers:read"}, register: registerIdentityProviderReadTools},
	// Security logs are a log endpoint, not a security-settings one, so this
	// area needs no clusters:security:read.
	{name: "observability", scopes: []string{"clusters:logs:read", "clusters:events:read"}, register: registerObservabilityReadTools},
	{name: "domains", scopes: []string{"domains:read"}, register: registerDomainReadTools},
	{name: "branding", scopes: []string{"themes:read", "branding:read"}, register: registerBrandingReadTools},
	{name: "extensions", scopes: []string{"extensions:read", "clusters:extensions:read"}, register: registerExtensionReadTools},
	{name: "exports", scopes: []string{"clusters:exports:read"}, register: registerExportReadTools},
	{name: "rbac", scopes: []string{"realm-roles:read", "realm-groups:read", "realm-users:read"}, register: registerRBACReadTools},
	{name: "application roles", scopes: []string{"applications:read"}, register: registerApplicationRoleReadTools},
	{name: "read parity", scopes: []string{"realms:read", "applications:read", "identity-providers:read", "clusters:read", "domains:read"}, register: registerReadParityTools},
	{name: "parity reads", scopes: []string{"smtp:read", "themes:read", "domains:read", "realm-roles:read", "realm-groups:read"}, register: registerParityReadTools},
	{name: "actions", scopes: []string{"identity-providers:read"}, register: registerActionReadTools},
	{name: "edge security", scopes: []string{"clusters:security:read"}, register: registerSecurityReadTools},
	{name: "siem", scopes: []string{"siem:read"}, register: registerSIEMReadTools},
	{name: "webhooks", scopes: []string{"webhooks:read"}, register: registerWebhookReadTools},
	{name: "cluster detail reads", scopes: []string{"clusters:read", "clusters:insights:read", "realm-roles:read", "realm-groups:read"}, register: registerReads2Tools},
	{name: "cluster credentials", scopes: []string{clusterCredentialsScope}, register: registerClusterCredentialsTool},
	{name: "realm transfer reads", scopes: []string{"clusters:exports:read", "clusters:imports:read", "themes:read"}, register: registerRealmTransferReadTools},

	// verify_domain triggers a DNS check and the API scopes it as a read.
	{name: "domain writes", write: true, scopes: []string{"domains:write", "domains:read"}, register: registerDomainWriteTools},
	{name: "branding writes", write: true, scopes: []string{"themes:write"}, register: registerBrandingWriteTools},
	{name: "extension writes", write: true, scopes: []string{"clusters:extensions:write"}, register: registerExtensionWriteTools},
	{name: "export writes", write: true, scopes: []string{"clusters:exports:write"}, register: registerExportWriteTools},
	{name: "rbac writes", write: true, scopes: []string{"realm-roles:write", "realm-groups:write", "realm-users:write"}, register: registerRBACWriteTools},
	{name: "application role writes", write: true, scopes: []string{"applications:write"}, register: registerApplicationRoleWriteTools},
	{name: "parity writes", write: true, scopes: []string{"applications:write", "realms:write", "smtp:write", "domains:write", "themes:write", "extensions:write", "clusters:exports:write"}, register: registerParityWriteTools},
	{name: "action writes", write: true, scopes: []string{"smtp:write", "identity-providers:write", "clusters:write"}, register: registerActionWriteTools},
	// update_cluster_security is a read-modify-write: it reads the current
	// config so the sections it does not manage survive the update.
	{name: "edge security writes", write: true, scopes: []string{"clusters:security:write", "clusters:security:read"}, register: registerSecurityWriteTools},
	{name: "siem writes", write: true, scopes: []string{"siem:write"}, register: registerSIEMWriteTools},
	{name: "webhook writes", write: true, scopes: []string{"webhooks:write"}, register: registerWebhookWriteTools},
	{name: "detail writes", write: true, scopes: []string{"realm-roles:write", "realm-groups:write", "realm-users:write", "domains:write", "applications:write", "identity-providers:write", "clusters:write", "extensions:write", "themes:write", "smtp:write", "branding:write", "clusters:events:read"}, register: registerWrites2Tools},
	{name: "realm transfer writes", write: true, scopes: []string{"clusters:exports:write", "clusters:imports:write"}, register: registerRealmTransferWriteTools},
	{name: "cluster writes", write: true, scopes: []string{"clusters:write"}, register: registerClusterWriteTools},
	{name: "application writes", write: true, scopes: []string{"applications:write"}, register: registerApplicationWriteTools},
	{name: "identity provider writes", write: true, scopes: []string{"identity-providers:write"}, register: registerIdentityProviderWriteTools},
	{name: "realm writes", write: true, scopes: []string{"realms:write"}, register: registerRealmWriteTools},
}

// Register adds tools and prompts to the server.
//
// Read-only tools are registered when the caller's scopes cover them. Mutating
// tools additionally need allowWrites, so a server started read-only stays
// read-only whatever the credential could do. Pass nil scopes when the
// credential's grant is not knowable. Prompts follow the same gating as the
// tools they name.
func Register(s *mcp.Server, api API, allowWrites bool, scopes Scopes) {
	for _, area := range toolAreas {
		if area.write && !allowWrites {
			continue
		}
		if !scopes.grants(area.scopes...) {
			continue
		}
		area.register(s, api)
	}
	registerPrompts(s, allowWrites, scopes)
}

// ptr returns a pointer to v. Used for optional *bool tool annotations.
func ptr[T any](v T) *T { return &v }

// toolError converts an error into a tool-call error result the model can read
// and act on. Transport-level failures are returned as Go errors; API-level
// failures (4xx/5xx) are surfaced as IsError results with actionable hints.
func toolError(err error) *mcp.CallToolResult {
	msg := err.Error()
	if apiErr, ok := skycloak.AsAPIError(err); ok {
		switch apiErr.StatusCode {
		case 401:
			msg = "Unauthorized — the API key is missing or invalid. " + msg
		case 403:
			msg = "Forbidden — your API key lacks the required scope for this action. " + msg
		case 429:
			msg = "Rate limited by the Skycloak gateway — wait and retry. " + msg
		}
	}
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

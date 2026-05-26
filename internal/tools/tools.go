// Package tools registers Skycloak MCP tools on a server.
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
	GetClusterCredentials(ctx context.Context, clusterID string) (*skycloak.ClusterCredentials, error)
	ListClusterBuilds(ctx context.Context, clusterID string) ([]skycloak.ClusterBuild, error)
	GetClusterBuild(ctx context.Context, clusterID, buildID string) (*skycloak.ClusterBuild, error)
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
	UpdateCluster(ctx context.Context, clusterID, version, size string) (*skycloak.Cluster, error)
	UpdateExtension(ctx context.Context, extensionID, name, description string) (*skycloak.ExtensionInfo, error)
	UpdateTheme(ctx context.Context, clusterID, themeID, name, description, version string) (*skycloak.Theme, error)
	UpsertSMTP(ctx context.Context, clusterID, realm string, req skycloak.UpsertSMTPRequest) (*skycloak.SMTPConfig, error)
	UpsertLoginBranding(ctx context.Context, clusterID, realm string, req skycloak.UpsertLoginBrandingRequest) (*skycloak.LoginBranding, error)
	UpsertEmailBranding(ctx context.Context, clusterID, realm string, req skycloak.UpsertEmailBrandingRequest) (*skycloak.EmailBranding, error)
	DeleteLoginBranding(ctx context.Context, clusterID, realm string) error
	DeleteEmailBranding(ctx context.Context, clusterID, realm string) error
	ExportClusterEvents(ctx context.Context, clusterID string) ([]byte, error)
}

// Register adds all tools to the server.
//
// Read-only tools are always registered. Mutating tools are registered only
// when allowWrites is true and the API key carries the matching write scope.
func Register(s *mcp.Server, api API, allowWrites bool) {
	registerClusterReadTools(s, api)
	registerRealmReadTools(s, api)
	registerApplicationReadTools(s, api)
	registerIdentityProviderReadTools(s, api)
	registerObservabilityReadTools(s, api)
	registerDomainReadTools(s, api)
	registerBrandingReadTools(s, api)
	registerExtensionReadTools(s, api)
	registerExportReadTools(s, api)
	registerRBACReadTools(s, api)
	registerApplicationRoleReadTools(s, api)
	registerReadParityTools(s, api)
	registerParityReadTools(s, api)
	registerActionReadTools(s, api)
	registerSecurityReadTools(s, api)
	registerReads2Tools(s, api)
	if allowWrites {
		registerWriteTools(s, api)
	}
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
			msg = "Unauthorized — check that SKYCLOAK_API_KEY is set and valid. " + msg
		case 403:
			msg = "Forbidden — your API key lacks the required scope for this action. " + msg
		case 429:
			msg = "Rate limited by the Skycloak gateway — wait and retry. " + msg
		}
	}
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

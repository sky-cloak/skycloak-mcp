package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

type stubAPI struct {
	clusters  []skycloak.Cluster
	cluster   *skycloak.Cluster
	realms    []skycloak.Realm
	apps      []skycloak.Application
	idps      []skycloak.IdentityProvider
	logs      []skycloak.LogEntry
	secLogs   []skycloak.SecurityLogEntry
	events    []skycloak.EventEntry
	domains   []skycloak.Domain
	domain    *skycloak.Domain
	themes    []skycloak.Theme
	assign    *skycloak.ThemeAssignment
	login     *skycloak.LoginBranding
	email     *skycloak.EmailBranding
	catalog   []skycloak.ExtensionInfo
	clusExts  []skycloak.ClusterExtension
	exports   []skycloak.Export
	export    *skycloak.Export
	rroles    []skycloak.RealmRole
	rgroups   []skycloak.RealmGroup
	rusers    []skycloak.RealmUser
	ruser     *skycloak.RealmUser
	appRoles  []skycloak.ApplicationRole
	appSess   []skycloak.ApplicationSession
	locations []skycloak.ClusterLocationInfo
	ctypes    []skycloak.ClusterTypeInfo
	features  []skycloak.ClusterFeatureInfo
	versions  []string
	upgrades  []skycloak.ClusterUpgrade
	templates []skycloak.ProviderTemplate
	routes    []skycloak.DomainRoute
	app       *skycloak.Application
	idp       *skycloak.IdentityProvider
	realm     *skycloak.Realm
	smtp      *skycloak.SMTPConfig
	theme     *skycloak.Theme
	route     *skycloak.DomainRoute
	upPath    []skycloak.UpgradePathStep
	err       error
}

func (s stubAPI) ListClusters(context.Context, skycloak.ListClustersParams) ([]skycloak.Cluster, error) {
	return s.clusters, s.err
}

func (s stubAPI) GetCluster(context.Context, string) (*skycloak.Cluster, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.cluster == nil {
		return nil, errors.New("no cluster configured in stub")
	}
	return s.cluster, nil
}

func (s stubAPI) ListRealms(context.Context, string) ([]skycloak.Realm, error) {
	return s.realms, s.err
}

func (s stubAPI) ListApplications(context.Context, string, string) ([]skycloak.Application, error) {
	return s.apps, s.err
}

func (s stubAPI) ListIdentityProviders(context.Context, string, string) ([]skycloak.IdentityProvider, error) {
	return s.idps, s.err
}

func (s stubAPI) CreateRealm(_ context.Context, _ string, r skycloak.Realm) (*skycloak.Realm, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &r, nil
}

func (s stubAPI) DeleteRealm(context.Context, string, string) error {
	return s.err
}

func (s stubAPI) CreateCluster(_ context.Context, req skycloak.CreateClusterRequest) (*skycloak.Cluster, error) {
	if s.err != nil {
		return nil, s.err
	}
	autoUpgradeEnabled := false
	if req.AutoUpgradeEnabled != nil {
		autoUpgradeEnabled = *req.AutoUpgradeEnabled
	}
	return &skycloak.Cluster{ID: "new", Name: req.Name, Status: "provisioning", Type: req.Type, Size: req.Size, Version: req.Version, Location: req.Location, AutoUpgradeEnabled: autoUpgradeEnabled}, nil
}

func (s stubAPI) DeleteCluster(context.Context, string) error {
	return s.err
}

func (s stubAPI) CreateApplication(_ context.Context, _, _ string, req skycloak.CreateApplicationRequest) (string, string, error) {
	if s.err != nil {
		return "", "", s.err
	}
	return req.ClientID, "generated-secret", nil
}

func (s stubAPI) DeleteApplication(context.Context, string, string, string) error {
	return s.err
}

func (s stubAPI) CreateOIDCIdentityProvider(context.Context, string, string, skycloak.CreateOIDCIdentityProviderRequest) error {
	return s.err
}

func (s stubAPI) DeleteIdentityProvider(context.Context, string, string, string) error {
	return s.err
}

func (s stubAPI) GetLogs(context.Context, string, skycloak.LogQuery) ([]skycloak.LogEntry, error) {
	return s.logs, s.err
}

func (s stubAPI) GetSecurityLogs(context.Context, string, skycloak.SecurityLogQuery) ([]skycloak.SecurityLogEntry, error) {
	return s.secLogs, s.err
}

func (s stubAPI) QueryEvents(context.Context, string, skycloak.EventQuery) ([]skycloak.EventEntry, error) {
	return s.events, s.err
}

func (s stubAPI) ListDomains(context.Context, string) ([]skycloak.Domain, error) {
	return s.domains, s.err
}

func (s stubAPI) GetDomain(context.Context, string, string) (*skycloak.Domain, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.domain == nil {
		return nil, errors.New("no domain configured in stub")
	}
	return s.domain, nil
}

func (s stubAPI) CreateDomain(_ context.Context, _, domain, subdomain string) (*skycloak.Domain, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.Domain{ID: "d1", Domain: domain, Subdomain: subdomain, VerificationStatus: "pending"}, nil
}

func (s stubAPI) VerifyDomain(context.Context, string, string) (*skycloak.Domain, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.domain == nil {
		return &skycloak.Domain{ID: "d1", VerificationStatus: "verified"}, nil
	}
	return s.domain, nil
}

func (s stubAPI) DeleteDomain(context.Context, string, string) error {
	return s.err
}

func (s stubAPI) ListThemes(context.Context, string) ([]skycloak.Theme, error) {
	return s.themes, s.err
}

func (s stubAPI) GetThemeAssignment(context.Context, string, string) (*skycloak.ThemeAssignment, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.assign == nil {
		return &skycloak.ThemeAssignment{}, nil
	}
	return s.assign, nil
}

func (s stubAPI) SetThemeAssignment(_ context.Context, _, _ string, a skycloak.ThemeAssignment) (*skycloak.ThemeAssignment, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &a, nil
}

func (s stubAPI) GetLoginBranding(context.Context, string, string) (*skycloak.LoginBranding, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.login == nil {
		return &skycloak.LoginBranding{Status: "applied"}, nil
	}
	return s.login, nil
}

func (s stubAPI) GetEmailBranding(context.Context, string, string) (*skycloak.EmailBranding, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.email == nil {
		return &skycloak.EmailBranding{Status: "applied"}, nil
	}
	return s.email, nil
}

func (s stubAPI) ListExtensions(context.Context) ([]skycloak.ExtensionInfo, error) {
	return s.catalog, s.err
}

func (s stubAPI) ListClusterExtensions(context.Context, string) ([]skycloak.ClusterExtension, error) {
	return s.clusExts, s.err
}

func (s stubAPI) InstallExtension(_ context.Context, _, extensionID string, _ map[string]string) (*skycloak.ClusterExtension, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.ClusterExtension{ExtensionID: extensionID, ExtensionName: "Ext", Status: "installing"}, nil
}

func (s stubAPI) UpgradeExtension(_ context.Context, _, extensionID string) (*skycloak.ClusterExtension, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.ClusterExtension{ExtensionID: extensionID, ExtensionName: "Ext", Status: "upgrading"}, nil
}

func (s stubAPI) UninstallExtension(context.Context, string, string) error {
	return s.err
}

func (s stubAPI) ListExports(context.Context, string) ([]skycloak.Export, error) {
	return s.exports, s.err
}

func (s stubAPI) GetExport(context.Context, string, string) (*skycloak.Export, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.export == nil {
		return &skycloak.Export{ID: "x1", Status: "completed", DownloadURL: "https://dl/x.zip"}, nil
	}
	return s.export, nil
}

func (s stubAPI) CreateExport(_ context.Context, _, format string, _ bool, _ string) (*skycloak.Export, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.Export{ID: "x1", Format: format, Status: "pending"}, nil
}

func (s stubAPI) ListRealmRoles(context.Context, string, string) ([]skycloak.RealmRole, error) {
	return s.rroles, s.err
}

func (s stubAPI) CreateRealmRole(_ context.Context, _, _, name, description string) (*skycloak.RealmRole, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmRole{Name: name, Description: description}, nil
}

func (s stubAPI) DeleteRealmRole(context.Context, string, string, string) error { return s.err }

func (s stubAPI) ListRealmGroups(context.Context, string, string) ([]skycloak.RealmGroup, error) {
	return s.rgroups, s.err
}

func (s stubAPI) CreateRealmGroup(_ context.Context, _, _, name, _ string) (*skycloak.RealmGroup, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmGroup{ID: "g1", Name: name, Path: "/" + name}, nil
}

func (s stubAPI) DeleteRealmGroup(context.Context, string, string, string) error { return s.err }

func (s stubAPI) ListRealmUsers(context.Context, string, string) ([]skycloak.RealmUser, error) {
	return s.rusers, s.err
}

func (s stubAPI) GetRealmUser(context.Context, string, string, string) (*skycloak.RealmUser, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.ruser == nil {
		return &skycloak.RealmUser{ID: "u1", Username: "jdoe", Email: "jdoe@example.com", Enabled: true}, nil
	}
	return s.ruser, nil
}

func (s stubAPI) CreateRealmUser(_ context.Context, _, _, username, email, _, _, _ string, _ bool) (*skycloak.RealmUser, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmUser{ID: "u1", Username: username, Email: email, Enabled: true}, nil
}

func (s stubAPI) DeleteRealmUser(context.Context, string, string, string) error { return s.err }

func (s stubAPI) AssignRealmUserRole(context.Context, string, string, string, string) error {
	return s.err
}

func (s stubAPI) RemoveRealmUserRole(context.Context, string, string, string, string) error {
	return s.err
}

func (s stubAPI) AddRealmUserToGroup(context.Context, string, string, string, string) error {
	return s.err
}

func (s stubAPI) RemoveRealmUserFromGroup(context.Context, string, string, string, string) error {
	return s.err
}

func (s stubAPI) ListApplicationRoles(context.Context, string, string, string) ([]skycloak.ApplicationRole, error) {
	return s.appRoles, s.err
}

func (s stubAPI) AssignApplicationRole(context.Context, string, string, string, string, string) error {
	return s.err
}

func (s stubAPI) RemoveApplicationRole(context.Context, string, string, string, string, string) error {
	return s.err
}

func (s stubAPI) ListApplicationSessions(context.Context, string, string, string) ([]skycloak.ApplicationSession, error) {
	return s.appSess, s.err
}

func (s stubAPI) GetRealm(context.Context, string, string) (*skycloak.Realm, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.realm == nil {
		return &skycloak.Realm{Name: "app", Enabled: true}, nil
	}
	return s.realm, nil
}

func (s stubAPI) GetApplication(context.Context, string, string, string) (*skycloak.Application, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.app == nil {
		return &skycloak.Application{ClientID: "web", Name: "Web", Type: "confidential"}, nil
	}
	return s.app, nil
}

func (s stubAPI) GetIdentityProvider(context.Context, string, string, string) (*skycloak.IdentityProvider, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.idp == nil {
		return &skycloak.IdentityProvider{ProviderID: "google", Type: "oidc", Enabled: true}, nil
	}
	return s.idp, nil
}

func (s stubAPI) ListClusterLocations(context.Context) ([]skycloak.ClusterLocationInfo, error) {
	return s.locations, s.err
}

func (s stubAPI) ListClusterTypes(context.Context) ([]skycloak.ClusterTypeInfo, error) {
	return s.ctypes, s.err
}

func (s stubAPI) ListClusterFeatures(context.Context) ([]skycloak.ClusterFeatureInfo, error) {
	return s.features, s.err
}

func (s stubAPI) ClusterTypeVersions(context.Context, string) ([]string, error) {
	return s.versions, s.err
}

func (s stubAPI) ListClusterUpgrades(context.Context, string) ([]skycloak.ClusterUpgrade, error) {
	return s.upgrades, s.err
}

func (s stubAPI) ListIdentityProviderTemplates(context.Context) ([]skycloak.ProviderTemplate, error) {
	return s.templates, s.err
}

func (s stubAPI) ListDomainRoutes(context.Context, string, string) ([]skycloak.DomainRoute, error) {
	return s.routes, s.err
}

func (s stubAPI) GetSMTP(context.Context, string, string) (*skycloak.SMTPConfig, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.smtp == nil {
		return &skycloak.SMTPConfig{Host: "smtp.example.com", Port: 587, FromEmail: "no-reply@example.com", AuthType: "basic"}, nil
	}
	return s.smtp, nil
}

func (s stubAPI) DeleteSMTP(context.Context, string, string) error { return s.err }

func (s stubAPI) RotateApplicationSecret(context.Context, string, string, string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "rotated-secret", nil
}

func (s stubAPI) GetTheme(context.Context, string, string) (*skycloak.Theme, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.theme == nil {
		return &skycloak.Theme{ID: "t1", Name: "corp", Status: "deployed"}, nil
	}
	return s.theme, nil
}

func (s stubAPI) DeleteTheme(context.Context, string, string) error  { return s.err }
func (s stubAPI) DeleteExtension(context.Context, string) error      { return s.err }
func (s stubAPI) DeleteExport(context.Context, string, string) error { return s.err }
func (s stubAPI) DeleteDomainRoute(context.Context, string, string, string) error {
	return s.err
}

func (s stubAPI) GetDomainRoute(context.Context, string, string, string) (*skycloak.DomainRoute, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.route == nil {
		return &skycloak.DomainRoute{ID: "r1", Realm: "app"}, nil
	}
	return s.route, nil
}

func (s stubAPI) CreateDomainRoute(_ context.Context, _, _, realm string, admin, hide bool) (*skycloak.DomainRoute, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.DomainRoute{ID: "r1", Realm: realm, AllowAdminAccess: admin, HideRealmPath: hide}, nil
}

func (s stubAPI) GetClientThemeAssignment(context.Context, string, string, string) (string, error) {
	return "", s.err
}

func (s stubAPI) SetClientThemeAssignment(_ context.Context, _, _, _, login string) (string, error) {
	return login, s.err
}

func (s stubAPI) ListRealmUserRoles(context.Context, string, string, string) ([]skycloak.RealmRole, error) {
	return s.rroles, s.err
}

func (s stubAPI) ListRealmUserGroups(context.Context, string, string, string) ([]skycloak.RealmGroup, error) {
	return s.rgroups, s.err
}

func (s stubAPI) UpdateRealm(_ context.Context, _, realm, displayName string, enabled bool) (*skycloak.Realm, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.Realm{Name: realm, DisplayName: displayName, Enabled: enabled}, nil
}

func (s stubAPI) DiscoverOIDC(context.Context, string) (*skycloak.OIDCDiscovery, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.OIDCDiscovery{Issuer: "https://idp", TokenEndpoint: "https://idp/token", AuthorizationEndpoint: "https://idp/auth"}, nil
}

func (s stubAPI) TestSMTP(context.Context, string, string, string) (*skycloak.TestResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.TestResult{Success: true, Message: "sent"}, nil
}

func (s stubAPI) TestIdentityProviderConnection(context.Context, string, string, string, string, string) (*skycloak.TestResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.TestResult{Success: true, Message: "ok"}, nil
}

func (s stubAPI) CancelClusterUpgrade(context.Context, string) error { return s.err }

func (s stubAPI) GetClusterSecurity(context.Context, string) (*skycloak.ClusterSecurity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.ClusterSecurity{WAF: &skycloak.WAF{Enabled: true, Mode: "block", Preset: "owasp_top_10"}}, nil
}

func (s stubAPI) UpdateClusterSecurity(_ context.Context, _ string, sec *skycloak.ClusterSecurity) (*skycloak.ClusterSecurity, error) {
	if s.err != nil {
		return nil, s.err
	}
	return sec, nil
}

func (s stubAPI) GetClusterCredentials(context.Context, string) (*skycloak.ClusterCredentials, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.ClusterCredentials{ClientID: "skycloak-automation", ClientSecret: "s3cr3t", TokenURL: "https://auth.example.com/realms/master/protocol/openid-connect/token"}, nil
}

func (s stubAPI) GetClusterUpgradePath(context.Context, string) ([]skycloak.UpgradePathStep, error) {
	return s.upPath, s.err
}

func (s stubAPI) ClusterInsights(context.Context, string, string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []byte(`{"ok":true}`), nil
}

func (s stubAPI) GetRealmRole(context.Context, string, string, string) (*skycloak.RealmRole, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmRole{Name: "admin"}, nil
}

func (s stubAPI) GetRealmGroup(context.Context, string, string, string) (*skycloak.RealmGroup, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmGroup{ID: "g1", Name: "eng", Path: "/eng"}, nil
}

func (s stubAPI) ListRealmGroupMembers(context.Context, string, string, string) ([]skycloak.RealmUser, error) {
	return s.rusers, s.err
}

func (s stubAPI) UpdateRealmRole(_ context.Context, _, _, name, newName, _ string) (*skycloak.RealmRole, error) {
	if s.err != nil {
		return nil, s.err
	}
	if newName != "" {
		name = newName
	}
	return &skycloak.RealmRole{Name: name}, nil
}

func (s stubAPI) UpdateRealmGroup(_ context.Context, _, _, _, name string) (*skycloak.RealmGroup, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmGroup{ID: "g1", Name: name}, nil
}

func (s stubAPI) UpdateRealmUser(_ context.Context, _, _, _, email string, _, _ string, _, _ bool) (*skycloak.RealmUser, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.RealmUser{ID: "u1", Username: "jdoe", Email: email}, nil
}

func (s stubAPI) UpdateDomainRoute(_ context.Context, _, _, _ string, admin bool, _ []string) (*skycloak.DomainRoute, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.DomainRoute{ID: "r1", Realm: "app", AllowAdminAccess: admin}, nil
}

func (s stubAPI) UpdateApplication(_ context.Context, _, _, clientID, _, _ string, _ []string) (*skycloak.Application, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.Application{ClientID: clientID, Name: "Web"}, nil
}

func (s stubAPI) UpdateIdentityProvider(_ context.Context, _, _, providerID, _ string, enabled bool) (*skycloak.IdentityProvider, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.IdentityProvider{ProviderID: providerID, Enabled: enabled}, nil
}

func (s stubAPI) UpdateCluster(_ context.Context, _, version, _ string, autoUpgradeEnabled *bool) (*skycloak.Cluster, error) {
	if s.err != nil {
		return nil, s.err
	}
	autoUpgrade := false
	if autoUpgradeEnabled != nil {
		autoUpgrade = *autoUpgradeEnabled
	}
	return &skycloak.Cluster{ID: "c1", Name: "prod", Version: version, AutoUpgradeEnabled: autoUpgrade}, nil
}

func (s stubAPI) UpdateExtension(_ context.Context, _, name, _ string) (*skycloak.ExtensionInfo, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.ExtensionInfo{ID: "e1", Name: name}, nil
}

func (s stubAPI) UpdateTheme(_ context.Context, _, _, name, _, _ string) (*skycloak.Theme, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.Theme{ID: "t1", Name: name}, nil
}

func (s stubAPI) UpsertSMTP(_ context.Context, _, _ string, req skycloak.UpsertSMTPRequest) (*skycloak.SMTPConfig, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.SMTPConfig{Host: req.Host, Port: req.Port, FromEmail: req.FromEmail, AuthType: req.AuthType}, nil
}

func (s stubAPI) UpsertLoginBranding(_ context.Context, _, _ string, req skycloak.UpsertLoginBrandingRequest) (*skycloak.LoginBranding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.LoginBranding{PrimaryColor: req.PrimaryColor, Status: "applied"}, nil
}

func (s stubAPI) UpsertEmailBranding(_ context.Context, _, _ string, req skycloak.UpsertEmailBrandingRequest) (*skycloak.EmailBranding, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.EmailBranding{PrimaryColor: req.PrimaryColor, Status: "applied"}, nil
}

func (s stubAPI) DeleteLoginBranding(context.Context, string, string) error { return s.err }
func (s stubAPI) DeleteEmailBranding(context.Context, string, string) error { return s.err }

func (s stubAPI) ExportClusterEvents(context.Context, string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	return []byte("id,type\n1,LOGIN\n"), nil
}

func (s stubAPI) GetClusterMaintenanceWindow(context.Context, string) (*skycloak.MaintenanceWindow, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &skycloak.MaintenanceWindow{Enabled: true, DaysOfWeek: []int32{1, 2}, StartLocal: "02:00", EndLocal: "04:00", Timezone: "Europe/Berlin"}, nil
}

func (s stubAPI) SetClusterMaintenanceWindow(_ context.Context, _ string, window skycloak.MaintenanceWindow) (*skycloak.MaintenanceWindow, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &window, nil
}

func (s stubAPI) DeleteClusterMaintenanceWindow(context.Context, string) error {
	return s.err
}

func TestListClustersHandler(t *testing.T) {
	api := stubAPI{clusters: []skycloak.Cluster{
		{ID: "c1", Name: "prod", Status: "available", Type: "keycloak", Size: "small", Version: "26.1", Location: "eu"},
	}}

	res, out, err := listClustersHandler(api)(context.Background(), nil, ListClustersInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("expected a non-error result")
	}
	if out.Count != 1 || out.Clusters[0].Name != "prod" {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestListClustersHandler_APIError(t *testing.T) {
	api := stubAPI{err: &skycloak.APIError{StatusCode: 401}}

	res, _, err := listClustersHandler(api)(context.Background(), nil, ListClustersInput{})
	if err != nil {
		t.Fatalf("API errors must be surfaced as IsError results, not Go errors: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError result for a 401")
	}
}

func TestGetClusterHandler(t *testing.T) {
	api := stubAPI{cluster: &skycloak.Cluster{ID: "c1", Name: "prod", Status: "available", Type: "keycloak", Size: "small", Version: "26.1", Location: "eu"}}

	res, out, err := getClusterHandler(api)(context.Background(), nil, GetClusterInput{ID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.ID != "c1" || out.Status != "available" {
		t.Fatalf("unexpected result: err=%v out=%+v", res.IsError, out)
	}
}

func TestGetClusterHandler_MissingID(t *testing.T) {
	res, _, err := getClusterHandler(stubAPI{})(context.Background(), nil, GetClusterInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError when id is empty")
	}
}

func TestListRealmsHandler(t *testing.T) {
	api := stubAPI{realms: []skycloak.Realm{{Name: "app", DisplayName: "App", Enabled: true}}}

	res, out, err := listRealmsHandler(api)(context.Background(), nil, ListRealmsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Count != 1 || out.Realms[0].Name != "app" {
		t.Fatalf("unexpected result: err=%v out=%+v", res.IsError, out)
	}
}

func TestListRealmsHandler_MissingClusterID(t *testing.T) {
	res, _, err := listRealmsHandler(stubAPI{})(context.Background(), nil, ListRealmsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError when cluster_id is empty")
	}
}

// TestRegister ensures tool registration (and JSON-schema inference for every
// tool's input/output) does not panic — this is what would break at startup.
func TestRegister(_ *testing.T) {
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "test"}, nil)
	Register(s, stubAPI{}, true) // allowWrites=true exercises both paths; must not panic
}

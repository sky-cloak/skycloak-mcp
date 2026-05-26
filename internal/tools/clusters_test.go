package tools

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

type stubAPI struct {
	clusters []skycloak.Cluster
	cluster  *skycloak.Cluster
	realms   []skycloak.Realm
	apps     []skycloak.Application
	idps     []skycloak.IdentityProvider
	logs     []skycloak.LogEntry
	secLogs  []skycloak.SecurityLogEntry
	events   []skycloak.EventEntry
	domains  []skycloak.Domain
	domain   *skycloak.Domain
	themes   []skycloak.Theme
	assign   *skycloak.ThemeAssignment
	login    *skycloak.LoginBranding
	email    *skycloak.EmailBranding
	catalog  []skycloak.ExtensionInfo
	clusExts []skycloak.ClusterExtension
	exports  []skycloak.Export
	export   *skycloak.Export
	rroles   []skycloak.RealmRole
	rgroups  []skycloak.RealmGroup
	rusers   []skycloak.RealmUser
	ruser    *skycloak.RealmUser
	err      error
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
	return &skycloak.Cluster{ID: "new", Name: req.Name, Status: "provisioning", Type: req.Type, Size: req.Size, Version: req.Version, Location: req.Location}, nil
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

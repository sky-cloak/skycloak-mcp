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

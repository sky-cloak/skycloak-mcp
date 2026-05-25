// Package skycloak is a thin facade over the generated Skycloak API client
// (internal/apiclient). It exposes the domain structs and methods the MCP
// tools consume, mapping them to/from the generated wire types. The HTTP layer
// and wire types are generated from the OpenAPI spec and stay in sync on
// `make generate`.
package skycloak

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/oapi-codegen/nullable"

	"github.com/sky-cloak/skycloak-mcp/internal/apiclient"
)

const defaultEndpoint = "https://api.skycloak.io"

// Client wraps the generated API client.
type Client struct {
	gen *apiclient.ClientWithResponses
}

// Option configures a Client.
type Option func(*config)

type config struct {
	httpClient *http.Client
	userAgent  string
}

// WithHTTPClient overrides the underlying HTTP client (useful in tests).
func WithHTTPClient(h *http.Client) Option { return func(c *config) { c.httpClient = h } }

// WithUserAgent sets the User-Agent header sent on every request.
func WithUserAgent(ua string) Option { return func(c *config) { c.userAgent = ua } }

// New builds a Client. endpoint defaults to https://api.skycloak.io when empty.
func New(endpoint, apiKey, apiVersion string, opts ...Option) *Client {
	cfg := &config{httpClient: &http.Client{Timeout: 30 * time.Second}, userAgent: "skycloak-go/dev"}
	for _, o := range opts {
		o(cfg)
	}
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	// Retry 429/5xx with Retry-After-aware backoff.
	cfg.httpClient.Transport = &retryTransport{base: cfg.httpClient.Transport, maxRetries: 4}

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("apikey", apiKey)
		req.Header.Set("Accept", "application/json")
		if apiVersion != "" {
			req.Header.Set("API-Version", apiVersion)
		}
		if cfg.userAgent != "" {
			req.Header.Set("User-Agent", cfg.userAgent)
		}
		return nil
	}

	gen, err := apiclient.NewClientWithResponses(endpoint,
		apiclient.WithHTTPClient(cfg.httpClient),
		apiclient.WithRequestEditorFn(editor),
	)
	if err != nil {
		panic(fmt.Sprintf("skycloak: invalid endpoint %q: %v", endpoint, err))
	}
	return &Client{gen: gen}
}

// Problem is the RFC 9457 application/problem+json error body.
type Problem struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// APIError wraps a non-2xx response.
type APIError struct {
	StatusCode int
	Problem    Problem
}

func (e *APIError) Error() string {
	if e.Problem.Detail != "" {
		return fmt.Sprintf("skycloak api %d %s: %s", e.StatusCode, e.Problem.Title, e.Problem.Detail)
	}
	if e.Problem.Title != "" {
		return fmt.Sprintf("skycloak api %d: %s", e.StatusCode, e.Problem.Title)
	}
	return fmt.Sprintf("skycloak api: unexpected status %d", e.StatusCode)
}

// AsAPIError returns the underlying *APIError if err is (or wraps) one.
func AsAPIError(err error) (*APIError, bool) {
	var e *APIError
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func statusError(resp *http.Response, body []byte) error {
	code := 0
	if resp != nil {
		code = resp.StatusCode
	}
	e := &APIError{StatusCode: code}
	_ = json.Unmarshal(body, &e.Problem)
	return e
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// cid parses a cluster ID string into the generated UUID type.
func cid(s string) apiclient.ClusterId {
	id, _ := uuid.Parse(s)
	return id
}

// Cluster mirrors the public API Cluster resource (subset used by the tools).
type Cluster struct {
	ID        string
	Name      string
	Type      string
	Size      string
	Version   string
	Location  string
	Status    string
	URL       string
	CreatedAt string
	UpdatedAt string
}

// ListClustersParams holds optional pagination parameters (the clusters list is
// not paginated server-side today, so they are accepted for forward
// compatibility but ignored).
type ListClustersParams struct {
	Limit  int
	Offset int
}

// ListClusters returns the workspace's clusters.
func (c *Client) ListClusters(ctx context.Context, _ ListClustersParams) ([]Cluster, error) {
	resp, err := c.gen.ListClustersWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Cluster, 0, len(*resp.JSON200))
	for _, s := range *resp.JSON200 {
		out = append(out, Cluster{
			ID: s.Id.String(), Name: string(s.Name), Type: string(s.Type), Size: string(s.Size),
			Version: string(s.Version), Location: string(s.Location), Status: string(s.Status),
			URL: s.Url, CreatedAt: fmtTime(s.CreatedAt), UpdatedAt: fmtTime(s.UpdatedAt),
		})
	}
	return out, nil
}

func clusterFromAPI(cl *apiclient.Cluster) *Cluster {
	return &Cluster{
		ID: cl.Id.String(), Name: string(cl.Name), Type: string(cl.Type), Size: string(cl.Size),
		Version: string(cl.Version), Location: string(cl.Location), Status: string(cl.Status),
		URL: cl.Url, CreatedAt: fmtTime(cl.CreatedAt), UpdatedAt: fmtTime(cl.UpdatedAt),
	}
}

// GetCluster returns a single cluster by ID.
func (c *Client) GetCluster(ctx context.Context, id string) (*Cluster, error) {
	resp, err := c.gen.GetClusterWithResponse(ctx, cid(id))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return clusterFromAPI(resp.JSON200), nil
}

// CreateClusterRequest is the body for creating a cluster.
type CreateClusterRequest struct {
	Name     string
	Type     string
	Size     string
	Version  string
	Location string
}

// CreateCluster provisions a new cluster (asynchronous; the returned cluster is
// in a provisioning state).
func (c *Client) CreateCluster(ctx context.Context, req CreateClusterRequest) (*Cluster, error) {
	body := apiclient.CreateClusterJSONRequestBody{
		Name:     apiclient.ClusterName(req.Name),
		Size:     apiclient.ClusterSize(req.Size),
		Version:  apiclient.KeycloakVersion(req.Version),
		Location: apiclient.ClusterLocation(req.Location),
	}
	if req.Type != "" {
		t := apiclient.ClusterType(req.Type)
		body.Type = &t
	}
	resp, err := c.gen.CreateClusterWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return clusterFromAPI(resp.JSON201), nil
}

// DeleteCluster deletes a cluster.
func (c *Client) DeleteCluster(ctx context.Context, id string) error {
	resp, err := c.gen.DeleteClusterWithResponse(ctx, cid(id))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// Realm mirrors the public API Realm resource (subset used by the tools).
type Realm struct {
	Name        string
	DisplayName string
	Enabled     bool
}

// ListRealms returns the realms in a cluster.
func (c *Client) ListRealms(ctx context.Context, clusterID string) ([]Realm, error) {
	resp, err := c.gen.ListRealmsWithResponse(ctx, cid(clusterID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Realm, 0, len(*resp.JSON200))
	for _, r := range *resp.JSON200 {
		out = append(out, Realm{Name: string(r.Name), DisplayName: string(r.DisplayName), Enabled: r.Enabled})
	}
	return out, nil
}

// CreateRealm creates a realm (name + optional display name).
func (c *Client) CreateRealm(ctx context.Context, clusterID string, r Realm) (*Realm, error) {
	body := apiclient.CreateRealmJSONRequestBody{Name: apiclient.RealmName(r.Name)}
	if r.DisplayName != "" {
		dn := apiclient.RealmDisplayName(r.DisplayName)
		body.DisplayName = &dn
	}
	resp, err := c.gen.CreateRealmWithResponse(ctx, cid(clusterID), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := resp.JSON201
	return &Realm{Name: string(out.Name), DisplayName: string(out.DisplayName), Enabled: out.Enabled}, nil
}

// DeleteRealm deletes a realm and all of its data.
func (c *Client) DeleteRealm(ctx context.Context, clusterID, name string) error {
	resp, err := c.gen.DeleteRealmWithResponse(ctx, cid(clusterID), apiclient.RealmName(name))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// Application mirrors the public API Application resource (subset used by the tools).
type Application struct {
	ClientID string
	Name     string
	Type     string
	Protocol string
	Status   string
}

func applicationFromAPI(a *apiclient.Application) Application {
	return Application{
		ClientID: string(a.ClientId), Name: a.Name, Type: string(a.Type),
		Protocol: string(a.Protocol), Status: string(a.Status),
	}
}

// ListApplications returns all applications in a realm, following pagination.
func (c *Client) ListApplications(ctx context.Context, clusterID, realm string) ([]Application, error) {
	const limit = 100
	var out []Application
	for offset := 0; ; offset += limit {
		l := apiclient.PaginationLimit(limit)
		o := apiclient.PaginationOffset(offset)
		resp, err := c.gen.ListApplicationsWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm),
			&apiclient.ListApplicationsParams{Limit: &l, Offset: &o})
		if err != nil {
			return nil, err
		}
		if resp.JSON200 == nil {
			return nil, statusError(resp.HTTPResponse, resp.Body)
		}
		page := *resp.JSON200
		for i := range page {
			out = append(out, applicationFromAPI(&page[i]))
		}
		if len(page) < limit {
			break
		}
	}
	return out, nil
}

// CreateApplicationRequest is the input for creating an application.
type CreateApplicationRequest struct {
	ClientID     string
	Name         string
	Type         string
	Protocol     string
	RedirectURIs []string
}

// CreateApplication creates an OIDC/SAML client in a realm. The returned
// ClientSecret is only present for confidential clients on creation.
func (c *Client) CreateApplication(ctx context.Context, clusterID, realm string, req CreateApplicationRequest) (clientID, clientSecret string, err error) {
	body := apiclient.CreateApplicationJSONRequestBody{
		ClientId:   apiclient.ApplicationClientId(req.ClientID),
		Name:       req.Name,
		GrantTypes: []apiclient.GrantType{},
	}
	if req.Type != "" {
		t := apiclient.ApplicationType(req.Type)
		body.Type = &t
	}
	if req.Protocol != "" {
		p := apiclient.ApplicationProtocol(req.Protocol)
		body.Protocol = &p
	}
	if len(req.RedirectURIs) > 0 {
		ru := req.RedirectURIs
		body.RedirectUris = &ru
	}
	resp, err := c.gen.CreateApplicationWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), body)
	if err != nil {
		return "", "", err
	}
	if resp.JSON201 == nil {
		return "", "", statusError(resp.HTTPResponse, resp.Body)
	}
	secret := ""
	if resp.JSON201.ClientSecret != nil {
		secret = *resp.JSON201.ClientSecret
	}
	return string(resp.JSON201.ClientId), secret, nil
}

// DeleteApplication deletes an application.
func (c *Client) DeleteApplication(ctx context.Context, clusterID, realm, clientID string) error {
	resp, err := c.gen.DeleteApplicationWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// CreateOIDCIdentityProviderRequest is the input for creating an OIDC identity
// provider (the common case exposed via MCP).
type CreateOIDCIdentityProviderRequest struct {
	ProviderID       string
	DisplayName      string
	ClientID         string
	ClientSecret     string
	Issuer           string
	AuthorizationURL string
	TokenURL         string
}

// CreateOIDCIdentityProvider creates an OIDC identity provider.
func (c *Client) CreateOIDCIdentityProvider(ctx context.Context, clusterID, realm string, req CreateOIDCIdentityProviderRequest) error {
	cfg := &apiclient.ProviderConfig{Oidc: &apiclient.OIDCConfig{}}
	if req.Issuer != "" {
		cfg.Oidc.Issuer = &req.Issuer
	}
	if req.AuthorizationURL != "" {
		cfg.Oidc.AuthorizationUrl = &req.AuthorizationURL
	}
	if req.TokenURL != "" {
		cfg.Oidc.TokenUrl = &req.TokenURL
	}
	body := apiclient.CreateIdentityProviderJSONRequestBody{
		ProviderId:  apiclient.SkycloakProviderId(req.ProviderID),
		Type:        apiclient.ProviderType("oidc"),
		DisplayName: req.DisplayName,
		Config:      cfg,
	}
	if req.ClientID != "" {
		body.ClientId = &req.ClientID
	}
	if req.ClientSecret != "" {
		body.ClientSecret = &req.ClientSecret
	}
	resp, err := c.gen.CreateIdentityProviderWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), body)
	if err != nil {
		return err
	}
	if resp.JSON201 == nil {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// DeleteIdentityProvider deletes an identity provider.
func (c *Client) DeleteIdentityProvider(ctx context.Context, clusterID, realm, providerID string) error {
	resp, err := c.gen.DeleteIdentityProviderWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ProviderId(providerID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// IdentityProvider mirrors the public API identity-provider resource (subset).
type IdentityProvider struct {
	ProviderID  string
	Type        string
	DisplayName string
	Enabled     bool
}

// ListIdentityProviders returns the identity providers in a realm.
func (c *Client) ListIdentityProviders(ctx context.Context, clusterID, realm string) ([]IdentityProvider, error) {
	resp, err := c.gen.ListIdentityProvidersWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]IdentityProvider, 0, len(*resp.JSON200))
	for _, p := range *resp.JSON200 {
		out = append(out, IdentityProvider{
			ProviderID: string(p.ProviderId), Type: string(p.Type), DisplayName: p.DisplayName, Enabled: p.Enabled,
		})
	}
	return out, nil
}

// ---- Observability: logs, security logs, events ----

func nstr(n nullable.Nullable[string]) string {
	if v, err := n.Get(); err == nil {
		return v
	}
	return ""
}

// LogQuery filters a cluster log query.
type LogQuery struct {
	Limit  int
	Level  string
	Search string
}

// LogEntry is one cluster log line.
type LogEntry struct {
	Timestamp  string `json:"timestamp"`
	Level      string `json:"level"`
	Category   string `json:"category"`
	Message    string `json:"message"`
	Source     string `json:"source,omitempty"`
	ThreadName string `json:"thread_name,omitempty"`
}

// GetLogs returns a page of cluster logs.
func (c *Client) GetLogs(ctx context.Context, clusterID string, q LogQuery) ([]LogEntry, error) {
	params := &apiclient.ListClusterLogsParams{}
	if q.Limit > 0 {
		l := apiclient.LogPageLimit(q.Limit)
		params.Limit = &l
	}
	if q.Level != "" {
		lv := apiclient.LogLevel(q.Level)
		params.Level = &lv
	}
	if q.Search != "" {
		params.Search = &q.Search
	}
	resp, err := c.gen.ListClusterLogsWithResponse(ctx, cid(clusterID), params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]LogEntry, 0, len(*resp.JSON200))
	for _, l := range *resp.JSON200 {
		out = append(out, LogEntry{
			Timestamp: l.Timestamp.Format(time.RFC3339), Level: string(l.Level), Category: l.Category,
			Message: l.Message, Source: l.Source, ThreadName: l.ThreadName,
		})
	}
	return out, nil
}

// SecurityLogQuery filters a security log query.
type SecurityLogQuery struct {
	Limit  int
	Search string
}

// SecurityLogEntry is one WAF/security log line.
type SecurityLogEntry struct {
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	Action    string `json:"action"`
	SourceIP  string `json:"source_ip,omitempty"`
	Country   string `json:"country,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Method    string `json:"method,omitempty"`
	URI       string `json:"uri,omitempty"`
	Message   string `json:"message,omitempty"`
}

// GetSecurityLogs returns a page of cluster security (WAF) logs.
func (c *Client) GetSecurityLogs(ctx context.Context, clusterID string, q SecurityLogQuery) ([]SecurityLogEntry, error) {
	params := &apiclient.ListClusterSecurityLogsParams{}
	if q.Limit > 0 {
		l := apiclient.LogPageLimit(q.Limit)
		params.Limit = &l
	}
	if q.Search != "" {
		params.Search = &q.Search
	}
	resp, err := c.gen.ListClusterSecurityLogsWithResponse(ctx, cid(clusterID), params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]SecurityLogEntry, 0, len(*resp.JSON200))
	for _, s := range *resp.JSON200 {
		out = append(out, SecurityLogEntry{
			Timestamp: s.Timestamp.Format(time.RFC3339), Type: string(s.Type), Action: string(s.Action),
			SourceIP: s.SourceIp, Country: nstr(s.Country), Severity: nstr(s.Severity),
			Method: s.Method, URI: s.Uri, Message: s.Message,
		})
	}
	return out, nil
}

// EventQuery filters an events query.
type EventQuery struct {
	Limit    int
	Category string
	Realm    string
	Username string
	Search   string
}

// EventEntry is one Keycloak user/admin event.
type EventEntry struct {
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"`
	Type      string `json:"type,omitempty"`
	RealmName string `json:"realm_name,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Error     string `json:"error,omitempty"`
}

func strDeref(p *string) string {
	if p != nil {
		return *p
	}
	return ""
}

// QueryEvents returns a page of Keycloak events (user and admin).
func (c *Client) QueryEvents(ctx context.Context, clusterID string, q EventQuery) ([]EventEntry, error) {
	params := &apiclient.ListClusterEventsParams{}
	if q.Limit > 0 {
		l := apiclient.PageLimit(q.Limit)
		params.Limit = &l
	}
	if q.Category != "" {
		cat := apiclient.EventCategory(q.Category)
		params.Category = &cat
	}
	if q.Realm != "" {
		rn := apiclient.RealmName(q.Realm)
		params.Realm = &rn
	}
	if q.Username != "" {
		params.Username = &q.Username
	}
	if q.Search != "" {
		params.Search = &q.Search
	}
	resp, err := c.gen.ListClusterEventsWithResponse(ctx, cid(clusterID), params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]EventEntry, 0, len(*resp.JSON200))
	for _, e := range *resp.JSON200 {
		typ := strDeref((*string)(e.Type))
		if typ == "" && e.OperationType != nil {
			typ = string(*e.OperationType)
		}
		out = append(out, EventEntry{
			Timestamp: e.Timestamp.Format(time.RFC3339), Category: string(e.Category), Type: typ,
			RealmName: e.RealmName, ClientID: strDeref(e.ClientId), Username: strDeref(e.Username),
			IPAddress: strDeref(e.IpAddress), Error: strDeref(e.Error),
		})
	}
	return out, nil
}

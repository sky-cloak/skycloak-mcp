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
	openapitypes "github.com/oapi-codegen/runtime/types"

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

// ---- Custom domains ----

func uid(s string) uuid.UUID { id, _ := uuid.Parse(s); return id }

// DNSRecord is a DNS record the customer must create for a domain.
type DNSRecord struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Domain is a custom domain (subset used by the tools).
type Domain struct {
	ID                 string      `json:"id"`
	Domain             string      `json:"domain"`
	Subdomain          string      `json:"subdomain,omitempty"`
	CnameTarget        string      `json:"cname_target,omitempty"`
	SSLStatus          string      `json:"ssl_status,omitempty"`
	VerificationStatus string      `json:"verification_status,omitempty"`
	IsActive           bool        `json:"is_active"`
	DNSRecords         []DNSRecord `json:"dns_records,omitempty"`
}

func domainFromAPI(d *apiclient.Domain) Domain {
	out := Domain{
		ID: d.Id.String(), Domain: string(d.Domain), CnameTarget: d.CnameTarget,
		SSLStatus: string(d.SslStatus), VerificationStatus: string(d.VerificationStatus), IsActive: d.IsActive,
	}
	if d.Subdomain != nil {
		out.Subdomain = *d.Subdomain
	}
	for _, r := range d.DnsRecords {
		out.DNSRecords = append(out.DNSRecords, DNSRecord{Type: string(r.Type), Name: r.Name, Value: r.Value})
	}
	return out
}

// ListDomains returns the custom domains on a cluster.
func (c *Client) ListDomains(ctx context.Context, clusterID string) ([]Domain, error) {
	resp, err := c.gen.ListDomainsWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Domain, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, domainFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// GetDomain returns a custom domain by ID.
func (c *Client) GetDomain(ctx context.Context, clusterID, domainID string) (*Domain, error) {
	resp, err := c.gen.GetDomainWithResponse(ctx, cid(clusterID), uid(domainID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	d := domainFromAPI(resp.JSON200)
	return &d, nil
}

// CreateDomain adds a custom domain; the returned DNSRecords must be created by the customer.
func (c *Client) CreateDomain(ctx context.Context, clusterID, domain, subdomain string) (*Domain, error) {
	body := apiclient.CreateDomainJSONRequestBody{Domain: domain}
	if subdomain != "" {
		body.Subdomain = &subdomain
	}
	resp, err := c.gen.CreateDomainWithResponse(ctx, cid(clusterID), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	d := domainFromAPI(resp.JSON201)
	return &d, nil
}

// VerifyDomain triggers DNS verification and returns the updated domain.
func (c *Client) VerifyDomain(ctx context.Context, clusterID, domainID string) (*Domain, error) {
	resp, err := c.gen.VerifyDomainWithResponse(ctx, cid(clusterID), uid(domainID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	d := domainFromAPI(resp.JSON200)
	return &d, nil
}

// DeleteDomain removes a custom domain.
func (c *Client) DeleteDomain(ctx context.Context, clusterID, domainID string) error {
	resp, err := c.gen.DeleteDomainWithResponse(ctx, cid(clusterID), uid(domainID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// ---- Branding & themes ----

// Theme is a custom theme uploaded to a cluster (subset used by the tools).
type Theme struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Status     string   `json:"status"`
	ThemeTypes []string `json:"theme_types"`
	Version    string   `json:"version,omitempty"`
	FileSize   int64    `json:"file_size"`
}

func themeFromAPI(t *apiclient.Theme) Theme {
	out := Theme{ID: t.Id.String(), Name: t.Name, Status: string(t.Status), FileSize: t.FileSize}
	out.Version = strDeref(t.Version)
	for _, tt := range t.ThemeTypes {
		out.ThemeTypes = append(out.ThemeTypes, string(tt))
	}
	return out
}

// ListThemes returns the custom themes uploaded to a cluster.
func (c *Client) ListThemes(ctx context.Context, clusterID string) ([]Theme, error) {
	resp, err := c.gen.ListThemesWithResponse(ctx, cid(clusterID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Theme, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, themeFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// ThemeAssignment is the active theme per Keycloak theme type for a realm. An
// empty field means the realm uses Keycloak's built-in default.
type ThemeAssignment struct {
	Login   string `json:"login,omitempty"`
	Account string `json:"account,omitempty"`
	Admin   string `json:"admin,omitempty"`
	Email   string `json:"email,omitempty"`
}

func nThemeID(n nullable.Nullable[apiclient.ThemeId]) string {
	if !n.IsSpecified() || n.IsNull() {
		return ""
	}
	v, err := n.Get()
	if err != nil {
		return ""
	}
	return v.String()
}

func themeIDNullable(s string) nullable.Nullable[apiclient.ThemeId] {
	if s == "" {
		return nullable.NewNullNullable[apiclient.ThemeId]()
	}
	return nullable.NewNullableWithValue(uid(s))
}

func themeAssignmentFromAPI(a *apiclient.ThemeAssignment) *ThemeAssignment {
	return &ThemeAssignment{Login: nThemeID(a.Login), Account: nThemeID(a.Account), Admin: nThemeID(a.Admin), Email: nThemeID(a.Email)}
}

// GetThemeAssignment returns the realm-level theme assignment.
func (c *Client) GetThemeAssignment(ctx context.Context, clusterID, realm string) (*ThemeAssignment, error) {
	resp, err := c.gen.GetThemeAssignmentWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return themeAssignmentFromAPI(resp.JSON200), nil
}

// SetThemeAssignment sets the realm-level theme assignment. Empty fields are
// sent as explicit null (reset to Keycloak's built-in default).
func (c *Client) SetThemeAssignment(ctx context.Context, clusterID, realm string, a ThemeAssignment) (*ThemeAssignment, error) {
	body := apiclient.SetThemeAssignmentJSONRequestBody{
		Login: themeIDNullable(a.Login), Account: themeIDNullable(a.Account),
		Admin: themeIDNullable(a.Admin), Email: themeIDNullable(a.Email),
	}
	resp, err := c.gen.SetThemeAssignmentWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return themeAssignmentFromAPI(resp.JSON200), nil
}

// LoginBranding is the login-page branding for a realm (subset used by the tools).
type LoginBranding struct {
	PrimaryColor          string `json:"primary_color,omitempty"`
	BackgroundColor       string `json:"background_color,omitempty"`
	LogoURL               string `json:"logo_url,omitempty"`
	RegistrationEnabled   bool   `json:"registration_enabled"`
	ForgotPasswordEnabled bool   `json:"forgot_password_enabled"`
	Status                string `json:"status"`
}

// GetLoginBranding returns the login-branding configuration for a realm.
func (c *Client) GetLoginBranding(ctx context.Context, clusterID, realm string) (*LoginBranding, error) {
	resp, err := c.gen.GetLoginBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	b := resp.JSON200
	return &LoginBranding{
		PrimaryColor: strDeref(b.PrimaryColor), BackgroundColor: strDeref(b.BackgroundColor), LogoURL: strDeref(b.LogoUrl),
		RegistrationEnabled: b.RegistrationEnabled, ForgotPasswordEnabled: b.ForgotPasswordEnabled, Status: string(b.Status),
	}, nil
}

// EmailBranding is the email-template branding for a realm (subset used by the tools).
type EmailBranding struct {
	PrimaryColor       string `json:"primary_color,omitempty"`
	HeaderLogoLightURL string `json:"header_logo_light_url,omitempty"`
	FooterCompanyName  string `json:"footer_company_name,omitempty"`
	Status             string `json:"status"`
}

// GetEmailBranding returns the email-branding configuration for a realm.
func (c *Client) GetEmailBranding(ctx context.Context, clusterID, realm string) (*EmailBranding, error) {
	resp, err := c.gen.GetEmailBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	b := resp.JSON200
	return &EmailBranding{
		PrimaryColor: strDeref(b.PrimaryColor), HeaderLogoLightURL: strDeref(b.HeaderLogoLightUrl),
		FooterCompanyName: strDeref(b.FooterCompanyName), Status: string(b.Status),
	}, nil
}

// ---- Extensions ----

func nstrN(n nullable.Nullable[string]) string {
	if !n.IsSpecified() || n.IsNull() {
		return ""
	}
	v, err := n.Get()
	if err != nil {
		return ""
	}
	return v
}

// ExtensionInfo is a catalog entry from the extensions marketplace.
type ExtensionInfo struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	Source           string   `json:"source"`
	KeycloakVersions []string `json:"keycloak_versions"`
	DocumentationURL string   `json:"documentation_url,omitempty"`
}

func extensionInfoFromAPI(e *apiclient.Extension) ExtensionInfo {
	return ExtensionInfo{
		ID: e.Id.String(), Name: e.Name, Description: nstrN(e.Description), Source: string(e.Source),
		KeycloakVersions: e.KeycloakVersions, DocumentationURL: nstrN(e.DocumentationUrl),
	}
}

// ListExtensions returns the extension catalog available to the workspace.
func (c *Client) ListExtensions(ctx context.Context) ([]ExtensionInfo, error) {
	resp, err := c.gen.ListExtensionsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ExtensionInfo, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, extensionInfoFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// GetExtension returns a single catalog extension by ID.
func (c *Client) GetExtension(ctx context.Context, extensionID string) (*ExtensionInfo, error) {
	resp, err := c.gen.GetExtensionWithResponse(ctx, uid(extensionID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := extensionInfoFromAPI(resp.JSON200)
	return &e, nil
}

// ClusterExtension is an extension installed on a cluster.
type ClusterExtension struct {
	ExtensionID      string `json:"extension_id"`
	ExtensionName    string `json:"extension_name"`
	Source           string `json:"source"`
	InstalledVersion string `json:"installed_version"`
	AvailableVersion string `json:"available_version,omitempty"`
	Status           string `json:"status"`
	UpgradeAvailable bool   `json:"upgrade_available"`
}

func clusterExtensionFromAPI(e *apiclient.ClusterExtension) ClusterExtension {
	return ClusterExtension{
		ExtensionID: e.ExtensionId.String(), ExtensionName: e.ExtensionName, Source: string(e.ExtensionSource),
		InstalledVersion: e.InstalledVersion, AvailableVersion: nstrN(e.AvailableVersion),
		Status: string(e.Status), UpgradeAvailable: e.UpgradeAvailable,
	}
}

// ListClusterExtensions returns the extensions installed on a cluster.
func (c *Client) ListClusterExtensions(ctx context.Context, clusterID string) ([]ClusterExtension, error) {
	resp, err := c.gen.ListClusterExtensionsWithResponse(ctx, cid(clusterID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ClusterExtension, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, clusterExtensionFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// InstallExtension installs an extension on a cluster (asynchronous).
func (c *Client) InstallExtension(ctx context.Context, clusterID, extensionID string, params map[string]string) (*ClusterExtension, error) {
	body := apiclient.InstallExtensionJSONRequestBody{ExtensionId: uid(extensionID)}
	if len(params) > 0 {
		body.Parameters = &params
	}
	resp, err := c.gen.InstallExtensionWithResponse(ctx, cid(clusterID), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON202 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := clusterExtensionFromAPI(resp.JSON202)
	return &e, nil
}

// UpgradeExtension upgrades an installed extension to the latest version (asynchronous).
func (c *Client) UpgradeExtension(ctx context.Context, clusterID, extensionID string) (*ClusterExtension, error) {
	resp, err := c.gen.UpgradeClusterExtensionWithResponse(ctx, cid(clusterID), uid(extensionID))
	if err != nil {
		return nil, err
	}
	if resp.JSON202 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := clusterExtensionFromAPI(resp.JSON202)
	return &e, nil
}

// UninstallExtension removes an extension from a cluster.
func (c *Client) UninstallExtension(ctx context.Context, clusterID, extensionID string) error {
	resp, err := c.gen.UninstallExtensionWithResponse(ctx, cid(clusterID), uid(extensionID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// ---- Database exports ----

func ntimeN(n nullable.Nullable[time.Time]) string {
	if !n.IsSpecified() || n.IsNull() {
		return ""
	}
	v, err := n.Get()
	if err != nil {
		return ""
	}
	return v.Format(time.RFC3339)
}

func nintN(n nullable.Nullable[int]) int64 {
	if !n.IsSpecified() || n.IsNull() {
		return 0
	}
	v, err := n.Get()
	if err != nil {
		return 0
	}
	return int64(v)
}

// Export is a database export job (subset used by the tools).
type Export struct {
	ID            string `json:"id"`
	Format        string `json:"format"`
	Status        string `json:"status"`
	Progress      int64  `json:"progress"`
	IsEncrypted   bool   `json:"is_encrypted"`
	FileSizeBytes int64  `json:"file_size_bytes,omitempty"`
	DownloadURL   string `json:"download_url,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
	CompletedAt   string `json:"completed_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

func exportFromAPI(e *apiclient.Export) Export {
	return Export{
		ID: e.Id.String(), Format: string(e.Format), Status: string(e.Status), Progress: int64(e.Progress),
		IsEncrypted: e.IsEncrypted, FileSizeBytes: nintN(e.FileSizeBytes), DownloadURL: nstrN(e.DownloadUrl),
		ErrorMessage: nstrN(e.ErrorMessage), CompletedAt: ntimeN(e.CompletedAt), ExpiresAt: ntimeN(e.ExpiresAt),
	}
}

// ListExports returns the export jobs for a cluster.
func (c *Client) ListExports(ctx context.Context, clusterID string) ([]Export, error) {
	resp, err := c.gen.ListExportsWithResponse(ctx, cid(clusterID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Export, 0, len(*resp.JSON200))
	for _, s := range *resp.JSON200 {
		out = append(out, Export{ID: s.Id.String(), Format: string(s.Format), Status: string(s.Status), CompletedAt: ntimeN(s.CompletedAt), ExpiresAt: ntimeN(s.ExpiresAt)})
	}
	return out, nil
}

// GetExport returns a single export job by ID.
func (c *Client) GetExport(ctx context.Context, clusterID, exportID string) (*Export, error) {
	resp, err := c.gen.GetExportWithResponse(ctx, cid(clusterID), uid(exportID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := exportFromAPI(resp.JSON200)
	return &e, nil
}

// CreateExport starts a database export job (asynchronous).
func (c *Client) CreateExport(ctx context.Context, clusterID, format string, includeCredentials bool, encryptionPassword string) (*Export, error) {
	body := apiclient.CreateExportJSONRequestBody{Format: apiclient.ExportFormat(format)}
	if includeCredentials {
		inc := true
		body.IncludeCredentials = &inc
	}
	if encryptionPassword != "" {
		body.EncryptionPassword = &encryptionPassword
	}
	resp, err := c.gen.CreateExportWithResponse(ctx, cid(clusterID), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON202 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := exportFromAPI(resp.JSON202)
	return &e, nil
}

// ---- Realm RBAC ----

// RealmRole is a realm-scoped role.
type RealmRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Composite   bool   `json:"composite"`
}

func realmRoleFromAPI(r *apiclient.RealmRole) RealmRole {
	out := RealmRole{Name: r.Name, Description: nstrN(r.Description)}
	if r.Composite != nil {
		out.Composite = *r.Composite
	}
	return out
}

// ListRealmRoles returns the realm-scoped roles of a realm.
func (c *Client) ListRealmRoles(ctx context.Context, clusterID, realm string) ([]RealmRole, error) {
	resp, err := c.gen.ListRealmRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]RealmRole, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, realmRoleFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// CreateRealmRole creates a realm role.
func (c *Client) CreateRealmRole(ctx context.Context, clusterID, realm, name, description string) (*RealmRole, error) {
	body := apiclient.CreateRealmRoleJSONRequestBody{Name: name}
	if description != "" {
		body.Description = &description
	}
	resp, err := c.gen.CreateRealmRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := realmRoleFromAPI(resp.JSON201)
	return &r, nil
}

// DeleteRealmRole removes a realm role.
func (c *Client) DeleteRealmRole(ctx context.Context, clusterID, realm, name string) error {
	resp, err := c.gen.DeleteRealmRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), name)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// RealmGroup is a realm group.
type RealmGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

func realmGroupFromAPI(g *apiclient.RealmGroup) RealmGroup {
	return RealmGroup{ID: g.Id.String(), Name: g.Name, Path: g.Path}
}

// ListRealmGroups returns the top-level groups of a realm.
func (c *Client) ListRealmGroups(ctx context.Context, clusterID, realm string) ([]RealmGroup, error) {
	resp, err := c.gen.ListRealmGroupsWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]RealmGroup, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, realmGroupFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// CreateRealmGroup creates a realm group, optionally nested under a parent.
func (c *Client) CreateRealmGroup(ctx context.Context, clusterID, realm, name, parentID string) (*RealmGroup, error) {
	body := apiclient.CreateRealmGroupJSONRequestBody{Name: name}
	if parentID != "" {
		pid := uid(parentID)
		body.ParentId = &pid
	}
	resp, err := c.gen.CreateRealmGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	g := realmGroupFromAPI(resp.JSON201)
	return &g, nil
}

// DeleteRealmGroup removes a realm group.
func (c *Client) DeleteRealmGroup(ctx context.Context, clusterID, realm, groupID string) error {
	resp, err := c.gen.DeleteRealmGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), uid(groupID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// RealmUser is a realm user.
type RealmUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	FirstName     string `json:"first_name,omitempty"`
	LastName      string `json:"last_name,omitempty"`
	Enabled       bool   `json:"enabled"`
	EmailVerified bool   `json:"email_verified"`
}

func realmUserFromAPI(u *apiclient.RealmUser) RealmUser {
	out := RealmUser{ID: u.Id, Username: string(u.Username), Email: string(u.Email), Enabled: u.Enabled}
	out.FirstName = strDeref(u.FirstName)
	out.LastName = strDeref(u.LastName)
	if u.EmailVerified != nil {
		out.EmailVerified = *u.EmailVerified
	}
	return out
}

// ListRealmUsers returns the users of a realm.
func (c *Client) ListRealmUsers(ctx context.Context, clusterID, realm string) ([]RealmUser, error) {
	resp, err := c.gen.ListRealmUsersWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]RealmUser, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, realmUserFromAPI(&(*resp.JSON200)[i]))
	}
	return out, nil
}

// GetRealmUser returns a single realm user by ID.
func (c *Client) GetRealmUser(ctx context.Context, clusterID, realm, userID string) (*RealmUser, error) {
	resp, err := c.gen.GetRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	u := realmUserFromAPI(resp.JSON200)
	return &u, nil
}

// CreateRealmUser creates a realm user.
func (c *Client) CreateRealmUser(ctx context.Context, clusterID, realm, username, email, firstName, lastName, temporaryPassword string, enabled bool) (*RealmUser, error) {
	en := enabled
	body := apiclient.CreateRealmUserJSONRequestBody{Username: username, Email: openapitypes.Email(email), TemporaryPassword: temporaryPassword, Enabled: &en}
	if firstName != "" {
		body.FirstName = &firstName
	}
	if lastName != "" {
		body.LastName = &lastName
	}
	resp, err := c.gen.CreateRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	u := realmUserFromAPI(resp.JSON201)
	return &u, nil
}

// DeleteRealmUser removes a realm user.
func (c *Client) DeleteRealmUser(ctx context.Context, clusterID, realm, userID string) error {
	resp, err := c.gen.DeleteRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// AssignRealmUserRole assigns a realm role to a user.
func (c *Client) AssignRealmUserRole(ctx context.Context, clusterID, realm, userID, roleName string) error {
	body := apiclient.AssignRealmUserRolesJSONRequestBody{RoleNames: []apiclient.RealmRoleName{roleName}}
	resp, err := c.gen.AssignRealmUserRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, body)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// RemoveRealmUserRole removes a realm role from a user.
func (c *Client) RemoveRealmUserRole(ctx context.Context, clusterID, realm, userID, roleName string) error {
	resp, err := c.gen.RemoveRealmUserRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, roleName)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// AddRealmUserToGroup adds a user to a group.
func (c *Client) AddRealmUserToGroup(ctx context.Context, clusterID, realm, userID, groupID string) error {
	resp, err := c.gen.AddRealmUserToGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, uid(groupID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// RemoveRealmUserFromGroup removes a user from a group.
func (c *Client) RemoveRealmUserFromGroup(ctx context.Context, clusterID, realm, userID, groupID string) error {
	resp, err := c.gen.RemoveRealmUserFromGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, uid(groupID))
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// ---- Application roles & sessions ----

// ApplicationRole is a role assigned to an application's service account.
type ApplicationRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	ClientRole  bool   `json:"client_role"`
}

// ListApplicationRoles returns the roles on an application's service account.
func (c *Client) ListApplicationRoles(ctx context.Context, clusterID, realm, clientID string) ([]ApplicationRole, error) {
	resp, err := c.gen.ListApplicationRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ApplicationRole, 0, len(*resp.JSON200))
	for _, r := range *resp.JSON200 {
		out = append(out, ApplicationRole{Name: r.Name, Description: strDeref(r.Description), ClientRole: r.ClientRole})
	}
	return out, nil
}

// AssignApplicationRole assigns a role to an application's service account.
func (c *Client) AssignApplicationRole(ctx context.Context, clusterID, realm, clientID, roleName, roleClientID string) error {
	body := apiclient.AssignApplicationRoleJSONRequestBody{Name: roleName}
	if roleClientID != "" {
		body.RoleClientId = &roleClientID
	}
	resp, err := c.gen.AssignApplicationRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), body)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// RemoveApplicationRole removes a role from an application's service account.
func (c *Client) RemoveApplicationRole(ctx context.Context, clusterID, realm, clientID, roleName, roleClientID string) error {
	var params *apiclient.RemoveApplicationRoleParams
	if roleClientID != "" {
		params = &apiclient.RemoveApplicationRoleParams{RoleClientId: &roleClientID}
	}
	resp, err := c.gen.RemoveApplicationRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), roleName, params)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// ApplicationSession is an active user session for an application.
type ApplicationSession struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email,omitempty"`
	IPAddress    string `json:"ip_address,omitempty"`
	LastAccessAt string `json:"last_access_at"`
}

// ListApplicationSessions returns active user sessions for an application.
func (c *Client) ListApplicationSessions(ctx context.Context, clusterID, realm, clientID string) ([]ApplicationSession, error) {
	resp, err := c.gen.ListApplicationSessionsWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ApplicationSession, 0, len(*resp.JSON200))
	for _, s := range *resp.JSON200 {
		out = append(out, ApplicationSession{ID: s.Id, Username: s.Username, Email: strDeref(s.Email), IPAddress: strDeref(s.IpAddress), LastAccessAt: fmtTime(s.LastAccessAt)})
	}
	return out, nil
}

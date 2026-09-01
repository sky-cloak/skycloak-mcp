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
	httpClient        *http.Client
	userAgent         string
	perAttemptTimeout time.Duration
}

// defaultPerAttemptTimeout bounds a single HTTP attempt. It deliberately does
// not bound the whole call: retry backoff can exceed it (the gateway may ask
// for a 60s Retry-After), and the caller's context is what limits the total.
const defaultPerAttemptTimeout = 30 * time.Second

// WithHTTPClient overrides the underlying HTTP client (useful in tests). The
// client is copied, not mutated. Note that its Timeout, if set, bounds the whole
// call including retry backoff; use WithPerAttemptTimeout to bound one attempt.
func WithHTTPClient(h *http.Client) Option { return func(c *config) { c.httpClient = h } }

// WithUserAgent sets the User-Agent header sent on every request.
func WithUserAgent(ua string) Option { return func(c *config) { c.userAgent = ua } }

// WithPerAttemptTimeout overrides how long a single attempt may take.
func WithPerAttemptTimeout(d time.Duration) Option {
	return func(c *config) { c.perAttemptTimeout = d }
}

// New builds a Client. endpoint defaults to https://api.skycloak.io when empty.
func New(endpoint, apiKey, apiVersion string, opts ...Option) *Client {
	cfg := &config{httpClient: &http.Client{}, userAgent: "skycloak-go/dev", perAttemptTimeout: defaultPerAttemptTimeout}
	for _, o := range opts {
		o(cfg)
	}
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	// Copy rather than mutate: the caller's client is theirs, and installing our
	// transport on it would leak retry behavior into their other requests.
	hc := *cfg.httpClient
	// Retry 429/5xx with Retry-After-aware backoff.
	hc.Transport = &retryTransport{base: hc.Transport, maxRetries: 4, perAttempt: cfg.perAttemptTimeout, totalWaitBudget: defaultTotalWaitBudget}
	cfg.httpClient = &hc

	editor := func(_ context.Context, req *http.Request) error {
		req.Header.Set("API-Key", apiKey)
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
	ID                 string
	Name               string
	Type               string
	Size               string
	Version            string
	Location           string
	Status             string
	URL                string
	CreatedAt          string
	UpdatedAt          string
	AutoUpgradeEnabled bool
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
	resp, err := c.gen.ListClustersWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Cluster, 0, len(*resp.JSON200))
	for _, s := range *resp.JSON200 {
		out = append(out, clusterSummaryFromAPI(&s))
	}
	return out, nil
}

func clusterSummaryFromAPI(cl *apiclient.ClusterSummary) Cluster {
	autoUpgradeEnabled := false
	if cl.AutoUpgradeEnabled != nil {
		autoUpgradeEnabled = *cl.AutoUpgradeEnabled
	}
	return Cluster{
		ID: cl.Id.String(), Name: string(cl.Name), Type: string(cl.Type), Size: string(cl.Size),
		Version: string(cl.Version), Location: string(cl.Location), Status: string(cl.Status),
		URL: cl.Url, CreatedAt: fmtTime(cl.CreatedAt), UpdatedAt: fmtTime(cl.UpdatedAt),
		AutoUpgradeEnabled: autoUpgradeEnabled,
	}
}

func clusterFromAPI(cl *apiclient.Cluster) *Cluster {
	autoUpgradeEnabled := false
	if cl.AutoUpgradeEnabled != nil {
		autoUpgradeEnabled = *cl.AutoUpgradeEnabled
	}
	return &Cluster{
		ID: cl.Id.String(), Name: string(cl.Name), Type: string(cl.Type), Size: string(cl.Size),
		Version: string(cl.Version), Location: string(cl.Location), Status: string(cl.Status),
		URL: cl.Url, CreatedAt: fmtTime(cl.CreatedAt), UpdatedAt: fmtTime(cl.UpdatedAt),
		AutoUpgradeEnabled: autoUpgradeEnabled,
	}
}

// GetCluster returns a single cluster by ID.
func (c *Client) GetCluster(ctx context.Context, id string) (*Cluster, error) {
	resp, err := c.gen.GetClusterWithResponse(ctx, cid(id), nil)
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
	Name               string
	Type               string
	Size               string
	Version            string
	Location           string
	AutoUpgradeEnabled *bool
	MaintenanceWindow  *MaintenanceWindow
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
	body.AutoUpgradeEnabled = req.AutoUpgradeEnabled
	if req.MaintenanceWindow != nil {
		body.MaintenanceWindow = maintenanceWindowToAPI(req.MaintenanceWindow)
	}
	resp, err := c.gen.CreateClusterWithResponse(ctx, nil, body)
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
	resp, err := c.gen.DeleteClusterWithResponse(ctx, cid(id), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// Realm mirrors the public API Realm resource (subset used by the tools).
// Realm is a Keycloak realm.
//
// The security settings are plain bools, not pointers: the API marks every one
// of them required, so there is no "the API did not say" case to represent. If
// that ever becomes optional upstream they must become pointers, or an omitted
// value would silently read as "registration is off" — a wrong answer to a
// security question rather than a missing one.
type Realm struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`

	ID                          string `json:"id,omitempty"`
	SSLRequired                 string `json:"ssl_required,omitempty"`
	RegistrationAllowed         bool   `json:"registration_allowed"`
	RegistrationEmailAsUsername bool   `json:"registration_email_as_username"`
	LoginWithEmailAllowed       bool   `json:"login_with_email_allowed"`
	DuplicateEmailsAllowed      bool   `json:"duplicate_emails_allowed"`
}

// ListRealms returns the realms in a cluster.
func (c *Client) ListRealms(ctx context.Context, clusterID string) ([]Realm, error) {
	resp, err := c.gen.ListRealmsWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Realm, 0, len(*resp.JSON200))
	for i := range *resp.JSON200 {
		out = append(out, realmFromAPI(&(*resp.JSON200)[i]))
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
	resp, err := c.gen.CreateRealmWithResponse(ctx, cid(clusterID), nil, body)
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
	resp, err := c.gen.DeleteRealmWithResponse(ctx, cid(clusterID), apiclient.RealmName(name), nil)
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
	resp, err := c.gen.CreateApplicationWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
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
	resp, err := c.gen.DeleteApplicationWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil)
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
	resp, err := c.gen.CreateIdentityProviderWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
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
	resp, err := c.gen.DeleteIdentityProviderWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ProviderId(providerID), nil)
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
	resp, err := c.gen.ListIdentityProvidersWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
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
	Offset   int
	Category string
	Realm    string
	Username string
	Search   string

	// StartTime and EndTime are RFC3339. The API defaults to the last 24 hours
	// when both are empty, so a caller asking about last week gets silence
	// rather than an error unless it sets these.
	StartTime string
	EndTime   string

	// Types filters user events, OperationTypes admin events. The API rejects
	// them together, and each is ignored for the other category.
	Types          []string
	OperationTypes []string

	// Error filters user events by Keycloak error code.
	Error string

	// Order is asc or desc over timestamp; the API defaults to desc.
	Order string
}

// EventEntry is one Keycloak user/admin event.
//
// The admin fields matter more than their size suggests: an admin event whose
// operation is UPDATE says nothing on its own, since a realm-settings change, a
// user edit and a client edit all look identical without the resource.
type EventEntry struct {
	Timestamp string `json:"timestamp"`
	Category  string `json:"category"`
	Type      string `json:"type,omitempty"`
	RealmName string `json:"realm_name,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Error     string `json:"error,omitempty"`

	// Admin events.
	OperationType string `json:"operation_type,omitempty"`
	ResourceType  string `json:"resource_type,omitempty"`
	ResourcePath  string `json:"resource_path,omitempty"`

	// User events.
	UserID           string `json:"user_id,omitempty"`
	SessionID        string `json:"session_id,omitempty"`
	AuthMethod       string `json:"auth_method,omitempty"`
	IdentityProvider string `json:"identity_provider,omitempty"`
	GrantType        string `json:"grant_type,omitempty"`
	IsM2M            *bool  `json:"is_m2m,omitempty"`
}

// parseEventTime accepts RFC3339.
//
// An unparseable value is an error, not a silent drop. Dropping it would leave
// the API to apply its default 24-hour window while the caller believes its own
// range applied, so a question about last week answers from yesterday and reads
// as "nothing happened". That is the failure this whole change exists to remove,
// and it would be worse here than a rejected call: "2026-08-25" and a zone-less
// timestamp are both plausible inputs.
func parseEventTime(field, v string) (time.Time, bool, error) {
	if v == "" {
		return time.Time{}, false, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("%s must be RFC3339 (e.g. 2026-08-31T00:00:00Z), got %q", field, v)
	}
	return t, true, nil
}

// realmFromAPI is shared by GetRealm and ListRealms so the same entity cannot
// serialise two different ways depending on which call produced it.
func realmFromAPI(r *apiclient.Realm) Realm {
	return Realm{
		Name:        string(r.Name),
		DisplayName: string(r.DisplayName),
		Enabled:     r.Enabled,
		ID:          r.Id.String(),
		SSLRequired: string(r.SslRequired),

		RegistrationAllowed:         r.RegistrationAllowed,
		RegistrationEmailAsUsername: r.RegistrationEmailAsUsername,
		LoginWithEmailAllowed:       r.LoginWithEmailAllowed,
		DuplicateEmailsAllowed:      r.DuplicateEmailsAllowed,
	}
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
	if q.Offset < 0 {
		return nil, fmt.Errorf("offset must not be negative, got %d", q.Offset)
	}
	if q.Offset > 0 {
		o := apiclient.PageOffset(q.Offset)
		params.Offset = &o
	}
	if t, ok, err := parseEventTime("start_time", q.StartTime); err != nil {
		return nil, err
	} else if ok {
		params.StartTime = &t
	}
	if t, ok, err := parseEventTime("end_time", q.EndTime); err != nil {
		return nil, err
	} else if ok {
		params.EndTime = &t
	}
	// types applies to user events, operation_types to admin events, and the
	// spec rejects each for the other category.
	//
	// Every mismatch here is refused rather than quietly resolved. Dropping a
	// filter that does not apply would return the whole category unfiltered
	// while the caller believes it narrowed the query — the same "filter that
	// silently did not apply" this change exists to remove, and the one that
	// reads as a confident answer rather than an error.
	switch {
	case len(q.Types) > 0 && len(q.OperationTypes) > 0:
		// Even with a category naming one of them, asking for both says the
		// caller expects both to apply, and only one ever can.
		return nil, fmt.Errorf("types and operation_types are mutually exclusive: pass only the one matching the category you want")
	case len(q.Types) > 0 && q.Category == "admin":
		return nil, fmt.Errorf("types filters user events but category is admin: use operation_types, or set category to user")
	case len(q.OperationTypes) > 0 && q.Category == "user":
		return nil, fmt.Errorf("operation_types filters admin events but category is user: use types, or set category to admin")
	}
	if len(q.Types) > 0 {
		ts := make([]apiclient.UserEventType, 0, len(q.Types))
		for _, t := range q.Types {
			ts = append(ts, apiclient.UserEventType(t))
		}
		params.Types = &ts
	}
	if len(q.OperationTypes) > 0 {
		os := make([]apiclient.AdminOperationType, 0, len(q.OperationTypes))
		for _, t := range q.OperationTypes {
			os = append(os, apiclient.AdminOperationType(t))
		}
		params.OperationTypes = &os
	}
	if q.Error != "" {
		params.Error = &q.Error
	}
	if q.Order != "" {
		o := apiclient.SortOrder(q.Order)
		params.Order = &o
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
		entry := EventEntry{
			Timestamp: e.Timestamp.Format(time.RFC3339), Category: string(e.Category), Type: typ,
			RealmName: e.RealmName, ClientID: strDeref(e.ClientId), Username: strDeref(e.Username),
			IPAddress: strDeref(e.IpAddress), Error: strDeref(e.Error),
			ResourceType: strDeref(e.ResourceType), ResourcePath: strDeref(e.ResourcePath),
			SessionID: strDeref(e.SessionId), AuthMethod: strDeref(e.AuthMethod),
			IdentityProvider: strDeref(e.IdentityProvider), GrantType: strDeref(e.GrantType),
		}
		if e.OperationType != nil {
			entry.OperationType = string(*e.OperationType)
		}
		if e.UserId != nil {
			entry.UserID = e.UserId.String()
		}
		// Carried as a pointer: admin events have no machine-to-machine notion,
		// and a bare false would assert one rather than leave it unstated.
		entry.IsM2M = e.IsM2m
		out = append(out, entry)
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
	resp, err := c.gen.GetDomainWithResponse(ctx, cid(clusterID), uid(domainID), nil)
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
	resp, err := c.gen.CreateDomainWithResponse(ctx, cid(clusterID), nil, body)
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
	resp, err := c.gen.VerifyDomainWithResponse(ctx, cid(clusterID), uid(domainID), nil)
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
	resp, err := c.gen.DeleteDomainWithResponse(ctx, cid(clusterID), uid(domainID), nil)
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
	resp, err := c.gen.ListThemesWithResponse(ctx, cid(clusterID), nil)
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
	resp, err := c.gen.GetThemeAssignmentWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
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
	resp, err := c.gen.SetThemeAssignmentWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
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
	resp, err := c.gen.GetLoginBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
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
	resp, err := c.gen.GetEmailBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
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
	resp, err := c.gen.ListExtensionsWithResponse(ctx, nil)
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
	resp, err := c.gen.GetExtensionWithResponse(ctx, uid(extensionID), nil)
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
	resp, err := c.gen.ListClusterExtensionsWithResponse(ctx, cid(clusterID), nil)
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
	resp, err := c.gen.InstallExtensionWithResponse(ctx, cid(clusterID), nil, body)
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
	resp, err := c.gen.UpgradeClusterExtensionWithResponse(ctx, cid(clusterID), uid(extensionID), nil)
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
	resp, err := c.gen.UninstallExtensionWithResponse(ctx, cid(clusterID), uid(extensionID), nil)
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
	resp, err := c.gen.ListExportsWithResponse(ctx, cid(clusterID), nil)
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
	resp, err := c.gen.GetExportWithResponse(ctx, cid(clusterID), uid(exportID), nil)
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
	resp, err := c.gen.CreateExportWithResponse(ctx, cid(clusterID), nil, body)
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
	resp, err := c.gen.ListRealmRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
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
	resp, err := c.gen.CreateRealmRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
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
	resp, err := c.gen.DeleteRealmRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), name, nil)
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
	resp, err := c.gen.CreateRealmGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
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
	resp, err := c.gen.DeleteRealmGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), uid(groupID), nil)
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
	resp, err := c.gen.GetRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, nil)
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
	resp, err := c.gen.CreateRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
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
	resp, err := c.gen.DeleteRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, nil)
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
	resp, err := c.gen.AssignRealmUserRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, nil, body)
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
	resp, err := c.gen.RemoveRealmUserRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, roleName, nil)
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
	resp, err := c.gen.AddRealmUserToGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, uid(groupID), nil)
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
	resp, err := c.gen.RemoveRealmUserFromGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, uid(groupID), nil)
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
	resp, err := c.gen.ListApplicationRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil)
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
	resp, err := c.gen.AssignApplicationRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil, body)
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
	resp, err := c.gen.ListApplicationSessionsWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil)
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

// ---- Read parity: get-by-id, cluster metadata, lists ----

// GetRealm returns a single realm by name.
func (c *Client) GetRealm(ctx context.Context, clusterID, realm string) (*Realm, error) {
	resp, err := c.gen.GetRealmWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := realmFromAPI(resp.JSON200)
	return &r, nil
}

// GetApplication returns a single application by client ID.
func (c *Client) GetApplication(ctx context.Context, clusterID, realm, clientID string) (*Application, error) {
	resp, err := c.gen.GetApplicationWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	a := applicationFromAPI(resp.JSON200)
	return &a, nil
}

// GetIdentityProvider returns a single identity provider by provider ID.
func (c *Client) GetIdentityProvider(ctx context.Context, clusterID, realm, providerID string) (*IdentityProvider, error) {
	resp, err := c.gen.GetIdentityProviderWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), providerID, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	p := resp.JSON200
	return &IdentityProvider{ProviderID: string(p.ProviderId), Type: string(p.Type), DisplayName: p.DisplayName, Enabled: p.Enabled}, nil
}

// ClusterLocationInfo is a supported deployment region.
type ClusterLocationInfo struct {
	Location  string `json:"location"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

// ListClusterLocations returns the supported deployment regions.
func (c *Client) ListClusterLocations(ctx context.Context) ([]ClusterLocationInfo, error) {
	resp, err := c.gen.ListClusterLocationsWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ClusterLocationInfo, 0, len(*resp.JSON200))
	for _, l := range *resp.JSON200 {
		out = append(out, ClusterLocationInfo{Location: string(l.Location), Name: l.Name, Available: l.Available})
	}
	return out, nil
}

// ClusterTypeInfo is a supported cluster type.
type ClusterTypeInfo struct {
	Type      string `json:"type"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

// ListClusterTypes returns the supported cluster types.
func (c *Client) ListClusterTypes(ctx context.Context) ([]ClusterTypeInfo, error) {
	resp, err := c.gen.ListClusterTypesWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ClusterTypeInfo, 0, len(*resp.JSON200))
	for _, t := range *resp.JSON200 {
		out = append(out, ClusterTypeInfo{Type: string(t.Type), Name: t.Name, Available: t.Available})
	}
	return out, nil
}

// ClusterFeatureInfo is an available Keycloak feature flag.
type ClusterFeatureInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description,omitempty"`
	Preview     bool   `json:"preview"`
}

// ListClusterFeatures returns the available Keycloak feature flags.
func (c *Client) ListClusterFeatures(ctx context.Context) ([]ClusterFeatureInfo, error) {
	resp, err := c.gen.ListClusterFeaturesWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ClusterFeatureInfo, 0, len(*resp.JSON200))
	for _, f := range *resp.JSON200 {
		out = append(out, ClusterFeatureInfo{Name: f.Name, DisplayName: f.DisplayName, Description: nstrN(f.Description), Preview: f.Preview})
	}
	return out, nil
}

// ClusterTypeVersions returns the Keycloak versions available for a cluster type.
func (c *Client) ClusterTypeVersions(ctx context.Context, clusterType string) ([]string, error) {
	resp, err := c.gen.GetClusterTypeVersionsWithResponse(ctx, apiclient.ClusterType(clusterType), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return *resp.JSON200, nil
}

// ClusterUpgrade is a cluster version-upgrade record.
type ClusterUpgrade struct {
	ID          string `json:"id"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Phase       string `json:"phase"`
}

// ListClusterUpgrades returns the upgrade history for a cluster.
func (c *Client) ListClusterUpgrades(ctx context.Context, clusterID string) ([]ClusterUpgrade, error) {
	resp, err := c.gen.ListClusterUpgradesWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ClusterUpgrade, 0, len(*resp.JSON200))
	for _, u := range *resp.JSON200 {
		out = append(out, ClusterUpgrade{ID: u.Id, FromVersion: string(u.FromVersion), ToVersion: string(u.ToVersion), Phase: u.Phase})
	}
	return out, nil
}

// ProviderTemplate is a pre-configured identity-provider template.
type ProviderTemplate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"`
}

// ListIdentityProviderTemplates returns the identity-provider template catalog.
func (c *Client) ListIdentityProviderTemplates(ctx context.Context) ([]ProviderTemplate, error) {
	resp, err := c.gen.ListIdentityProviderTemplatesWithResponse(ctx, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]ProviderTemplate, 0, len(*resp.JSON200))
	for _, t := range *resp.JSON200 {
		out = append(out, ProviderTemplate{ID: t.Id, Name: t.Name, Description: t.Description, Type: string(t.Type)})
	}
	return out, nil
}

// DomainRoute maps a realm onto a custom domain.
type DomainRoute struct {
	ID               string `json:"id"`
	Realm            string `json:"realm"`
	AllowAdminAccess bool   `json:"allow_admin_access"`
	HideRealmPath    bool   `json:"hide_realm_path"`
}

// ListDomainRoutes returns the routes configured on a custom domain.
func (c *Client) ListDomainRoutes(ctx context.Context, clusterID, domainID string) ([]DomainRoute, error) {
	resp, err := c.gen.ListDomainRoutesWithResponse(ctx, cid(clusterID), uid(domainID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]DomainRoute, 0, len(*resp.JSON200))
	for _, r := range *resp.JSON200 {
		out = append(out, DomainRoute{ID: r.Id.String(), Realm: string(r.Realm), AllowAdminAccess: r.AllowAdminAccess, HideRealmPath: r.HideRealmPath})
	}
	return out, nil
}

// ---- Write/read parity (SMTP, rotate, routes, themes, deletes, update realm) ----

// SMTPConfig is a realm's SMTP configuration (non-secret subset).
type SMTPConfig struct {
	Host        string `json:"host"`
	Port        int64  `json:"port"`
	Encryption  string `json:"encryption,omitempty"`
	FromEmail   string `json:"from_email"`
	FromName    string `json:"from_name,omitempty"`
	AuthType    string `json:"auth_type"`
	HasPassword bool   `json:"has_password"`
	Status      string `json:"status,omitempty"`
}

// GetSMTP returns the SMTP configuration for a realm.
func (c *Client) GetSMTP(ctx context.Context, clusterID, realm string) (*SMTPConfig, error) {
	resp, err := c.gen.GetSmtpConfigWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	s := resp.JSON200
	out := &SMTPConfig{
		Host: string(s.Host), Port: int64(s.Port), Encryption: string(s.Encryption), FromEmail: string(s.FromEmail),
		AuthType: string(s.AuthType), HasPassword: s.HasPassword, Status: string(s.Status),
	}
	out.FromName = strDeref(s.FromName)
	return out, nil
}

// DeleteSMTP removes the SMTP configuration for a realm.
func (c *Client) DeleteSMTP(ctx context.Context, clusterID, realm string) error {
	resp, err := c.gen.DeleteSmtpConfigWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// RotateApplicationSecret regenerates and returns an application's client secret.
func (c *Client) RotateApplicationSecret(ctx context.Context, clusterID, realm, clientID string) (string, error) {
	resp, err := c.gen.RotateApplicationSecretWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil)
	if err != nil {
		return "", err
	}
	if resp.JSON200 == nil {
		return "", statusError(resp.HTTPResponse, resp.Body)
	}
	return resp.JSON200.ClientSecret, nil
}

// GetTheme returns a single custom theme by ID.
func (c *Client) GetTheme(ctx context.Context, clusterID, themeID string) (*Theme, error) {
	resp, err := c.gen.GetThemeWithResponse(ctx, cid(clusterID), uid(themeID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	t := themeFromAPI(resp.JSON200)
	return &t, nil
}

// DeleteTheme removes a custom theme from a cluster.
func (c *Client) DeleteTheme(ctx context.Context, clusterID, themeID string) error {
	resp, err := c.gen.DeleteThemeWithResponse(ctx, cid(clusterID), uid(themeID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// DeleteExtension removes a custom extension from the workspace catalog.
func (c *Client) DeleteExtension(ctx context.Context, extensionID string) error {
	resp, err := c.gen.DeleteExtensionWithResponse(ctx, uid(extensionID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// DeleteExport removes an export archive.
func (c *Client) DeleteExport(ctx context.Context, clusterID, exportID string) error {
	resp, err := c.gen.DeleteExportWithResponse(ctx, cid(clusterID), uid(exportID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// GetDomainRoute returns a single domain route.
func (c *Client) GetDomainRoute(ctx context.Context, clusterID, domainID, routeID string) (*DomainRoute, error) {
	resp, err := c.gen.GetDomainRouteWithResponse(ctx, cid(clusterID), uid(domainID), uid(routeID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := resp.JSON200
	return &DomainRoute{ID: r.Id.String(), Realm: string(r.Realm), AllowAdminAccess: r.AllowAdminAccess, HideRealmPath: r.HideRealmPath}, nil
}

// CreateDomainRoute adds a realm route to a domain.
func (c *Client) CreateDomainRoute(ctx context.Context, clusterID, domainID, realm string, allowAdminAccess, hideRealmPath bool) (*DomainRoute, error) {
	admin, hide := allowAdminAccess, hideRealmPath
	body := apiclient.CreateDomainRouteJSONRequestBody{Realm: apiclient.RealmName(realm), AllowAdminAccess: &admin, HideRealmPath: &hide}
	resp, err := c.gen.CreateDomainRouteWithResponse(ctx, cid(clusterID), uid(domainID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := resp.JSON201
	return &DomainRoute{ID: r.Id.String(), Realm: string(r.Realm), AllowAdminAccess: r.AllowAdminAccess, HideRealmPath: r.HideRealmPath}, nil
}

// DeleteDomainRoute removes a route from a domain.
func (c *Client) DeleteDomainRoute(ctx context.Context, clusterID, domainID, routeID string) error {
	resp, err := c.gen.DeleteDomainRouteWithResponse(ctx, cid(clusterID), uid(domainID), uid(routeID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// GetClientThemeAssignment returns a client's login-theme override ("" = realm default).
func (c *Client) GetClientThemeAssignment(ctx context.Context, clusterID, realm, clientID string) (string, error) {
	resp, err := c.gen.GetClientThemeAssignmentWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil)
	if err != nil {
		return "", err
	}
	if resp.JSON200 == nil {
		return "", statusError(resp.HTTPResponse, resp.Body)
	}
	return nThemeID(resp.JSON200.Login), nil
}

// SetClientThemeAssignment sets a client's login-theme override; "" resets to the realm default.
func (c *Client) SetClientThemeAssignment(ctx context.Context, clusterID, realm, clientID, login string) (string, error) {
	body := apiclient.SetClientThemeAssignmentJSONRequestBody{Login: themeIDNullable(login)}
	resp, err := c.gen.SetClientThemeAssignmentWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil, body)
	if err != nil {
		return "", err
	}
	if resp.JSON200 == nil {
		return "", statusError(resp.HTTPResponse, resp.Body)
	}
	return nThemeID(resp.JSON200.Login), nil
}

// ListRealmUserRoles returns the realm roles assigned to a user.
func (c *Client) ListRealmUserRoles(ctx context.Context, clusterID, realm, userID string) ([]RealmRole, error) {
	resp, err := c.gen.ListRealmUserRolesWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, nil)
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

// ListRealmUserGroups returns the groups a user belongs to.
func (c *Client) ListRealmUserGroups(ctx context.Context, clusterID, realm, userID string) ([]RealmGroup, error) {
	resp, err := c.gen.ListRealmUserGroupsWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, nil)
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

// UpdateRealm updates a realm's mutable settings.
func (c *Client) UpdateRealm(ctx context.Context, clusterID, realm, displayName string, enabled bool) (*Realm, error) {
	en := enabled
	body := apiclient.UpdateRealmJSONRequestBody{Enabled: &en}
	if displayName != "" {
		dn := apiclient.RealmDisplayName(displayName)
		body.DisplayName = &dn
	}
	resp, err := c.gen.UpdateRealmWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := resp.JSON200
	return &Realm{Name: string(r.Name), DisplayName: string(r.DisplayName), Enabled: r.Enabled}, nil
}

// ---- Actions: discover, test, cancel upgrade ----

// OIDCDiscovery is the subset of an OIDC discovery document used to pre-fill a provider.
type OIDCDiscovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JwksURI               string   `json:"jwks_uri,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// DiscoverOIDC fetches the OIDC discovery document for an issuer URL.
func (c *Client) DiscoverOIDC(ctx context.Context, issuerURL string) (*OIDCDiscovery, error) {
	resp, err := c.gen.DiscoverOIDCWithResponse(ctx, nil, apiclient.DiscoverOIDCJSONRequestBody{IssuerUrl: issuerURL})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	d := resp.JSON200
	out := &OIDCDiscovery{Issuer: d.Issuer, AuthorizationEndpoint: d.AuthorizationEndpoint, TokenEndpoint: d.TokenEndpoint}
	out.UserinfoEndpoint = strDeref(d.UserinfoEndpoint)
	out.JwksURI = strDeref(d.JwksUri)
	if d.ScopesSupported != nil {
		out.ScopesSupported = *d.ScopesSupported
	}
	return out, nil
}

// TestResult is the outcome of a connectivity/config test.
type TestResult struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// TestSMTP sends a test email through a realm's SMTP configuration.
func (c *Client) TestSMTP(ctx context.Context, clusterID, realm, email string) (*TestResult, error) {
	body := apiclient.TestSmtpConfigJSONRequestBody{Email: openapitypes.Email(email)}
	resp, err := c.gen.TestSmtpConfigWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return &TestResult{Success: resp.JSON200.Success, Message: strDeref(resp.JSON200.Message)}, nil
}

// TestIdentityProviderConnection tests connectivity to an identity provider,
// optionally overriding the client credentials for the test only.
func (c *Client) TestIdentityProviderConnection(ctx context.Context, clusterID, realm, providerID, clientID, clientSecret string) (*TestResult, error) {
	body := apiclient.TestIdentityProviderConnectionJSONRequestBody{}
	if clientID != "" {
		body.ClientId = &clientID
	}
	if clientSecret != "" {
		body.ClientSecret = &clientSecret
	}
	resp, err := c.gen.TestIdentityProviderConnectionWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), providerID, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return &TestResult{Success: resp.JSON200.Success, Message: resp.JSON200.Message}, nil
}

// CancelClusterUpgrade cancels an in-progress cluster upgrade.
func (c *Client) CancelClusterUpgrade(ctx context.Context, clusterID string) error {
	resp, err := c.gen.CancelClusterUpgradeWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// ---- Read parity: credentials, builds, upgrade path, insights, role/group get, members ----

// ClusterCredentials holds a cluster's Keycloak automation client credentials.
type ClusterCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	TokenURL     string `json:"token_url"`
}

// GetClusterCredentials returns a cluster's automation client credentials.
func (c *Client) GetClusterCredentials(ctx context.Context, clusterID string) (*ClusterCredentials, error) {
	resp, err := c.gen.GetClusterCredentialsWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return &ClusterCredentials{ClientID: resp.JSON200.ClientId, ClientSecret: resp.JSON200.ClientSecret, TokenURL: resp.JSON200.TokenUrl}, nil
}

// MaintenanceWindow describes when Skycloak can apply disruptive changes.
type MaintenanceWindow struct {
	Enabled    bool    `json:"enabled"`
	DaysOfWeek []int32 `json:"days_of_week"`
	StartLocal string  `json:"start_local"`
	EndLocal   string  `json:"end_local"`
	Timezone   string  `json:"timezone"`
}

func maintenanceWindowFromAPI(w *apiclient.MaintenanceWindow) *MaintenanceWindow {
	if w == nil {
		return nil
	}
	return &MaintenanceWindow{
		Enabled: w.Enabled, DaysOfWeek: w.DaysOfWeek,
		StartLocal: w.StartLocal, EndLocal: w.EndLocal, Timezone: w.Timezone,
	}
}

func maintenanceWindowToAPI(w *MaintenanceWindow) *apiclient.MaintenanceWindow {
	if w == nil {
		return nil
	}
	return &apiclient.MaintenanceWindow{
		Enabled: w.Enabled, DaysOfWeek: w.DaysOfWeek,
		StartLocal: w.StartLocal, EndLocal: w.EndLocal, Timezone: w.Timezone,
	}
}

// GetClusterMaintenanceWindow returns a cluster-specific maintenance window.
func (c *Client) GetClusterMaintenanceWindow(ctx context.Context, clusterID string) (*MaintenanceWindow, error) {
	resp, err := c.gen.GetClusterMaintenanceWindowWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return maintenanceWindowFromAPI(resp.JSON200), nil
}

// SetClusterMaintenanceWindow creates or replaces a cluster-specific maintenance window.
func (c *Client) SetClusterMaintenanceWindow(ctx context.Context, clusterID string, window MaintenanceWindow) (*MaintenanceWindow, error) {
	resp, err := c.gen.SetClusterMaintenanceWindowWithResponse(ctx, cid(clusterID), nil, *maintenanceWindowToAPI(&window))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return maintenanceWindowFromAPI(resp.JSON200), nil
}

// DeleteClusterMaintenanceWindow removes a cluster-specific maintenance window.
func (c *Client) DeleteClusterMaintenanceWindow(ctx context.Context, clusterID string) error {
	resp, err := c.gen.DeleteClusterMaintenanceWindowWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// UpgradePathStep is one step in a cluster's recommended upgrade path.
type UpgradePathStep struct {
	Version  string `json:"version"`
	Required bool   `json:"required"`
}

// GetClusterUpgradePath returns the recommended version-upgrade path.
func (c *Client) GetClusterUpgradePath(ctx context.Context, clusterID string) ([]UpgradePathStep, error) {
	resp, err := c.gen.GetClusterUpgradePathWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]UpgradePathStep, 0, len(*resp.JSON200))
	for _, s := range *resp.JSON200 {
		out = append(out, UpgradePathStep{Version: string(s.Version), Required: s.Required})
	}
	return out, nil
}

// ClusterInsights returns a cluster analytics document as raw JSON. kind is one
// of: overview, authentication, events, performance, security.
func (c *Client) ClusterInsights(ctx context.Context, clusterID, kind string) ([]byte, error) {
	id := cid(clusterID)
	var raw []byte
	var resp *http.Response
	var err error
	switch kind {
	case "authentication":
		r, e := c.gen.GetClusterInsightsAuthenticationWithResponse(ctx, id, nil)
		err = e
		if r != nil {
			raw, resp = r.Body, r.HTTPResponse
		}
	case "events":
		r, e := c.gen.GetClusterInsightsEventsWithResponse(ctx, id, nil)
		err = e
		if r != nil {
			raw, resp = r.Body, r.HTTPResponse
		}
	case "performance":
		r, e := c.gen.GetClusterInsightsPerformanceWithResponse(ctx, id, nil)
		err = e
		if r != nil {
			raw, resp = r.Body, r.HTTPResponse
		}
	case "security":
		r, e := c.gen.GetClusterInsightsSecurityWithResponse(ctx, id, nil)
		err = e
		if r != nil {
			raw, resp = r.Body, r.HTTPResponse
		}
	default:
		r, e := c.gen.GetClusterInsightsOverviewWithResponse(ctx, id, nil)
		err = e
		if r != nil {
			raw, resp = r.Body, r.HTTPResponse
		}
	}
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, statusError(resp, raw)
	}
	return raw, nil
}

// GetRealmRole returns a single realm role by name.
func (c *Client) GetRealmRole(ctx context.Context, clusterID, realm, name string) (*RealmRole, error) {
	resp, err := c.gen.GetRealmRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), name, nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := realmRoleFromAPI(resp.JSON200)
	return &r, nil
}

// GetRealmGroup returns a single realm group by ID.
func (c *Client) GetRealmGroup(ctx context.Context, clusterID, realm, groupID string) (*RealmGroup, error) {
	resp, err := c.gen.GetRealmGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), uid(groupID), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	g := realmGroupFromAPI(resp.JSON200)
	return &g, nil
}

// ListRealmGroupMembers returns the users that belong to a group.
func (c *Client) ListRealmGroupMembers(ctx context.Context, clusterID, realm, groupID string) ([]RealmUser, error) {
	resp, err := c.gen.ListRealmGroupMembersWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), uid(groupID), nil)
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

// ---- Updates, upserts, branding deletes, export ----

// UpdateRealmRole updates a realm role's description (and optionally renames it).
func (c *Client) UpdateRealmRole(ctx context.Context, clusterID, realm, name, newName, description string) (*RealmRole, error) {
	body := apiclient.UpdateRealmRoleJSONRequestBody{}
	if newName != "" && newName != name {
		body.Name = &newName
	}
	if description != "" {
		body.Description = &description
	}
	resp, err := c.gen.UpdateRealmRoleWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), name, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := realmRoleFromAPI(resp.JSON200)
	return &r, nil
}

// UpdateRealmGroup renames a realm group.
func (c *Client) UpdateRealmGroup(ctx context.Context, clusterID, realm, groupID, name string) (*RealmGroup, error) {
	body := apiclient.UpdateRealmGroupJSONRequestBody{Name: &name}
	resp, err := c.gen.UpdateRealmGroupWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), uid(groupID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	g := realmGroupFromAPI(resp.JSON200)
	return &g, nil
}

// UpdateRealmUser updates a realm user's profile fields.
func (c *Client) UpdateRealmUser(ctx context.Context, clusterID, realm, userID, email, firstName, lastName string, enabled, emailVerified bool) (*RealmUser, error) {
	en, ev := enabled, emailVerified
	body := apiclient.UpdateRealmUserJSONRequestBody{Enabled: &en, EmailVerified: &ev}
	if email != "" {
		e := openapitypes.Email(email)
		body.Email = &e
	}
	if firstName != "" {
		body.FirstName = &firstName
	}
	if lastName != "" {
		body.LastName = &lastName
	}
	resp, err := c.gen.UpdateRealmUserWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), userID, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	u := realmUserFromAPI(resp.JSON200)
	return &u, nil
}

// UpdateDomainRoute updates a route's mutable fields.
func (c *Client) UpdateDomainRoute(ctx context.Context, clusterID, domainID, routeID string, allowAdminAccess bool, cors []string) (*DomainRoute, error) {
	admin := allowAdminAccess
	body := apiclient.UpdateDomainRouteJSONRequestBody{AllowAdminAccess: &admin}
	if len(cors) > 0 {
		body.CorsAllowedOrigins = &cors
	}
	resp, err := c.gen.UpdateDomainRouteWithResponse(ctx, cid(clusterID), uid(domainID), uid(routeID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	r := resp.JSON200
	return &DomainRoute{ID: r.Id.String(), Realm: string(r.Realm), AllowAdminAccess: r.AllowAdminAccess, HideRealmPath: r.HideRealmPath}, nil
}

// UpdateApplication updates an application's mutable fields.
func (c *Client) UpdateApplication(ctx context.Context, clusterID, realm, clientID, name, description string, redirectURIs []string) (*Application, error) {
	body := apiclient.UpdateApplicationJSONRequestBody{}
	if name != "" {
		body.Name = &name
	}
	if description != "" {
		body.Description = &description
	}
	if redirectURIs != nil {
		body.RedirectUris = &redirectURIs
	}
	resp, err := c.gen.UpdateApplicationWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), apiclient.ApplicationClientId(clientID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	a := applicationFromAPI(resp.JSON200)
	return &a, nil
}

// UpdateIdentityProvider updates an identity provider's display name and enabled state.
func (c *Client) UpdateIdentityProvider(ctx context.Context, clusterID, realm, providerID, displayName string, enabled bool) (*IdentityProvider, error) {
	en := enabled
	body := apiclient.UpdateIdentityProviderJSONRequestBody{Enabled: &en}
	if displayName != "" {
		body.DisplayName = &displayName
	}
	resp, err := c.gen.UpdateIdentityProviderWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), providerID, nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	p := resp.JSON200
	return &IdentityProvider{ProviderID: string(p.ProviderId), Type: string(p.Type), DisplayName: p.DisplayName, Enabled: p.Enabled}, nil
}

// UpdateCluster updates a cluster's mutable fields (e.g. version for an upgrade).
func (c *Client) UpdateCluster(ctx context.Context, clusterID, version, size string, autoUpgradeEnabled *bool) (*Cluster, error) {
	body := apiclient.UpdateClusterJSONRequestBody{}
	if version != "" {
		v := apiclient.KeycloakVersion(version)
		body.Version = &v
	}
	if size != "" {
		sz := apiclient.ClusterSize(size)
		body.Size = &sz
	}
	body.AutoUpgradeEnabled = autoUpgradeEnabled
	resp, err := c.gen.UpdateClusterWithResponse(ctx, cid(clusterID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return clusterFromAPI(resp.JSON200), nil
}

// UpdateExtension updates a custom extension's name/description.
func (c *Client) UpdateExtension(ctx context.Context, extensionID, name, description string) (*ExtensionInfo, error) {
	body := apiclient.UpdateExtensionJSONRequestBody{}
	if name != "" {
		body.Name = &name
	}
	if description != "" {
		body.Description = nullable.NewNullableWithValue(description)
	}
	resp, err := c.gen.UpdateExtensionWithResponse(ctx, uid(extensionID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	e := extensionInfoFromAPI(resp.JSON200)
	return &e, nil
}

// UpdateTheme updates a theme's name/description/version.
func (c *Client) UpdateTheme(ctx context.Context, clusterID, themeID, name, description, version string) (*Theme, error) {
	body := apiclient.UpdateThemeJSONRequestBody{}
	if name != "" {
		body.Name = &name
	}
	if description != "" {
		body.Description = &description
	}
	if version != "" {
		body.Version = &version
	}
	resp, err := c.gen.UpdateThemeWithResponse(ctx, cid(clusterID), uid(themeID), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	t := themeFromAPI(resp.JSON200)
	return &t, nil
}

// UpsertSMTPRequest is the body for setting a realm's SMTP config.
type UpsertSMTPRequest struct {
	Host       string
	Port       int64
	Encryption string
	FromEmail  string
	FromName   string
	AuthType   string
	Username   string
	Password   string
}

// UpsertSMTP creates or updates a realm's SMTP configuration.
func (c *Client) UpsertSMTP(ctx context.Context, clusterID, realm string, req UpsertSMTPRequest) (*SMTPConfig, error) {
	body := apiclient.UpsertSmtpConfigJSONRequestBody{
		Host: apiclient.SmtpHost(req.Host), Port: apiclient.SmtpPort(req.Port),
		FromEmail: openapitypes.Email(req.FromEmail), AuthType: apiclient.SmtpAuthType(req.AuthType),
	}
	if req.Encryption != "" {
		enc := apiclient.SmtpEncryption(req.Encryption)
		body.Encryption = &enc
	}
	body.FromName = sptr(req.FromName)
	body.Username = sptr(req.Username)
	body.Password = sptr(req.Password)
	resp, err := c.gen.UpsertSmtpConfigWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	s := resp.JSON200
	return &SMTPConfig{Host: string(s.Host), Port: int64(s.Port), Encryption: string(s.Encryption), FromEmail: string(s.FromEmail), AuthType: string(s.AuthType), HasPassword: s.HasPassword, Status: string(s.Status)}, nil
}

// UpsertLoginBrandingRequest holds the common login-branding fields.
type UpsertLoginBrandingRequest struct {
	PrimaryColor        string
	BackgroundColor     string
	LogoURL             string
	RegistrationEnabled *bool
}

// UpsertLoginBranding creates or updates login-page branding.
func (c *Client) UpsertLoginBranding(ctx context.Context, clusterID, realm string, req UpsertLoginBrandingRequest) (*LoginBranding, error) {
	body := apiclient.UpsertLoginBrandingJSONRequestBody{RegistrationEnabled: req.RegistrationEnabled}
	body.PrimaryColor = sptr(req.PrimaryColor)
	body.BackgroundColor = sptr(req.BackgroundColor)
	body.LogoUrl = sptr(req.LogoURL)
	resp, err := c.gen.UpsertLoginBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	b := resp.JSON200
	return &LoginBranding{PrimaryColor: strDeref(b.PrimaryColor), BackgroundColor: strDeref(b.BackgroundColor), LogoURL: strDeref(b.LogoUrl), RegistrationEnabled: b.RegistrationEnabled, ForgotPasswordEnabled: b.ForgotPasswordEnabled, Status: string(b.Status)}, nil
}

// UpsertEmailBrandingRequest holds the common email-branding fields.
type UpsertEmailBrandingRequest struct {
	PrimaryColor       string
	HeaderLogoLightURL string
	FooterCompanyName  string
}

// UpsertEmailBranding creates or updates email-template branding.
func (c *Client) UpsertEmailBranding(ctx context.Context, clusterID, realm string, req UpsertEmailBrandingRequest) (*EmailBranding, error) {
	body := apiclient.UpsertEmailBrandingJSONRequestBody{}
	body.PrimaryColor = sptr(req.PrimaryColor)
	body.HeaderLogoLightUrl = sptr(req.HeaderLogoLightURL)
	body.FooterCompanyName = sptr(req.FooterCompanyName)
	resp, err := c.gen.UpsertEmailBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	b := resp.JSON200
	return &EmailBranding{PrimaryColor: strDeref(b.PrimaryColor), HeaderLogoLightURL: strDeref(b.HeaderLogoLightUrl), FooterCompanyName: strDeref(b.FooterCompanyName), Status: string(b.Status)}, nil
}

// DeleteLoginBranding reverts login branding to defaults.
func (c *Client) DeleteLoginBranding(ctx context.Context, clusterID, realm string) error {
	resp, err := c.gen.DeleteLoginBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// DeleteEmailBranding reverts email branding to defaults.
func (c *Client) DeleteEmailBranding(ctx context.Context, clusterID, realm string) error {
	resp, err := c.gen.DeleteEmailBrandingWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return statusError(resp.HTTPResponse, resp.Body)
	}
	return nil
}

// ExportClusterEvents exports a cluster's events as a raw document (CSV/JSON).
func (c *Client) ExportClusterEvents(ctx context.Context, clusterID string) ([]byte, error) {
	resp, err := c.gen.ExportClusterEventsWithResponse(ctx, cid(clusterID), nil)
	if err != nil {
		return nil, err
	}
	if sc := resp.StatusCode(); sc < 200 || sc >= 300 {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	return resp.Body, nil
}

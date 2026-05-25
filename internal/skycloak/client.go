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

// GetCluster returns a single cluster by ID.
func (c *Client) GetCluster(ctx context.Context, id string) (*Cluster, error) {
	resp, err := c.gen.GetClusterWithResponse(ctx, cid(id))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	cl := resp.JSON200
	return &Cluster{
		ID: cl.Id.String(), Name: string(cl.Name), Type: string(cl.Type), Size: string(cl.Size),
		Version: string(cl.Version), Location: string(cl.Location), Status: string(cl.Status),
		URL: cl.Url, CreatedAt: fmtTime(cl.CreatedAt), UpdatedAt: fmtTime(cl.UpdatedAt),
	}, nil
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

// ListApplications returns the applications in a realm.
func (c *Client) ListApplications(ctx context.Context, clusterID, realm string) ([]Application, error) {
	resp, err := c.gen.ListApplicationsWithResponse(ctx, cid(clusterID), apiclient.RealmName(realm), nil)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, statusError(resp.HTTPResponse, resp.Body)
	}
	out := make([]Application, 0, len(*resp.JSON200))
	for _, a := range *resp.JSON200 {
		out = append(out, Application{
			ClientID: string(a.ClientId), Name: a.Name, Type: string(a.Type),
			Protocol: string(a.Protocol), Status: string(a.Status),
		})
	}
	return out, nil
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

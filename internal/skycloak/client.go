// Package skycloak is a minimal typed client for the Skycloak public API.
//
// This is a hand-written subset covering the endpoints the MCP server uses
// today. The full client is generated from the OpenAPI spec via oapi-codegen
// (internal/apiclient); the types and method shapes here are kept compatible
// with that client.
package skycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const defaultEndpoint = "https://api.skycloak.io"

// Client talks to the Skycloak public API. Every request is workspace-scoped by
// the API key.
type Client struct {
	httpClient *http.Client
	endpoint   string
	apiKey     string
	apiVersion string
	userAgent  string
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient overrides the underlying HTTP client (useful in tests).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// WithUserAgent sets the User-Agent header sent on every request.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// New builds a Client. endpoint defaults to https://api.skycloak.io when empty.
func New(endpoint, apiKey, apiVersion string, opts ...Option) *Client {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	c := &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		endpoint:   endpoint,
		apiKey:     apiKey,
		apiVersion: apiVersion,
		userAgent:  "skycloak-go/dev",
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Problem is the RFC 9457 application/problem+json error body.
type Problem struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Status int    `json:"status,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// APIError wraps a non-2xx response from the public API.
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

// Cluster mirrors the public API Cluster resource (subset used today).
type Cluster struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Size      string `json:"size"`
	Version   string `json:"version"`
	Location  string `json:"location"`
	Status    string `json:"status"`
	URL       string `json:"url,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// ListClustersParams holds the query parameters for ListClusters.
type ListClustersParams struct {
	Limit  int
	Offset int
}

// ListClusters returns the clusters in the workspace the API key belongs to.
func (c *Client) ListClusters(ctx context.Context, p ListClustersParams) ([]Cluster, error) {
	q := url.Values{}
	if p.Limit > 0 {
		q.Set("limit", strconv.Itoa(p.Limit))
	}
	if p.Offset > 0 {
		q.Set("offset", strconv.Itoa(p.Offset))
	}
	var out []Cluster
	if err := c.do(ctx, http.MethodGet, "/clusters", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetCluster returns a single cluster by its ID.
func (c *Client) GetCluster(ctx context.Context, id string) (*Cluster, error) {
	var out Cluster
	if err := c.do(ctx, http.MethodGet, "/clusters/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Realm mirrors the public API Realm resource (subset used today).
type Realm struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ListRealms returns the realms in a cluster.
func (c *Client) ListRealms(ctx context.Context, clusterID string) ([]Realm, error) {
	var out []Realm
	if err := c.do(ctx, http.MethodGet, "/clusters/"+url.PathEscape(clusterID)+"/realms", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Application mirrors the public API Application resource (subset used today).
type Application struct {
	ClientID string `json:"client_id"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Status   string `json:"status,omitempty"`
}

// ListApplications returns the applications in a realm.
func (c *Client) ListApplications(ctx context.Context, clusterID, realm string) ([]Application, error) {
	var out []Application
	path := "/clusters/" + url.PathEscape(clusterID) + "/realms/" + url.PathEscape(realm) + "/applications"
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// IdentityProvider mirrors the public API identity-provider resource (subset).
type IdentityProvider struct {
	ProviderID  string `json:"provider_id"`
	Type        string `json:"type,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ListIdentityProviders returns the identity providers in a realm.
func (c *Client) ListIdentityProviders(ctx context.Context, clusterID, realm string) ([]IdentityProvider, error) {
	var out []IdentityProvider
	path := "/clusters/" + url.PathEscape(clusterID) + "/realms/" + url.PathEscape(realm) + "/identity-providers"
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateRealm creates a realm in a cluster.
func (c *Client) CreateRealm(ctx context.Context, clusterID string, r Realm) (*Realm, error) {
	var out Realm
	path := "/clusters/" + url.PathEscape(clusterID) + "/realms"
	if err := c.doBody(ctx, http.MethodPost, path, r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRealm deletes a realm and all of its data.
func (c *Client) DeleteRealm(ctx context.Context, clusterID, name string) error {
	path := "/clusters/" + url.PathEscape(clusterID) + "/realms/" + url.PathEscape(name)
	return c.doBody(ctx, http.MethodDelete, path, nil, nil)
}

// doBody performs a request with an optional JSON body and optional JSON
// response decoding. Used by the write methods.
func (c *Client) doBody(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiVersion != "" {
		req.Header.Set("API-Version", c.apiVersion)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(data, &apiErr.Problem)
		return apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, out any) error {
	u := c.endpoint + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")
	if c.apiVersion != "" {
		req.Header.Set("API-Version", c.apiVersion)
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(data, &apiErr.Problem)
		return apiErr
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

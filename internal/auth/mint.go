package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// mintRequest mirrors the dashboard's CreateAPIKeyRequest body
// (internal/apikeys/models.go). Name and at least one scope are required.
type mintRequest struct {
	Name      string     `json:"name"`
	Notes     string     `json:"notes,omitempty"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// mintResponse mirrors CreateAPIKeyResponse: full_key is shown only once.
type mintResponse struct {
	FullKey string `json:"full_key"`
}

// mintAPIKey exchanges a user access token for a workspace-scoped API key via
// POST {dashboard}/api/api-keys. The dashboard validates the bearer token
// against Keycloak's userinfo endpoint, so any valid realm token is accepted;
// the user's own workspace role gates the create. Returns the full key.
func mintAPIKey(ctx context.Context, hc *http.Client, cfg Config, token, workspaceID string, scopes []string, name string, ttl time.Duration) (string, error) {
	body := mintRequest{
		Name:   name,
		Scopes: scopes,
		Notes:  "Created by `skycloak-mcp init` (device sign-in).",
	}
	if ttl > 0 {
		exp := time.Now().Add(ttl).UTC()
		body.ExpiresAt = &exp
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.DashboardURL+"/api/api-keys", bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Workspace-ID", workspaceID)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("create api key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("create api key: status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var mr mintResponse
	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		return "", fmt.Errorf("decode api key response: %w", err)
	}
	if mr.FullKey == "" {
		return "", fmt.Errorf("create api key: empty key in response")
	}
	return mr.FullKey, nil
}

// workspace is the subset of a workspace list entry we need.
type workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// listWorkspaces is a best-effort fetch of the signed-in user's workspaces. It
// returns (nil, nil) when the endpoint is absent or its shape is unrecognized,
// so the caller falls back to the --workspace flag rather than failing hard.
func listWorkspaces(ctx context.Context, hc *http.Client, cfg Config, token string) ([]workspace, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.DashboardURL+"/api/workspaces", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseWorkspaces(raw), nil
}

// getDefaultWorkspace fetches the signed-in user's default workspace via
// GET {dashboard}/api/workspaces/default, which returns a bare workspace object.
// Returns a zero workspace (no error) when unavailable, so the caller can fall
// back to listing.
func getDefaultWorkspace(ctx context.Context, hc *http.Client, cfg Config, token string) workspace {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.DashboardURL+"/api/workspaces/default", nil)
	if err != nil {
		return workspace{}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return workspace{}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return workspace{}
	}
	var w workspace
	if err := json.NewDecoder(resp.Body).Decode(&w); err != nil {
		return workspace{}
	}
	return w
}

// parseWorkspaces accepts either a bare array or a {"workspaces": [...]} or
// {"data": [...]} envelope, keeping only entries that carry an id.
func parseWorkspaces(raw []byte) []workspace {
	keep := func(in []workspace) []workspace {
		out := in[:0]
		for _, w := range in {
			if w.ID != "" {
				out = append(out, w)
			}
		}
		return out
	}
	var direct []workspace
	if json.Unmarshal(raw, &direct) == nil && len(direct) > 0 {
		return keep(direct)
	}
	var env struct {
		Workspaces []workspace `json:"workspaces"`
		Data       []workspace `json:"data"`
	}
	if json.Unmarshal(raw, &env) == nil {
		if len(env.Workspaces) > 0 {
			return keep(env.Workspaces)
		}
		if len(env.Data) > 0 {
			return keep(env.Data)
		}
	}
	return nil
}

// defaultReadScopes is the fallback set requested when the live scopes endpoint
// is unavailable. Read-only; write scopes are added only with --allow-writes.
var defaultReadScopes = []string{
	"clusters:read", "realms:read", "applications:read", "users:read",
	"realm-users:read", "realm-roles:read", "realm-groups:read",
	"identity-providers:read", "cluster-logs:read", "cluster-insights:read",
	"cluster-events:read", "cluster-security:read",
}

// scopesResponse mirrors GET /api/api-keys/scopes ({"scopes": ["clusters:read", ...]}).
type scopesResponse struct {
	Scopes []string `json:"scopes"`
}

// resolveScopes asks the dashboard for the catalog of valid scopes and selects
// the read scopes (plus write scopes when allowWrites). It falls back to
// defaultReadScopes if the catalog cannot be fetched. clusters:credentials:read
// is never auto-selected: it exposes admin credentials and must be opted into
// explicitly via a hand-made key.
func resolveScopes(ctx context.Context, hc *http.Client, cfg Config, token string, allowWrites bool) []string {
	catalog := fetchScopes(ctx, hc, cfg, token)
	if len(catalog) == 0 {
		catalog = defaultReadScopes
		if allowWrites {
			catalog = append(catalog, "clusters:write", "realms:write", "applications:write",
				"users:write", "realm-users:write", "identity-providers:write", "cluster-security:write")
		}
	}
	out := make([]string, 0, len(catalog))
	for _, s := range catalog {
		if s == "clusters:credentials:read" {
			continue
		}
		if strings.HasSuffix(s, ":write") && !allowWrites {
			continue
		}
		out = append(out, s)
	}
	return out
}

func fetchScopes(ctx context.Context, hc *http.Client, cfg Config, token string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.DashboardURL+"/api/api-keys/scopes", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var sr scopesResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil
	}
	return sr.Scopes
}

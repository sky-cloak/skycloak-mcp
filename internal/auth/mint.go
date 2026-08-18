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

// cliKeyRequest is the body for POST /api/cli/keys. Every field is optional: the
// server authenticates the Bearer token, resolves the caller's default
// workspace (workspace_id overrides), and applies read-only scopes when none
// are given.
type cliKeyRequest struct {
	Name        string     `json:"name,omitempty"`
	Scopes      []string   `json:"scopes,omitempty"`
	WorkspaceID string     `json:"workspace_id,omitempty"`
	Notes       string     `json:"notes,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// cliKeyResponse mirrors the dashboard CreateAPIKeyResponse. full_key is shown
// only once; api_key.workspace_id reports which workspace the server chose.
type cliKeyResponse struct {
	FullKey string `json:"full_key"`
	APIKey  struct {
		WorkspaceID string `json:"workspace_id"`
	} `json:"api_key"`
}

// clusterCredentialsScope exposes a cluster's Keycloak admin credentials. It is
// never in the default grant: an assistant holding the key can read whatever the
// key can, and that is a bigger thing to hand over than the rest of the API.
const clusterCredentialsScope = "clusters:credentials:read"

// readScopes is the read half of writeScopes, derived so the two cannot drift.
var readScopes = func() []string {
	var out []string
	for _, s := range writeScopes {
		if strings.HasSuffix(s, ":read") {
			out = append(out, s)
		}
	}
	return out
}()

// requestedScopes is the scope list to send when minting. An empty result means
// send none, which leaves the server's own read-only default in place.
func requestedScopes(opts InitOptions) []string {
	var out []string
	switch {
	case opts.AllowWrites:
		out = append(out, writeScopes...)
	case opts.AllowCredentials:
		// An explicit list replaces the server default entirely, so the read
		// scopes have to come along or the key could read nothing else.
		out = append(out, readScopes...)
	}
	if opts.AllowCredentials {
		out = append(out, clusterCredentialsScope)
	}
	return out
}

// writeScopes is the read+write set requested with --allow-writes: every scope
// the API defines, except clusters:credentials:read, which exposes a cluster's
// admin credentials and is not something a general-purpose key should carry.
//
// Names must match the API exactly. A scope that does not exist is not an
// error at mint time; it simply is not granted, and only surfaces later as a
// 403 on a tool call. The tests in scopes_test.go check this list against the
// x-scopes declared in the committed OpenAPI spec, so adding a tool for a new
// area fails there until its scope is added here.
var writeScopes = []string{
	"clusters:read", "clusters:write",
	"clusters:events:read", "clusters:insights:read", "clusters:logs:read",
	"clusters:security:read", "clusters:security:write",
	"clusters:exports:read", "clusters:exports:write",
	"clusters:imports:read", "clusters:imports:write",
	"clusters:extensions:read", "clusters:extensions:write",
	"realms:read", "realms:write",
	"realm-users:read", "realm-users:write",
	"realm-roles:read", "realm-roles:write",
	"realm-groups:read", "realm-groups:write",
	"applications:read", "applications:write",
	"identity-providers:read", "identity-providers:write",
	"domains:read", "domains:write",
	"themes:read", "themes:write",
	"branding:read", "branding:write",
	"extensions:read", "extensions:write",
	"smtp:read", "smtp:write",
	"siem:read", "siem:write",
	"webhooks:read", "webhooks:write",
}

// mintCLIKey exchanges the device-flow Bearer token for a workspace-scoped API
// key via POST {dashboard}/api/cli/keys. The server authenticates the token and
// resolves the workspace (no cookie session needed). It returns the full key
// and the workspace the server scoped it to.
func mintCLIKey(ctx context.Context, hc *http.Client, cfg Config, token string, opts InitOptions) (fullKey, workspaceID string, err error) {
	body := cliKeyRequest{
		Name:        keyName(),
		WorkspaceID: opts.WorkspaceID,
		Notes:       "Created by `skycloak-mcp init` (device sign-in).",
	}
	// Empty means omit, and the server applies its read-only default.
	if scopes := requestedScopes(opts); len(scopes) > 0 {
		body.Scopes = scopes
	}
	if opts.TTL > 0 {
		exp := time.Now().Add(opts.TTL).UTC()
		body.ExpiresAt = &exp
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.DashboardURL+"/api/cli/keys", bytes.NewReader(buf))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("create api key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("create api key: %s", describeMintError(resp))
	}
	var mr cliKeyResponse
	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		return "", "", fmt.Errorf("decode api key response: %w", err)
	}
	if mr.FullKey == "" {
		return "", "", fmt.Errorf("create api key: empty key in response")
	}
	return mr.FullKey, mr.APIKey.WorkspaceID, nil
}

// describeMintError turns a non-201 mint response into an actionable message.
func describeMintError(resp *http.Response) string {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return "the server did not accept your sign-in (401)"
	case http.StatusForbidden:
		return "not permitted (403): you must be an owner/admin and a member of the workspace"
	case http.StatusNotFound:
		return "endpoint not found (404): the server may be older than this client"
	default:
		return fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
}

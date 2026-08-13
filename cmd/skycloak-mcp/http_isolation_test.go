package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeUpstream stands in for api.skycloak.io and records which API key each
// request actually carried, so tests can prove whose credential was used.
type fakeUpstream struct {
	mu   sync.Mutex
	keys []string
	srv  *httptest.Server
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	u := &fakeUpstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.keys = append(u.keys, r.Header.Get("API-Key"))
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) seenKeys() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.keys...)
}

// mcpPost sends one JSON-RPC message to the MCP endpoint with the given
// credential and optional session id, returning the response.
func mcpPost(t *testing.T, url, cred, sessionID, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("Authorization", "Bearer "+cred)
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

const initBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
const listClustersBody = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"skycloak_list_clusters","arguments":{}}}`

// A caller must never be able to act with another caller's credential by
// replaying their MCP session id. Every request's own credential decides which
// Skycloak key is used upstream.
func TestHTTPHandlerDoesNotLeakCredentialAcrossSessions(t *testing.T) {
	upstream := newFakeUpstream(t)
	ts := httptest.NewServer(newHTTPHandler(httpConfig{
		endpoint: upstream.srv.URL, apiVersion: "v1", userAgent: "test", allowWrites: false,
	}))
	defer ts.Close()

	// Victim establishes a session.
	resp := mcpPost(t, ts.URL, "sk_sc_VICTIM", "", initBody)
	sessionID := resp.Header.Get("Mcp-Session-Id")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// Attacker replays the victim's session id with their own credential.
	resp = mcpPost(t, ts.URL, "sk_sc_ATTACKER", sessionID, listClustersBody)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	for _, k := range upstream.seenKeys() {
		if k == "sk_sc_VICTIM" {
			t.Fatalf("attacker's request used the VICTIM's key upstream (session hijack); "+
				"status=%d keys=%v body=%s", resp.StatusCode, upstream.seenKeys(), truncate(body))
		}
	}
	if resp.StatusCode == http.StatusOK && len(upstream.seenKeys()) == 0 {
		t.Fatalf("tool call reported success but never reached upstream: %s", truncate(body))
	}
}

// Each caller's own credential must reach Skycloak unchanged.
func TestHTTPHandlerUsesEachCallersOwnCredential(t *testing.T) {
	upstream := newFakeUpstream(t)
	ts := httptest.NewServer(newHTTPHandler(httpConfig{
		endpoint: upstream.srv.URL, apiVersion: "v1", userAgent: "test", allowWrites: false,
	}))
	defer ts.Close()

	for _, key := range []string{"sk_sc_ALICE", "sk_sc_BOB"} {
		resp := mcpPost(t, ts.URL, key, "", initBody)
		sessionID := resp.Header.Get("Mcp-Session-Id")
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		resp = mcpPost(t, ts.URL, key, sessionID, listClustersBody)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d: %s", key, resp.StatusCode, truncate(body))
		}
	}

	seen := upstream.seenKeys()
	for _, want := range []string{"sk_sc_ALICE", "sk_sc_BOB"} {
		found := false
		for _, k := range seen {
			if k == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("upstream never saw %s; saw %v", want, seen)
		}
	}
}

// Write tools must stay hidden unless the server allows writes and the session
// did not ask to be read-only.
func TestHTTPHandlerReadonlyHidesWriteTools(t *testing.T) {
	upstream := newFakeUpstream(t)
	for _, tt := range []struct {
		name        string
		allowWrites bool
		query       string
		wantWrite   bool
	}{
		{"writes enabled", true, "", true},
		{"writes enabled but session readonly", true, "?readonly=true", false},
		{"server readonly", false, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(newHTTPHandler(httpConfig{
				endpoint: upstream.srv.URL, apiVersion: "v1", userAgent: "test", allowWrites: tt.allowWrites,
			}))
			defer ts.Close()

			resp := mcpPost(t, ts.URL+tt.query, "sk_sc_test", "", initBody)
			sessionID := resp.Header.Get("Mcp-Session-Id")
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()

			resp = mcpPost(t, ts.URL+tt.query, "sk_sc_test", sessionID,
				`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			hasWrite := strings.Contains(string(body), "skycloak_delete_realm")
			if hasWrite != tt.wantWrite {
				t.Fatalf("write tool exposed = %v, want %v", hasWrite, tt.wantWrite)
			}
		})
	}
}

func truncate(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "..."
	}
	return string(b)
}

var _ = json.Marshal

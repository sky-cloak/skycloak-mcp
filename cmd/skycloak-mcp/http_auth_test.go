package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An unauthenticated MCP request must be refused with 401 and a challenge, so
// clients can tell "you need credentials" from "your request was malformed".
func TestHTTPHandlerMissingCredentialIsUnauthorized(t *testing.T) {
	handler := newHTTPHandler(httpConfig{allowWrites: true})
	req := httptest.NewRequest("POST", "http://example.com/mcp", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer") {
		t.Fatalf("WWW-Authenticate = %q, want a Bearer challenge", got)
	}
}

// Bearer is the MCP-standard shape; API-Key matches the Skycloak REST API. Both
// must work so existing clients and spec-compliant clients both connect.
func TestHTTPHandlerAcceptsBothCredentialHeaders(t *testing.T) {
	for _, tt := range []struct{ name, header, value string }{
		{"bearer", "Authorization", "Bearer sk_sc_test"},
		{"bearer lowercase scheme", "Authorization", "bearer sk_sc_test"},
		{"api-key", "API-Key", "sk_sc_test"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/mcp", nil)
			req.Header.Set(tt.header, tt.value)
			key, err := credentialFromRequest(req)
			if err != nil {
				t.Fatalf("credentialFromRequest: %v", err)
			}
			if key != "sk_sc_test" {
				t.Fatalf("key = %q, want sk_sc_test", key)
			}
		})
	}
}

// Kubernetes probes cannot present a credential, so health endpoints must be
// reachable without one while every MCP path stays guarded.
func TestHealthEndpointsAreUnauthenticated(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(httpConfig{allowWrites: false}))
	defer ts.Close()

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
		}
	}
}

func TestMCPPathsStillRequireCredential(t *testing.T) {
	ts := httptest.NewServer(newHTTPHandler(httpConfig{allowWrites: false}))
	defer ts.Close()

	for _, path := range []string{"/", "/mcp"} {
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("POST %s = %d, want 401", path, resp.StatusCode)
		}
	}
}

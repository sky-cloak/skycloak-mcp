package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadonlyModeDefaultsToFalse(t *testing.T) {
	req := httptest.NewRequest("POST", "http://example.com/mcp", nil)
	got, err := readonlyMode(req)
	if err != nil {
		t.Fatalf("readonlyMode returned error: %v", err)
	}
	if got {
		t.Fatal("readonlyMode = true, want false")
	}
}

func TestReadonlyModeQueryParamOverridesDefault(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{url: "http://example.com/mcp?readonly=true", want: true},
		{url: "http://example.com/mcp?readonly=false", want: false},
		{url: "http://example.com/mcp?readonly=true&readonly=false", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.url, nil)
			got, err := readonlyMode(req)
			if err != nil {
				t.Fatalf("readonlyMode returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("readonlyMode = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadonlyModeRejectsInvalidQueryParam(t *testing.T) {
	tests := []string{
		"http://example.com/mcp?readonly=",
		"http://example.com/mcp?readonly=1",
		"http://example.com/mcp?readonly=TRUE",
	}

	for _, url := range tests {
		t.Run(url, func(t *testing.T) {
			req := httptest.NewRequest("POST", url, nil)
			if _, err := readonlyMode(req); err == nil {
				t.Fatal("readonlyMode returned nil error, want invalid readonly error")
			}
		})
	}
}

func TestHTTPAllowWritesRequiresServerAllowWritesAndReadonlyFalse(t *testing.T) {
	tests := []struct {
		name              string
		serverAllowWrites bool
		readonly          bool
		want              bool
	}{
		{name: "allow writes and session write mode", serverAllowWrites: true, readonly: false, want: true},
		{name: "allow writes but session readonly", serverAllowWrites: true, readonly: true, want: false},
		{name: "server readonly and query write mode", serverAllowWrites: false, readonly: false, want: false},
		{name: "server readonly and session readonly", serverAllowWrites: false, readonly: true, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := httpAllowWrites(tt.serverAllowWrites, tt.readonly)
			if got != tt.want {
				t.Fatalf("httpAllowWrites(%v, %v) = %v, want %v", tt.serverAllowWrites, tt.readonly, got, tt.want)
			}
		})
	}
}

func TestHTTPHandlerRejectsInvalidReadonlyQueryParam(t *testing.T) {
	handler := newHTTPHandler(httpConfig{allowWrites: true})
	req := httptest.NewRequest("POST", "http://example.com/mcp?readonly=1", nil)
	req.Header.Set("API-Key", "sk_sc_test")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestOpenAIChallenge(t *testing.T) {
	// The portal compares the body byte for byte, so anything other than the
	// bare token fails verification. Guard the shape, not just the status.
	h := newHTTPHandler(httpConfig{openAIChallenge: "tok-abc123"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openai-apps-challenge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "tok-abc123" {
		t.Errorf("body = %q, want the bare token with no newline or JSON", got)
	}
}

func TestOpenAIChallengeAbsentWhenUnset(t *testing.T) {
	// No token configured means no route, rather than a route serving nothing.
	h := newHTTPHandler(httpConfig{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/openai-apps-challenge", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when OPENAI_APPS_CHALLENGE_TOKEN is unset", rec.Code)
	}
}

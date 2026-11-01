package skycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// headerLog records the headers of every request a test server receives.
type headerLog struct {
	mu   sync.Mutex
	seen []http.Header
}

func (l *headerLog) add(h http.Header) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, h.Clone())
}

func (l *headerLog) all() []http.Header {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]http.Header(nil), l.seen...)
}

func TestWithInvocationMakesAFreshCallID(t *testing.T) {
	a, ok := InvocationFrom(WithInvocation(context.Background(), "skycloak_list_clusters"))
	if !ok || a.Tool != "skycloak_list_clusters" {
		t.Fatalf("invocation = %+v, %v", a, ok)
	}
	if _, err := uuid.Parse(a.CallID); err != nil || len(a.CallID) != 36 {
		t.Fatalf("call ID %q is not a UUID: %v", a.CallID, err)
	}
	b, _ := InvocationFrom(WithInvocation(context.Background(), "skycloak_list_clusters"))
	if a.CallID == b.CallID {
		t.Fatalf("two invocations share call ID %q", a.CallID)
	}
}

func TestInvocationFromWithoutInvocation(t *testing.T) {
	if inv, ok := InvocationFrom(context.Background()); ok {
		t.Fatalf("plain context reports invocation %+v", inv)
	}
}

func TestInvocationEditor(t *testing.T) {
	ctx := WithInvocation(context.Background(), "skycloak_get_cluster")
	inv, _ := InvocationFrom(ctx)

	inside, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.com/clusters", nil)
	if err := invocationEditor(ctx, inside); err != nil {
		t.Fatal(err)
	}
	if got := inside.Header.Get(HeaderMCPTool); got != "skycloak_get_cluster" {
		t.Errorf("%s = %q", HeaderMCPTool, got)
	}
	if got := inside.Header.Get(HeaderMCPCallID); got != inv.CallID {
		t.Errorf("%s = %q, want %q", HeaderMCPCallID, got, inv.CallID)
	}

	outside, _ := http.NewRequest(http.MethodGet, "https://api.example.com/clusters", nil)
	if err := invocationEditor(context.Background(), outside); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{HeaderMCPTool, HeaderMCPCallID} {
		if _, set := outside.Header[http.CanonicalHeaderKey(h)]; set {
			t.Errorf("%s set outside an invocation", h)
		}
	}
}

// Every attempt of a retried request belongs to the same invocation, so the
// gateway must see one call ID across the 429 and the retry. The other headers
// are unchanged by the invocation.
func TestInvocationHeadersSurviveRetry(t *testing.T) {
	var log headerLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Header)
		if len(log.all()) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(w, 200, `[{"id":"`+cuid+`","name":"prod","status":"available"}]`)
	}))
	defer srv.Close()

	ctx := WithInvocation(context.Background(), "skycloak_list_clusters")
	inv, _ := InvocationFrom(ctx)
	c := New(srv.URL, "sk_sc_test_aaa_bbb", "2026-03-01", WithUserAgent("skycloak-mcp/test"))
	if _, err := c.ListClusters(ctx, ListClustersParams{}); err != nil {
		t.Fatalf("ListClusters: %v", err)
	}

	seen := log.all()
	if len(seen) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(seen))
	}
	for i, h := range seen {
		if got := h.Get(HeaderMCPTool); got != "skycloak_list_clusters" {
			t.Errorf("attempt %d: %s = %q", i, HeaderMCPTool, got)
		}
		if got := h.Get(HeaderMCPCallID); got != inv.CallID {
			t.Errorf("attempt %d: %s = %q, want %q", i, HeaderMCPCallID, got, inv.CallID)
		}
		if h.Get("API-Key") != "sk_sc_test_aaa_bbb" || h.Get("API-Version") != "2026-03-01" || h.Get("User-Agent") != "skycloak-mcp/test" {
			t.Errorf("attempt %d: API-Key, API-Version or User-Agent changed", i)
		}
	}
}

func TestNoInvocationHeadersOutsideAnInvocation(t *testing.T) {
	var log headerLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Header)
		writeJSON(w, 200, `[]`)
	}))
	defer srv.Close()

	if _, err := newTestClient(srv.URL).ListClusters(context.Background(), ListClustersParams{}); err != nil {
		t.Fatalf("ListClusters: %v", err)
	}
	for _, h := range log.all() {
		for _, name := range []string{HeaderMCPTool, HeaderMCPCallID} {
			if _, set := h[http.CanonicalHeaderKey(name)]; set {
				t.Errorf("%s sent outside an invocation", name)
			}
		}
		if h.Get("API-Key") != "sk_sc_test_aaa_bbb" || h.Get("API-Version") != "2026-03-01" {
			t.Errorf("API-Key or API-Version changed")
		}
	}
}

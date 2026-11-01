package tools

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

const (
	invClusterA = "44444444-4444-4444-4444-444444444444"
	invClusterB = "55555555-5555-5555-5555-555555555555"
)

type taggedRequest struct {
	path   string
	tool   string
	callID string
}

// Every request one tool call makes, the fleet listing, one per cluster, and
// the retry after a 429, carries the tool's name and one shared call ID. A
// second call of the same tool gets a different ID.
func TestToolCallsTagAPIRequests(t *testing.T) {
	var (
		mu        sync.Mutex
		seen      []taggedRequest
		throttled bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, taggedRequest{
			path:   r.URL.Path,
			tool:   r.Header.Get(skycloak.HeaderMCPTool),
			callID: r.Header.Get(skycloak.HeaderMCPCallID),
		})
		throttle := r.URL.Path == "/clusters/"+invClusterB+"/realms" && !throttled
		if throttle {
			throttled = true
		}
		mu.Unlock()

		if throttle {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/clusters":
			_, _ = io.WriteString(w, `[{"id":"`+invClusterA+`","name":"a","status":"available"},{"id":"`+invClusterB+`","name":"b","status":"available"}]`)
		case "/clusters/" + invClusterA + "/realms", "/clusters/" + invClusterB + "/realms":
			_, _ = io.WriteString(w, `[{"name":"acme","display_name":"Acme","enabled":true}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cs := liveSession(t, srv)

	call := func() []taggedRequest {
		t.Helper()
		mu.Lock()
		seen = nil
		mu.Unlock()
		res, err := cs.CallTool(t.Context(), &mcp.CallToolParams{Name: "skycloak_list_realms", Arguments: map[string]any{}})
		if err != nil || res.IsError {
			t.Fatalf("skycloak_list_realms: %v %s", err, resultText(res))
		}
		mu.Lock()
		defer mu.Unlock()
		return append([]taggedRequest(nil), seen...)
	}

	first := call()
	// The listing, cluster a, the throttled cluster b and its retry.
	if len(first) != 4 {
		t.Fatalf("expected 4 API requests, got %d: %+v", len(first), first)
	}
	callID := first[0].callID
	if _, err := uuid.Parse(callID); err != nil || len(callID) != 36 {
		t.Fatalf("call ID %q is not a UUID", callID)
	}
	for _, r := range first {
		if r.tool != "skycloak_list_realms" {
			t.Errorf("%s: tool = %q", r.path, r.tool)
		}
		if r.callID != callID {
			t.Errorf("%s: call ID = %q, want %q", r.path, r.callID, callID)
		}
	}

	second := call()
	if len(second) == 0 || second[0].callID == "" || second[0].callID == callID {
		t.Fatalf("second invocation reused or lacks a call ID: %+v", second)
	}
}

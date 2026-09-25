package tools

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

const westID = "33333333-3333-3333-3333-333333333333"

// liveSession registers the real tool surface against the real API client,
// pointed at srv, so a test covers the tool, the client and the wire format.
func liveSession(t *testing.T, srv *httptest.Server) *mcp.ClientSession {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(s, skycloak.New(srv.URL, "sk_sc_test_aaa_bbb", "2026-03-01"), true, nil)

	ct, st := mcp.NewInMemoryTransports()
	ss, err := s.Connect(t.Context(), st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// us-west is a location of its own: the cluster tools must accept it in any
// case, send it as us-west, and report it back without folding it into us.
func TestClusterToolsCarryUSWest(t *testing.T) {
	const west = `{"id":"` + westID + `","name":"west","status":"available","type":"keycloak","size":"small","version":"26.1","location":"us-west"}`
	var sentLocation any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/clusters":
			_, _ = io.WriteString(w, `[`+west+`]`)
		case r.Method == http.MethodGet && r.URL.Path == "/clusters/"+westID:
			_, _ = io.WriteString(w, west)
		case r.Method == http.MethodPost && r.URL.Path == "/clusters":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			sentLocation = body["location"]
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, west)
		case r.Method == http.MethodGet && r.URL.Path == "/cluster-locations":
			_, _ = io.WriteString(w, `[{"location":"us","name":"US East","available":true},{"location":"us-west","name":"US West","available":true}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	cs := liveSession(t, srv)

	for _, tc := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"skycloak_list_clusters", map[string]any{}, "@ us-west"},
		{"skycloak_get_cluster", map[string]any{"id": westID}, "location: us-west"},
		{"skycloak_list_cluster_locations", map[string]any{}, "- us-west (US West) available=true"},
	} {
		res := callTool(t, cs, tc.tool, tc.args)
		if res.IsError {
			t.Fatalf("%s: %s", tc.tool, resultText(res))
		}
		if !strings.Contains(resultText(res), tc.want) {
			t.Errorf("%s text = %q, want it to contain %q", tc.tool, resultText(res), tc.want)
		}
		out, _ := json.Marshal(res.StructuredContent)
		if !strings.Contains(string(out), `"us-west"`) {
			t.Errorf("%s structured output = %s, want us-west in it", tc.tool, out)
		}
	}

	res := callTool(t, cs, "skycloak_create_cluster", map[string]any{"name": "west", "size": "small", "version": "26.1", "location": "US-West"})
	if res.IsError {
		t.Fatalf("create: %s", resultText(res))
	}
	if sentLocation != "us-west" {
		t.Errorf("create sent location %v, want us-west", sentLocation)
	}
	if out, _ := json.Marshal(res.StructuredContent); !strings.Contains(string(out), `"location":"us-west"`) {
		t.Errorf("create structured output = %s, want location us-west", out)
	}
}

// Without access to us-west the API refuses the create with 400, like any
// closed region, and the tool must hand that reason to the caller.
func TestCreateClusterUSWestWithoutAccessShowsTheAPIReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"title":"Bad Request","status":400,"detail":"location not available"}`)
	}))
	defer srv.Close()

	res := callTool(t, liveSession(t, srv), "skycloak_create_cluster", map[string]any{"name": "west", "size": "small", "version": "26.1", "location": "us-west"})
	if !res.IsError {
		t.Fatalf("create succeeded, want the API's 400: %s", resultText(res))
	}
	if !strings.Contains(resultText(res), "location not available") {
		t.Errorf("error text = %q, want the API's reason", resultText(res))
	}
}

// us and us-west are different regions: folding the case of one must never
// land on the other.
func TestClusterLocationEnumKeepsUSAndUSWestApart(t *testing.T) {
	for in, want := range map[string]string{"us": "us", "US": "us", "us-west": "us-west", "US-West": "us-west", " US-WEST ": "us-west"} {
		if got := enumClusterLocation.canonical(in); got != want {
			t.Errorf("canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

package tools

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// apiScopes returns every scope the committed OpenAPI spec declares via
// x-scopes. The spec is the authority: a scope that appears nowhere in it does
// not exist, and an area requiring it would silently never register.
func apiScopes(t *testing.T) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "apiclient", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}

	found := map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			for k, child := range v {
				if k == "x-scopes" {
					for _, s := range child.([]any) {
						found[s.(string)] = true
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	if len(found) == 0 {
		t.Fatal("no x-scopes found in the spec; the parser is looking in the wrong place")
	}
	return found
}

// dashboardSessionScopes mirrors what POST /api/mcp/session-key hands back: all
// API scopes except cluster credentials, with the write half dropped for a
// read-only role.
func dashboardSessionScopes(t *testing.T, withWrites bool) []string {
	t.Helper()
	var out []string
	for s := range apiScopes(t) {
		if s == clusterCredentialsScope {
			continue
		}
		if strings.HasSuffix(s, ":write") && !withWrites {
			continue
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// registeredTools returns the names of every tool a server exposes, by asking
// it the way a real client would.
func registeredTools(t *testing.T, allowWrites bool, scopes Scopes) []string {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(s, stubAPI{}, allowWrites, scopes)

	ct, st := mcp.NewInMemoryTransports()
	ctx := t.Context()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer func() { _ = ss.Close() }()

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer func() { _ = cs.Close() }()

	var names []string
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// Stdio holds a key whose scopes cannot be enumerated, so it must keep getting
// the whole surface.
func TestUnknownScopesRegisterEverything(t *testing.T) {
	all := registeredTools(t, true, nil)
	for _, name := range []string{"skycloak_delete_realm", "skycloak_get_cluster_credentials", "skycloak_list_clusters"} {
		if !slices.Contains(all, name) {
			t.Fatalf("%s missing when scopes are unknown", name)
		}
	}
}

// A read-only member must not be shown dozens of write tools that will 403.
func TestReadOnlyScopesHideEveryWriteTool(t *testing.T) {
	readOnly := registeredTools(t, true, NewScopes(dashboardSessionScopes(t, false)))
	full := registeredTools(t, true, NewScopes(dashboardSessionScopes(t, true)))

	if len(readOnly) >= len(full) {
		t.Fatalf("read-only surface (%d tools) is not smaller than the write surface (%d)", len(readOnly), len(full))
	}
	for _, name := range readOnly {
		if !slices.Contains(full, name) {
			t.Fatalf("%s appears with read-only scopes but not with write scopes", name)
		}
	}
	for _, mutating := range []string{
		"skycloak_delete_realm", "skycloak_create_cluster", "skycloak_update_realm_user",
		"skycloak_upsert_smtp", "skycloak_assign_realm_user_role", "skycloak_install_extension",
		"skycloak_create_siem_destination", "skycloak_create_realm_import",
		"skycloak_add_cluster_captcha_domain", "skycloak_create_domain",
		"skycloak_rotate_application_secret", "skycloak_test_smtp",
	} {
		if slices.Contains(readOnly, mutating) {
			t.Fatalf("%s is exposed to a caller holding only read scopes", mutating)
		}
	}
}

// Filtering must not overshoot: a read-only member still gets the entire read
// surface, minus the one tool whose scope a session key never carries.
func TestReadOnlyScopesKeepEveryReadTool(t *testing.T) {
	readOnly := registeredTools(t, true, NewScopes(dashboardSessionScopes(t, false)))
	readSurface := registeredTools(t, false, nil)

	for _, name := range readSurface {
		if name == "skycloak_get_cluster_credentials" {
			continue // needs clusters:credentials:read, which no session key carries
		}
		if !slices.Contains(readOnly, name) {
			t.Fatalf("read tool %s was filtered out of a read-scoped session", name)
		}
	}
}

// A write-scoped session must reach the whole write surface, or an owner is
// quietly less capable over OAuth than with an API key.
func TestWriteScopesKeepEveryWriteTool(t *testing.T) {
	scoped := registeredTools(t, true, NewScopes(dashboardSessionScopes(t, true)))
	unscoped := registeredTools(t, true, nil)

	for _, name := range unscoped {
		if name == "skycloak_get_cluster_credentials" {
			continue
		}
		if !slices.Contains(scoped, name) {
			t.Fatalf("%s was filtered out of a fully write-scoped session", name)
		}
	}
}

// clusters:credentials:read exposes a cluster's Keycloak admin credentials.
// The dashboard never grants it, so the tool must not be advertised.
func TestClusterCredentialsToolNeedsItsOwnScope(t *testing.T) {
	granted := dashboardSessionScopes(t, true)
	if slices.Contains(registeredTools(t, true, NewScopes(granted)), "skycloak_get_cluster_credentials") {
		t.Fatal("get_cluster_credentials is exposed without clusters:credentials:read")
	}
	if !slices.Contains(registeredTools(t, true, NewScopes(append(granted, clusterCredentialsScope))), "skycloak_get_cluster_credentials") {
		t.Fatal("get_cluster_credentials is hidden from a caller who does hold clusters:credentials:read")
	}
}

// A caller with no usable scope at all gets no tools rather than the full set:
// an empty set must not be mistaken for "unknown".
func TestEmptyScopeSetIsNotTreatedAsUnknown(t *testing.T) {
	if got := registeredTools(t, true, NewScopes(nil)); len(got) != 0 {
		t.Fatalf("an empty scope set registered %d tools", len(got))
	}
}

// A scope the API does not define makes its area unreachable forever, and the
// only symptom is a missing tool.
func TestAreaScopesAreRealAPIScopes(t *testing.T) {
	known := apiScopes(t)
	for _, area := range toolAreas {
		for _, s := range area.scopes {
			if !known[s] {
				t.Errorf("area %q requires %q, which no operation in the API spec declares", area.name, s)
			}
		}
	}
}

// An area with no scopes registers for every caller, because "all of none" is
// vacuously satisfied. That is the one way a tool can slip past the filter
// entirely, and it looks like an ordinary table entry.
func TestEveryToolAreaDeclaresAtLeastOneScope(t *testing.T) {
	for _, area := range toolAreas {
		if len(area.scopes) == 0 {
			t.Errorf("area %q declares no scopes, so it registers for everyone", area.name)
		}
	}
}

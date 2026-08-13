package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// apiScopes returns every scope any operation in the committed OpenAPI spec
// declares, via its x-scopes extension. The spec is the authority on scope
// names; a scope that appears nowhere in it does not exist.
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
					list, ok := child.([]any)
					if !ok {
						t.Fatalf("x-scopes is %T, not a list; the parser would silently skip it", child)
					}
					for _, s := range list {
						str, ok := s.(string)
						if !ok {
							t.Fatalf("x-scopes entry is %T, not a string", s)
						}
						found[str] = true
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

// A scope the API does not define is silently useless: the minted key simply
// will not carry the permission, and the failure only shows up later as a 403
// on a tool call.
func TestWriteScopesAreAllRealAPIScopes(t *testing.T) {
	known := apiScopes(t)
	for _, s := range writeScopes {
		if !known[s] {
			t.Errorf("writeScopes requests %q, which no operation in the API spec declares", s)
		}
	}
}

// Every mutating area the API exposes should be requestable with
// --allow-writes, or a write tool registers and then 403s.
func TestWriteScopesCoverEveryWritableArea(t *testing.T) {
	requested := map[string]bool{}
	for _, s := range writeScopes {
		requested[s] = true
	}
	for s := range apiScopes(t) {
		if !strings.HasSuffix(s, ":write") {
			continue
		}
		if !requested[s] {
			t.Errorf("the API defines %q but --allow-writes never requests it, so those tools will 403", s)
		}
	}
}

// A write scope without its matching read scope leaves the tools that verify a
// change unable to read it back.
func TestWriteScopesIncludeMatchingReadScopes(t *testing.T) {
	requested := map[string]bool{}
	for _, s := range writeScopes {
		requested[s] = true
	}
	known := apiScopes(t)
	for _, s := range writeScopes {
		if !strings.HasSuffix(s, ":write") {
			continue
		}
		read := strings.TrimSuffix(s, ":write") + ":read"
		if known[read] && !requested[read] {
			t.Errorf("writeScopes has %q but not %q", s, read)
		}
	}
}

// The exclusion is a deliberate security choice, so it needs a test: nothing
// else here would notice it being added back.
func TestWriteScopesExcludeClusterCredentials(t *testing.T) {
	const excluded = "clusters:credentials:read"
	if !apiScopes(t)[excluded] {
		t.Fatalf("%s no longer exists in the spec; this test is stale", excluded)
	}
	for _, s := range writeScopes {
		if s == excluded {
			t.Fatalf("writeScopes requests %s, which exposes a cluster's admin credentials", excluded)
		}
	}
}

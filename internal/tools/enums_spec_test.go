package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// The committed spec is the authority on what the API accepts. Comparing the
// tools against it, rather than against literals that only agree with
// themselves, is what stops this file rotting: an enum that gains a value, is
// re-cased, or is newly attached to a parameter shows up here as a failure
// instead of as a 422 in front of a user.

func specDoc(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "apiclient", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	return doc
}

// resolveRef follows $ref chains within the document.
func resolveRef(doc map[string]any, n any) any {
	for range 16 {
		m, ok := n.(map[string]any)
		if !ok {
			return n
		}
		ref, ok := m["$ref"].(string)
		if !ok {
			return n
		}
		cur := any(doc)
		for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
			cm, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = cm[seg]
		}
		n = cur
	}
	return n
}

// enumOf returns the values a schema node accepts, looking through $ref, array
// items and the single-branch allOf wrapper the spec uses to attach a
// description to a $ref.
func enumOf(doc map[string]any, n any) []string {
	m, ok := resolveRef(doc, n).(map[string]any)
	if !ok {
		return nil
	}
	if raw, ok := m["enum"].([]any); ok {
		var out []string
		for _, v := range raw {
			s, ok := v.(string)
			if !ok {
				return nil // a non-string enum is not a casing problem
			}
			out = append(out, s)
		}
		return out
	}
	if items, ok := m["items"]; ok {
		if e := enumOf(doc, items); e != nil {
			return e
		}
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		branches, ok := m[key].([]any)
		if !ok {
			continue
		}
		for _, b := range branches {
			if e := enumOf(doc, b); e != nil {
				return e
			}
		}
	}
	return nil
}

// specEnum returns the values a named component schema declares.
func specEnum(t *testing.T, doc map[string]any, schema string) []string {
	t.Helper()
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	node, ok := schemas[schema]
	if !ok {
		t.Fatalf("the spec has no %s schema; this test is looking in the wrong place", schema)
	}
	values := enumOf(doc, node)
	if len(values) == 0 {
		t.Fatalf("%s declares no enum in the spec", schema)
	}
	return values
}

// An enum whose values we spell differently from the spec is the bug this
// whole change is about, only now on our side of the wire.
func TestEnumValuesMatchTheSpec(t *testing.T) {
	doc := specDoc(t)
	seen := map[string]bool{}
	for _, p := range enumParams {
		if p.enum.schema == "" || seen[p.enum.schema] {
			continue
		}
		seen[p.enum.schema] = true

		want := slices.Clone(specEnum(t, doc, p.enum.schema))
		got := slices.Clone(p.enum.values)
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("%s: we accept %v, the spec declares %v", p.enum.schema, got, want)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no schema-backed enums were checked")
	}
}

// The insight kinds are five sibling endpoints rather than one enum, so the
// paths are what says which values exist. A value that is not one of them used
// to fall through to the overview document, answering a different question
// without erroring.
func TestInsightTypesMatchTheSpecPaths(t *testing.T) {
	doc := specDoc(t)
	paths, _ := doc["paths"].(map[string]any)
	re := regexp.MustCompile(`^/clusters/\{[^}]+\}/insights/([a-z_]+)$`)

	var want []string
	for p := range paths {
		if m := re.FindStringSubmatch(p); m != nil {
			want = append(want, m[1])
		}
	}
	if len(want) == 0 {
		t.Fatal("no /insights/… paths in the spec; this test is looking in the wrong place")
	}
	got := slices.Clone(enumInsightType.values)
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("get_cluster_insights accepts %v, the spec serves %v", got, want)
	}
}

// enumFieldNames is every field name the spec attaches an enum to, anywhere:
// request bodies, query strings and path segments alike. It is what says
// whether a tool parameter carries an API enum.
func enumFieldNames(t *testing.T) map[string]bool {
	t.Helper()
	doc := specDoc(t)
	out := map[string]bool{}
	add := func(name string, node any) {
		if enumOf(doc, node) != nil {
			out[name] = true
		}
	}

	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	for _, node := range schemas {
		m, ok := node.(map[string]any)
		if !ok {
			continue
		}
		props, _ := m["properties"].(map[string]any)
		for name, prop := range props {
			add(name, prop)
		}
	}

	paths, _ := doc["paths"].(map[string]any)
	for _, item := range paths {
		im, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, op := range im {
			om, ok := op.(map[string]any)
			if !ok {
				continue
			}
			params, _ := om["parameters"].([]any)
			for _, p := range params {
				pm, ok := resolveRef(doc, p).(map[string]any)
				if !ok {
					continue
				}
				// Headers are set by the client, never by a model.
				if pm["in"] == "header" {
					continue
				}
				name, _ := pm["name"].(string)
				add(name, pm["schema"])
			}
		}
	}

	if len(out) == 0 {
		t.Fatal("no enum-backed field names found in the spec; this test is looking in the wrong place")
	}
	return out
}

// toolInputFields returns every input field a model fills in with a string, per
// tool, by dotted path, with its description.
func toolInputFields(t *testing.T) map[string]map[string]string {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(s, stubAPI{}, true, nil)

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

	out := map[string]map[string]string{}
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		raw, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("marshal %s input schema: %v", tool.Name, err)
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("decode %s input schema: %v", tool.Name, err)
		}
		fields := map[string]string{}
		walkLeafFields(schema, "", fields)
		out[tool.Name] = fields
	}
	if len(out) == 0 {
		t.Fatal("no tools registered")
	}
	return out
}

// walkLeafFields collects every field a model fills in with a string, whether
// singly or as a list, and recurses through nested objects. Lists count: an
// array-of-enum parameter has the same casing problem as a scalar one.
func walkLeafFields(schema map[string]any, prefix string, out map[string]string) {
	props, _ := schema["properties"].(map[string]any)
	for name, raw := range props {
		prop, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		path := prefix + name
		desc, _ := prop["description"].(string)
		items, _ := prop["items"].(map[string]any)
		if schemaHasType(prop, "string") || (items != nil && schemaHasType(items, "string")) {
			out[path] = desc
		}
		if sub, ok := prop["properties"].(map[string]any); ok {
			walkLeafFields(map[string]any{"properties": sub}, path+".", out)
		}
		if sub, ok := items["properties"].(map[string]any); ok {
			walkLeafFields(map[string]any{"properties": sub}, path+"[].", out)
		}
	}
}

func schemaHasType(prop map[string]any, want string) bool {
	switch tv := prop["type"].(type) {
	case string:
		return tv == want
	case []any:
		return slices.Contains(tv, any(want))
	}
	return false
}

// enumParamExemptions lists tool fields that share a name with an enum-backed
// API field but are not one, so the coverage check can stay strict. Each entry
// needs a reason; an empty map means every name-matched field is normalised.
var enumParamExemptions = map[string]string{}

// The point of the sweep: a parameter that carries an API enum and is not
// normalised fails the caller with a 422 that never mentions the case. Adding a
// tool with such a parameter must fail here rather than in front of a user.
//
// The link is by field name, which is how the API and the tools spell the same
// parameter today. A tool that renamed one would slip past, so the registry is
// still the record of intent.
func TestEveryEnumBackedToolParamIsNormalised(t *testing.T) {
	enumNames := enumFieldNames(t)
	normalised := map[string]bool{}
	for _, p := range enumParams {
		normalised[p.key()] = true
	}

	for tool, fields := range toolInputFields(t) {
		for path := range fields {
			if leaf := path[strings.LastIndex(path, ".")+1:]; !enumNames[leaf] {
				continue
			}
			key := tool + "." + path
			if normalised[key] || enumParamExemptions[key] != "" {
				continue
			}
			t.Errorf("%s maps to an API enum but is not normalised: add it to enumParams, or to enumParamExemptions with a reason", key)
		}
	}
}

// Every normalised parameter must say so, and say what it accepts. Two of
// fifteen advertising case-insensitivity is worse than none: a model
// generalising from those two hits an opaque failure on the rest.
func TestEnumParamDescriptionsStateTheAcceptedValues(t *testing.T) {
	const maxListed = 8 // beyond this the list stops being a useful description
	fields := toolInputFields(t)

	for _, p := range enumParams {
		desc, ok := fields[p.tool][p.field]
		if !ok {
			t.Errorf("%s is not a string field of its tool's input schema", p.key())
			continue
		}
		words := map[string]bool{}
		for _, w := range regexp.MustCompile(`[^A-Za-z0-9_-]+`).Split(strings.ToLower(desc), -1) {
			words[w] = true
		}
		if !words["case-insensitive"] {
			t.Errorf("%s: description %q does not tell the caller case does not matter", p.key(), desc)
		}
		if len(p.enum.values) > maxListed {
			continue
		}
		for _, v := range p.enum.values {
			if !words[v] {
				t.Errorf("%s: description %q does not list the accepted value %q", p.key(), desc, v)
			}
		}
	}
}

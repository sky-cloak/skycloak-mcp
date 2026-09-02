package tools

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// An output schema that forbids unknown properties makes every added field a
// breaking change for anyone already connected: MCP clients cache tool schemas
// when they connect, so the next release's new field fails validation and the
// tool errors until the session reconnects. That happened on 0.10.0 and again
// on 0.11.0.
//
// Strictness buys nothing here. The server is the sole authority on its own
// output, so there is no caller mistake to catch, unlike an input schema where
// a mistyped parameter should be refused.
func TestOutputSchemasAcceptUnknownProperties(t *testing.T) {
	for name, tool := range advertisedTools(t) {
		if tool.OutputSchema == nil {
			continue
		}
		raw, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("%s: marshal output schema: %v", name, err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: unmarshal output schema: %v", name, err)
		}
		for _, path := range strictPaths(doc, "") {
			t.Errorf("%s output schema forbids unknown properties at %s; a field added next release breaks every connected client until it reconnects", name, path)
		}
	}
}

// Input schemas stay strict: a mistyped parameter is a caller mistake worth
// refusing, and rejecting it costs nothing at the client's end.
func TestInputSchemasStayStrict(t *testing.T) {
	var strict int
	for _, tool := range advertisedTools(t) {
		raw, _ := json.Marshal(tool.InputSchema)
		var doc map[string]any
		if json.Unmarshal(raw, &doc) == nil {
			if v, ok := doc["additionalProperties"]; ok && v == false {
				strict++
			}
		}
	}
	if strict == 0 {
		t.Error("no input schema rejects unknown parameters; relaxing outputs must not have relaxed inputs too")
	}
}

// strictPaths returns every location in a schema that sets
// additionalProperties to false.
func strictPaths(node any, path string) []string {
	var out []string
	switch n := node.(type) {
	case map[string]any:
		if v, ok := n["additionalProperties"]; ok {
			if b, isBool := v.(bool); isBool && !b {
				out = append(out, path+"/additionalProperties")
			}
		}
		for k, v := range n {
			out = append(out, strictPaths(v, path+"/"+k)...)
		}
	case []any:
		for i, v := range n {
			out = append(out, strictPaths(v, path+"/"+itoa(i))...)
		}
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// advertisedTools lists the tools the server actually advertises.
func advertisedTools(t *testing.T) map[string]*mcp.Tool {
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

	out := map[string]*mcp.Tool{}
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		out[tool.Name] = tool
	}
	return out
}

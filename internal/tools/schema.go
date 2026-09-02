package tools

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// addTool registers a tool whose output schema tolerates properties the client
// has not seen.
//
// The SDK infers output schemas from the result type and marks them
// additionalProperties:false. MCP clients cache tool schemas when they connect
// and validate every result against that copy, so the first release to add a
// field makes the tool fail for everyone already connected, until each session
// reconnects. That has now happened twice.
//
// Strictness earns nothing on the way out: the server is the sole authority on
// its own output, so there is no caller mistake to catch. Input schemas keep
// theirs, where a mistyped parameter is worth refusing.
//
// A preset OutputSchema suppresses the SDK's inference, so the schema is
// inferred here and relaxed before registration. Inference failure falls back
// to the SDK's own, which is strict but correct: a tool that registers is
// better than one that does not.
func addTool[In, Out any](s *mcp.Server, t *mcp.Tool, h mcp.ToolHandlerFor[In, Out]) {
	if t.OutputSchema == nil {
		if schema, err := jsonschema.For[Out](nil); err == nil && schema != nil {
			relaxSchema(schema)
			t.OutputSchema = schema
		}
	}
	mcp.AddTool(s, t, h)
}

// isFalseSchema reports whether a schema rejects everything, which is how
// jsonschema-go spells additionalProperties:false. Compared by marshalling
// rather than by shape: the library canonicalises several forms to false, and
// the marshalled result is what a client validates against.
func isFalseSchema(s *jsonschema.Schema) bool {
	if s == nil {
		return false
	}
	b, err := json.Marshal(s)
	return err == nil && string(b) == "false"
}

// relaxSchema clears additionalProperties everywhere in a schema, including
// nested objects and array items, so a nested row type added later is as
// forgiving as the envelope around it. An absent additionalProperties means
// "anything else is allowed" in JSON Schema, which is the intent.
func relaxSchema(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	// additionalProperties carries two different meanings. On a struct it is the
	// prohibition being removed here; on a map it is the value type, and
	// clearing it would turn map[string]string into "any object", losing real
	// information for no benefit. Only the prohibition is dropped.
	if isFalseSchema(s.AdditionalProperties) {
		s.AdditionalProperties = nil
	} else {
		relaxSchema(s.AdditionalProperties)
	}
	for _, p := range s.Properties {
		relaxSchema(p)
	}
	relaxSchema(s.Items)
	for _, sub := range [][]*jsonschema.Schema{s.AllOf, s.AnyOf, s.OneOf} {
		for _, x := range sub {
			relaxSchema(x)
		}
	}
	relaxSchema(s.Not)
	for _, d := range s.Defs {
		relaxSchema(d)
	}
}

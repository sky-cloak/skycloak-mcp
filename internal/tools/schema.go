package tools

import (
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

// relaxSchema clears additionalProperties everywhere in a schema, including
// nested objects and array items, so a nested row type added later is as
// forgiving as the envelope around it. An absent additionalProperties means
// "anything else is allowed" in JSON Schema, which is the intent.
func relaxSchema(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	s.AdditionalProperties = nil
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

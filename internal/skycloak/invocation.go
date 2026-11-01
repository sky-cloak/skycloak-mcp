package skycloak

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

// Headers that tie an API request to the MCP tool invocation it served.
//
// The gateway logs requests by route, and routes do not map to tools: one
// invocation can call the API once per cluster when cluster_id is omitted, and
// the retry transport can replay a request after a 429 or 5xx. The tool name
// says which tool asked, and the call ID groups every request one invocation
// made, so usage can be counted per invocation rather than per request.
const (
	HeaderMCPTool   = "X-MCP-Tool"
	HeaderMCPCallID = "X-MCP-Call-Id"
)

// Invocation identifies one tool call: the tool's registered name and an ID
// made once for that call.
type Invocation struct {
	Tool   string
	CallID string
}

type invocationKey struct{}

// WithInvocation returns a context for serving one call of the named tool,
// carrying a fresh random call ID. Every API request made with the returned
// context, or one derived from it, is tagged with both.
func WithInvocation(ctx context.Context, tool string) context.Context {
	return context.WithValue(ctx, invocationKey{}, Invocation{Tool: tool, CallID: uuid.NewString()})
}

// InvocationFrom returns the invocation ctx is serving, if any.
func InvocationFrom(ctx context.Context) (Invocation, bool) {
	inv, ok := ctx.Value(invocationKey{}).(Invocation)
	return inv, ok && inv.Tool != ""
}

// invocationEditor tags a request with the invocation its context carries.
//
// Outside an invocation it sets nothing, rather than an empty or placeholder
// value: a request with no tool behind it should be recorded as having none.
// The retry transport clones the request, headers included, so every attempt
// of a retried request carries the same call ID.
func invocationEditor(ctx context.Context, req *http.Request) error {
	inv, ok := InvocationFrom(ctx)
	if !ok {
		return nil
	}
	req.Header.Set(HeaderMCPTool, inv.Tool)
	req.Header.Set(HeaderMCPCallID, inv.CallID)
	return nil
}

package tools

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Workspace is the workspace a session acts on and why it was picked. The
// zero value means the session has not told us: an API key names no workspace
// we can read back, and an older server does not report one.
type Workspace struct {
	ID     string `json:"workspace_id,omitempty" jsonschema:"the workspace ID the session acts on"`
	Name   string `json:"workspace_name,omitempty" jsonschema:"the workspace name"`
	Reason string `json:"pick_reason,omitempty" jsonschema:"why it was picked: requested, only_membership, owned or oldest_membership"`
}

// maxWorkspaceFieldRunes caps how much of a workspace name, ID or reason is
// passed on to the assistant. A longer value is cut and ends in an ellipsis.
const (
	maxWorkspaceFieldRunes = 80
	cutMarker              = "..."
)

// clean makes a value that someone else chose safe to place in text the
// assistant treats as the server's own: control characters, newlines and other
// invisible separators are dropped, whitespace runs collapse, and the result is
// cut to a fixed length.
func clean(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r), unicode.Is(unicode.Zp, r):
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > maxWorkspaceFieldRunes {
		s = strings.TrimSpace(string(r[:maxWorkspaceFieldRunes-len(cutMarker)])) + cutMarker
	}
	return s
}

// sanitized returns w with every field cleaned.
func (w Workspace) sanitized() Workspace {
	return Workspace{ID: clean(w.ID), Name: clean(w.Name), Reason: clean(w.Reason)}
}

// Known reports whether there is anything to tell the assistant.
func (w Workspace) Known() bool {
	return w.ID != "" || w.Name != ""
}

// reasonText spells a pick reason out for a person. An unrecognised value is
// passed through quoted, so a reason a newer server adds still shows up and
// reads as a value.
func reasonText(reason string) string {
	switch reason {
	case "requested":
		return "it was named in the connection URL"
	case "only_membership":
		return "it is the only workspace this account belongs to"
	case "owned":
		return "this account owns it and no workspace was named"
	case "oldest_membership":
		return "no workspace was named and this is the one this account joined first"
	case "":
		return ""
	default:
		return fmt.Sprintf("%q", reason)
	}
}

// label names the workspace with its name quoted, so the name reads as a value
// and not as part of the sentence around it. w must be sanitized.
func (w Workspace) label() string {
	switch {
	case w.Name != "" && w.ID != "":
		return fmt.Sprintf("%q (%s)", w.Name, w.ID)
	case w.Name != "":
		return fmt.Sprintf("%q", w.Name)
	default:
		return w.ID
	}
}

// Instructions is the text a server hands a client when it connects, naming the
// workspace the session acts on. It is empty when the workspace is not known.
func (w Workspace) Instructions() string {
	w = w.sanitized()
	if !w.Known() {
		return ""
	}
	text := "This session acts on the Skycloak workspace " + w.label() + "."
	if r := reasonText(w.Reason); r != "" {
		text += " It was picked because " + r + "."
	}
	text += " Every tool call reads and changes that workspace only. Call skycloak_get_workspace to check it again, and tell the user which workspace you are acting on before making a change."
	return text
}

// RegisterWorkspace adds skycloak_get_workspace. It needs no scope, because the
// answer is what the session was connected with rather than anything read from
// the API, and nothing is registered when the workspace is not known.
func RegisterWorkspace(s *mcp.Server, w Workspace) {
	if !w.sanitized().Known() {
		return
	}
	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_workspace",
		Description: "Get the workspace this session acts on: its name, its ID and why it was picked (requested, only_membership, owned or oldest_membership). Every other tool reads and changes this workspace only. To act on another one, reconnect with ?workspace=<id> on the server URL.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get workspace"},
	}, getWorkspaceHandler(w))
}

func getWorkspaceHandler(w Workspace) mcp.ToolHandlerFor[NoInput, Workspace] {
	w = w.sanitized()
	return func(context.Context, *mcp.CallToolRequest, NoInput) (*mcp.CallToolResult, Workspace, error) {
		text := "Workspace: " + w.label()
		if r := reasonText(w.Reason); r != "" {
			text += ". Picked because " + r
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, w, nil
	}
}

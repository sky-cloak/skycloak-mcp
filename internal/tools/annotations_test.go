package tools

import (
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestEveryToolIsFullyAnnotated guards the directory submissions.
//
// OpenAI's plugin portal validates readOnlyHint, openWorldHint and
// destructiveHint on every tool and blocks a submission when one is absent;
// Anthropic's needs a title. All four are easy to forget on a new tool, and
// because the SDK tags these fields omitempty a nil pointer simply vanishes
// from the wire, so the mistake is invisible in Go and surfaces only in someone
// else's review queue days later.
//
// This asserts against what a client actually receives rather than against the
// structs, which is the only view that can catch the omitempty problem.
func TestEveryToolIsFullyAnnotated(t *testing.T) {
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

	seen := 0
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		seen++
		a := tool.Annotations
		if a == nil {
			t.Errorf("%s: no annotations on the wire", tool.Name)
			continue
		}
		if a.Title == "" {
			t.Errorf("%s: missing Title", tool.Name)
		}
		if a.OpenWorldHint == nil {
			t.Errorf("%s: missing openWorldHint; the spec defaults it to true, which is wrong for a tool acting on one tenant", tool.Name)
		}
		// destructiveHint only carries meaning for a tool that writes.
		if !a.ReadOnlyHint && a.DestructiveHint == nil {
			t.Errorf("%s: write tool with no destructiveHint", tool.Name)
		}
	}
	if seen == 0 {
		t.Fatal("no tools listed, so this test is not exercising anything")
	}
}

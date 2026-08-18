package tools

import (
	"regexp"
	"slices"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// promptSession connects a client to a server built with the given gating, the
// same way registeredTools does for tools.
func promptSession(t *testing.T, allowWrites bool, scopes Scopes) *mcp.ClientSession {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	Register(s, stubAPI{}, allowWrites, scopes)

	ct, st := mcp.NewInMemoryTransports()
	ctx := t.Context()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func listedPrompts(t *testing.T, allowWrites bool, scopes Scopes) []*mcp.Prompt {
	t.Helper()
	cs := promptSession(t, allowWrites, scopes)
	var out []*mcp.Prompt
	for p, err := range cs.Prompts(t.Context(), nil) {
		if err != nil {
			t.Fatalf("list prompts: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// fillArgs supplies a placeholder for every declared argument, so prompts/get
// renders the fully-specified variant of each body.
func fillArgs(p *mcp.Prompt) map[string]string {
	args := make(map[string]string, len(p.Arguments))
	for _, a := range p.Arguments {
		args[a.Name] = "example"
	}
	return args
}

// promptText fetches a prompt over the wire and returns its concatenated text.
func promptText(t *testing.T, cs *mcp.ClientSession, name string, args map[string]string) string {
	t.Helper()
	res, err := cs.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("get prompt %s: %v", name, err)
	}
	if len(res.Messages) == 0 {
		t.Fatalf("%s: prompts/get returned no messages", name)
	}
	var text string
	for _, m := range res.Messages {
		tc, ok := m.Content.(*mcp.TextContent)
		if !ok {
			t.Fatalf("%s: message content is %T, want text", name, m.Content)
		}
		if tc.Text == "" {
			t.Fatalf("%s: empty message text", name)
		}
		text += tc.Text
	}
	return text
}

// TestEveryPromptIsFullyDescribed mirrors the tool-annotations guard: a prompt
// or argument without a description reads as an unlabeled button in a client's
// prompt picker, and nothing in Go stops one from shipping that way.
func TestEveryPromptIsFullyDescribed(t *testing.T) {
	cs := promptSession(t, true, nil)

	seen := 0
	for p, err := range cs.Prompts(t.Context(), nil) {
		if err != nil {
			t.Fatalf("list prompts: %v", err)
		}
		seen++
		if p.Description == "" {
			t.Errorf("%s: missing description", p.Name)
		}
		if p.Title == "" {
			t.Errorf("%s: missing title", p.Name)
		}
		for _, a := range p.Arguments {
			if a.Description == "" {
				t.Errorf("%s: argument %q has no description", p.Name, a.Name)
			}
		}
		if txt := promptText(t, cs, p.Name, fillArgs(p)); txt == "" {
			t.Errorf("%s: prompts/get returned empty content", p.Name)
		}
	}
	if seen == 0 {
		t.Fatal("no prompts listed, so this test is not exercising anything")
	}
}

var toolNameRE = regexp.MustCompile(`skycloak_[a-z0-9_]+`)

// TestPromptsNameOnlyToolsTheSessionHas guards the whole point of the prompts:
// every tool a body mentions must exist, and a read-only session must never be
// handed a workflow that names a write tool it cannot call.
func TestPromptsNameOnlyToolsTheSessionHas(t *testing.T) {
	for _, tc := range []struct {
		name        string
		allowWrites bool
	}{
		{"write session", true},
		{"read-only session", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			available := registeredTools(t, tc.allowWrites, nil)
			cs := promptSession(t, tc.allowWrites, nil)
			for p, err := range cs.Prompts(t.Context(), nil) {
				if err != nil {
					t.Fatalf("list prompts: %v", err)
				}
				text := promptText(t, cs, p.Name, fillArgs(p))
				mentions := toolNameRE.FindAllString(text, -1)
				if len(mentions) == 0 {
					t.Errorf("%s: body names no tools, so it cannot be guiding anyone", p.Name)
				}
				for _, m := range mentions {
					if !slices.Contains(available, m) {
						t.Errorf("%s: names %s, which this session does not have", p.Name, m)
					}
				}
			}
		})
	}
}

// TestWritePromptsAreGatedLikeWriteTools checks both halves of the gate: the
// local read-only default (no allowWrites) and an OAuth session whose scopes
// are known to be read-only.
func TestWritePromptsAreGatedLikeWriteTools(t *testing.T) {
	writePrompts := []string{"provision_environment", "set_up_custom_domain", "rotate_client_secret"}
	readPrompts := []string{"audit_self_registration", "review_upgrades", "triage_failed_logins", "review_identity_providers", "review_admin_changes"}

	names := func(prompts []*mcp.Prompt) []string {
		var out []string
		for _, p := range prompts {
			out = append(out, p.Name)
		}
		return out
	}

	for _, tc := range []struct {
		name        string
		allowWrites bool
		scopes      Scopes
	}{
		{"writes disabled", false, nil},
		{"read-only scopes", true, NewScopes(dashboardSessionScopes(t, false))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := names(listedPrompts(t, tc.allowWrites, tc.scopes))
			for _, w := range writePrompts {
				if slices.Contains(got, w) {
					t.Errorf("write prompt %s offered to a session that cannot write", w)
				}
			}
			for _, r := range readPrompts {
				if !slices.Contains(got, r) {
					t.Errorf("read prompt %s missing from a read-capable session", r)
				}
			}
		})
	}

	full := names(listedPrompts(t, true, NewScopes(dashboardSessionScopes(t, true))))
	for _, w := range append(writePrompts, readPrompts...) {
		if !slices.Contains(full, w) {
			t.Errorf("prompt %s missing from a fully write-scoped session", w)
		}
	}
}

// TestEmptyScopeSetRegistersNoPrompts: like tools, an empty grant must not be
// mistaken for an unknown one.
func TestEmptyScopeSetRegistersNoPrompts(t *testing.T) {
	if got := listedPrompts(t, true, NewScopes(nil)); len(got) != 0 {
		t.Fatalf("an empty scope set registered %d prompts", len(got))
	}
}

// TestPromptScopesCoverTheirTools derives, for every tool a prompt body
// mentions, the scopes of the area that registers it, and requires the
// prompt's declared scopes to cover them. Otherwise a scoped session could be
// offered a prompt while missing one of its tools.
func TestPromptScopesCoverTheirTools(t *testing.T) {
	areaScopes := map[string][]string{}
	for _, area := range toolAreas {
		s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
		area.register(s, stubAPI{})

		ct, st := mcp.NewInMemoryTransports()
		ctx := t.Context()
		ss, err := s.Connect(ctx, st, nil)
		if err != nil {
			t.Fatalf("server connect: %v", err)
		}
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, ct, nil)
		if err != nil {
			t.Fatalf("client connect: %v", err)
		}
		for tool, err := range cs.Tools(ctx, nil) {
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			areaScopes[tool.Name] = area.scopes
		}
		_ = cs.Close()
		_ = ss.Close()
	}

	known := apiScopes(t)
	for _, def := range promptDefs {
		if len(def.scopes) == 0 {
			t.Errorf("prompt %q declares no scopes, so it registers for everyone", def.prompt.Name)
		}
		for _, s := range def.scopes {
			if !known[s] {
				t.Errorf("prompt %q requires %q, which no operation in the API spec declares", def.prompt.Name, s)
			}
		}
		granted := NewScopes(def.scopes)
		for _, m := range toolNameRE.FindAllString(def.text(fillArgs(def.prompt)), -1) {
			need, ok := areaScopes[m]
			if !ok {
				t.Errorf("prompt %q names %s, which no tool area registers", def.prompt.Name, m)
				continue
			}
			if !granted.grants(need...) {
				t.Errorf("prompt %q names %s but does not require its scopes %v", def.prompt.Name, m, need)
			}
		}
	}
}

// A missing required argument must fail prompts/get rather than render a body
// with a hole where the realm name should be.
func TestMissingRequiredArgumentFailsPromptsGet(t *testing.T) {
	cs := promptSession(t, true, nil)
	if _, err := cs.GetPrompt(t.Context(), &mcp.GetPromptParams{Name: "triage_failed_logins"}); err == nil {
		t.Fatal("prompts/get succeeded without the required realm argument")
	}
}

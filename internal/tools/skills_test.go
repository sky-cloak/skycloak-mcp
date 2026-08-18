package tools

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// skillSession connects a client to a server built with the given gating, the
// way a skills-aware host would: the server declares the SEP-2640 extension
// and the client registers the two custom methods before connecting.
func skillSession(t *testing.T, allowWrites bool, scopes Scopes) *mcp.ClientSession {
	t.Helper()
	s := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, &mcp.ServerOptions{Capabilities: Capabilities()})
	Register(s, stubAPI{}, allowWrites, scopes)

	ct, st := mcp.NewInMemoryTransports()
	ctx := t.Context()
	ss, err := s.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil)
	if err := mcp.AddSendingCustomMethod[*skillsListParams, *skillsListResult](c, "skills/list"); err != nil {
		t.Fatalf("register skills/list: %v", err)
	}
	if err := mcp.AddSendingCustomMethod[*skillsGetParams, *skillsGetResult](c, "skills/get"); err != nil {
		t.Fatalf("register skills/get: %v", err)
	}
	cs, err := c.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func listSkills(t *testing.T, cs *mcp.ClientSession) []skillEntry {
	t.Helper()
	res, err := mcp.CallCustomMethod[*skillsListParams, *skillsListResult](t.Context(), cs, "skills/list", &skillsListParams{})
	if err != nil {
		t.Fatalf("skills/list: %v", err)
	}
	return res.Skills
}

// readSkill fetches a skill's SKILL.md the way SEP-2640 says to: a plain
// resources/read of its URI.
func readSkill(t *testing.T, cs *mcp.ClientSession, uri string) string {
	t.Helper()
	res, err := cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
	if err != nil {
		t.Fatalf("resources/read %s: %v", uri, err)
	}
	if len(res.Contents) != 1 {
		t.Fatalf("%s: got %d contents, want 1", uri, len(res.Contents))
	}
	c := res.Contents[0]
	if c.MIMEType != "text/markdown" {
		t.Errorf("%s: mimeType %q, want text/markdown", uri, c.MIMEType)
	}
	if c.Text == "" {
		t.Fatalf("%s: empty content", uri)
	}
	return c.Text
}

// TestInitializeDeclaresSkillsExtension: a host only calls skills/list after
// seeing the io.modelcontextprotocol/skills capability, so it has to be on
// the wire in the initialize result.
func TestInitializeDeclaresSkillsExtension(t *testing.T) {
	cs := skillSession(t, true, nil)
	exts := cs.InitializeResult().Capabilities.Extensions
	if _, ok := exts[SkillsExtension]; !ok {
		t.Fatalf("initialize declares extensions %v, missing %q", exts, SkillsExtension)
	}
}

// TestSkillsListEntriesVerifyEndToEnd walks the full consumer flow OpenAI's
// importer follows: list the skills, read each SKILL.md via resources/read,
// and check what SEP-2640 promises about each entry, including that the
// digest matches the bytes actually served and that the frontmatter in the
// entry is identical to the frontmatter in the file.
func TestSkillsListEntriesVerifyEndToEnd(t *testing.T) {
	cs := skillSession(t, true, nil)
	entries := listSkills(t, cs)
	if len(entries) != len(skillDefs) {
		t.Fatalf("skills/list returned %d skills, want %d", len(entries), len(skillDefs))
	}
	for _, e := range entries {
		name, _ := e.Frontmatter["name"].(string)
		if name == "" {
			t.Errorf("%s: frontmatter has no name", e.URI)
			continue
		}
		if desc, _ := e.Frontmatter["description"].(string); desc == "" {
			t.Errorf("%s: frontmatter has no description", e.URI)
		}
		if want := "skill://" + name + "/SKILL.md"; e.URI != want {
			t.Errorf("uri %q, want %q (final path segment must equal the skill name)", e.URI, want)
		}
		if len(e.Resources) == 0 {
			t.Errorf("%s: entry lists no resources, so it cannot be verified", e.URI)
			continue
		}
		if !slices.ContainsFunc(e.Resources, func(r skillResourceEntry) bool { return r.URI == e.URI }) {
			t.Errorf("%s: resources omit the SKILL.md itself", e.URI)
		}
		for _, r := range e.Resources {
			body := readSkill(t, cs, r.URI)
			sum := sha256.Sum256([]byte(body))
			if got := "sha256:" + hex.EncodeToString(sum[:]); got != r.Digest {
				t.Errorf("%s: digest %s, but served content hashes to %s", r.URI, r.Digest, got)
			}
		}
		fm, err := parseFrontmatter([]byte(readSkill(t, cs, e.URI)))
		if err != nil {
			t.Errorf("%s: served SKILL.md frontmatter does not parse: %v", e.URI, err)
		} else if !reflect.DeepEqual(fm, e.Frontmatter) {
			t.Errorf("%s: entry frontmatter %v differs from the file's %v", e.URI, e.Frontmatter, fm)
		}
	}
}

// TestSkillsGetMirrorsTheListing: skills/get must return the same entry the
// listing carries for every listed URI, and reject a URI it does not serve.
func TestSkillsGetMirrorsTheListing(t *testing.T) {
	cs := skillSession(t, true, nil)
	for _, want := range listSkills(t, cs) {
		res, err := mcp.CallCustomMethod[*skillsGetParams, *skillsGetResult](t.Context(), cs, "skills/get", &skillsGetParams{URI: want.URI})
		if err != nil {
			t.Fatalf("skills/get %s: %v", want.URI, err)
		}
		if !reflect.DeepEqual(res.Skill, want) {
			t.Errorf("skills/get %s returned a different entry than skills/list", want.URI)
		}
	}
	if _, err := mcp.CallCustomMethod[*skillsGetParams, *skillsGetResult](t.Context(), cs, "skills/get", &skillsGetParams{URI: "skill://no-such-skill/SKILL.md"}); err == nil {
		t.Fatal("skills/get succeeded for a skill this server does not serve")
	}
}

// TestSkillsGetNilParamsErrs: custom methods tolerate absent params, so the
// SDK hands the handler a nil pointer for them. The SDK client cannot put
// that on the wire (it always injects _meta), so the handler is exercised
// directly: it must answer invalid-params, not panic.
func TestSkillsGetNilParamsErrs(t *testing.T) {
	if _, err := skillsGetHandler(nil)(t.Context(), nil, nil); err == nil {
		t.Fatal("skills/get with nil params did not error")
	}
}

// TestSkillsNameOnlyToolsTheSessionHas: like prompts, a skill is a workflow
// over named tools, so every tool a served SKILL.md mentions must exist in
// that same session.
func TestSkillsNameOnlyToolsTheSessionHas(t *testing.T) {
	for _, tc := range []struct {
		name        string
		allowWrites bool
	}{
		{"write session", true},
		{"read-only session", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			available := registeredTools(t, tc.allowWrites, nil)
			cs := skillSession(t, tc.allowWrites, nil)
			for _, e := range listSkills(t, cs) {
				body := readSkill(t, cs, e.URI)
				mentions := toolNameRE.FindAllString(body, -1)
				if len(mentions) == 0 {
					t.Errorf("%s: body names no tools, so it cannot be guiding anyone", e.URI)
				}
				for _, m := range mentions {
					if !slices.Contains(available, m) {
						t.Errorf("%s: names %s, which this session does not have", e.URI, m)
					}
				}
			}
		})
	}
}

// TestWriteSkillsAreGatedLikeWriteTools checks both halves of the gate, the
// same way the prompt test does: the local read-only default and an OAuth
// session whose scopes are known to be read-only.
func TestWriteSkillsAreGatedLikeWriteTools(t *testing.T) {
	writeSkills := []string{"enterprise-sso-rollout", "keycloak-migration-doctor", "keycloak-upgrade-readiness"}
	readSkills := []string{"auth-incident-triage"}

	names := func(entries []skillEntry) []string {
		var out []string
		for _, e := range entries {
			name, _ := e.Frontmatter["name"].(string)
			out = append(out, name)
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
			got := names(listSkills(t, skillSession(t, tc.allowWrites, tc.scopes)))
			for _, w := range writeSkills {
				if slices.Contains(got, w) {
					t.Errorf("write skill %s offered to a session that cannot write", w)
				}
			}
			for _, r := range readSkills {
				if !slices.Contains(got, r) {
					t.Errorf("read skill %s missing from a read-capable session", r)
				}
			}
		})
	}

	full := names(listSkills(t, skillSession(t, true, NewScopes(dashboardSessionScopes(t, true)))))
	for _, w := range append(writeSkills, readSkills...) {
		if !slices.Contains(full, w) {
			t.Errorf("skill %s missing from a fully write-scoped session", w)
		}
	}
}

// TestEmptyScopeSetServesNoSkills: the methods still answer, with an empty
// catalog rather than an error, and no skill resources are registered.
func TestEmptyScopeSetServesNoSkills(t *testing.T) {
	cs := skillSession(t, true, NewScopes(nil))
	if got := listSkills(t, cs); len(got) != 0 {
		t.Fatalf("an empty scope set served %d skills", len(got))
	}
	for r, err := range cs.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatalf("list resources: %v", err)
		}
		if strings.HasPrefix(r.URI, "skill://") {
			t.Errorf("an empty scope set registered resource %s", r.URI)
		}
	}
}

// TestSkillScopeSetsAreSelfSufficient runs every skill under the minimal
// grant: a session holding exactly the skill's declared scopes, through the
// real Register path. The skill must be offered there, and every tool its
// served body names must be registered in that same session. This is the
// wire-level counterpart of TestSkillScopesCoverTheirTools, which reasons
// from the toolAreas table rather than from what a client receives.
func TestSkillScopeSetsAreSelfSufficient(t *testing.T) {
	for _, def := range skillDefs {
		t.Run(def.name, func(t *testing.T) {
			scopes := NewScopes(def.scopes)
			cs := skillSession(t, true, scopes)

			uri := "skill://" + def.name + "/SKILL.md"
			if !slices.ContainsFunc(listSkills(t, cs), func(e skillEntry) bool { return e.URI == uri }) {
				t.Fatalf("skills/list under the skill's own scopes omits %s", uri)
			}

			available := registeredTools(t, true, scopes)
			for _, m := range toolNameRE.FindAllString(readSkill(t, cs, uri), -1) {
				if !slices.Contains(available, m) {
					t.Errorf("%s names %s, which its own scope set does not register", uri, m)
				}
			}
		})
	}
}

// TestSkillScopesCoverTheirTools mirrors the prompt-scope guard: for every
// tool a SKILL.md mentions, the skill's declared scopes must cover the
// scopes of the area that registers it, or a scoped session could be offered
// a skill while missing one of its tools.
func TestSkillScopesCoverTheirTools(t *testing.T) {
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
	for _, sk := range skills {
		if len(sk.def.scopes) == 0 {
			t.Errorf("skill %q declares no scopes, so it registers for everyone", sk.def.name)
		}
		for _, s := range sk.def.scopes {
			if !known[s] {
				t.Errorf("skill %q requires %q, which no operation in the API spec declares", sk.def.name, s)
			}
		}
		granted := NewScopes(sk.def.scopes)
		for _, m := range toolNameRE.FindAllString(sk.body, -1) {
			need, ok := areaScopes[m]
			if !ok {
				t.Errorf("skill %q names %s, which no tool area registers", sk.def.name, m)
				continue
			}
			if !granted.grants(need...) {
				t.Errorf("skill %q names %s but does not require its scopes %v", sk.def.name, m, need)
			}
		}
	}
}

package tools

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// Skills are served per the draft SEP-2640 Skills extension
// (https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2640):
// each SKILL.md is an ordinary resource under skill://<name>/SKILL.md, and the
// skills/list and skills/get methods return entries carrying the frontmatter
// and per-file sha256 digests. OpenAI's plugin directory imports exactly this
// bounded, static shape at submission time.

//go:embed skills/*/SKILL.md
var skillFS embed.FS

// SkillsExtension is the capability identifier SEP-2640 assigns. Declaring it
// commits the server to answering skills/list and skills/get.
const SkillsExtension = "io.modelcontextprotocol/skills"

// Capabilities returns the capabilities to pass to mcp.NewServer. Setting
// ServerOptions.Capabilities replaces the SDK's default, so logging is
// restated here to keep the wire behavior it had before skills existed.
func Capabilities() *mcp.ServerCapabilities {
	caps := &mcp.ServerCapabilities{Logging: &mcp.LoggingCapabilities{}} //nolint:staticcheck // logging is deprecated protocol-wide, but dropping the advertised capability is its own change, not a side effect of adding skills
	caps.AddExtension(SkillsExtension, map[string]any{})
	return caps
}

// skillDef pairs an embedded skill with the gating of the tools its body
// names, mirroring promptDef: scopes is the union of the scopes of every tool
// area the body references, and write withholds the skill from read-only
// sessions because its workflow cannot be followed without write tools.
type skillDef struct {
	name   string
	write  bool
	scopes []string
}

var skillDefs = []skillDef{
	{
		name: "auth-incident-triage",
		scopes: []string{
			"clusters:read", "clusters:logs:read", "clusters:events:read", "clusters:insights:read",
			"clusters:security:read", "realms:read", "applications:read", "identity-providers:read",
			"domains:read", "smtp:read", "themes:read", "realm-roles:read", "realm-groups:read",
		},
	},
	{
		name:  "enterprise-sso-rollout",
		write: true,
		scopes: []string{
			"clusters:read", "realms:read", "applications:read", "identity-providers:read",
			"domains:read", "clusters:logs:read", "clusters:events:read",
			"identity-providers:write", "smtp:write", "clusters:write", "realms:write",
			"realm-roles:write", "realm-groups:write", "realm-users:write", "domains:write",
			"applications:write", "extensions:write", "themes:write", "branding:write",
		},
	},
	{
		name:  "keycloak-upgrade-readiness",
		write: true,
		scopes: []string{
			"clusters:read", "clusters:insights:read", "clusters:logs:read", "clusters:events:read",
			"realms:read", "applications:read", "identity-providers:read", "domains:read",
			"extensions:read", "clusters:extensions:read", "themes:read", "branding:read",
			"clusters:exports:read", "realm-roles:read", "realm-groups:read",
			"clusters:exports:write", "clusters:extensions:write", "clusters:write",
			"realm-roles:write", "realm-groups:write", "realm-users:write", "domains:write",
			"applications:write", "identity-providers:write", "extensions:write", "themes:write",
			"smtp:write", "branding:write",
		},
	},
}

// A skill is a loaded skillDef: the embedded SKILL.md plus everything the
// wire entry derives from it.
type skill struct {
	def         skillDef
	uri         string
	body        string
	digest      string
	description string
	frontmatter map[string]any
}

// skillEntry is the SEP-2640 wire shape shared by skills/list and skills/get.
type skillEntry struct {
	URI         string               `json:"uri"`
	Frontmatter map[string]any       `json:"frontmatter"`
	Resources   []skillResourceEntry `json:"resources"`
}

type skillResourceEntry struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

type skillsListParams struct {
	mcp.ParamsBase
	Cursor string `json:"cursor,omitempty"`
}

type skillsListResult struct {
	mcp.ResultBase
	Skills []skillEntry `json:"skills"`
}

type skillsGetParams struct {
	mcp.ParamsBase
	URI string `json:"uri"`
}

type skillsGetResult struct {
	mcp.ResultBase
	Skill skillEntry `json:"skill"`
}

var skills = loadSkills()

// loadSkills reads every embedded skill and derives its wire entry. Panics are
// deliberate: a malformed embedded file is a build defect, caught by any test
// run, never a runtime condition.
func loadSkills() []skill {
	out := make([]skill, 0, len(skillDefs))
	for _, def := range skillDefs {
		raw, err := skillFS.ReadFile("skills/" + def.name + "/SKILL.md")
		if err != nil {
			panic(fmt.Sprintf("skill %s: %v", def.name, err))
		}
		fm, err := parseFrontmatter(raw)
		if err != nil {
			panic(fmt.Sprintf("skill %s: %v", def.name, err))
		}
		// SEP-2640 requires the final URI segment to equal frontmatter.name.
		if name, _ := fm["name"].(string); name != def.name {
			panic(fmt.Sprintf("skill %s: frontmatter name %q does not match its directory", def.name, name))
		}
		desc, _ := fm["description"].(string)
		if desc == "" {
			panic(fmt.Sprintf("skill %s: frontmatter has no description", def.name))
		}
		sum := sha256.Sum256(raw)
		out = append(out, skill{
			def:         def,
			uri:         "skill://" + def.name + "/SKILL.md",
			body:        string(raw),
			digest:      "sha256:" + hex.EncodeToString(sum[:]),
			description: desc,
			frontmatter: fm,
		})
	}
	return out
}

// parseFrontmatter returns the YAML between the leading --- fence pair,
// decoded as the JSON-ready object SEP-2640 puts in each entry verbatim.
func parseFrontmatter(raw []byte) (map[string]any, error) {
	const fence = "---\n"
	s := string(raw)
	if !strings.HasPrefix(s, fence) {
		return nil, fmt.Errorf("SKILL.md does not start with YAML frontmatter")
	}
	rest := s[len(fence):]
	end := strings.Index(rest, "\n"+fence)
	if end < 0 {
		return nil, fmt.Errorf("unterminated YAML frontmatter")
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(rest[:end]), &fm); err != nil {
		return nil, fmt.Errorf("parse frontmatter: %w", err)
	}
	return fm, nil
}

func (sk skill) entry() skillEntry {
	return skillEntry{
		URI:         sk.uri,
		Frontmatter: sk.frontmatter,
		Resources:   []skillResourceEntry{{URI: sk.uri, Digest: sk.digest}},
	}
}

// registerSkills adds the skills whose gating the session satisfies, under
// the same rules as tools and prompts. The methods are registered even when
// nothing is granted: a server declaring the extension must answer
// skills/list, and an empty catalog is the answer, not method-not-found.
func registerSkills(s *mcp.Server, allowWrites bool, scopes Scopes) {
	var entries []skillEntry
	for _, sk := range skills {
		if sk.def.write && !allowWrites {
			continue
		}
		if !scopes.grants(sk.def.scopes...) {
			continue
		}
		entries = append(entries, sk.entry())
		body := sk.body
		s.AddResource(&mcp.Resource{
			URI:         sk.uri,
			Name:        sk.def.name,
			Description: sk.description,
			MIMEType:    "text/markdown",
		}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{
				{URI: req.Params.URI, MIMEType: "text/markdown", Text: body},
			}}, nil
		})
	}

	// The only registration error is shadowing a standard MCP method, which
	// these names cannot; a failure here is a programming error.
	if err := mcp.AddReceivingCustomMethod(s, "skills/list",
		func(context.Context, *mcp.ServerSession, *skillsListParams) (*skillsListResult, error) {
			return &skillsListResult{Skills: entries}, nil
		}); err != nil {
		panic(err)
	}
	if err := mcp.AddReceivingCustomMethod(s, "skills/get", skillsGetHandler(entries)); err != nil {
		panic(err)
	}
}

func skillsGetHandler(entries []skillEntry) func(context.Context, *mcp.ServerSession, *skillsGetParams) (*skillsGetResult, error) {
	return func(_ context.Context, _ *mcp.ServerSession, params *skillsGetParams) (*skillsGetResult, error) {
		// Custom methods tolerate absent params, so params can be nil here.
		if params == nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "missing required \"uri\""}
		}
		for _, e := range entries {
			if e.URI == params.URI {
				return &skillsGetResult{Skill: e}, nil
			}
		}
		// The code resources/read uses for unknown resources, per SEP-2640.
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: fmt.Sprintf("no skill at %q", params.URI)}
	}
}

package tools

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestBundledPluginSkillsMatchTheEmbeddedSources guards against drift between
// the skills this server serves and the copies bundled in the Claude plugin at
// plugins/skycloak. The plugin folder has to be self-contained because people
// who install it receive only that folder, so the files cannot be symlinks and
// an edit to one side is silently invisible to the other.
func TestBundledPluginSkillsMatchTheEmbeddedSources(t *testing.T) {
	for _, def := range skillDefs {
		want, err := skillFS.ReadFile("skills/" + def.name + "/SKILL.md")
		if err != nil {
			t.Fatalf("embedded skill %s: %v", def.name, err)
		}
		path := filepath.Join("..", "..", "plugins", "skycloak", "skills", def.name, "SKILL.md")
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v; copy internal/tools/skills/%s/SKILL.md there", path, err, def.name)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the embedded source; re-copy internal/tools/skills/%s/SKILL.md", path, def.name)
		}
	}
}

package platformclient

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The copy of the spec in this folder is the public one. A staff path in it
// would put an operation that is not for customers into a public repository
// and its generated client, so this fails the build rather than trusting the
// source to have removed them.
func TestSpecHasNoStaffPath(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Paths) == 0 {
		t.Fatal("the spec has no paths")
	}
	for p := range doc.Paths {
		if p == "/v1/staff" || strings.HasPrefix(p, "/v1/staff/") {
			t.Errorf("the public copy has a staff path: %s", p)
		}
	}
}

func TestSourceCommitIsAFullHash(t *testing.T) {
	raw, err := os.ReadFile("SOURCE_COMMIT")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}\n$`).Match(raw) {
		t.Errorf("SOURCE_COMMIT must hold one full commit hash, got %q", raw)
	}
}

// The spec's paths already start with /v1, so a client pointed at an address
// that also ends in /v1 would call /v1/v1.
func TestSpecServerHasNoVersionSuffix(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Servers []struct {
			URL string `yaml:"url"`
		} `yaml:"servers"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Servers) == 0 {
		t.Fatal("the spec names no server")
	}
	if strings.HasSuffix(strings.TrimRight(doc.Servers[0].URL, "/"), "/v1") {
		t.Errorf("server %q must not end in /v1; the paths carry it", doc.Servers[0].URL)
	}
}

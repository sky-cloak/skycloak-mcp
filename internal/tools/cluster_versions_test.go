package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// active=false means the version is still recognised, for a cluster already
// running it, but is no longer offered for new clusters or upgrades. Returning
// it indistinguishably from an offered version lets the tool recommend a
// version nobody should choose, which the upgrade-audit prompt does verbatim:
// "call skycloak_list_cluster_versions to learn the newest available version".

func TestClusterVersionsMarkWhichAreStillOffered(t *testing.T) {
	api := stubAPI{versionInfo: []skycloak.ClusterTypeVersion{
		{Version: "26.7.1", Active: true},
		{Version: "26.6.3", Active: false},
	}}

	res, out, err := listClusterVersionsHandler(api)(context.Background(), nil, ClusterTypeInput{Type: "keycloak"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out.Versions) != 2 {
		t.Fatalf("both versions must be returned, not silently filtered: %+v", out.Versions)
	}
	if !out.Versions[0].Active || out.Versions[1].Active {
		t.Fatalf("active state dropped: %+v", out.Versions)
	}
	text := renderedText(res)
	if !strings.Contains(text, "26.6.3") {
		t.Errorf("a recognised version must still be listed: %q", text)
	}
	if !strings.Contains(text, "no longer offered") {
		t.Errorf("an unofferred version must be marked as such, or it reads as a valid choice: %q", text)
	}
}

// The upgrade-risk fields answer "is this step safe", which is the question
// asked right after "what is available".
func TestClusterVersionsSurfaceUpgradeRisk(t *testing.T) {
	api := stubAPI{versionInfo: []skycloak.ClusterTypeVersion{
		{Version: "27.0.0", Active: true, IsMajorChange: true, BreakingChangeCount: 3},
	}}

	res, out, err := listClusterVersionsHandler(api)(context.Background(), nil, ClusterTypeInput{Type: "keycloak"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !out.Versions[0].IsMajorChange || out.Versions[0].BreakingChangeCount != 3 {
		t.Fatalf("upgrade risk dropped: %+v", out.Versions[0])
	}
	text := renderedText(res)
	for _, want := range []string{"major", "3"} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered text missing %q, so the risk is invisible to a model: %q", want, text)
		}
	}
}

// A version with nothing notable renders clean, so the annotations mean
// something when they do appear.
func TestClusterVersionsStayQuietWhenUnremarkable(t *testing.T) {
	api := stubAPI{versionInfo: []skycloak.ClusterTypeVersion{{Version: "26.7.1", Active: true}}}
	res, _, err := listClusterVersionsHandler(api)(context.Background(), nil, ClusterTypeInput{Type: "keycloak"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	text := renderedText(res)
	if strings.Contains(text, "major") || strings.Contains(text, "no longer offered") {
		t.Errorf("an ordinary version must render without warnings: %q", text)
	}
}

func TestClusterVersionsEmptyListIsArray(t *testing.T) {
	_, out, err := listClusterVersionsHandler(stubAPI{})(context.Background(), nil, ClusterTypeInput{Type: "keycloak"})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Versions == nil {
		t.Error("versions must marshal as [], not null")
	}
}

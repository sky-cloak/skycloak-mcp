package tools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestGetClusterFeaturesHandler(t *testing.T) {
	api := stubAPI{clusterFeatures: &skycloak.ClusterFeatures{
		Features: []string{"cimd", "token-exchange"},
		Change:   &skycloak.FeatureChange{State: "pending", NextWindow: "2026-12-01T03:00:00Z"},
	}}
	res, out, err := getClusterFeaturesHandler(api)(context.Background(), nil, GetClusterFeaturesInput{ClusterID: "c1"})
	if err != nil || res.IsError || len(out.Features) != 2 || out.Change == nil || out.Change.State != "pending" {
		t.Fatalf("get features: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	txt := resultText(res)
	if !strings.Contains(txt, "cimd, token-exchange") || !strings.Contains(txt, "pending") || !strings.Contains(txt, "2026-12-01T03:00:00Z") {
		t.Fatalf("text = %q", txt)
	}
}

func TestGetClusterFeaturesRequiresCluster(t *testing.T) {
	res, _, _ := getClusterFeaturesHandler(stubAPI{})(context.Background(), nil, GetClusterFeaturesInput{})
	if !res.IsError {
		t.Fatal("expected an error result for a missing cluster_id")
	}
}

func TestGetClusterFeaturesAPIError(t *testing.T) {
	res, _, _ := getClusterFeaturesHandler(stubAPI{err: errors.New("boom")})(context.Background(), nil, GetClusterFeaturesInput{ClusterID: "c1"})
	if !res.IsError {
		t.Fatal("expected an error result")
	}
}

func TestSetClusterFeaturesStatesRestartAndExperimental(t *testing.T) {
	api := stubAPI{
		features: []skycloak.ClusterFeatureInfo{
			{Name: "cimd", Experimental: true},
			{Name: "token-exchange"},
		},
		featuresUpdate: &skycloak.ClusterFeaturesUpdate{
			Features:         []string{"cimd", "token-exchange"},
			RestartsKeycloak: true,
			Change:           &skycloak.FeatureChange{State: "applying"},
			Impact:           "Sign-ins fail for about a minute.",
		},
	}
	res, out, err := setClusterFeaturesHandler(api)(context.Background(), nil,
		SetClusterFeaturesInput{ClusterID: "c1", Features: []string{"cimd", "token-exchange"}, ApplyNow: true, Confirm: true})
	if err != nil || res.IsError {
		t.Fatalf("set features: err=%v res=%+v", err, res)
	}
	if !out.RestartsKeycloak || len(out.ExperimentalFeatures) != 1 || out.ExperimentalFeatures[0] != "cimd" {
		t.Fatalf("out = %+v", out)
	}
	txt := resultText(res)
	for _, want := range []string{"Keycloak restarts", "applying", "Sign-ins fail", "Experimental in Keycloak", "between releases: cimd."} {
		if !strings.Contains(txt, want) {
			t.Errorf("text %q does not contain %q", txt, want)
		}
	}
}

func TestSetClusterFeaturesApplyNowNeedsConfirm(t *testing.T) {
	res, _, _ := setClusterFeaturesHandler(stubAPI{featuresUpdate: &skycloak.ClusterFeaturesUpdate{}})(context.Background(), nil,
		SetClusterFeaturesInput{ClusterID: "c1", Features: []string{"cimd"}, ApplyNow: true})
	if !res.IsError || !strings.Contains(resultText(res), "confirm=true") {
		t.Fatalf("res=%v text=%q", res.IsError, resultText(res))
	}
}

func TestSetClusterFeaturesNoneExperimental(t *testing.T) {
	api := stubAPI{
		features:       []skycloak.ClusterFeatureInfo{{Name: "token-exchange"}},
		featuresUpdate: &skycloak.ClusterFeaturesUpdate{Features: []string{"token-exchange"}, RestartsKeycloak: true},
	}
	res, _, _ := setClusterFeaturesHandler(api)(context.Background(), nil, SetClusterFeaturesInput{ClusterID: "c1", Features: []string{"token-exchange"}})
	if txt := resultText(res); !strings.Contains(txt, "None of the enabled flags is experimental") {
		t.Fatalf("text = %q", txt)
	}
}

func TestSetClusterFeaturesPending(t *testing.T) {
	api := stubAPI{featuresUpdate: &skycloak.ClusterFeaturesUpdate{
		Features: []string{"cimd"}, RestartsKeycloak: true,
		Change: &skycloak.FeatureChange{State: "pending", NextWindow: "2026-12-01T03:00:00Z"},
	}, features: []skycloak.ClusterFeatureInfo{{Name: "cimd", Experimental: true}}}
	res, _, _ := setClusterFeaturesHandler(api)(context.Background(), nil, SetClusterFeaturesInput{ClusterID: "c1", Features: []string{"cimd"}})
	txt := resultText(res)
	if !strings.Contains(txt, "Keycloak restarts") || !strings.Contains(txt, "pending until the maintenance window opens at 2026-12-01T03:00:00Z") {
		t.Fatalf("text = %q", txt)
	}
}

func TestSetClusterFeaturesNoRestart(t *testing.T) {
	api := stubAPI{featuresUpdate: &skycloak.ClusterFeaturesUpdate{Features: []string{}}}
	res, out, _ := setClusterFeaturesHandler(api)(context.Background(), nil, SetClusterFeaturesInput{ClusterID: "c1", Features: []string{}})
	if res.IsError || out.RestartsKeycloak || !strings.Contains(resultText(res), "does not restart") {
		t.Fatalf("res=%v text=%q out=%+v", res.IsError, resultText(res), out)
	}
}

func TestSetClusterFeaturesCatalogUnavailable(t *testing.T) {
	// The catalog read fails after the change went through; the result still
	// says Keycloak restarts and notes that some flags are experimental.
	api := catalogFailsAPI{stubAPI{featuresUpdate: &skycloak.ClusterFeaturesUpdate{Features: []string{"cimd"}, RestartsKeycloak: true}}}
	res, _, _ := setClusterFeaturesHandler(api)(context.Background(), nil, SetClusterFeaturesInput{ClusterID: "c1", Features: []string{"cimd"}})
	txt := resultText(res)
	if res.IsError || !strings.Contains(txt, "Keycloak restarts") || !strings.Contains(txt, "experimental") {
		t.Fatalf("res=%v text=%q", res.IsError, txt)
	}
}

type catalogFailsAPI struct{ stubAPI }

func (catalogFailsAPI) ListClusterFeatures(context.Context) ([]skycloak.ClusterFeatureInfo, error) {
	return nil, errors.New("catalog down")
}

func TestSetClusterFeaturesValidation(t *testing.T) {
	h := setClusterFeaturesHandler(stubAPI{})
	for name, in := range map[string]SetClusterFeaturesInput{
		"no cluster":  {Features: []string{}},
		"no features": {ClusterID: "c1"},
	} {
		if res, _, _ := h(context.Background(), nil, in); !res.IsError {
			t.Errorf("%s: expected an error result", name)
		}
	}
	res, _, _ := setClusterFeaturesHandler(stubAPI{err: errors.New("boom")})(context.Background(), nil, SetClusterFeaturesInput{ClusterID: "c1", Features: []string{}})
	if !res.IsError {
		t.Error("expected an error result when the API fails")
	}
}

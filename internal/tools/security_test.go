package tools

import (
	"context"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestGetClusterSecurityHandler(t *testing.T) {
	res, out, err := getClusterSecurityHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.WAF == nil || !out.WAF.Enabled {
		t.Fatalf("getClusterSecurity: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestUpdateClusterSecurityHandler(t *testing.T) {
	res, out, err := updateClusterSecurityHandler(stubAPI{})(context.Background(), nil, UpdateClusterSecurityInput{
		ClusterID:   "c1",
		WAF:         &skycloak.WAF{Enabled: true, Mode: "block", Preset: "owasp_top_10", ParanoiaLevel: 1},
		GeoBlocking: &skycloak.GeoBlocking{Enabled: true, Mode: "blocklist", Countries: []string{"KP"}},
	})
	if err != nil || res.IsError || out.WAF == nil || out.GeoBlocking == nil {
		t.Fatalf("updateClusterSecurity: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestUpdateClusterSecurityRequiresClusterID(t *testing.T) {
	res, _, err := updateClusterSecurityHandler(stubAPI{})(context.Background(), nil, UpdateClusterSecurityInput{})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result for missing cluster_id")
	}
}

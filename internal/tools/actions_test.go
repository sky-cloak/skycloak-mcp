package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestDiscoverOIDCHandler(t *testing.T) {
	res, out, err := discoverOIDCHandler(stubAPI{})(context.Background(), nil, DiscoverOIDCInput{IssuerURL: "https://idp"})
	if err != nil || res.IsError || out.TokenEndpoint == "" {
		t.Fatalf("discoverOIDC: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestDiscoverOIDCRequiresIssuer(t *testing.T) {
	res, _, err := discoverOIDCHandler(stubAPI{})(context.Background(), nil, DiscoverOIDCInput{})
	if err != nil || !res.IsError {
		t.Fatalf("expected error result for missing issuer_url")
	}
}

func TestTestSMTPHandler(t *testing.T) {
	res, out, err := testSMTPHandler(stubAPI{})(context.Background(), nil, TestSMTPInput{ClusterID: "c1", Realm: "app", Email: "a@b.com"})
	if err != nil || res.IsError || !out.Success {
		t.Fatalf("testSMTP: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestTestIdentityProviderHandler(t *testing.T) {
	res, out, err := testIdentityProviderHandler(stubAPI{})(context.Background(), nil, TestIDPInput{ClusterID: "c1", Realm: "app", ProviderID: "google"})
	if err != nil || res.IsError || !out.Success {
		t.Fatalf("testIdP: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCancelClusterUpgradeHandler(t *testing.T) {
	if res, _, _ := cancelClusterUpgradeHandler(stubAPI{})(context.Background(), nil, CancelUpgradeInput{ClusterID: "c1"}); !res.IsError {
		t.Fatalf("cancel should require confirm")
	}
	if res, _, err := cancelClusterUpgradeHandler(stubAPI{})(context.Background(), nil, CancelUpgradeInput{ClusterID: "c1", Confirm: true}); err != nil || res.IsError {
		t.Fatalf("cancel confirmed should succeed: res=%v err=%v", res.IsError, err)
	}
}

func TestRestartClusterInstancesHandlerRequiresConfirm(t *testing.T) {
	res, _, err := restartClusterInstancesHandler(stubAPI{})(context.Background(), nil, RestartClusterInstancesInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("restart should require confirm")
	}
}

func TestRestartClusterInstancesHandlerImmediate(t *testing.T) {
	api := stubAPI{restart: &skycloak.ClusterRestartOutcome{Impact: "brief interruption"}}
	res, out, err := restartClusterInstancesHandler(api)(context.Background(), nil, RestartClusterInstancesInput{ClusterID: "c1", Confirm: true})
	if err != nil || res.IsError {
		t.Fatalf("restart confirmed should succeed: res=%v err=%v", res.IsError, err)
	}
	if out.Deferred || out.Impact != "brief interruption" {
		t.Fatalf("unexpected outcome: %+v", out)
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; strings.Contains(txt, "deferred") {
		t.Errorf("an immediate restart must not claim to be deferred: %q", txt)
	}
}

func TestRestartClusterInstancesHandlerDeferred(t *testing.T) {
	api := stubAPI{restart: &skycloak.ClusterRestartOutcome{Deferred: true, NextWindow: "2026-09-20T02:00:00Z", Impact: "queued"}}
	res, out, err := restartClusterInstancesHandler(api)(context.Background(), nil, RestartClusterInstancesInput{ClusterID: "c1", Confirm: true})
	if err != nil || res.IsError {
		t.Fatalf("restart confirmed should succeed: res=%v err=%v", res.IsError, err)
	}
	if !out.Deferred {
		t.Fatalf("unexpected outcome: %+v", out)
	}
	txt := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(txt, "2026-09-20T02:00:00Z") {
		t.Errorf("deferred restart should report next_window, got %q", txt)
	}
}

// The restart-instances 409 carries a code the model should be able to act on
// (retry later vs. escalate), not just an opaque status.
func TestRestartClusterInstancesHandlerSurfacesConflictCode(t *testing.T) {
	api := stubAPI{err: &skycloak.APIError{StatusCode: 409, Problem: skycloak.Problem{Detail: "cluster is busy", Code: "cluster_busy"}}}
	res, _, err := restartClusterInstancesHandler(api)(context.Background(), nil, RestartClusterInstancesInput{ClusterID: "c1", Confirm: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error result")
	}
	txt := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(txt, "cluster_busy") || !strings.Contains(txt, "already in progress") {
		t.Errorf("conflict message should explain cluster_busy, got %q", txt)
	}
}

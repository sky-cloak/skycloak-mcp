package tools

import (
	"context"
	"testing"
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

package tools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestGetClusterPrivateLinkHandler(t *testing.T) {
	res, out, err := getClusterPrivateLinkHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || res.IsError {
		t.Fatalf("getClusterPrivateLink: err=%v res=%v", err, res)
	}
	if !out.Enabled || out.Alias != "pls.alias" || out.DNSName != "c1.private.example" || out.Status != "waiting" || len(out.AzureSubscriptionIDs) != 1 {
		t.Fatalf("unexpected private link: %+v", out)
	}
}

func TestGetClusterPrivateLinkRequiresClusterID(t *testing.T) {
	res, _, err := getClusterPrivateLinkHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{})
	if err != nil || !res.IsError {
		t.Fatalf("want a tool error, got err=%v res=%v", err, res)
	}
}

func TestUpdateClusterPrivateLinkHandler(t *testing.T) {
	ids := []string{"22222222-2222-2222-2222-222222222222"}
	res, out, err := updateClusterPrivateLinkHandler(stubAPI{})(context.Background(), nil, UpdateClusterPrivateLinkInput{ClusterID: "c1", AzureSubscriptionIDs: &ids})
	if err != nil || res.IsError {
		t.Fatalf("updateClusterPrivateLink: err=%v res=%v", err, res)
	}
	if len(out.AzureSubscriptionIDs) != 1 || out.AzureSubscriptionIDs[0] != ids[0] {
		t.Fatalf("returned list = %v, want %v", out.AzureSubscriptionIDs, ids)
	}
}

func TestUpdateClusterPrivateLinkNeedsSomethingToChange(t *testing.T) {
	res, _, err := updateClusterPrivateLinkHandler(stubAPI{})(context.Background(), nil, UpdateClusterPrivateLinkInput{ClusterID: "c1"})
	if err != nil || !res.IsError {
		t.Fatalf("want a tool error, got err=%v res=%v", err, res)
	}
	res, _, err = updateClusterPrivateLinkHandler(stubAPI{})(context.Background(), nil, UpdateClusterPrivateLinkInput{AzureSubscriptionIDs: &[]string{}})
	if err != nil || !res.IsError {
		t.Fatalf("missing cluster_id: want a tool error, got err=%v res=%v", err, res)
	}
}

func TestPrivateLinkErrorsKeepTheAPIStatusAndMessage(t *testing.T) {
	apiErr := &skycloak.APIError{StatusCode: 409}
	apiErr.Problem.Detail = "turn public access back on first"
	api := stubAPI{err: apiErr}
	res, _, _ := updateClusterPrivateLinkHandler(api)(context.Background(), nil, UpdateClusterPrivateLinkInput{ClusterID: "c1", Enabled: ptr(false)})
	if !res.IsError || !strings.Contains(resultText(res), "409") || !strings.Contains(resultText(res), "turn public access back on first") {
		t.Fatalf("refusal lost its status or message: %q", resultText(res))
	}
	res, _, _ = getClusterPrivateLinkHandler(stubAPI{err: errors.New("boom")})(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if !res.IsError {
		t.Fatal("read error should be a tool error")
	}
}

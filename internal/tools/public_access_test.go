package tools

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestGetClusterPublicAccessHandler(t *testing.T) {
	res, out, err := getClusterPublicAccessHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil || res.IsError {
		t.Fatalf("getClusterPublicAccess: err=%v res=%v", err, res)
	}
	if !out.Enabled {
		t.Fatalf("unexpected public access: %+v", out)
	}
}

func TestGetClusterPublicAccessRequiresClusterID(t *testing.T) {
	res, _, err := getClusterPublicAccessHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{})
	if err != nil || !res.IsError {
		t.Fatalf("want a tool error, got err=%v res=%v", err, res)
	}
}

func TestSetClusterPublicAccessOffNeedsConfirm(t *testing.T) {
	res, _, err := setClusterPublicAccessHandler(stubAPI{})(context.Background(), nil, SetClusterPublicAccessInput{ClusterID: "c1", Enabled: false})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "confirm=true") {
		t.Fatalf("want a refusal asking for confirm, got err=%v res=%v", err, res)
	}
}

func TestSetClusterPublicAccessOffConfirmed(t *testing.T) {
	res, out, err := setClusterPublicAccessHandler(stubAPI{})(context.Background(), nil, SetClusterPublicAccessInput{ClusterID: "c1", Enabled: false, Confirm: true})
	if err != nil || res.IsError {
		t.Fatalf("setClusterPublicAccess: err=%v res=%v", err, res)
	}
	if out.Enabled {
		t.Fatalf("public access still on: %+v", out)
	}
}

func TestSetClusterPublicAccessOnNeedsNoConfirm(t *testing.T) {
	res, out, err := setClusterPublicAccessHandler(stubAPI{})(context.Background(), nil, SetClusterPublicAccessInput{ClusterID: "c1", Enabled: true})
	if err != nil || res.IsError || !out.Enabled {
		t.Fatalf("err=%v res=%v out=%+v", err, res, out)
	}
}

func TestSetClusterPublicAccessRequiresClusterID(t *testing.T) {
	res, _, err := setClusterPublicAccessHandler(stubAPI{})(context.Background(), nil, SetClusterPublicAccessInput{Enabled: true})
	if err != nil || !res.IsError {
		t.Fatalf("want a tool error, got err=%v res=%v", err, res)
	}
}

// The API's refusals reach the caller with their status and message.
func TestPublicAccessRefusalsPassThrough(t *testing.T) {
	for _, status := range []int{403, 409, 422} {
		apiErr := &skycloak.APIError{StatusCode: status}
		apiErr.Problem.Detail = "refused by the API"
		api := stubAPI{err: apiErr}

		res, _, err := setClusterPublicAccessHandler(api)(context.Background(), nil, SetClusterPublicAccessInput{ClusterID: "c1", Enabled: false, Confirm: true})
		if err != nil || !res.IsError || !strings.Contains(resultText(res), "refused by the API") {
			t.Fatalf("status %d: err=%v res=%v", status, err, res)
		}
		if !strings.Contains(resultText(res), strconv.Itoa(status)) {
			t.Errorf("status %d missing from %q", status, resultText(res))
		}
	}
	res, _, _ := getClusterPublicAccessHandler(stubAPI{err: errors.New("boom")})(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if !res.IsError {
		t.Fatal("a read failure should be a tool error")
	}
}

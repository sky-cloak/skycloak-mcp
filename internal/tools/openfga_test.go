package tools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListOpenFGAInstancesHandler(t *testing.T) {
	api := stubAPI{fgaInstances: []skycloak.OpenFGAInstance{{ID: "f1", ClusterID: "c1", RealmName: "acme", Status: "ready"}}}
	res, out, err := listOpenFGAInstancesHandler(api)(context.Background(), nil, ListOpenFGAInstancesInput{})
	if err != nil || res.IsError || out.Count != 1 || out.Instances[0].RealmName != "acme" {
		t.Fatalf("list: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if !strings.Contains(resultText(res), "realm acme") {
		t.Errorf("text should name the realm: %q", resultText(res))
	}
}

func TestListOpenFGAInstancesEmpty(t *testing.T) {
	res, out, err := listOpenFGAInstancesHandler(stubAPI{})(context.Background(), nil, ListOpenFGAInstancesInput{})
	if err != nil || res.IsError || out.Count != 0 || !strings.Contains(resultText(res), "No OpenFGA instances") {
		t.Fatalf("empty list: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestGetOpenFGAInstanceHandler(t *testing.T) {
	res, out, err := getOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, OpenFGAInstanceRef{InstanceID: "f1"})
	if err != nil || res.IsError || out.APIURL == "" || out.Audience == "" {
		t.Fatalf("get: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	for _, want := range []string{"api_url:", "issuer:", "audience:"} {
		if !strings.Contains(resultText(res), want) {
			t.Errorf("text missing %q: %q", want, resultText(res))
		}
	}
}

func TestGetOpenFGAInstanceRequiresID(t *testing.T) {
	res, _, err := getOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, OpenFGAInstanceRef{})
	if err != nil || !res.IsError {
		t.Fatalf("expected an error result without instance_id")
	}
}

func TestCreateOpenFGAInstanceHandler(t *testing.T) {
	res, out, err := createOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, CreateOpenFGAInstanceInput{ClusterID: "c1", RealmName: "acme"})
	if err != nil || res.IsError || out.ID != "f1" || out.Status != "provisioning" || out.RealmName != "acme" {
		t.Fatalf("create: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateOpenFGAInstanceRequiresClusterAndRealm(t *testing.T) {
	for _, in := range []CreateOpenFGAInstanceInput{{ClusterID: "c1"}, {RealmName: "acme"}} {
		res, _, err := createOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, in)
		if err != nil || !res.IsError {
			t.Fatalf("expected an error result for %+v", in)
		}
	}
}

func TestCreateOpenFGAInstanceSurfacesForbidden(t *testing.T) {
	api := stubAPI{err: &skycloak.APIError{StatusCode: 403, Problem: skycloak.Problem{Title: "OpenFGA is not enabled for this workspace"}}}
	res, _, err := createOpenFGAInstanceHandler(api)(context.Background(), nil, CreateOpenFGAInstanceInput{ClusterID: "c1", RealmName: "acme"})
	if err != nil || !res.IsError {
		t.Fatalf("expected a tool error, got err=%v res=%+v", err, res)
	}
}

func TestDeleteOpenFGAInstanceRequiresConfirm(t *testing.T) {
	res, _, err := deleteOpenFGAInstanceHandler(stubAPI{err: errors.New("must not be called")})(context.Background(), nil, DeleteOpenFGAInstanceInput{InstanceID: "f1"})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "confirm=true") {
		t.Fatalf("expected a refusal naming confirm: err=%v res=%+v", err, res)
	}
}

func TestDeleteOpenFGAInstanceHandler(t *testing.T) {
	res, _, err := deleteOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, DeleteOpenFGAInstanceInput{InstanceID: "f1", Confirm: true})
	if err != nil || res.IsError {
		t.Fatalf("delete: err=%v res=%+v", err, res)
	}
	res, _, _ = deleteOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, DeleteOpenFGAInstanceInput{Confirm: true})
	if !res.IsError {
		t.Fatalf("expected an error result without instance_id")
	}
}

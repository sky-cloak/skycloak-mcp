package tools

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListOpenFGAInstancesHandler(t *testing.T) {
	api := stubAPI{fgaInstances: []skycloak.OpenFGAInstance{{ID: "f1", ClusterID: "c1", Realm: "acme", Status: "ready"}}}
	res, out, err := listOpenFGAInstancesHandler(api)(context.Background(), nil, ListOpenFGAInstancesInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.Count != 1 || out.Instances[0].Realm != "acme" {
		t.Fatalf("list: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	if !strings.Contains(resultText(res), "realm acme") {
		t.Errorf("text should name the realm: %q", resultText(res))
	}
}

func TestListOpenFGAInstancesEmpty(t *testing.T) {
	res, out, err := listOpenFGAInstancesHandler(stubAPI{})(context.Background(), nil, ListOpenFGAInstancesInput{ClusterID: "c1"})
	if err != nil || res.IsError || out.Count != 0 || !strings.Contains(resultText(res), "No OpenFGA instances") {
		t.Fatalf("empty list: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestListOpenFGAInstancesRequiresCluster(t *testing.T) {
	res, _, err := listOpenFGAInstancesHandler(stubAPI{})(context.Background(), nil, ListOpenFGAInstancesInput{})
	if err != nil || !res.IsError {
		t.Fatalf("expected an error result without cluster_id")
	}
}

func TestGetOpenFGAInstanceHandler(t *testing.T) {
	res, out, err := getOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, OpenFGAInstanceRef{ClusterID: "c1", InstanceID: "f1"})
	if err != nil || res.IsError || out.APIURL == "" || out.Audience == "" {
		t.Fatalf("get: err=%v res=%v out=%+v", err, res.IsError, out)
	}
	for _, want := range []string{"api_url:", "issuer:", "audience:"} {
		if !strings.Contains(resultText(res), want) {
			t.Errorf("text missing %q: %q", want, resultText(res))
		}
	}
}

func TestGetOpenFGAInstanceRequiresClusterAndID(t *testing.T) {
	for _, in := range []OpenFGAInstanceRef{{}, {ClusterID: "c1"}, {InstanceID: "f1"}} {
		res, _, err := getOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, in)
		if err != nil || !res.IsError {
			t.Fatalf("expected an error result for %+v", in)
		}
	}
}

func TestCreateOpenFGAInstanceHandler(t *testing.T) {
	res, out, err := createOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, CreateOpenFGAInstanceInput{ClusterID: "c1", Realm: "acme"})
	if err != nil || res.IsError || out.ID != "f1" || out.Status != "provisioning" || out.Realm != "acme" {
		t.Fatalf("create: err=%v res=%v out=%+v", err, res.IsError, out)
	}
}

func TestCreateOpenFGAInstanceRequiresClusterAndRealm(t *testing.T) {
	for _, in := range []CreateOpenFGAInstanceInput{{ClusterID: "c1"}, {Realm: "acme"}} {
		res, _, err := createOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, in)
		if err != nil || !res.IsError {
			t.Fatalf("expected an error result for %+v", in)
		}
	}
}

func TestCreateOpenFGAInstanceSurfacesAPIErrors(t *testing.T) {
	for _, code := range []int{403, 409, 422} {
		api := stubAPI{err: &skycloak.APIError{StatusCode: code, Problem: skycloak.Problem{Title: "refused"}}}
		res, _, err := createOpenFGAInstanceHandler(api)(context.Background(), nil, CreateOpenFGAInstanceInput{ClusterID: "c1", Realm: "acme"})
		if err != nil || !res.IsError {
			t.Fatalf("%d: expected a tool error, got err=%v res=%+v", code, err, res)
		}
	}
}

func TestDeleteOpenFGAInstanceRequiresConfirm(t *testing.T) {
	res, _, err := deleteOpenFGAInstanceHandler(stubAPI{err: errors.New("must not be called")})(context.Background(), nil, DeleteOpenFGAInstanceInput{ClusterID: "c1", InstanceID: "f1"})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "confirm=true") {
		t.Fatalf("expected a refusal naming confirm: err=%v res=%+v", err, res)
	}
}

func TestDeleteOpenFGAInstanceDeleting(t *testing.T) {
	api := stubAPI{fgaInstance: &skycloak.OpenFGAInstance{ID: "f1", Status: "deleting"}}
	res, _, err := deleteOpenFGAInstanceHandler(api)(context.Background(), nil, DeleteOpenFGAInstanceInput{ClusterID: "c1", InstanceID: "f1", Confirm: true})
	if err != nil || res.IsError || !strings.Contains(resultText(res), "status=deleting") {
		t.Fatalf("delete: err=%v res=%+v", err, res)
	}
}

func TestDeleteOpenFGAInstanceAlreadyGone(t *testing.T) {
	res, _, err := deleteOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, DeleteOpenFGAInstanceInput{ClusterID: "c1", InstanceID: "f1", Confirm: true})
	if err != nil || res.IsError || !strings.Contains(resultText(res), "already gone") {
		t.Fatalf("204 delete: err=%v res=%+v", err, res)
	}
}

func TestDeleteOpenFGAInstanceRequiresClusterAndID(t *testing.T) {
	for _, in := range []DeleteOpenFGAInstanceInput{{Confirm: true, ClusterID: "c1"}, {Confirm: true, InstanceID: "f1"}} {
		res, _, _ := deleteOpenFGAInstanceHandler(stubAPI{})(context.Background(), nil, in)
		if !res.IsError {
			t.Fatalf("expected an error result for %+v", in)
		}
	}
}

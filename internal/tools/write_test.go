package tools

import (
	"context"
	"testing"
)

func TestCreateClusterHandler(t *testing.T) {
	res, out, err := createClusterHandler(stubAPI{})(context.Background(), nil, CreateClusterInput{Name: "prod", Size: "small", Version: "26.1", Location: "eu"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Name != "prod" || out.Status != "provisioning" {
		t.Fatalf("unexpected result: err=%v out=%+v", res.IsError, out)
	}
}

func TestCreateClusterHandler_MissingArgs(t *testing.T) {
	res, _, err := createClusterHandler(stubAPI{})(context.Background(), nil, CreateClusterInput{Name: "prod"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError when required fields are missing")
	}
}

func TestDeleteClusterHandler_RequiresConfirmation(t *testing.T) {
	res, _, err := deleteClusterHandler(stubAPI{})(context.Background(), nil, DeleteClusterInput{ID: "c1", Confirm: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("delete without confirm must return IsError")
	}
}

func TestDeleteClusterHandler_Confirmed(t *testing.T) {
	res, _, err := deleteClusterHandler(stubAPI{})(context.Background(), nil, DeleteClusterInput{ID: "c1", Confirm: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("confirmed delete should succeed")
	}
}

func TestCreateRealmHandler(t *testing.T) {
	res, out, err := createRealmHandler(stubAPI{})(context.Background(), nil, CreateRealmInput{ClusterID: "c1", Name: "acme", DisplayName: "Acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError || out.Name != "acme" || !out.Enabled {
		t.Fatalf("unexpected result: err=%v out=%+v", res.IsError, out)
	}
}

func TestCreateRealmHandler_MissingArgs(t *testing.T) {
	res, _, err := createRealmHandler(stubAPI{})(context.Background(), nil, CreateRealmInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected IsError when name is empty")
	}
}

func TestDeleteRealmHandler_RequiresConfirmation(t *testing.T) {
	res, _, err := deleteRealmHandler(stubAPI{})(context.Background(), nil, DeleteRealmInput{ClusterID: "c1", Name: "acme", Confirm: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("delete without confirm must return IsError (guard against accidental deletion)")
	}
}

func TestDeleteRealmHandler_Confirmed(t *testing.T) {
	res, _, err := deleteRealmHandler(stubAPI{})(context.Background(), nil, DeleteRealmInput{ClusterID: "c1", Name: "acme", Confirm: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("confirmed delete should succeed, got error result")
	}
}

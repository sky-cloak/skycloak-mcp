package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCreateApplicationRoleRequiresTheEssentials(t *testing.T) {
	res, _, err := createClientRoleHandler(stubAPI{})(context.Background(), nil,
		CreateClientRoleInput{ClusterID: "c1", Realm: "app"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error without client_id and name")
	}
}

func TestCreateApplicationRoleForwardsDescription(t *testing.T) {
	_, out, err := createClientRoleHandler(stubAPI{})(context.Background(), nil,
		CreateClientRoleInput{ClusterID: "c1", Realm: "app", ClientID: "web", Name: "invoices-read", Description: "Read invoices"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Name != "invoices-read" || out.Description != "Read invoices" || out.ClientID != "web" {
		t.Fatalf("out = %+v", out)
	}
}

// An update naming neither field would send an empty patch and report success
// while changing nothing.
func TestUpdateApplicationRoleRefusesAnEmptyChange(t *testing.T) {
	res, _, err := updateClientRoleHandler(stubAPI{})(context.Background(), nil,
		UpdateClientRoleInput{ClusterID: "c1", Realm: "app", ClientID: "web", RoleName: "invoices-read"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected an error when neither new_name nor description is given")
	}
	if txt := res.Content[0].(*mcp.TextContent).Text; !strings.Contains(txt, "new_name") {
		t.Errorf("message does not say what to pass: %q", txt)
	}
}

func TestUpdateApplicationRoleKeepsTheNameWhenOnlyDescribing(t *testing.T) {
	_, out, err := updateClientRoleHandler(stubAPI{})(context.Background(), nil,
		UpdateClientRoleInput{ClusterID: "c1", Realm: "app", ClientID: "web", RoleName: "invoices-read", Description: "Read and export"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.Name != "invoices-read" {
		t.Fatalf("name = %q, want the role to keep its name", out.Name)
	}
}

// Deleting a role strips it from every user and group holding it, so it needs
// the same confirmation gate as the other destructive tools.
func TestDeleteApplicationRoleNeedsConfirmation(t *testing.T) {
	ref := ClientRoleRef{ClusterID: "c1", Realm: "app", ClientID: "web", RoleName: "invoices-read"}
	res, _, err := deleteClientRoleHandler(stubAPI{})(context.Background(), nil,
		ClientRoleDeleteInput{ClientRoleRef: ref})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatal("expected a refusal without confirm=true")
	}
	res, _, err = deleteClientRoleHandler(stubAPI{})(context.Background(), nil,
		ClientRoleDeleteInput{ClientRoleRef: ref, Confirm: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatal("confirm=true must proceed")
	}
}

// The write tools must not be registered on a read-only server.
func TestClientRoleWritesAreGatedOnAllowWrites(t *testing.T) {
	readOnly := map[string]bool{}
	for _, name := range registeredTools(t, false, nil) {
		readOnly[name] = true
	}
	for _, name := range []string{"skycloak_create_application_role", "skycloak_update_application_role", "skycloak_delete_application_role"} {
		if readOnly[name] {
			t.Errorf("%s is registered without --allow-writes", name)
		}
	}
	if !readOnly["skycloak_get_application_role"] {
		t.Error("skycloak_get_application_role is a read and should be registered")
	}
}

func TestGetApplicationRoleRequiresTheFullPath(t *testing.T) {
	for _, in := range []ClientRoleRef{
		{Realm: "app", ClientID: "web", RoleName: "r"},
		{ClusterID: "c1", ClientID: "web", RoleName: "r"},
		{ClusterID: "c1", Realm: "app", RoleName: "r"},
		{ClusterID: "c1", Realm: "app", ClientID: "web"},
	} {
		res, _, err := getClientRoleHandler(stubAPI{})(context.Background(), nil, in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.IsError {
			t.Errorf("expected an error for %+v: a role is only identified by all four", in)
		}
	}
}

func TestGetApplicationRoleReturnsTheRole(t *testing.T) {
	res, out, err := getClientRoleHandler(stubAPI{})(context.Background(), nil,
		ClientRoleRef{ClusterID: "c1", Realm: "app", ClientID: "web", RoleName: "invoices-read"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatal("expected success")
	}
	if out.Name != "invoices-read" || out.ClientID != "web" {
		t.Fatalf("out = %+v", out)
	}
	// The rendered line is what a reader sees, so it has to name both.
	txt := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(txt, "invoices-read") || !strings.Contains(txt, "web") {
		t.Errorf("text names neither the role nor its application: %q", txt)
	}
}

// A write-only key should still get the write tools: none of them read.
func TestClientRoleWritesDoNotRequireTheReadScope(t *testing.T) {
	names := map[string]bool{}
	for _, n := range registeredTools(t, true, Scopes{"client-roles:write": true}) {
		names[n] = true
	}
	for _, want := range []string{"skycloak_create_application_role", "skycloak_update_application_role", "skycloak_delete_application_role"} {
		if !names[want] {
			t.Errorf("%s is hidden from a key holding client-roles:write, though it never reads", want)
		}
	}
}

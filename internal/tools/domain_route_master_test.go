package tools

import (
	"strings"
	"testing"
)

// Routing a custom domain to master locks Skycloak out of the cluster, and
// skycloak_list_realms lists master like any other realm. The API refuses the
// route, but the guidance has to steer agents away from master before they try.

func TestCreateDomainRouteDescriptionExcludesMaster(t *testing.T) {
	cs := promptSession(t, true, nil)
	var desc string
	for tool, err := range cs.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		if tool.Name == "skycloak_create_domain_route" {
			desc = tool.Description
		}
	}
	if desc == "" {
		t.Fatal("skycloak_create_domain_route not registered or has no description")
	}
	if !strings.Contains(desc, "Never use the master realm") {
		t.Errorf("description does not warn against master: %q", desc)
	}
}

func TestSetUpCustomDomainPromptExcludesMaster(t *testing.T) {
	cs := promptSession(t, true, nil)
	for _, tc := range []struct {
		name string
		args map[string]string
	}{
		{"realm chosen from the list", map[string]string{"domain": "auth.example.com"}},
		{"realm named by the user", map[string]string{"domain": "auth.example.com", "realm": "app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := promptText(t, cs, "set_up_custom_domain", tc.args)
			for _, want := range []string{
				"Never use the master realm",
				"If master is the only realm on the cluster, ask the user to create or name an app realm",
			} {
				if !strings.Contains(text, want) {
					t.Errorf("prompt is missing %q:\n%s", want, text)
				}
			}
		})
	}
	text := promptText(t, cs, "set_up_custom_domain", map[string]string{"domain": "auth.example.com"})
	if !strings.Contains(text, "skycloak_list_realms to pick the realm and excluding master") {
		t.Errorf("realm choice from skycloak_list_realms does not exclude master:\n%s", text)
	}
}

package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func TestListDomainsHandler(t *testing.T) {
	api := stubAPI{domains: []skycloak.Domain{
		{ID: "d1", Domain: "auth.example.com", VerificationStatus: "verified", SSLStatus: "active", IsActive: true},
	}}

	res, out, err := listDomainsHandler(api)(context.Background(), nil, ListDomainsInput{ClusterID: "c1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error")
	}
	if out.Count != 1 || out.Domains[0].Domain != "auth.example.com" {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestListDomainsHandlerRequiresClusterID(t *testing.T) {
	res, _, err := listDomainsHandler(stubAPI{})(context.Background(), nil, ListDomainsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result for missing cluster_id")
	}
}

func TestGetDomainHandler(t *testing.T) {
	api := stubAPI{domain: &skycloak.Domain{
		ID: "d1", Domain: "auth.example.com", VerificationStatus: "pending", IsActive: false,
		DNSRecords: []skycloak.DNSRecord{{Type: "CNAME", Name: "auth.example.com", Value: "ingress.skycloak.io"}},
	}}

	res, out, err := getDomainHandler(api)(context.Background(), nil, DomainRef{ClusterID: "c1", DomainID: "d1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error")
	}
	if out.ID != "d1" {
		t.Fatalf("unexpected output: %+v", out)
	}
	txt := res.Content[0].(*mcp.TextContent).Text
	if !strings.Contains(txt, "CNAME") {
		t.Fatalf("expected DNS records in text, got: %s", txt)
	}
}

func TestCreateDomainHandler(t *testing.T) {
	res, out, err := createDomainHandler(stubAPI{})(context.Background(), nil, CreateDomainInput{ClusterID: "c1", Domain: "auth.example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error")
	}
	if out.Domain != "auth.example.com" {
		t.Fatalf("unexpected output: %+v", out)
	}
}

func TestDeleteDomainHandlerRequiresConfirm(t *testing.T) {
	res, _, err := deleteDomainHandler(stubAPI{})(context.Background(), nil, DeleteDomainInput{ClusterID: "c1", DomainID: "d1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.IsError {
		t.Fatalf("expected error result without confirm")
	}
}

func TestDeleteDomainHandlerConfirmed(t *testing.T) {
	res, _, err := deleteDomainHandler(stubAPI{})(context.Background(), nil, DeleteDomainInput{ClusterID: "c1", DomainID: "d1", Confirm: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected tool error")
	}
}

package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerDomainReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_domains",
		Description: "List the custom domains configured on a cluster.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "List domains"},
	}, listDomainsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_domain",
		Description: "Get a custom domain by ID, including its DNS records and verification/SSL status.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get domain"},
	}, getDomainHandler(api))
}

func registerDomainWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_create_domain",
		Description: "Add a custom domain to a cluster. Returns the DNS records the customer must create to verify and route the domain.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create domain"},
	}, createDomainHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_verify_domain",
		Description: "Trigger DNS verification for a custom domain and return its updated status.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Verify domain"},
	}, verifyDomainHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_delete_domain",
		Description: "Remove a custom domain from a cluster. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete domain"},
	}, deleteDomainHandler(api))
}

// DomainRef identifies a domain.
type DomainRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID  string `json:"domain_id" jsonschema:"the domain ID"`
}

// ListDomainsInput is the input for skycloak_list_domains.
type ListDomainsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
}

// DomainsOutput is the structured result of a domain list.
type DomainsOutput struct {
	Domains []skycloak.Domain `json:"domains"`
	Count   int               `json:"count"`
}

func listDomainsHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, DomainsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, DomainsOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), DomainsOutput{}, nil
		}
		domains, err := api.ListDomains(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), DomainsOutput{}, nil
		}
		var b strings.Builder
		for _, d := range domains {
			fmt.Fprintf(&b, "- %s (%s) — verification=%s ssl=%s active=%t\n", d.Domain, d.ID, d.VerificationStatus, d.SSLStatus, d.IsActive)
		}
		if len(domains) == 0 {
			b.WriteString("No custom domains on this cluster.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, DomainsOutput{Domains: domains, Count: len(domains)}, nil
	}
}

func getDomainHandler(api API) mcp.ToolHandlerFor[DomainRef, skycloak.Domain] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DomainRef) (*mcp.CallToolResult, skycloak.Domain, error) {
		if in.ClusterID == "" || in.DomainID == "" {
			return errResult("cluster_id and domain_id are required"), skycloak.Domain{}, nil
		}
		d, err := api.GetDomain(ctx, in.ClusterID, in.DomainID)
		if err != nil {
			return toolError(err), skycloak.Domain{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: domainText(d)}}}, *d, nil
	}
}

// CreateDomainInput is the input for skycloak_create_domain.
type CreateDomainInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Domain    string `json:"domain" jsonschema:"the fully-qualified domain name"`
	Subdomain string `json:"subdomain,omitempty" jsonschema:"optional subdomain"`
}

func createDomainHandler(api API) mcp.ToolHandlerFor[CreateDomainInput, skycloak.Domain] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateDomainInput) (*mcp.CallToolResult, skycloak.Domain, error) {
		if in.ClusterID == "" || in.Domain == "" {
			return errResult("cluster_id and domain are required"), skycloak.Domain{}, nil
		}
		d, err := api.CreateDomain(ctx, in.ClusterID, in.Domain, in.Subdomain)
		if err != nil {
			return toolError(err), skycloak.Domain{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Created domain. " + domainText(d)}}}, *d, nil
	}
}

func verifyDomainHandler(api API) mcp.ToolHandlerFor[DomainRef, skycloak.Domain] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DomainRef) (*mcp.CallToolResult, skycloak.Domain, error) {
		if in.ClusterID == "" || in.DomainID == "" {
			return errResult("cluster_id and domain_id are required"), skycloak.Domain{}, nil
		}
		d, err := api.VerifyDomain(ctx, in.ClusterID, in.DomainID)
		if err != nil {
			return toolError(err), skycloak.Domain{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: domainText(d)}}}, *d, nil
	}
}

// DeleteDomainInput is the input for skycloak_delete_domain.
type DeleteDomainInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID  string `json:"domain_id" jsonschema:"the domain ID to delete"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm deletion"`
}

func deleteDomainHandler(api API) mcp.ToolHandlerFor[DeleteDomainInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteDomainInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.DomainID == "" {
			return errResult("cluster_id and domain_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete domain %s: set confirm=true.", in.DomainID)), struct{}{}, nil
		}
		if err := api.DeleteDomain(ctx, in.ClusterID, in.DomainID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleted domain %s.", in.DomainID)}}}, struct{}{}, nil
	}
}

func domainText(d *skycloak.Domain) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s) — verification=%s, ssl=%s, active=%t\n", d.Domain, d.ID, d.VerificationStatus, d.SSLStatus, d.IsActive)
	if len(d.DNSRecords) > 0 {
		b.WriteString("DNS records to create:\n")
		for _, r := range d.DNSRecords {
			fmt.Fprintf(&b, "  %s %s -> %s\n", r.Type, r.Name, r.Value)
		}
	}
	return b.String()
}

func errResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
}

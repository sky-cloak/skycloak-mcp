package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerDomainReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_list_domains",
		Description: "List the custom domains attached to one cluster, each with its domain_id, hostname, verification status, SSL status and active flag. " +
			"Needs cluster_id from skycloak_list_clusters, and it is where domain_id comes from. Not the realm routes on a domain; use skycloak_list_domain_routes for those.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List domains"},
	}, listDomainsHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_domain",
		Description: "Get one custom domain of a cluster by domain_id, with the DNS records to create and its verification and SSL status. " +
			"Needs cluster_id and domain_id from skycloak_list_domains. For the realms served on it, use skycloak_list_domain_routes.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get domain"},
	}, getDomainHandler(api))
}

func registerDomainWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_create_domain",
		Description: "Attach a custom domain to a cluster and return its new domain_id with the DNS records the customer must create. " +
			"The domain serves nothing yet: the records have to exist, skycloak_verify_domain has to pass, and a realm has to be routed onto it with skycloak_create_domain_route.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create domain"},
	}, createDomainHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_verify_domain",
		Description: "Run a DNS check against one custom domain and return its updated verification and SSL status. " +
			"Safe to repeat: when the records are not in place it only reports that the domain is still unverified. Needs domain_id from skycloak_list_domains; skycloak_get_domain reads the status without rechecking.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Verify domain"},
	}, verifyDomainHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_delete_domain",
		Description: "Remove one custom domain from a cluster, so the hostname stops serving Keycloak along with every realm route on it. " +
			"Set confirm=true to proceed. To drop a single realm from the domain instead, use skycloak_delete_domain_route.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete domain"},
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

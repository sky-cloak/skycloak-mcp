package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerSecurityReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_security",
		Description: "Get a cluster's edge-security configuration: IP allow-listing, rate limiting, WAF, geo-blocking, and bot management.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster security"},
	}, getClusterSecurityHandler(api))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_cluster_captcha_domains",
		Description: "List hostnames registered for CAPTCHA protection on a cluster.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List CAPTCHA domains"},
	}, listClusterCAPTCHADomainsHandler(api))
}

func registerSecurityWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_update_cluster_security",
		Description: "Update a cluster's edge-security configuration. Only the sections you provide are changed; CAPTCHA settings are preserved. Supports IP allow-listing, rate limiting, WAF, geo-blocking, and bot management.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Update cluster security"},
	}, updateClusterSecurityHandler(api))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_add_cluster_captcha_domain",
		Description: "Register a hostname for CAPTCHA protection on a cluster.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Add CAPTCHA domain"},
	}, addClusterCAPTCHADomainHandler(api))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_remove_cluster_captcha_domain",
		Description: "Remove a hostname from CAPTCHA protection on a cluster. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Remove CAPTCHA domain"},
	}, removeClusterCAPTCHADomainHandler(api))
}

func getClusterSecurityHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, skycloak.ClusterSecurity] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, skycloak.ClusterSecurity, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.ClusterSecurity{}, nil
		}
		sec, err := api.GetClusterSecurity(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.ClusterSecurity{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: securityText(sec)}}}, *sec, nil
	}
}

// UpdateClusterSecurityInput is the input for skycloak_update_cluster_security.
type UpdateClusterSecurityInput struct {
	ClusterID       string                    `json:"cluster_id" jsonschema:"the cluster ID"`
	IPAccessControl *skycloak.IPAccessControl `json:"ip_access_control,omitempty" jsonschema:"per-path IP allow rules"`
	RateLimiting    *skycloak.RateLimiting    `json:"rate_limiting,omitempty" jsonschema:"request-rate ceilings"`
	WAF             *skycloak.WAF             `json:"waf,omitempty" jsonschema:"web application firewall settings"`
	GeoBlocking     *skycloak.GeoBlocking     `json:"geo_blocking,omitempty" jsonschema:"country-based access control"`
	BotManagement   *skycloak.BotManagement   `json:"bot_management,omitempty" jsonschema:"bot detection and challenge settings"`
}

func updateClusterSecurityHandler(api API) mcp.ToolHandlerFor[UpdateClusterSecurityInput, skycloak.ClusterSecurity] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in UpdateClusterSecurityInput) (*mcp.CallToolResult, skycloak.ClusterSecurity, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.ClusterSecurity{}, nil
		}
		sec := &skycloak.ClusterSecurity{
			IPAccessControl: in.IPAccessControl, RateLimiting: in.RateLimiting, WAF: in.WAF,
			GeoBlocking: in.GeoBlocking, BotManagement: in.BotManagement,
		}
		normaliseClusterSecurity(sec)
		updated, err := api.UpdateClusterSecurity(ctx, in.ClusterID, sec)
		if err != nil {
			return toolError(err), skycloak.ClusterSecurity{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated cluster security. " + securityText(updated)}}}, *updated, nil
	}
}

// CAPTCHADomainsOutput is the structured list result for CAPTCHA domains.
type CAPTCHADomainsOutput struct {
	Domains    []skycloak.CAPTCHADomain `json:"domains"`
	MaxAllowed int                      `json:"max_allowed"`
	Count      int                      `json:"count"`
}

func listClusterCAPTCHADomainsHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, CAPTCHADomainsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, CAPTCHADomainsOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), CAPTCHADomainsOutput{}, nil
		}
		info, err := api.ListClusterCAPTCHADomains(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), CAPTCHADomainsOutput{}, nil
		}
		var b strings.Builder
		for _, d := range info.Domains {
			fmt.Fprintf(&b, "- %s (created %s)\n", d.Hostname, d.CreatedAt)
		}
		if len(info.Domains) == 0 {
			b.WriteString("No CAPTCHA domains configured.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, CAPTCHADomainsOutput{Domains: info.Domains, MaxAllowed: info.MaxAllowed, Count: len(info.Domains)}, nil
	}
}

// CAPTCHADomainInput identifies a CAPTCHA domain on a cluster.
type CAPTCHADomainInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Hostname  string `json:"hostname" jsonschema:"the hostname to register for CAPTCHA protection"`
}

func addClusterCAPTCHADomainHandler(api API) mcp.ToolHandlerFor[CAPTCHADomainInput, skycloak.CAPTCHADomain] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CAPTCHADomainInput) (*mcp.CallToolResult, skycloak.CAPTCHADomain, error) {
		if in.ClusterID == "" || in.Hostname == "" {
			return errResult("cluster_id and hostname are required"), skycloak.CAPTCHADomain{}, nil
		}
		domain, err := api.AddClusterCAPTCHADomain(ctx, in.ClusterID, in.Hostname)
		if err != nil {
			return toolError(err), skycloak.CAPTCHADomain{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Added CAPTCHA domain %s.", domain.Hostname)}}}, *domain, nil
	}
}

// RemoveCAPTCHADomainInput confirms removal of a CAPTCHA domain.
type RemoveCAPTCHADomainInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Hostname  string `json:"hostname" jsonschema:"the hostname to remove"`
	Confirm   bool   `json:"confirm" jsonschema:"must be true to confirm removal"`
}

func removeClusterCAPTCHADomainHandler(api API) mcp.ToolHandlerFor[RemoveCAPTCHADomainInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RemoveCAPTCHADomainInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.Hostname == "" {
			return errResult("cluster_id and hostname are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to remove CAPTCHA domain %s: set confirm=true.", in.Hostname)), struct{}{}, nil
		}
		if err := api.RemoveClusterCAPTCHADomain(ctx, in.ClusterID, in.Hostname); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Removed CAPTCHA domain %s.", in.Hostname)}}}, struct{}{}, nil
	}
}

func securityText(s *skycloak.ClusterSecurity) string {
	var on []string
	if s.IPAccessControl != nil {
		on = append(on, fmt.Sprintf("ip_access_control(%d rules)", len(s.IPAccessControl.PathRules)))
	}
	if s.RateLimiting != nil {
		on = append(on, fmt.Sprintf("rate_limiting(enabled=%t)", s.RateLimiting.Enabled))
	}
	if s.WAF != nil {
		on = append(on, fmt.Sprintf("waf(enabled=%t mode=%s preset=%s)", s.WAF.Enabled, s.WAF.Mode, s.WAF.Preset))
	}
	if s.GeoBlocking != nil {
		on = append(on, fmt.Sprintf("geo_blocking(enabled=%t mode=%s)", s.GeoBlocking.Enabled, s.GeoBlocking.Mode))
	}
	if s.BotManagement != nil {
		on = append(on, fmt.Sprintf("bot_management(enabled=%t)", s.BotManagement.Enabled))
	}
	if len(on) == 0 {
		return "No managed security sections configured."
	}
	return strings.Join(on, ", ")
}

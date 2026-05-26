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
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, Title: "Get cluster security"},
	}, getClusterSecurityHandler(api))
}

func registerSecurityWriteTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_update_cluster_security",
		Description: "Update a cluster's edge-security configuration. Only the sections you provide are changed; CAPTCHA settings are preserved. Supports IP allow-listing, rate limiting, WAF, geo-blocking, and bot management.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: ptr(false), IdempotentHint: true, Title: "Update cluster security"},
	}, updateClusterSecurityHandler(api))
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
		updated, err := api.UpdateClusterSecurity(ctx, in.ClusterID, sec)
		if err != nil {
			return toolError(err), skycloak.ClusterSecurity{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Updated cluster security. " + securityText(updated)}}}, *updated, nil
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

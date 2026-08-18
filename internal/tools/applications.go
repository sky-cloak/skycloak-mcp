package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListApplicationsInput is the input schema for skycloak_list_applications.
type ListApplicationsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the ID of the cluster"`
	Realm     string `json:"realm" jsonschema:"the realm name whose applications to list"`
}

// ApplicationSummary is one row of the list output.
type ApplicationSummary struct {
	ClientID string `json:"client_id"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Status   string `json:"status,omitempty"`
}

// ListApplicationsOutput is the structured result.
type ListApplicationsOutput struct {
	Applications []ApplicationSummary `json:"applications"`
	Count        int                  `json:"count"`
}

func registerApplicationReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_applications",
		Description: "List the OIDC/SAML clients (applications) in a realm.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List applications"},
	}, listApplicationsHandler(api))
}

func listApplicationsHandler(api API) mcp.ToolHandlerFor[ListApplicationsInput, ListApplicationsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListApplicationsInput) (*mcp.CallToolResult, ListApplicationsOutput, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id and realm are required"}}}, ListApplicationsOutput{}, nil
		}
		apps, err := api.ListApplications(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), ListApplicationsOutput{}, nil
		}
		out := ListApplicationsOutput{Count: len(apps)}
		var b strings.Builder
		for _, a := range apps {
			out.Applications = append(out.Applications, ApplicationSummary{ClientID: a.ClientID, Name: a.Name, Type: a.Type, Protocol: a.Protocol, Status: a.Status})
			fmt.Fprintf(&b, "- %s (%s) — %s · %s\n", a.ClientID, a.Name, a.Type, a.Protocol)
		}
		if len(apps) == 0 {
			b.WriteString("No applications found in this realm.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
	}
}

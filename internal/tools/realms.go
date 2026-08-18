package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListRealmsInput is the input schema for skycloak_list_realms.
type ListRealmsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the ID of the cluster whose realms to list"`
}

// RealmSummary is one row of the list output.
type RealmSummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`
}

// ListRealmsOutput is the structured result of skycloak_list_realms.
type ListRealmsOutput struct {
	Realms []RealmSummary `json:"realms"`
	Count  int            `json:"count"`
}

func registerRealmReadTools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_realms",
		Description: "List the Keycloak realms in a Skycloak cluster.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realms"},
	}, listRealmsHandler(api))
}

func listRealmsHandler(api API) mcp.ToolHandlerFor[ListRealmsInput, ListRealmsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListRealmsInput) (*mcp.CallToolResult, ListRealmsOutput, error) {
		if in.ClusterID == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "cluster_id is required"}}}, ListRealmsOutput{}, nil
		}
		realms, err := api.ListRealms(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), ListRealmsOutput{}, nil
		}

		out := ListRealmsOutput{Count: len(realms)}
		var b strings.Builder
		for _, r := range realms {
			out.Realms = append(out.Realms, RealmSummary{Name: r.Name, DisplayName: r.DisplayName, Enabled: r.Enabled})
			fmt.Fprintf(&b, "- %s (%s) — enabled=%t\n", r.Name, r.DisplayName, r.Enabled)
		}
		if len(realms) == 0 {
			b.WriteString("No realms found in this cluster.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
	}
}

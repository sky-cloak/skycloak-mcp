package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// ListClustersInput is the input schema for skycloak_list_clusters.
type ListClustersInput struct {
	Limit  int `json:"limit,omitempty" jsonschema:"maximum number of clusters to return. Omit to return every cluster in the workspace"`
	Offset int `json:"offset,omitempty" jsonschema:"number of clusters to skip before returning, for paging with limit"`
}

// ClusterSummary is one row of the list output.
type ClusterSummary struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Status             string `json:"status"`
	Type               string `json:"type"`
	Size               string `json:"size"`
	Version            string `json:"version"`
	Location           string `json:"location"`
	AutoUpgradeEnabled bool   `json:"auto_upgrade_enabled"`
}

// ListClustersOutput is the structured result of skycloak_list_clusters.
type ListClustersOutput struct {
	Clusters []ClusterSummary `json:"clusters"`
	Count    int              `json:"count"`
}

// ClusterDetail is the structured result of skycloak_get_cluster.
type ClusterDetail struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Status             string `json:"status"`
	Type               string `json:"type"`
	Size               string `json:"size"`
	Version            string `json:"version"`
	Location           string `json:"location"`
	URL                string `json:"url,omitempty"`
	CreatedAt          string `json:"created_at,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
	AutoUpgradeEnabled bool   `json:"auto_upgrade_enabled"`
}

// GetClusterInput is the input schema for skycloak_get_cluster.
type GetClusterInput struct {
	ID string `json:"id" jsonschema:"the cluster ID (UUID)"`
}

func registerClusterReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_clusters",
		Description: "List the Keycloak clusters in your Skycloak workspace, with their status, type, size, version and location.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List clusters"},
	}, listClustersHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster",
		Description: "Get full details for a single Keycloak cluster by its ID.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster"},
	}, getClusterHandler(api))
}

func getClusterHandler(api API) mcp.ToolHandlerFor[GetClusterInput, ClusterDetail] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GetClusterInput) (*mcp.CallToolResult, ClusterDetail, error) {
		if in.ID == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "id is required"}}}, ClusterDetail{}, nil
		}
		c, err := api.GetCluster(ctx, in.ID)
		if err != nil {
			return toolError(err), ClusterDetail{}, nil
		}
		detail := ClusterDetail{
			ID: c.ID, Name: c.Name, Status: c.Status, Type: c.Type, Size: c.Size,
			Version: c.Version, Location: c.Location, URL: c.URL,
			CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, AutoUpgradeEnabled: c.AutoUpgradeEnabled,
		}
		text := fmt.Sprintf("%s (%s)\n  status: %s\n  type/size: %s/%s\n  version: %s\n  location: %s\n  url: %s",
			c.Name, c.ID, c.Status, c.Type, c.Size, c.Version, c.Location, c.URL)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, detail, nil
	}
}

func listClustersHandler(api API) mcp.ToolHandlerFor[ListClustersInput, ListClustersOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListClustersInput) (*mcp.CallToolResult, ListClustersOutput, error) {
		clusters, err := api.ListClusters(ctx, skycloak.ListClustersParams{Limit: in.Limit, Offset: in.Offset})
		if err != nil {
			return toolError(err), ListClustersOutput{}, nil
		}

		out := ListClustersOutput{Count: len(clusters), Clusters: []ClusterSummary{}}
		var b strings.Builder
		for _, c := range clusters {
			out.Clusters = append(out.Clusters, ClusterSummary{
				ID: c.ID, Name: c.Name, Status: c.Status, Type: c.Type,
				Size: c.Size, Version: c.Version, Location: c.Location,
				AutoUpgradeEnabled: c.AutoUpgradeEnabled,
			})
			fmt.Fprintf(&b, "- %s (%s) — %s · %s/%s · v%s @ %s\n",
				c.Name, c.ID, c.Status, c.Type, c.Size, c.Version, c.Location)
		}
		if len(clusters) == 0 {
			if in.Offset > 0 {
				fmt.Fprintf(&b, "No clusters at offset %d.", in.Offset)
			} else {
				b.WriteString("No clusters found in this workspace.")
			}
		}
		// A windowed call returns a partial view, and nothing in the payload
		// says so. Left unsaid, a caller reads its page as the whole workspace,
		// which for a fleet question is the dangerous direction to be wrong in.
		if in.Limit > 0 || in.Offset > 0 {
			fmt.Fprintf(&b, "\nShowing a window of the workspace (offset %d, limit %d); omit both to list every cluster.", in.Offset, in.Limit)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
	}
}

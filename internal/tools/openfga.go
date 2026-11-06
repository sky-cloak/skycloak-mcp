package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerOpenFGAReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_openfga_instances",
		Description: "List the workspace's OpenFGA instances. Each is bound to one realm of one cluster and reports its status (provisioning, ready, failed or deleting).",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List OpenFGA instances"},
	}, listOpenFGAInstancesHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_openfga_instance",
		Description: "Get an OpenFGA instance by ID, including its status and the API URL, token issuer and audience to call it with.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get OpenFGA instance"},
	}, getOpenFGAInstanceHandler(api))
}

func registerOpenFGAWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_create_openfga_instance",
		Description: "Create a dedicated OpenFGA instance bound to one realm of a cluster; a realm has at most one. Asynchronous: poll skycloak_get_openfga_instance until the status is 'ready'. The instance accepts only tokens from that realm that carry the instance's audience. Fails with 403 when the workspace has no access to OpenFGA.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create OpenFGA instance"},
	}, createOpenFGAInstanceHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_delete_openfga_instance",
		Description: "Permanently delete an OpenFGA instance with its deployment, route and database. The authorization data in it cannot be recovered. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete OpenFGA instance"},
	}, deleteOpenFGAInstanceHandler(api))
}

// OpenFGAInstancesOutput is the structured result of an OpenFGA instance list.
type OpenFGAInstancesOutput struct {
	Instances []skycloak.OpenFGAInstance `json:"instances"`
	Count     int                        `json:"count"`
}

// ListOpenFGAInstancesInput is the (empty) input for skycloak_list_openfga_instances.
type ListOpenFGAInstancesInput struct{}

func listOpenFGAInstancesHandler(api API) mcp.ToolHandlerFor[ListOpenFGAInstancesInput, OpenFGAInstancesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ ListOpenFGAInstancesInput) (*mcp.CallToolResult, OpenFGAInstancesOutput, error) {
		instances, err := api.ListOpenFGAInstances(ctx)
		if err != nil {
			return toolError(err), OpenFGAInstancesOutput{}, nil
		}
		var b strings.Builder
		for _, i := range instances {
			fmt.Fprintf(&b, "- %s (cluster %s, realm %s) status=%s\n", i.ID, i.ClusterID, i.RealmName, i.Status)
		}
		if len(instances) == 0 {
			b.WriteString("No OpenFGA instances in this workspace.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, OpenFGAInstancesOutput{Instances: instances, Count: len(instances)}, nil
	}
}

// OpenFGAInstanceRef identifies an OpenFGA instance.
type OpenFGAInstanceRef struct {
	InstanceID string `json:"instance_id" jsonschema:"the OpenFGA instance ID"`
}

func getOpenFGAInstanceHandler(api API) mcp.ToolHandlerFor[OpenFGAInstanceRef, skycloak.OpenFGAInstance] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in OpenFGAInstanceRef) (*mcp.CallToolResult, skycloak.OpenFGAInstance, error) {
		if in.InstanceID == "" {
			return errResult("instance_id is required"), skycloak.OpenFGAInstance{}, nil
		}
		i, err := api.GetOpenFGAInstance(ctx, in.InstanceID)
		if err != nil {
			return toolError(err), skycloak.OpenFGAInstance{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: openFGAInstanceText(i)}}}, *i, nil
	}
}

// CreateOpenFGAInstanceInput is the input for skycloak_create_openfga_instance.
type CreateOpenFGAInstanceInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster that holds the realm"`
	RealmName string `json:"realm_name" jsonschema:"the realm to bind the instance to; it accepts only tokens from this realm"`
}

func createOpenFGAInstanceHandler(api API) mcp.ToolHandlerFor[CreateOpenFGAInstanceInput, skycloak.OpenFGAInstance] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateOpenFGAInstanceInput) (*mcp.CallToolResult, skycloak.OpenFGAInstance, error) {
		if in.ClusterID == "" || in.RealmName == "" {
			return errResult("cluster_id and realm_name are required"), skycloak.OpenFGAInstance{}, nil
		}
		i, err := api.CreateOpenFGAInstance(ctx, in.ClusterID, in.RealmName)
		if err != nil {
			return toolError(err), skycloak.OpenFGAInstance{}, nil
		}
		txt := fmt.Sprintf("Started OpenFGA instance %s (status=%s). Poll skycloak_get_openfga_instance until it is ready.\n%s", i.ID, i.Status, openFGAInstanceText(i))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *i, nil
	}
}

// DeleteOpenFGAInstanceInput is the input for skycloak_delete_openfga_instance.
type DeleteOpenFGAInstanceInput struct {
	InstanceID string `json:"instance_id" jsonschema:"the OpenFGA instance ID to delete"`
	Confirm    bool   `json:"confirm" jsonschema:"must be true to confirm permanent, irreversible deletion of the instance and its authorization data"`
}

func deleteOpenFGAInstanceHandler(api API) mcp.ToolHandlerFor[DeleteOpenFGAInstanceInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteOpenFGAInstanceInput) (*mcp.CallToolResult, struct{}, error) {
		if in.InstanceID == "" {
			return errResult("instance_id is required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete OpenFGA instance %s: set confirm=true. This is irreversible.", in.InstanceID)), struct{}{}, nil
		}
		if err := api.DeleteOpenFGAInstance(ctx, in.InstanceID); err != nil {
			return toolError(err), struct{}{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Deleting OpenFGA instance %s.", in.InstanceID)}}}, struct{}{}, nil
	}
}

func openFGAInstanceText(i *skycloak.OpenFGAInstance) string {
	s := fmt.Sprintf("OpenFGA instance %s (cluster %s, realm %s) status=%s\napi_url: %s\nissuer: %s\naudience: %s",
		i.ID, i.ClusterID, i.RealmName, i.Status, i.APIURL, i.Issuer, i.Audience)
	if i.StatusMessage != "" {
		s += "\nmessage: " + i.StatusMessage
	}
	return s
}

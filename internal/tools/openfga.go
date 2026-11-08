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
		Description: "List the OpenFGA instances bound to a cluster's realms, with each one's status (provisioning, ready, failed or deleting). Works on every plan, so a workspace that lost OpenFGA access still sees what it has.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List OpenFGA instances"},
	}, listOpenFGAInstancesHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_get_openfga_instance",
		Description: "Get one OpenFGA instance of a cluster, including its status and the API URL, token issuer and audience to call it with.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get OpenFGA instance"},
	}, getOpenFGAInstanceHandler(api))
}

func registerOpenFGAWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_create_openfga_instance",
		Description: "Create an OpenFGA instance bound to one realm of a cluster; a realm has at most one. Asynchronous: it starts in 'provisioning', so poll skycloak_get_openfga_instance until the status is 'ready' or 'failed'. The instance accepts only tokens from that realm that carry the instance's audience. Fails with 403 when the workspace's plan does not include OpenFGA or the workspace reached its instance limit, 409 when the realm already has an instance, and 422 when the realm is 'master', does not exist or is disabled.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(false), Title: "Create OpenFGA instance"},
	}, createOpenFGAInstanceHandler(api))

	addTool(s, &mcp.Tool{
		Name:        "skycloak_delete_openfga_instance",
		Description: "Permanently delete an OpenFGA instance with its deployment, route and database. The authorization data in it cannot be recovered. Works without OpenFGA access. Removal is asynchronous: the instance shows 'deleting' until it leaves the list. Set confirm=true to proceed.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, DestructiveHint: ptr(true), Title: "Delete OpenFGA instance"},
	}, deleteOpenFGAInstanceHandler(api))
}

// OpenFGAInstancesOutput is the structured result of an OpenFGA instance list.
type OpenFGAInstancesOutput struct {
	Instances []skycloak.OpenFGAInstance `json:"instances"`
	Count     int                        `json:"count"`
}

// ListOpenFGAInstancesInput is the input for skycloak_list_openfga_instances.
type ListOpenFGAInstancesInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster whose OpenFGA instances to list"`
}

func listOpenFGAInstancesHandler(api API) mcp.ToolHandlerFor[ListOpenFGAInstancesInput, OpenFGAInstancesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListOpenFGAInstancesInput) (*mcp.CallToolResult, OpenFGAInstancesOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), OpenFGAInstancesOutput{}, nil
		}
		instances, err := api.ListOpenFGAInstances(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), OpenFGAInstancesOutput{}, nil
		}
		var b strings.Builder
		for _, i := range instances {
			fmt.Fprintf(&b, "- %s (realm %s) status=%s\n", i.ID, i.Realm, i.Status)
		}
		if len(instances) == 0 {
			b.WriteString("No OpenFGA instances on this cluster.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, OpenFGAInstancesOutput{Instances: instances, Count: len(instances)}, nil
	}
}

// OpenFGAInstanceRef identifies an OpenFGA instance.
type OpenFGAInstanceRef struct {
	ClusterID  string `json:"cluster_id" jsonschema:"the cluster the instance belongs to"`
	InstanceID string `json:"instance_id" jsonschema:"the OpenFGA instance ID"`
}

func getOpenFGAInstanceHandler(api API) mcp.ToolHandlerFor[OpenFGAInstanceRef, skycloak.OpenFGAInstance] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in OpenFGAInstanceRef) (*mcp.CallToolResult, skycloak.OpenFGAInstance, error) {
		if in.ClusterID == "" || in.InstanceID == "" {
			return errResult("cluster_id and instance_id are required"), skycloak.OpenFGAInstance{}, nil
		}
		i, err := api.GetOpenFGAInstance(ctx, in.ClusterID, in.InstanceID)
		if err != nil {
			return toolError(err), skycloak.OpenFGAInstance{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: openFGAInstanceText(i)}}}, *i, nil
	}
}

// CreateOpenFGAInstanceInput is the input for skycloak_create_openfga_instance.
type CreateOpenFGAInstanceInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster that holds the realm"`
	Realm     string `json:"realm" jsonschema:"the realm to bind; it must exist and be enabled, must not be master, and must not already have an instance"`
}

func createOpenFGAInstanceHandler(api API) mcp.ToolHandlerFor[CreateOpenFGAInstanceInput, skycloak.OpenFGAInstance] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in CreateOpenFGAInstanceInput) (*mcp.CallToolResult, skycloak.OpenFGAInstance, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.OpenFGAInstance{}, nil
		}
		i, err := api.CreateOpenFGAInstance(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), skycloak.OpenFGAInstance{}, nil
		}
		txt := fmt.Sprintf("Started OpenFGA instance %s (status=%s). Poll skycloak_get_openfga_instance until it is ready or failed.\n%s", i.ID, i.Status, openFGAInstanceText(i))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, *i, nil
	}
}

// DeleteOpenFGAInstanceInput is the input for skycloak_delete_openfga_instance.
type DeleteOpenFGAInstanceInput struct {
	ClusterID  string `json:"cluster_id" jsonschema:"the cluster the instance belongs to"`
	InstanceID string `json:"instance_id" jsonschema:"the OpenFGA instance ID to delete"`
	Confirm    bool   `json:"confirm" jsonschema:"must be true to confirm permanent, irreversible deletion of the instance and its authorization data"`
}

func deleteOpenFGAInstanceHandler(api API) mcp.ToolHandlerFor[DeleteOpenFGAInstanceInput, struct{}] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DeleteOpenFGAInstanceInput) (*mcp.CallToolResult, struct{}, error) {
		if in.ClusterID == "" || in.InstanceID == "" {
			return errResult("cluster_id and instance_id are required"), struct{}{}, nil
		}
		if !in.Confirm {
			return errResult(fmt.Sprintf("Refusing to delete OpenFGA instance %s: set confirm=true. This is irreversible.", in.InstanceID)), struct{}{}, nil
		}
		i, err := api.DeleteOpenFGAInstance(ctx, in.ClusterID, in.InstanceID)
		if err != nil {
			return toolError(err), struct{}{}, nil
		}
		txt := fmt.Sprintf("OpenFGA instance %s was already gone.", in.InstanceID)
		if i != nil {
			txt = fmt.Sprintf("Deleting OpenFGA instance %s (status=%s). It leaves the list once its deployment, route and database are removed.", in.InstanceID, i.Status)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: txt}}}, struct{}{}, nil
	}
}

func openFGAInstanceText(i *skycloak.OpenFGAInstance) string {
	s := fmt.Sprintf("OpenFGA instance %s (cluster %s, realm %s) status=%s\napi_url: %s\nissuer: %s\naudience: %s",
		i.ID, i.ClusterID, i.Realm, i.Status, i.APIURL, i.Issuer, i.Audience)
	if i.StatusMessage != "" {
		s += "\nmessage: " + i.StatusMessage
	}
	return s
}

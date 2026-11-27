package tools

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerClusterFeatureReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_get_cluster_features",
		Description: "Read the Keycloak feature flags enabled on one cluster, and any change still rolling out: pending until the cluster's maintenance window, or applying while Keycloak restarts. " +
			"While a change is pending or applying, the flags listed are the requested set. Flags only Skycloak can set are not listed. skycloak_list_cluster_features gives the flags you can enable.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster features"},
	}, getClusterFeaturesHandler(api))
}

func registerClusterFeatureWriteTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_set_cluster_features",
		Description: "Replace the whole set of Keycloak feature flags enabled on one cluster: flags left out of the list are turned off, so read the current set with skycloak_get_cluster_features first. " +
			"A change restarts Keycloak. By default it waits for the cluster's maintenance window, and a cluster without a window restarts at once; set apply_now=true to restart at once whatever the window. " +
			"Some flags are experimental in Keycloak and may change or be removed between releases. The result states whether Keycloak restarts, whether the change is pending or applying, and which of the flags are experimental.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: false, IdempotentHint: true, DestructiveHint: ptr(true), Title: "Set cluster features"},
	}, setClusterFeaturesHandler(api))
}

// GetClusterFeaturesInput is the input for skycloak_get_cluster_features.
type GetClusterFeaturesInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
}

func getClusterFeaturesHandler(api API) mcp.ToolHandlerFor[GetClusterFeaturesInput, skycloak.ClusterFeatures] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in GetClusterFeaturesInput) (*mcp.CallToolResult, skycloak.ClusterFeatures, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.ClusterFeatures{}, nil
		}
		f, err := api.GetClusterFeatures(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.ClusterFeatures{}, nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Enabled feature flags: %s.", featureList(f.Features))
		if f.Change != nil {
			b.WriteString(" " + describeFeatureChange(f.Change))
		}
		return okResult(b.String()), *f, nil
	}
}

// SetClusterFeaturesInput is the input for skycloak_set_cluster_features.
type SetClusterFeaturesInput struct {
	ClusterID string   `json:"cluster_id" jsonschema:"the cluster ID"`
	Features  []string `json:"features" jsonschema:"the complete set of feature flags to enable; flags left out are turned off. Use an empty list to turn every flag off"`
	ApplyNow  bool     `json:"apply_now,omitempty" jsonschema:"restart Keycloak at once instead of waiting for the cluster's maintenance window; has no effect on a cluster without a window, which always applies at once"`
}

// SetClusterFeaturesOutput is the structured result of skycloak_set_cluster_features.
type SetClusterFeaturesOutput struct {
	skycloak.ClusterFeaturesUpdate
	// ExperimentalFeatures lists the enabled flags Keycloak marks experimental.
	ExperimentalFeatures []string `json:"experimental_features"`
}

func setClusterFeaturesHandler(api API) mcp.ToolHandlerFor[SetClusterFeaturesInput, SetClusterFeaturesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in SetClusterFeaturesInput) (*mcp.CallToolResult, SetClusterFeaturesOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), SetClusterFeaturesOutput{}, nil
		}
		if in.Features == nil {
			return errResult("features is required: send the complete set of flags to enable, or an empty list to turn every flag off"), SetClusterFeaturesOutput{}, nil
		}
		u, err := api.SetClusterFeatures(ctx, in.ClusterID, in.Features, in.ApplyNow)
		if err != nil {
			return toolError(err), SetClusterFeaturesOutput{}, nil
		}
		out := SetClusterFeaturesOutput{ClusterFeaturesUpdate: *u, ExperimentalFeatures: []string{}}

		// The catalog says which flags are experimental. If it cannot be read
		// the change has still been made, so the result falls back to a general note.
		catalogKnown := false
		if catalog, cerr := api.ListClusterFeatures(ctx); cerr == nil {
			catalogKnown = true
			for _, f := range catalog {
				if f.Experimental && slices.Contains(u.Features, f.Name) {
					out.ExperimentalFeatures = append(out.ExperimentalFeatures, f.Name)
				}
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "Enabled feature flags: %s. ", featureList(u.Features))
		switch {
		case !u.RestartsKeycloak:
			b.WriteString("Keycloak does not restart: the set was already as requested.")
		case u.Change != nil:
			b.WriteString("Keycloak restarts. " + describeFeatureChange(u.Change))
		default:
			b.WriteString("Keycloak restarts.")
		}
		if u.Impact != "" {
			b.WriteString(" " + u.Impact)
		}
		switch {
		case len(out.ExperimentalFeatures) > 0:
			fmt.Fprintf(&b, " Experimental in Keycloak and may change or be removed between releases: %s.", strings.Join(out.ExperimentalFeatures, ", "))
		case !catalogKnown:
			b.WriteString(" Some feature flags are experimental in Keycloak; skycloak_list_cluster_features marks which.")
		}
		return okResult(b.String()), out, nil
	}
}

func featureList(f []string) string {
	if len(f) == 0 {
		return "none"
	}
	return strings.Join(f, ", ")
}

func describeFeatureChange(c *skycloak.FeatureChange) string {
	switch c.State {
	case "pending":
		if c.NextWindow != "" {
			return "The change is pending until the maintenance window opens at " + c.NextWindow + "."
		}
		return "The change is pending until the maintenance window."
	case "applying":
		return "The change is applying: Keycloak is restarting."
	}
	return "Change state: " + c.State + "."
}

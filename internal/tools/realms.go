package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ListRealmsInput is the input schema for skycloak_list_realms.
type ListRealmsInput struct {
	ClusterID string `json:"cluster_id,omitempty" jsonschema:"the cluster whose realms to list. Omit to list realms across every cluster in the workspace"`
}

// RealmSummary is one row of the list output.
type RealmSummary struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Enabled     bool   `json:"enabled"`

	// Carried on the list rows as well as the single-realm read: a fleet
	// question ("which realms allow self-registration") otherwise costs one
	// extra call per realm to answer.
	RegistrationAllowed   bool   `json:"registration_allowed"`
	LoginWithEmailAllowed bool   `json:"login_with_email_allowed"`
	SSLRequired           string `json:"ssl_required,omitempty"`

	// Which cluster the realm lives in. Always set, so a fleet-wide result and a
	// single-cluster one have the same shape and rows are never ambiguous.
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name,omitempty"`
}

// ListRealmsOutput is the structured result of skycloak_list_realms.
type ListRealmsOutput struct {
	Realms []RealmSummary `json:"realms"`
	Count  int            `json:"count"`

	// Clusters a fleet-wide call could not read. Non-empty means the answer is
	// partial and must not be read as complete.
	Unreachable []UnreachableCluster `json:"unreachable,omitempty"`
}

func registerRealmReadTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name:        "skycloak_list_realms",
		Description: "List the Keycloak realms in a Skycloak cluster.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List realms"},
	}, listRealmsHandler(api))
}

func listRealmsHandler(api API) mcp.ToolHandlerFor[ListRealmsInput, ListRealmsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListRealmsInput) (*mcp.CallToolResult, ListRealmsOutput, error) {
		targets, err := fleetTargets(ctx, api, in.ClusterID)
		if err != nil {
			return toolError(err), ListRealmsOutput{}, nil
		}
		multi := len(targets) > 1 || in.ClusterID == ""

		out := ListRealmsOutput{Realms: []RealmSummary{}}
		var b strings.Builder
		for _, t := range targets {
			realms, err := api.ListRealms(ctx, t.id)
			if err != nil {
				out.Unreachable = append(out.Unreachable, UnreachableCluster{
					ClusterID: t.id, ClusterName: t.name, Error: err.Error(),
				})
				continue
			}
			for _, r := range realms {
				out.Realms = append(out.Realms, RealmSummary{
					Name: r.Name, DisplayName: r.DisplayName, Enabled: r.Enabled,
					RegistrationAllowed:   r.RegistrationAllowed,
					LoginWithEmailAllowed: r.LoginWithEmailAllowed,
					SSLRequired:           r.SSLRequired,
					ClusterID:             t.id,
					ClusterName:           t.name,
				})
				fmt.Fprintf(&b, "- %s%s (%s) — enabled=%t registration_allowed=%t\n",
					fleetHeader(t, multi), r.Name, r.DisplayName, r.Enabled, r.RegistrationAllowed)
			}
		}
		out.Count = len(out.Realms)

		// Nothing read at all is a failure, not an empty fleet: "no realms"
		// would read as "nobody has self-registration on".
		if len(out.Realms) == 0 && len(out.Unreachable) > 0 {
			return errResult("no cluster could be read." + fleetNote(out.Unreachable)), out, nil
		}
		if len(out.Realms) == 0 {
			b.WriteString("No realms found.")
		}
		b.WriteString(fleetNote(out.Unreachable))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, out, nil
	}
}

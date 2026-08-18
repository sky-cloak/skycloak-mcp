package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

// registerClusterCredentialsTool is separate from the rest of the cluster reads
// because it is the only tool gated on clusters:credentials:read, a scope no
// OAuth session ever carries.
func registerClusterCredentialsTool(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_credentials",
		Description: "Get a cluster's Keycloak automation client credentials for OAuth2 client_credentials. Needs a key with the clusters:credentials:read scope, which is not granted by default.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster credentials"},
	}, getClusterCredentialsHandler(api))
}

func registerReads2Tools(s *mcp.Server, api API) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_maintenance_window",
		Description: "Get a cluster-specific maintenance window. A 404 means the cluster follows the workspace default.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get maintenance window"},
	}, getClusterMaintenanceWindowHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_upgrade_path",
		Description: "Get the recommended version-upgrade path for a cluster.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get upgrade path"},
	}, getClusterUpgradePathHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_cluster_insights",
		Description: "Get cluster analytics as a JSON document. type is one of: overview, authentication, events, performance, security.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get cluster insights"},
	}, getClusterInsightsHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_realm_role",
		Description: "Get a realm role by name.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get realm role"},
	}, getRealmRoleHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_get_realm_group",
		Description: "Get a realm group by ID.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get realm group"},
	}, getRealmGroupHandler(api))

	mcp.AddTool(s, &mcp.Tool{
		Name:        "skycloak_list_realm_group_members",
		Description: "List the users that belong to a realm group.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List group members"},
	}, listRealmGroupMembersHandler(api))
}

func getClusterCredentialsHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, skycloak.ClusterCredentials] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, skycloak.ClusterCredentials, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.ClusterCredentials{}, nil
		}
		creds, err := api.GetClusterCredentials(ctx, in.ClusterID)
		if err != nil {
			// This is the one scope a sign-in does not grant by default, so a 403
			// here is usually that rather than a real permission problem.
			if apiErr, ok := skycloak.AsAPIError(err); ok && apiErr.StatusCode == 403 {
				// The advice has to hold for both transports: over stdio the key
				// usually comes from `init`, but a hosted HTTP caller supplies a
				// dashboard key and has no keychain here. Note the env var too,
				// since it outranks the keychain and would otherwise make a
				// freshly minted key look like it changed nothing.
				return errResult("Forbidden: reading cluster credentials needs the clusters:credentials:read scope, " +
					"which is not granted by default. Use a key that has it: create one in the Skycloak dashboard, " +
					"or over stdio run `skycloak-mcp init --allow-credentials`. If SKYCLOAK_API_KEY is set it takes " +
					"precedence over the stored key, so update that instead. " + err.Error()), skycloak.ClusterCredentials{}, nil
			}
			return toolError(err), skycloak.ClusterCredentials{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "client_id=" + creds.ClientID + " token_url=" + creds.TokenURL + " (client_secret in structured output)"}}}, *creds, nil
	}
}

func getClusterMaintenanceWindowHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, skycloak.MaintenanceWindow] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, skycloak.MaintenanceWindow, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), skycloak.MaintenanceWindow{}, nil
		}
		window, err := api.GetClusterMaintenanceWindow(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), skycloak.MaintenanceWindow{}, nil
		}
		return okResult(formatMaintenanceWindow(*window)), *window, nil
	}
}

func formatMaintenanceWindow(w skycloak.MaintenanceWindow) string {
	return fmt.Sprintf("enabled=%t days=%v start=%s end=%s timezone=%s", w.Enabled, w.DaysOfWeek, w.StartLocal, w.EndLocal, w.Timezone)
}

// UpgradePathOutput is the structured upgrade-path result.
type UpgradePathOutput struct {
	Steps []skycloak.UpgradePathStep `json:"steps"`
}

func getClusterUpgradePathHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, UpgradePathOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, UpgradePathOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), UpgradePathOutput{}, nil
		}
		steps, err := api.GetClusterUpgradePath(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), UpgradePathOutput{}, nil
		}
		parts := make([]string, 0, len(steps))
		for _, s := range steps {
			parts = append(parts, s.Version)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(parts, " -> ")}}}, UpgradePathOutput{Steps: steps}, nil
	}
}

// InsightsInput selects a cluster insight type.
type InsightsInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Type      string `json:"type,omitempty" jsonschema:"insight document: overview, authentication, events, performance, or security (case-insensitive); defaults to overview"`
}

// InsightsOutput carries the raw analytics JSON.
type InsightsOutput struct {
	JSON string `json:"json"`
}

func getClusterInsightsHandler(api API) mcp.ToolHandlerFor[InsightsInput, InsightsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in InsightsInput) (*mcp.CallToolResult, InsightsOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), InsightsOutput{}, nil
		}
		if in.Type != "" && !enumInsightType.has(in.Type) {
			return errResult(fmt.Sprintf("type %q is not an insight document; use one of: %s", in.Type, enumInsightType.list())), InsightsOutput{}, nil
		}
		raw, err := api.ClusterInsights(ctx, in.ClusterID, enumInsightType.canonical(in.Type))
		if err != nil {
			return toolError(err), InsightsOutput{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}}, InsightsOutput{JSON: string(raw)}, nil
	}
}

// RealmRoleRef identifies a realm role.
type RealmRoleRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	Name      string `json:"name" jsonschema:"the role name"`
}

func getRealmRoleHandler(api API) mcp.ToolHandlerFor[RealmRoleRef, skycloak.RealmRole] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmRoleRef) (*mcp.CallToolResult, skycloak.RealmRole, error) {
		if in.ClusterID == "" || in.Realm == "" || in.Name == "" {
			return errResult("cluster_id, realm and name are required"), skycloak.RealmRole{}, nil
		}
		role, err := api.GetRealmRole(ctx, in.ClusterID, in.Realm, in.Name)
		if err != nil {
			return toolError(err), skycloak.RealmRole{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: role.Name + descSuffix(role.Description)}}}, *role, nil
	}
}

// RealmGroupRef identifies a realm group.
type RealmGroupRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	GroupID   string `json:"group_id" jsonschema:"the group ID"`
}

func getRealmGroupHandler(api API) mcp.ToolHandlerFor[RealmGroupRef, skycloak.RealmGroup] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmGroupRef) (*mcp.CallToolResult, skycloak.RealmGroup, error) {
		if in.ClusterID == "" || in.Realm == "" || in.GroupID == "" {
			return errResult("cluster_id, realm and group_id are required"), skycloak.RealmGroup{}, nil
		}
		g, err := api.GetRealmGroup(ctx, in.ClusterID, in.Realm, in.GroupID)
		if err != nil {
			return toolError(err), skycloak.RealmGroup{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s (%s) path=%s", g.Name, g.ID, g.Path)}}}, *g, nil
	}
}

func listRealmGroupMembersHandler(api API) mcp.ToolHandlerFor[RealmGroupRef, UsersOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmGroupRef) (*mcp.CallToolResult, UsersOutput, error) {
		if in.ClusterID == "" || in.Realm == "" || in.GroupID == "" {
			return errResult("cluster_id, realm and group_id are required"), UsersOutput{}, nil
		}
		users, err := api.ListRealmGroupMembers(ctx, in.ClusterID, in.Realm, in.GroupID)
		if err != nil {
			return toolError(err), UsersOutput{}, nil
		}
		var b strings.Builder
		for _, u := range users {
			fmt.Fprintf(&b, "- %s (%s) <%s>\n", u.Username, u.ID, u.Email)
		}
		if len(users) == 0 {
			b.WriteString("No members in this group.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, UsersOutput{Users: users, Count: len(users)}, nil
	}
}

package tools

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sky-cloak/skycloak-mcp/internal/skycloak"
)

func registerReadParityTools(s *mcp.Server, api API) {
	addTool(s, &mcp.Tool{
		Name: "skycloak_get_realm",
		Description: "Get one Keycloak realm of a cluster by name, with its display name, enabled state, frontend_url (the public URL it serves on behind your own proxy, absent when none is set) and the security settings registration_allowed, login_with_email and ssl_required. " +
			"Needs cluster_id from skycloak_list_clusters; skycloak_list_realms gives the realm names and answers the same question for many realms at once.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get realm"},
	}, getRealmHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_application",
		Description: "Get one application (OIDC or SAML client) of a realm by its client ID, with name, type and protocol. " +
			"Needs cluster_id from skycloak_list_clusters and client_id from skycloak_list_applications. Not for the client's roles; use skycloak_get_application_role for a role it defines and skycloak_list_application_roles for what its service account holds.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get application"},
	}, getApplicationHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_get_identity_provider",
		Description: "Get one identity provider (SSO connection) of a realm by its alias, with display name, type and enabled state. " +
			"provider_id is the alias exactly as skycloak_list_identity_providers reports it, and it is case-sensitive.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "Get identity provider"},
	}, getIdentityProviderHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_cluster_locations",
		Description: "List the deployment regions, each with the name and an available flag for this workspace. " +
			"Workspace-wide and takes no arguments. Call it before skycloak_create_cluster: creating a cluster in a location the workspace cannot use is rejected.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List cluster locations"},
	}, listClusterLocationsHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_cluster_types",
		Description: "List the cluster types the workspace can provision, each with an available flag. " +
			"Workspace-wide and takes no arguments. For the versions offered within a type, use skycloak_list_cluster_versions.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List cluster types"},
	}, listClusterTypesHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_cluster_features",
		Description: "List the Keycloak feature flags available to tenant clusters, with each flag's name and display name. " +
			"Workspace-wide and takes no arguments; it does not say which flags one cluster has on.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List cluster features"},
	}, listClusterFeaturesHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_cluster_versions",
		Description: "List the Keycloak versions on offer for one cluster type, flagging versions no longer offered, major version changes and breaking-change counts. " +
			"Takes a type (keycloak or tidecloak), not a cluster_id. Not the plan for an existing cluster; use skycloak_get_cluster_upgrade_path for that.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List cluster versions"},
	}, listClusterVersionsHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_cluster_upgrades",
		Description: "List the version upgrades recorded for one cluster, each with its from_version, to_version and phase. " +
			"This is history, including anything in flight; for the recommended next versions use skycloak_get_cluster_upgrade_path. Needs cluster_id from skycloak_list_clusters.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List cluster upgrades"},
	}, listClusterUpgradesHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_identity_provider_templates",
		Description: "List the pre-configured identity-provider templates of the workspace, with each one's id, name and type. " +
			"Workspace-wide and takes no arguments. Pass a template id as provider_id to skycloak_create_identity_provider; for the providers a realm already has, use skycloak_list_identity_providers.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List IdP templates"},
	}, listIdentityProviderTemplatesHandler(api))

	addTool(s, &mcp.Tool{
		Name: "skycloak_list_domain_routes",
		Description: "List the realm routes configured on one custom domain, each with its route_id, realm, admin-access and hide_realm_path flags. " +
			"A route maps one realm onto the hostname. Not for the domains themselves; use skycloak_list_domains, which is also where domain_id comes from.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(false), ReadOnlyHint: true, Title: "List domain routes"},
	}, listDomainRoutesHandler(api))
}

func getRealmHandler(api API) mcp.ToolHandlerFor[RealmScopeInput, skycloak.Realm] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in RealmScopeInput) (*mcp.CallToolResult, skycloak.Realm, error) {
		if in.ClusterID == "" || in.Realm == "" {
			return errResult("cluster_id and realm are required"), skycloak.Realm{}, nil
		}
		r, err := api.GetRealm(ctx, in.ClusterID, in.Realm)
		if err != nil {
			return toolError(err), skycloak.Realm{}, nil
		}
		// The security settings are spelled out here, not just carried in the
		// structured payload: "which realms still allow self-registration" is
		// the question this tool exists to answer, and the rendered line is what
		// a model reads first.
		text := fmt.Sprintf("%s (%s) enabled=%t registration_allowed=%t login_with_email=%t ssl_required=%s",
			r.Name, r.DisplayName, r.Enabled, r.RegistrationAllowed, r.LoginWithEmailAllowed, r.SSLRequired)
		if r.FrontendURL != nil {
			text += " frontend_url=" + *r.FrontendURL
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, *r, nil
	}
}

// AppRef identifies an application client.
type AppRef struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm     string `json:"realm" jsonschema:"the Keycloak realm name"`
	ClientID  string `json:"client_id" jsonschema:"the application client ID"`
}

func getApplicationHandler(api API) mcp.ToolHandlerFor[AppRef, skycloak.Application] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in AppRef) (*mcp.CallToolResult, skycloak.Application, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ClientID == "" {
			return errResult("cluster_id, realm and client_id are required"), skycloak.Application{}, nil
		}
		a, err := api.GetApplication(ctx, in.ClusterID, in.Realm, in.ClientID)
		if err != nil {
			return toolError(err), skycloak.Application{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s (%s) type=%s", a.Name, a.ClientID, a.Type)}}}, *a, nil
	}
}

// IDPRef identifies an identity provider.
type IDPRef struct {
	ClusterID  string `json:"cluster_id" jsonschema:"the cluster ID"`
	Realm      string `json:"realm" jsonschema:"the Keycloak realm name"`
	ProviderID string `json:"provider_id" jsonschema:"the identity provider alias, exactly as skycloak_list_identity_providers reports it (case-sensitive)"`
}

func getIdentityProviderHandler(api API) mcp.ToolHandlerFor[IDPRef, skycloak.IdentityProvider] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in IDPRef) (*mcp.CallToolResult, skycloak.IdentityProvider, error) {
		if in.ClusterID == "" || in.Realm == "" || in.ProviderID == "" {
			return errResult("cluster_id, realm and provider_id are required"), skycloak.IdentityProvider{}, nil
		}
		p, err := api.GetIdentityProvider(ctx, in.ClusterID, in.Realm, in.ProviderID)
		if err != nil {
			return toolError(err), skycloak.IdentityProvider{}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%s (%s) type=%s enabled=%t", p.DisplayName, p.ProviderID, p.Type, p.Enabled)}}}, *p, nil
	}
}

// NoInput is for tools that take no arguments.
type NoInput struct{}

// LocationsOutput is the structured location list.
type LocationsOutput struct {
	Locations []skycloak.ClusterLocationInfo `json:"locations"`
}

func listClusterLocationsHandler(api API) mcp.ToolHandlerFor[NoInput, LocationsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ NoInput) (*mcp.CallToolResult, LocationsOutput, error) {
		locs, err := api.ListClusterLocations(ctx)
		if err != nil {
			return toolError(err), LocationsOutput{}, nil
		}
		var b strings.Builder
		for _, l := range locs {
			fmt.Fprintf(&b, "- %s (%s) available=%t\n", l.Location, l.Name, l.Available)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, LocationsOutput{Locations: locs}, nil
	}
}

// TypesOutput is the structured type list.
type TypesOutput struct {
	Types []skycloak.ClusterTypeInfo `json:"types"`
}

func listClusterTypesHandler(api API) mcp.ToolHandlerFor[NoInput, TypesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ NoInput) (*mcp.CallToolResult, TypesOutput, error) {
		types, err := api.ListClusterTypes(ctx)
		if err != nil {
			return toolError(err), TypesOutput{}, nil
		}
		var b strings.Builder
		for _, t := range types {
			fmt.Fprintf(&b, "- %s (%s) available=%t\n", t.Type, t.Name, t.Available)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, TypesOutput{Types: types}, nil
	}
}

// FeaturesOutput is the structured feature list.
type FeaturesOutput struct {
	Features []skycloak.ClusterFeatureInfo `json:"features"`
}

func listClusterFeaturesHandler(api API) mcp.ToolHandlerFor[NoInput, FeaturesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ NoInput) (*mcp.CallToolResult, FeaturesOutput, error) {
		features, err := api.ListClusterFeatures(ctx)
		if err != nil {
			return toolError(err), FeaturesOutput{}, nil
		}
		var b strings.Builder
		for _, f := range features {
			fmt.Fprintf(&b, "- %s (%s)\n", f.Name, f.DisplayName)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, FeaturesOutput{Features: features}, nil
	}
}

// ClusterTypeInput selects a cluster type.
type ClusterTypeInput struct {
	Type string `json:"type" jsonschema:"cluster type: keycloak or tidecloak (case-insensitive)"`
}

// VersionsOutput is the structured version list.
type VersionsOutput struct {
	Versions []skycloak.ClusterTypeVersion `json:"versions"`
}

func listClusterVersionsHandler(api API) mcp.ToolHandlerFor[ClusterTypeInput, VersionsOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ClusterTypeInput) (*mcp.CallToolResult, VersionsOutput, error) {
		clusterType := enumClusterType.canonical(in.Type)
		if clusterType == "" {
			return errResult("type is required"), VersionsOutput{}, nil
		}
		versions, err := api.ClusterTypeVersions(ctx, clusterType)
		if err != nil {
			return toolError(err), VersionsOutput{}, nil
		}
		if versions == nil {
			versions = []skycloak.ClusterTypeVersion{}
		}
		var b strings.Builder
		for i, v := range versions {
			if i > 0 {
				b.WriteString("\n")
			}
			// Annotations only where there is something to say, so their
			// presence carries meaning.
			fmt.Fprintf(&b, "- %s%s", v.Version, versionNotes(v))
		}
		if len(versions) == 0 {
			b.WriteString("No versions available for this cluster type.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, VersionsOutput{Versions: versions}, nil
	}
}

// versionNotes annotates a version with what a caller needs before choosing it:
// whether it can still be chosen at all, and what an upgrade onto it costs.
func versionNotes(v skycloak.ClusterTypeVersion) string {
	var notes []string
	if !v.Active {
		notes = append(notes, "no longer offered for new clusters or upgrades")
	}
	if v.IsMajorChange {
		notes = append(notes, "major version change")
	}
	if v.BreakingChangeCount > 0 {
		notes = append(notes, fmt.Sprintf("%d breaking change(s)", v.BreakingChangeCount))
	}
	if len(notes) == 0 {
		return ""
	}
	return " (" + strings.Join(notes, "; ") + ")"
}

// UpgradesOutput is the structured upgrade list.
type UpgradesOutput struct {
	Upgrades []skycloak.ClusterUpgrade `json:"upgrades"`
}

func listClusterUpgradesHandler(api API) mcp.ToolHandlerFor[ListDomainsInput, UpgradesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in ListDomainsInput) (*mcp.CallToolResult, UpgradesOutput, error) {
		if in.ClusterID == "" {
			return errResult("cluster_id is required"), UpgradesOutput{}, nil
		}
		upgrades, err := api.ListClusterUpgrades(ctx, in.ClusterID)
		if err != nil {
			return toolError(err), UpgradesOutput{}, nil
		}
		var b strings.Builder
		for _, u := range upgrades {
			fmt.Fprintf(&b, "- %s -> %s (%s)\n", u.FromVersion, u.ToVersion, u.Phase)
		}
		if len(upgrades) == 0 {
			b.WriteString("No upgrades recorded.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, UpgradesOutput{Upgrades: upgrades}, nil
	}
}

// TemplatesOutput is the structured template list.
type TemplatesOutput struct {
	Templates []skycloak.ProviderTemplate `json:"templates"`
}

func listIdentityProviderTemplatesHandler(api API) mcp.ToolHandlerFor[NoInput, TemplatesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, _ NoInput) (*mcp.CallToolResult, TemplatesOutput, error) {
		templates, err := api.ListIdentityProviderTemplates(ctx)
		if err != nil {
			return toolError(err), TemplatesOutput{}, nil
		}
		var b strings.Builder
		for _, t := range templates {
			fmt.Fprintf(&b, "- %s (%s) type=%s\n", t.Name, t.ID, t.Type)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, TemplatesOutput{Templates: templates}, nil
	}
}

// DomainRoutesInput targets a domain.
type DomainRoutesInput struct {
	ClusterID string `json:"cluster_id" jsonschema:"the cluster ID"`
	DomainID  string `json:"domain_id" jsonschema:"the domain ID"`
}

// DomainRoutesOutput is the structured route list.
type DomainRoutesOutput struct {
	Routes []skycloak.DomainRoute `json:"routes"`
}

func listDomainRoutesHandler(api API) mcp.ToolHandlerFor[DomainRoutesInput, DomainRoutesOutput] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in DomainRoutesInput) (*mcp.CallToolResult, DomainRoutesOutput, error) {
		if in.ClusterID == "" || in.DomainID == "" {
			return errResult("cluster_id and domain_id are required"), DomainRoutesOutput{}, nil
		}
		routes, err := api.ListDomainRoutes(ctx, in.ClusterID, in.DomainID)
		if err != nil {
			return toolError(err), DomainRoutesOutput{}, nil
		}
		var b strings.Builder
		for _, r := range routes {
			fmt.Fprintf(&b, "- %s realm=%s admin=%t hide_path=%t\n", r.ID, r.Realm, r.AllowAdminAccess, r.HideRealmPath)
		}
		if len(routes) == 0 {
			b.WriteString("No routes on this domain.")
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: b.String()}}}, DomainRoutesOutput{Routes: routes}, nil
	}
}

package tools

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The prompts below are packaged workflows: each one names the tools a task
// needs and the order to use them in, so a client that surfaces prompts gives
// the user a starting point instead of a bare 129-tool list. The bodies are
// instructions to the assistant, not text shown to the user.

// promptDef pairs a prompt with the gating of the tools its body names.
// scopes is the union of the scopes of every tool area the body references,
// so a prompt is offered only when every tool it names is registered. write
// marks a workflow built around mutating tools; like write tools, it is
// withheld unless writes are allowed.
type promptDef struct {
	write  bool
	scopes []string
	prompt *mcp.Prompt
	text   func(args map[string]string) string
}

var promptDefs = []promptDef{
	{
		scopes: []string{"clusters:read", "realms:read", "themes:read", "branding:read"},
		prompt: &mcp.Prompt{
			Name:        "audit_self_registration",
			Title:       "Audit self-registration",
			Description: "Find every realm that still allows self-registration, across one cluster or the whole workspace.",
			Arguments: []*mcp.PromptArgument{
				{Name: "cluster_id", Description: "Cluster ID to audit. Leave empty to sweep every cluster in the workspace."},
			},
		},
		text: auditSelfRegistrationText,
	},
	{
		scopes: []string{
			"clusters:read", "clusters:insights:read", "realm-roles:read", "realm-groups:read",
			"realms:read", "applications:read", "identity-providers:read", "domains:read",
		},
		prompt: &mcp.Prompt{
			Name:        "review_upgrades",
			Title:       "Review Keycloak upgrades",
			Description: "Find clusters behind on their Keycloak version and lay out the upgrade path for the ones furthest behind.",
			Arguments: []*mcp.PromptArgument{
				{Name: "cluster_id", Description: "Cluster ID to focus on. Leave empty to review every cluster."},
			},
		},
		text: reviewUpgradesText,
	},
	{
		scopes: []string{"clusters:read", "realms:read", "clusters:logs:read", "clusters:events:read"},
		prompt: &mcp.Prompt{
			Name:        "triage_failed_logins",
			Title:       "Triage failed logins",
			Description: "Pull recent failed logins for a realm and group them by source IP to spot brute force or password spraying.",
			Arguments: []*mcp.PromptArgument{
				{Name: "realm", Description: "The realm to investigate.", Required: true},
				{Name: "cluster_id", Description: "Cluster ID the realm lives in. Leave empty to locate it by realm name."},
				{Name: "limit", Description: "How many recent events to pull. Defaults to 200."},
			},
		},
		text: triageFailedLoginsText,
	},
	{
		scopes: []string{"clusters:read", "realms:read", "applications:read", "identity-providers:read", "domains:read"},
		prompt: &mcp.Prompt{
			Name:        "review_identity_providers",
			Title:       "Review identity providers",
			Description: "List the identity providers configured on a realm and check the state of a specific one.",
			Arguments: []*mcp.PromptArgument{
				{Name: "realm", Description: "The realm whose sign-in providers to review.", Required: true},
				{Name: "cluster_id", Description: "Cluster ID the realm lives in. Leave empty to locate it by realm name."},
				{Name: "provider", Description: "A specific provider alias to check in detail, for example google."},
			},
		},
		text: reviewIdentityProvidersText,
	},
	{
		scopes: []string{"clusters:read", "realms:read", "clusters:logs:read", "clusters:events:read"},
		prompt: &mcp.Prompt{
			Name:        "review_admin_changes",
			Title:       "Review admin changes",
			Description: "Show who changed what in a realm recently, with a focus on login and security settings.",
			Arguments: []*mcp.PromptArgument{
				{Name: "realm", Description: "The realm whose admin events to review.", Required: true},
				{Name: "cluster_id", Description: "Cluster ID the realm lives in. Leave empty to locate it by realm name."},
				{Name: "window", Description: "Time window to review, for example 'this week'. Defaults to the last 7 days."},
			},
		},
		text: reviewAdminChangesText,
	},
	{
		write: true,
		scopes: []string{
			"clusters:read", "realms:read", "applications:read", "identity-providers:read", "domains:read",
			"clusters:write", "realms:write", "identity-providers:write", "smtp:write",
		},
		prompt: &mcp.Prompt{
			Name:        "provision_environment",
			Title:       "Provision an environment",
			Description: "Create a cluster, add a realm, and wire up an identity provider, confirming each step with the user first.",
			Arguments: []*mcp.PromptArgument{
				{Name: "cluster_name", Description: "Name for the new cluster.", Required: true},
				{Name: "location", Description: "Deployment region: us, ca, au or eu. Leave empty to pick one interactively."},
				{Name: "realm", Description: "Realm to create in the new cluster."},
				{Name: "identity_provider", Description: "Identity provider to wire up, for example microsoft-entra or google."},
			},
		},
		text: provisionEnvironmentText,
	},
	{
		write: true,
		scopes: []string{
			"clusters:read", "realms:read", "applications:read", "identity-providers:read",
			"domains:read", "domains:write", "applications:write", "realms:write",
			"smtp:write", "themes:write", "extensions:write", "clusters:exports:write",
		},
		prompt: &mcp.Prompt{
			Name:        "set_up_custom_domain",
			Title:       "Set up a custom domain",
			Description: "Add a custom domain to a cluster, route it to a realm, and hand back the exact DNS records to create.",
			Arguments: []*mcp.PromptArgument{
				{Name: "domain", Description: "The fully-qualified domain name, for example login.acme.com.", Required: true},
				{Name: "cluster_id", Description: "Cluster ID to attach the domain to. Leave empty to pick one interactively."},
				{Name: "realm", Description: "Realm the domain should serve."},
			},
		},
		text: setUpCustomDomainText,
	},
	{
		write: true,
		scopes: []string{
			"clusters:read", "realms:read", "applications:read", "identity-providers:read",
			"domains:read", "applications:write", "realms:write", "smtp:write",
			"domains:write", "themes:write", "extensions:write", "clusters:exports:write",
		},
		prompt: &mcp.Prompt{
			Name:        "rotate_client_secret",
			Title:       "Rotate a client secret",
			Description: "Regenerate an application's client secret and hand the new value to the user, with the blast radius spelled out first.",
			Arguments: []*mcp.PromptArgument{
				{Name: "client_id", Description: "The application client ID whose secret to rotate.", Required: true},
				{Name: "realm", Description: "The realm the application lives in.", Required: true},
				{Name: "cluster_id", Description: "Cluster ID the realm lives in. Leave empty to locate it by realm name."},
			},
		},
		text: rotateClientSecretText,
	},
}

// registerPrompts adds the prompts whose gating the session satisfies, using
// the same rules as tools: writes need allowWrites, and known scopes must
// cover the prompt.
func registerPrompts(s *mcp.Server, allowWrites bool, scopes Scopes) {
	for _, def := range promptDefs {
		if def.write && !allowWrites {
			continue
		}
		if !scopes.grants(def.scopes...) {
			continue
		}
		s.AddPrompt(def.prompt, promptHandler(def))
	}
}

func promptHandler(def promptDef) mcp.PromptHandler {
	return func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		var args map[string]string
		if req.Params != nil {
			args = req.Params.Arguments
		}
		for _, a := range def.prompt.Arguments {
			if a.Required && args[a.Name] == "" {
				return nil, fmt.Errorf("missing required argument %q", a.Name)
			}
		}
		return &mcp.GetPromptResult{
			Description: def.prompt.Description,
			Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{Text: def.text(args)}},
			},
		}, nil
	}
}

// arg returns the named argument, or fallback when it is absent or empty.
func arg(args map[string]string, name, fallback string) string {
	if v := args[name]; v != "" {
		return v
	}
	return fallback
}

// findRealmStep phrases the cluster-resolution step shared by the
// realm-scoped prompts.
func findRealmStep(args map[string]string, realm string) string {
	if id := args["cluster_id"]; id != "" {
		return fmt.Sprintf("1. Work against cluster %s.", id)
	}
	return fmt.Sprintf("1. Find the cluster: call skycloak_list_clusters, then skycloak_list_realms per cluster until you find realm %q. If it exists in more than one cluster, ask the user which one they mean.", realm)
}

func auditSelfRegistrationText(args map[string]string) string {
	scope := "every cluster in the workspace"
	first := "1. Call skycloak_list_clusters to enumerate the clusters."
	if id := args["cluster_id"]; id != "" {
		scope = "cluster " + id
		first = fmt.Sprintf("1. Work against cluster %s only.", id)
	}
	return fmt.Sprintf(`Audit which realms still have self-registration enabled. Scope: %s.

%s
2. For each cluster in scope, call skycloak_list_realms.
3. For each realm, call skycloak_get_login_branding and read registration_enabled.
4. Report a table grouped by cluster: realm, whether the realm is enabled, and whether self-registration is on. Flag every realm where self-registration is enabled, and call out realms that are disabled entirely.

This is a read-only audit: change nothing, only report. If skycloak_get_login_branding fails for one realm, note the failure and continue with the rest instead of stopping.`, scope, first)
}

func reviewUpgradesText(args map[string]string) string {
	first := "1. Call skycloak_list_clusters and note each cluster's type and version."
	if id := args["cluster_id"]; id != "" {
		first = fmt.Sprintf("1. Call skycloak_get_cluster with id=%s and note its type and version.", id)
	}
	return fmt.Sprintf(`Review Keycloak versions and plan upgrades.

%s
2. For each cluster type in use, call skycloak_list_cluster_versions to learn the newest available version.
3. Rank the clusters by how far behind they are. For the cluster furthest behind (or each cluster that is behind, if there are only a few), call skycloak_get_cluster_upgrade_path for the recommended step-by-step path.
4. Where useful, call skycloak_list_cluster_upgrades to show recent upgrade history, and note whether auto_upgrade_enabled is set.
5. Report per cluster: current version, latest version, how far behind, and the exact upgrade path. Do not start an upgrade: end with recommendations only.`, first)
}

func triageFailedLoginsText(args map[string]string) string {
	realm := args["realm"]
	limit := arg(args, "limit", "200")
	return fmt.Sprintf(`Investigate failed logins in realm %q.

%s
2. Call skycloak_query_events with category=user, realm=%q, search=LOGIN_ERROR and limit=%s. If the search matches nothing, pull without it and keep only events whose type is LOGIN_ERROR or whose error field is set. The tool has no time filter, so read the timestamp field yourself and state what window the returned events actually cover.
3. Group the failures by ip_address. For each IP report the attempt count, the usernames tried, the error codes, and the first and last timestamp.
4. Call out the patterns that matter: one IP trying many usernames (password spraying), many IPs trying one username (credential stuffing), and a single user failing repeatedly against one client_id (usually a misconfigured client, not an attack).
5. Cross-check suspicious IPs against skycloak_get_security_logs to see whether the WAF already saw or blocked them.
6. Report findings and suggest next steps, for example blocking at the edge or forcing a password reset. Take no action: this workflow is investigation only.`, realm, findRealmStep(args, realm), realm, limit)
}

func reviewIdentityProvidersText(args map[string]string) string {
	realm := args["realm"]
	check := "3. If the user asks about a specific provider, call skycloak_get_identity_provider with the alias exactly as the listing reports it (it is case-sensitive)."
	if p := args["provider"]; p != "" {
		check = fmt.Sprintf("3. Call skycloak_get_identity_provider with provider_id=%q for full details, and state plainly whether it is enabled. Use the alias exactly as the listing reports it (it is case-sensitive).", p)
	}
	return fmt.Sprintf(`Review how users can sign in to realm %q.

%s
2. Call skycloak_list_identity_providers for the realm. Report each provider's alias, type, display name and enabled state.
%s
4. Flag anything odd: a disabled provider users may still expect to work, or no providers at all, which means only realm-local credentials work.

This is a read-only review: do not enable, disable or reconfigure anything.`, realm, findRealmStep(args, realm), check)
}

func reviewAdminChangesText(args map[string]string) string {
	realm := args["realm"]
	window := arg(args, "window", "the last 7 days")
	return fmt.Sprintf(`Review recent admin activity in realm %q. Window: %s.

%s
2. Call skycloak_query_events with category=admin and realm=%q. The tool has no time filter: pull a generous limit (start at 200), filter by timestamp to the window yourself, and say so if the events returned do not reach back far enough to cover it.
3. Summarise the changes grouped by what was touched: realm settings, clients, users, identity providers, and so on. For each, show when it happened, the operation, and who did it where the event carries a username.
4. Look specifically for changes to login and security settings: realm updates, identity provider changes, authentication configuration, client secret rotations.
5. If nothing in the window touched login settings, say that explicitly rather than leaving it implied.`, realm, window, findRealmStep(args, realm), realm)
}

func provisionEnvironmentText(args map[string]string) string {
	name := args["cluster_name"]
	location := "The user did not pick a region: show the available ones and ask before going further."
	if l := args["location"]; l != "" {
		location = fmt.Sprintf("Target region: %s.", l)
	}
	realmStep := "3. If the user wants a realm in the new cluster, create it with skycloak_create_realm, confirming the name first."
	if r := args["realm"]; r != "" {
		realmStep = fmt.Sprintf("3. Create realm %q with skycloak_create_realm, confirming with the user first.", r)
	}
	idpStep := "4. If the user wants SSO, call skycloak_list_identity_provider_templates to find the matching template id."
	idp := args["identity_provider"]
	if idp != "" {
		idpStep = fmt.Sprintf("4. Call skycloak_list_identity_provider_templates and use the template id matching %q.", idp)
	}
	return fmt.Sprintf(`Provision a new environment around a cluster named %q. This workflow mutates the workspace: before every create call, show the user exactly what you are about to create with which parameters and wait for their explicit go-ahead.

1. Gather the options first: skycloak_list_cluster_locations, skycloak_list_cluster_types and skycloak_list_cluster_versions. %s Pick the newest available version unless the user says otherwise, and ask for a size rather than assuming one.
2. Once the user confirms, call skycloak_create_cluster. It is asynchronous: poll skycloak_get_cluster until status is 'available' before touching the cluster.
%s
%s Creating the provider needs the upstream client_id and client_secret: ask the user for them, never invent credentials, then call skycloak_create_identity_provider. Offer to verify the connection with skycloak_test_identity_provider afterwards.
5. Finish by reporting what now exists: cluster id and status, realm, providers, and anything left to do manually.

Never delete or overwrite anything in this workflow. If a name collides, stop and ask instead of picking a variant on your own.`, name, location, realmStep, idpStep)
}

func setUpCustomDomainText(args map[string]string) string {
	domain := args["domain"]
	first := "1. Ask which cluster the domain belongs on, using skycloak_list_clusters to show the options."
	if id := args["cluster_id"]; id != "" {
		first = fmt.Sprintf("1. Work against cluster %s.", id)
	}
	routeStep := "4. If the user wants the domain to serve a realm, confirm and call skycloak_create_domain_route after verification, using skycloak_list_realms to pick the realm."
	if r := args["realm"]; r != "" {
		routeStep = fmt.Sprintf("4. After verification, confirm and call skycloak_create_domain_route to point the domain at realm %q.", r)
	}
	return fmt.Sprintf(`Set up %q as a custom domain. This workflow mutates the cluster: confirm with the user before each create call.

%s
2. Confirm, then call skycloak_create_domain with domain=%q. The response lists the DNS records the user must create: relay them verbatim (type, name, value) and be explicit that the user creates them at their DNS provider, Skycloak cannot do that for them.
3. Once the user says the records are in place, call skycloak_verify_domain. DNS propagation can take a while: if verification does not pass, say so and suggest retrying later instead of looping on it.
%s Ask before enabling allow_admin_access; the safe default is off.
5. Finish with the domain's state from skycloak_get_domain: verification status, SSL status, routes, and any DNS records still pending.`, domain, first, domain, routeStep)
}

func rotateClientSecretText(args map[string]string) string {
	clientID := args["client_id"]
	realm := args["realm"]
	return fmt.Sprintf(`Rotate the client secret for application %q in realm %q.

%s
2. Call skycloak_get_application to confirm the client exists and is the one the user means (check the name and type). Only confidential clients have a secret to rotate.
3. Spell out the blast radius before doing anything: rotating invalidates the current secret immediately, and every service still using it fails to authenticate until it is updated. Where useful, call skycloak_list_application_sessions to show how much is live right now.
4. Ask the user to explicitly confirm the rotation. Do not proceed on an ambiguous answer.
5. Call skycloak_rotate_application_secret. The new secret is returned exactly once and cannot be retrieved later: give it to the user immediately and tell them to store it in their secret manager now.
6. Remind the user to update every deployment that still holds the old secret.`, clientID, realm, findRealmStep(args, realm))
}

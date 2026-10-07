# Skycloak

Skycloak is an identity-as-a-service provider, and its main managed option today is managed Keycloak. This
plugin lets you run your Skycloak workspace from a conversation with Claude: list and create clusters, manage
realms and applications, wire up enterprise single sign-on, and administer roles, groups and users. It bundles
the hosted Skycloak connector together with four operational skills that tell Claude how to use it.

## What it does

The plugin declares one remote connector, the hosted Skycloak MCP server at `https://mcp.skycloak.io`, which
exposes the Skycloak platform API as tools: clusters and their versions, realms, applications and application
roles, identity providers, domains, extensions, branding, realm roles, groups and users, exports and imports,
and audit events. Read-only tools are always available. Write tools are bounded by your workspace role and the
scopes of the session, so a read-only member cannot change anything whatever the tool list shows. Destructive
tools such as deleting a realm require an explicit confirmation argument.

Four skills ship with the plugin and load when the situation fits:

- `auth-incident-triage`: work out why users cannot log in, separating a platform problem from an attack and
  from a configuration change. Read-only.
- `enterprise-sso-rollout`: wire an enterprise identity provider into a realm end to end and verify it against
  real login events.
- `keycloak-migration-doctor`: preflight an export, import or migration, and diagnose a job that already failed.
- `keycloak-upgrade-readiness`: assess version drift, work out what a new Keycloak version breaks, and sequence
  the rollout with a rollback plan.

## How to use it

1. Install the plugin.
2. Open the plugin's Connectors tab and add or connect the Skycloak connector. In Claude Code the connector is
   loaded with the plugin.
3. Sign in when the browser opens. Authentication is OAuth against the Skycloak login realm, so there is no API
   key, client ID or other value to paste anywhere. The session is scoped to your Skycloak workspace.
4. Ask for what you need, for example "which of my Keycloak clusters are behind on upgrades?" or "create a
   staging realm on the EU cluster with Google sign-in".

The connector URL accepts two optional query parameters if you want to narrow a session. Append `?readonly=true`
to force a read-only tool surface, and `?workspace=<workspace-id>` to pin the session to one workspace when your
account can reach several. Both are optional, and the default URL in this plugin uses neither.

## What data it sends

Your requests, including the arguments Claude passes to each tool, go to `mcp.skycloak.io`, which calls the
Skycloak platform API on behalf of your workspace and returns the result. Sign-in goes through the Skycloak login
realm, and the access token from that flow is exchanged for a short-lived, workspace-scoped key that the session
runs on. Nothing is stored in your Claude configuration, and the plugin itself stores no data and contacts no
other service.

Skycloak's handling of that data is described in its [privacy policy](https://skycloak.io/pp/). The connector,
its authentication and its tool surface are documented at
[skycloak.io/docs/mcp](https://skycloak.io/docs/mcp/).

## License

[Apache-2.0](./LICENSE), the same license as the [skycloak-mcp](https://github.com/sky-cloak/skycloak-mcp)
repository this plugin lives in.

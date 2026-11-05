# Skycloak

Skycloak is an identity-as-a-service provider. Its main managed option today is managed Keycloak: you get
production Keycloak clusters, realms, applications and enterprise single sign-on without running the
infrastructure yourself.

This plugin connects your agent to the hosted Skycloak MCP server at `https://mcp.skycloak.io`, so you can run
your Skycloak workspace from a conversation. The same folder is the plugin bundle for Antigravity
(`.antigravity-plugin/plugin.json` plus `mcp_config.json`) and for Claude (`.claude-plugin/plugin.json`).

## What you can do with it

The plugin declares one remote MCP server, which exposes the Skycloak platform API as tools:

- **Clusters.** List clusters and their locations, types, versions and features, create a cluster, read its
  insights and security posture, plan and sequence upgrades, set a maintenance window, restart instances.
- **Realms.** List, read, create and delete realms, manage realm roles and groups, configure login and email
  branding, export a realm and import one back.
- **Applications.** Create and update applications (Keycloak clients), manage application roles and their
  assignments, inspect active sessions, rotate a client secret.
- **Single sign-on.** Browse identity provider templates, create and configure an identity provider on a realm,
  and test it before you hand it to users.
- **Users.** List, read, create, update and delete realm users, assign and remove roles, add and remove group
  memberships.
- **Custom domains.** Create a domain and its routes, verify it, and manage CAPTCHA domains on a cluster.
- **Audit events.** Query login and admin events, export them, read security logs, and send them to a SIEM
  destination or a webhook subscription.

Read-only tools are always available. Write tools are bounded by your workspace role and the scopes of the
session, so a read-only member cannot change anything whatever the tool list shows. Destructive tools such as
deleting a realm require an explicit confirmation argument.

## Bundled skills

Four skills ship with the plugin and load when the situation fits:

- `auth-incident-triage`: work out why users cannot log in, separating a platform problem from an attack and
  from a configuration change. Read-only.
- `enterprise-sso-rollout`: wire an enterprise identity provider into a realm end to end and verify it against
  real login events.
- `keycloak-migration-doctor`: preflight an export, import or migration, and diagnose a job that already failed.
- `keycloak-upgrade-readiness`: assess version drift, work out what a new Keycloak version breaks, and sequence
  the rollout with a rollback plan.

They are byte-for-byte copies of the skills the server itself serves from `internal/tools/skills/`, because an
installer receives only this folder. A test in the repository fails if the two sides drift.

## Setup

1. Install the plugin from your client's marketplace, or point your CLI at this folder:

   ```bash
   agy plugin install ./plugins/skycloak          # Antigravity
   claude plugin validate ./plugins/skycloak      # Claude, before submitting
   ```

2. Sign in when your browser opens. Authentication is OAuth 2.1 against the Skycloak login realm, so there is no
   API key, client ID or other value to paste anywhere. The session is scoped to your Skycloak workspace.

3. Ask for what you need, for example "which of my Keycloak clusters are behind on upgrades?" or "create a
   staging realm on the EU cluster and connect Google sign-in".

You need a Skycloak account at [app.skycloak.io](https://app.skycloak.io). Without one the plugin installs and
signs in, but has no workspace to act on.

### Narrowing a session

The server URL accepts two optional query parameters. Append `?readonly=true` to force a read-only tool surface,
and `?workspace=<workspace-id>` to pin the session to one workspace when your account can reach several. The
default URL in this plugin uses neither.

## What data it sends

Your requests, including the arguments the agent passes to each tool, go to `mcp.skycloak.io`, which calls the
Skycloak platform API on behalf of your workspace and returns the result. Sign-in goes through the Skycloak login
realm, and the access token from that flow is exchanged for a short-lived, workspace-scoped key that the session
runs on. The plugin itself stores no data and contacts no other service.

Skycloak's handling of that data is described in its [privacy policy](https://skycloak.io/pp/). The server, its
authentication and its tool surface are documented at [skycloak.io/docs/mcp](https://skycloak.io/docs/mcp/).

## Directory updates

The Claude and Antigravity listings track `main` and rescan the commits on it, so every release has to leave a
new `version` on main for the directories to pick the change up. Four manifests carry that version:

- [`.claude-plugin/plugin.json`](./.claude-plugin/plugin.json)
- [`.antigravity-plugin/plugin.json`](./.antigravity-plugin/plugin.json)
- the [`plugin.json`](../../plugin.json) at the repository root, for Copilot and Agent Plugins
- the [`.grok-plugin/plugin.json`](../../.grok-plugin/plugin.json) at the repository root, for Grok

CI does the bump. When a `v*` tag is pushed, the `sync-plugin-manifests` job in
[`release.yml`](../../.github/workflows/release.yml) sets all four `version` fields to the tag without its
leading `v` and commits the result to main. So releasing is enough, and a pull request that changes the plugin,
a manifest or a skill does not need to touch a version field.

Edit a `version` by hand only to repair a lag, when main is behind the newest release tag. Keep the four values
identical when you do, and use the version of the existing tag rather than inventing a bump.

## Support

Open an issue on [github.com/sky-cloak/skycloak-mcp](https://github.com/sky-cloak/skycloak-mcp/issues), or write
to [support@skycloak.io](mailto:support@skycloak.io).

## License

[Apache-2.0](./LICENSE), the same license as the
[skycloak-mcp](https://github.com/sky-cloak/skycloak-mcp) repository this plugin lives in.

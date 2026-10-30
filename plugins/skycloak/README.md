# Skycloak

Skycloak is an identity-as-a-service provider. Its main managed option today is managed Keycloak: you get
production Keycloak clusters, realms, applications and enterprise single sign-on without running the
infrastructure yourself.

This plugin connects Antigravity to the hosted Skycloak MCP server at `https://mcp.skycloak.io`, so you can run
your Skycloak workspace from a conversation.

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

## Setup

1. Install the plugin from the Antigravity Marketplace, or point the CLI at this folder:

   ```bash
   agy plugin install ./plugins/skycloak
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

## Support

Open an issue on [github.com/sky-cloak/skycloak-mcp](https://github.com/sky-cloak/skycloak-mcp/issues), or write
to [support@skycloak.io](mailto:support@skycloak.io).

## License

[Apache-2.0](https://github.com/sky-cloak/skycloak-mcp/blob/main/LICENSE), the same license as the
[skycloak-mcp](https://github.com/sky-cloak/skycloak-mcp) repository this plugin lives in.

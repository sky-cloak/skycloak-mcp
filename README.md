# skycloak-mcp

Official [Model Context Protocol](https://modelcontextprotocol.io) server for **Skycloak** (managed Keycloak): manage your clusters, realms, applications, and SSO from any MCP client (Claude Desktop, Claude Code, Cursor).

> **Status:** early release. Tool coverage is growing; see the changelog for what's available.

## Authentication & safety

- **Hosted HTTP, with OAuth (no credential to configure).** Point your client at `https://mcp.skycloak.io` with no header. The server answers `401` with a pointer to its [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) metadata at `/.well-known/oauth-protected-resource`, the client runs the browser authorization-code flow against the Skycloak login realm, and the access token it gets back is exchanged for a short-lived, workspace-scoped API key that the session runs on. The key lasts an hour and is renewed automatically. Nothing is stored in your client configuration.
- **Hosted HTTP, with an API key.** Create a key in the [Skycloak dashboard](https://app.skycloak.io) and send it as `Authorization: Bearer <key>` (or `API-Key: <key>`). Every request carries its own credential and acts only as that credential's workspace. The server keeps no session state, so a request never inherits another caller's. Keys are not verified before use: the Skycloak API is the authority, so an invalid key surfaces as a `401` on the first tool call rather than at connect time.
- **Tools match your role.** Over OAuth, the tool list is trimmed to what the session's scopes allow, so a read-only workspace member is not shown write tools that would answer `403`. With an API key the whole surface is registered, because a key's scopes are not visible to the server, and an unauthorized call surfaces as a `403` from the API.
- **Local stdio.** Run `skycloak-mcp init` and approve in your browser (OAuth 2.0 device authorization flow). It mints a workspace-scoped API key, stores it in your operating-system keychain, and detects your default workspace automatically (pass `--workspace <id>` to pick another). `skycloak-mcp logout` removes the stored key.
- **Headless / CI.** Set the `SKYCLOAK_API_KEY` environment variable (create a key in the [Skycloak dashboard](https://app.skycloak.io)) to skip the browser entirely. It always takes precedence over the keychain.
- **Read-only by default.** Mutating tools are registered only when the server starts with `--allow-writes`.
- **Cluster credentials are opt-in.** `get_cluster_credentials` returns a cluster's Keycloak admin credentials, which an assistant holding the key would then see, so `init` does not request that scope by default. Use a key that carries it: create one in the dashboard, or over stdio sign in with `skycloak-mcp init --allow-credentials`. Without it the tool returns a 403 that explains both routes.
- **Destructive tools require confirmation:** deleting a realm, for example, needs an explicit `confirm=true` argument.
- Requests are rate limited according to your Skycloak plan; on a `429` response the server surfaces `Retry-After`.

## Tools

Read-only tools are always available. **Write** tools are registered only when the server is started with `--allow-writes`.

| Area | Read-only | Write (`--allow-writes`) |
|---|---|---|
| Clusters | `list_clusters`, `get_cluster`, `list_cluster_locations`, `list_cluster_types`, `list_cluster_features`, `list_cluster_versions`, `list_cluster_upgrades`, `get_cluster_upgrade_path`, `get_cluster_credentials`, `get_cluster_insights`, `get_cluster_maintenance_window` | `create_cluster`, `update_cluster`, `delete_cluster`, `cancel_cluster_upgrade`, `set_cluster_maintenance_window`, `delete_cluster_maintenance_window` |
| Edge security | `get_cluster_security`, `list_cluster_captcha_domains` | `update_cluster_security`, `add_cluster_captcha_domain`, `remove_cluster_captcha_domain` |
| Realms | `list_realms`, `get_realm` | `create_realm`, `update_realm`, `delete_realm` |
| Applications | `list_applications`, `get_application`, `list_application_roles`, `list_application_sessions` | `create_application`, `update_application`, `delete_application`, `assign_application_role`, `remove_application_role`, `rotate_application_secret` |
| Identity providers | `list_identity_providers`, `get_identity_provider`, `list_identity_provider_templates`, `discover_oidc` | `create_identity_provider` (OIDC), `update_identity_provider`, `delete_identity_provider`, `test_identity_provider` |
| Users, roles & groups | `list_realm_users`, `get_realm_user`, `list_realm_roles`, `get_realm_role`, `list_realm_groups`, `get_realm_group`, `list_realm_group_members`, `list_user_roles`, `list_user_groups` | `create_realm_user`, `update_realm_user`, `delete_realm_user`, `create_realm_role`, `update_realm_role`, `delete_realm_role`, `create_realm_group`, `update_realm_group`, `delete_realm_group`, `assign_realm_user_role`, `remove_realm_user_role`, `add_realm_user_to_group`, `remove_realm_user_from_group` |
| Custom domains | `list_domains`, `get_domain`, `list_domain_routes`, `get_domain_route` | `create_domain`, `verify_domain`, `delete_domain`, `create_domain_route`, `update_domain_route`, `delete_domain_route` |
| Branding & themes | `list_themes`, `get_theme`, `get_theme_assignment`, `get_client_theme_assignment`, `get_login_branding`, `get_email_branding`, `download_theme_content` | `set_theme_assignment`, `set_client_theme_assignment`, `update_theme`, `delete_theme`, `upsert_login_branding`, `delete_login_branding`, `upsert_email_branding`, `delete_email_branding` |
| Extensions | `list_extensions`, `list_cluster_extensions` | `install_extension`, `upgrade_extension`, `update_extension`, `uninstall_extension`, `delete_extension` |
| SMTP | `get_smtp` | `upsert_smtp`, `delete_smtp`, `test_smtp` |
| Exports & logs | `list_exports`, `get_export`, `get_logs`, `get_security_logs`, `query_events` | `create_export`, `delete_export`, `export_cluster_events` |
| Realm import & export | `get_realm_export`, `get_realm_import` | `create_realm_export`, `create_realm_import`, `create_realm_import_upload_url` |
| SIEM | `list_siem_destinations`, `get_siem_destination` | `create_siem_destination`, `update_siem_destination`, `delete_siem_destination`, `test_siem_destination` |
| Webhooks | `list_webhook_event_types`, `list_webhook_subscriptions`, `get_webhook_subscription` | `create_webhook_subscription`, `update_webhook_subscription`, `delete_webhook_subscription`, `test_webhook_subscription` |

**Conventions:** destructive tools (`delete_*`, `uninstall_extension`, `cancel_cluster_upgrade`) require `confirm=true`. `create_cluster` is asynchronous: poll `get_cluster` until the cluster is `available`. `create_domain` returns the DNS records the customer must create; `verify_domain` triggers a DNS check. `set_theme_assignment` activates a custom theme per Keycloak theme type (empty string resets to the built-in default). `update_cluster_security` leaves CAPTCHA settings untouched. Realm import/export moves one realm's configuration and is separate from `create_export`, which dumps a whole cluster's database: both are asynchronous, and the realm archive is always encrypted, so the password used to export it is needed to import it again. A realm can be imported straight from an existing export (`source_export_id`) or from an uploaded archive (`create_realm_import_upload_url`, PUT, then `upload_s3_key`); importing creates a realm and refuses a name collision rather than overwriting, and needs `confirm=true` because it brings users and credentials with it.

## Connecting

For hosted HTTP the simplest route is OAuth, which needs no credential at all:

```bash
claude mcp add --transport http skycloak https://mcp.skycloak.io
```

The first call opens your browser, you approve in the Skycloak login page, and the tools appear. If you belong to more than one workspace, name the one you want:

```bash
claude mcp add --transport http skycloak "https://mcp.skycloak.io?workspace=<workspace-id>"
```

Otherwise, create an API key in the Skycloak dashboard and configure your MCP client to send it as a bearer token:

```bash
claude mcp add --transport http skycloak https://mcp.skycloak.io --header "Authorization: Bearer sk_sc_XXX"
```

This adds the following to `.claude.json`:

```json
{
  "mcpServers": {
    "skycloak": {
      "type": "http",
      "url": "https://mcp.skycloak.io",
      "headers": {
        "Authorization": "Bearer sk_sc_XXX"
      }
    }
  }
}
```

For local stdio, sign in once, then point your client at `skycloak-mcp run`:

```bash
skycloak-mcp init        # one-time browser sign-in; stores a key in your keychain
```

**Claude Desktop / Cursor** (local, stdio):

```jsonc
{
  "mcpServers": {
    "skycloak": {
      "command": "skycloak-mcp",
      "args": ["run", "--transport", "stdio"]
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add skycloak -- skycloak-mcp run --transport stdio
```

For headless / CI (no browser), skip `init` and pass the key instead: add `"env": { "SKYCLOAK_API_KEY": "sk_sc_..." }` to the config, or `claude mcp add skycloak --env SKYCLOAK_API_KEY=sk_sc_... -- skycloak-mcp run --transport stdio`.

Add `--allow-writes` only when you intend to make changes (sign in with `skycloak-mcp init --allow-writes`, or use a write-scoped key).

Add `?readonly=true` to a hosted HTTP URL to expose only read-only tools for that HTTP session, or `?readonly=false` to request the write-capable tool surface. The query parameter defaults to `false`, but write tools are registered only when the server was started with `--allow-writes`.

Add `?workspace=<uuid>` to pick which workspace an OAuth session acts on. It is only needed when you belong to more than one; with a single workspace the server picks it for you, and if you belong to several and name none, the connection fails with a message listing them.

### Running the HTTP transport

```bash
skycloak-mcp run --transport http --http-addr :8080
```

It needs no credential of its own: callers supply theirs per request, so nothing is injected at deploy time. `GET /healthz` and `GET /readyz` are unauthenticated and report only that the process is up; they deliberately do not probe the Skycloak API, so an upstream blip cannot fail every replica's probe at once. The server holds no session state, so replicas need no session affinity and can be scaled or rolled freely. `SIGTERM` stops new connections and drains in-flight calls.

The OAuth path is on whenever `SKYCLOAK_ISSUER` and `SKYCLOAK_DASHBOARD_URL` are set, which they are by default. `GET /.well-known/oauth-protected-resource` is then served unauthenticated, naming the realm as the authorization server. Its `resource` value is taken from `SKYCLOAK_PUBLIC_URL` when set, and otherwise from the request's own scheme and `Host` (honouring `X-Forwarded-Proto`), so a single-host deployment behind an ingress needs no extra configuration. Set `SKYCLOAK_PUBLIC_URL` if your ingress rewrites `Host`. Blanking either of the issuer or dashboard variables turns OAuth off entirely, and the server goes back to challenging for an API key and nothing else.

## Configuration

| Env var | Default |
|---|---|
| `SKYCLOAK_API_KEY` | none (optional for stdio; HTTP clients provide `API-Key` headers instead) |
| `SKYCLOAK_ENDPOINT` | `https://api.skycloak.io` |
| `SKYCLOAK_API_VERSION` | current API version |
| `SKYCLOAK_ISSUER` | `https://login.app.skycloak.io/realms/skycloak` (CLI sign-in, and the authorization server the HTTP transport verifies tokens against) |
| `SKYCLOAK_CLIENT_ID` | `skycloak-mcp` (CLI device flow only) |
| `SKYCLOAK_DASHBOARD_URL` | `https://app.skycloak.io` (mints CLI keys and HTTP session keys) |
| `SKYCLOAK_PUBLIC_URL` | none (derived from each request; set it when the ingress rewrites `Host`) |

Commands: `init` (browser sign-in), `run` (serve), `logout` (remove the stored key). `init` accepts `--workspace <id>`, `--allow-writes`, `--allow-credentials`, and `--ttl-days` (default 90).

| Flag | Default | Description |
|---|---|---|
| `--transport` | `stdio` | `stdio` or `http` |
| `--http-addr` | `:8080` | listen address for the HTTP transport |
| `--allow-writes` | `false` | enable mutating tools for stdio and permit HTTP sessions with `readonly=false` to register write tools |

## Development

```bash
make build      # build the server binary
make test       # unit tests
make run        # run on stdio for local testing
make inspector  # MCP Inspector against the local binary
make lint       # golangci-lint
make generate   # regenerate the API client from the OpenAPI spec
```

The API client under `internal/apiclient` is generated from the Skycloak OpenAPI
specification with [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen).

## Keeping in sync with the API

The client in `internal/apiclient` is generated from `internal/apiclient/openapi.yaml` with [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen); run `make generate` to refresh it. CI fails if the committed generated code drifts from the spec. Requests are retried on `429`/`5xx` with `Retry-After`-aware backoff.

## Distribution

Released as GitHub binaries + a `ghcr.io/sky-cloak/skycloak-mcp` container image on each tag. See [DISTRIBUTION.md](./DISTRIBUTION.md) for the discovery channels (MCP Registry, Claude/Cursor directories).

## License

[Apache-2.0](./LICENSE).

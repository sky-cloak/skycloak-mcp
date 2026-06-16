# skycloak-mcp

Official [Model Context Protocol](https://modelcontextprotocol.io) server for **Skycloak** — manage your managed-Keycloak environment from any MCP client (Claude Desktop, Claude Code, Cursor). Sign in once with your browser; no API key to copy or paste.

> **Status:** early release. Tool coverage is growing; see the changelog for what's available.

## Authentication & safety

- **Sign in once:** run `skycloak-mcp init` and approve in your browser (OAuth 2.0 device authorization flow). It mints a workspace-scoped API key and stores it in your operating-system keychain — nothing to copy or paste. `skycloak-mcp logout` removes it.
- **Headless / CI:** set the `SKYCLOAK_API_KEY` environment variable (create a key in the [Skycloak dashboard](https://app.skycloak.io)) to skip the browser entirely. It always takes precedence over the keychain.
- Requests are rate limited according to your Skycloak plan; on a `429` response the server surfaces `Retry-After`.
- **Read-only by default.** Mutating tools are only registered when the server is started with `--allow-writes`.
- **Destructive tools require confirmation** — e.g. deleting a realm requires an explicit `confirm=true` argument.

## Tools

Read-only tools are always available. **Write** tools are registered only when the server is started with `--allow-writes`.

| Area | Read-only | Write (`--allow-writes`) |
|---|---|---|
| Clusters | `list_clusters`, `get_cluster`, `list_cluster_locations`, `list_cluster_types`, `list_cluster_features`, `list_cluster_versions`, `list_cluster_upgrades`, `get_cluster_upgrade_path`, `get_cluster_credentials`, `get_cluster_insights` | `create_cluster`, `update_cluster`, `delete_cluster`, `cancel_cluster_upgrade` |
| Edge security | `get_cluster_security` | `update_cluster_security` |
| Realms | `list_realms`, `get_realm` | `create_realm`, `update_realm`, `delete_realm` |
| Applications | `list_applications`, `get_application`, `list_application_roles`, `list_application_sessions` | `create_application`, `update_application`, `delete_application`, `assign_application_role`, `remove_application_role`, `rotate_application_secret` |
| Identity providers | `list_identity_providers`, `get_identity_provider`, `list_identity_provider_templates`, `discover_oidc` | `create_identity_provider` (OIDC), `update_identity_provider`, `delete_identity_provider`, `test_identity_provider` |
| Users, roles & groups | `list_realm_users`, `get_realm_user`, `list_realm_roles`, `get_realm_role`, `list_realm_groups`, `get_realm_group`, `list_realm_group_members`, `list_user_roles`, `list_user_groups` | `create_realm_user`, `update_realm_user`, `delete_realm_user`, `create_realm_role`, `update_realm_role`, `delete_realm_role`, `create_realm_group`, `update_realm_group`, `delete_realm_group`, `assign_realm_user_role`, `remove_realm_user_role`, `add_realm_user_to_group`, `remove_realm_user_from_group` |
| Custom domains | `list_domains`, `get_domain`, `list_domain_routes`, `get_domain_route` | `create_domain`, `verify_domain`, `delete_domain`, `create_domain_route`, `update_domain_route`, `delete_domain_route` |
| Branding & themes | `list_themes`, `get_theme`, `get_theme_assignment`, `get_client_theme_assignment`, `get_login_branding`, `get_email_branding` | `set_theme_assignment`, `set_client_theme_assignment`, `update_theme`, `delete_theme`, `upsert_login_branding`, `delete_login_branding`, `upsert_email_branding`, `delete_email_branding` |
| Extensions | `list_extensions`, `list_cluster_extensions` | `install_extension`, `upgrade_extension`, `update_extension`, `uninstall_extension`, `delete_extension` |
| SMTP | `get_smtp` | `upsert_smtp`, `delete_smtp`, `test_smtp` |
| Exports & logs | `list_exports`, `get_export`, `get_logs`, `get_security_logs`, `query_events` | `create_export`, `delete_export`, `export_cluster_events` |

**Conventions:** destructive tools (`delete_*`, `uninstall_extension`, `cancel_cluster_upgrade`) require `confirm=true`. `create_cluster` is asynchronous — poll `get_cluster` until the cluster is `available`. `create_domain` returns the DNS records the customer must create; `verify_domain` triggers a DNS check. `set_theme_assignment` activates a custom theme per Keycloak theme type (empty string resets to the built-in default). `update_cluster_security` leaves CAPTCHA settings untouched.

## Connecting

Sign in once, then point your client at `skycloak-mcp run`:

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

The server also supports a streamable-HTTP transport (`run --transport http`) for hosted/remote use.

## Configuration

| Env var | Default |
|---|---|
| `SKYCLOAK_API_KEY` | — (optional; for headless/CI. Otherwise sign in with `skycloak-mcp init`) |
| `SKYCLOAK_ENDPOINT` | `https://api.skycloak.io` |
| `SKYCLOAK_API_VERSION` | current API version |
| `SKYCLOAK_ISSUER` | `https://login.app.skycloak.io/realms/skycloak` |
| `SKYCLOAK_CLIENT_ID` | `skycloak-mcp` |
| `SKYCLOAK_DASHBOARD_URL` | `https://app.skycloak.io` |

Commands: `init` (browser sign-in), `run` (serve), `logout` (remove the stored key). `init` accepts `--workspace <id>`, `--allow-writes`, and `--ttl-days` (default 90).

| Flag | Default | Description |
|---|---|---|
| `--transport` | `stdio` | `stdio` or `http` |
| `--http-addr` | `:8080` | listen address for the http transport |
| `--allow-writes` | `false` | enable mutating tools |

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

The client in `internal/apiclient` is generated from `internal/apiclient/openapi.yaml` with [oapi-codegen](https://github.com/oapi-codegen/oapi-codegen) — run `make generate` to refresh it. CI fails if the committed generated code drifts from the spec. Requests are retried on `429`/`5xx` with `Retry-After`-aware backoff.

## Distribution

Released as GitHub binaries + a `ghcr.io/sky-cloak/skycloak-mcp` container image on each tag. See [DISTRIBUTION.md](./DISTRIBUTION.md) for the discovery channels (MCP Registry, Claude/Cursor directories).

## License

[Apache-2.0](./LICENSE).

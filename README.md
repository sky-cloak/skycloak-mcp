# skycloak-mcp

Official [Model Context Protocol](https://modelcontextprotocol.io) server for **Skycloak** — manage your managed-Keycloak environment from any MCP client (Claude Desktop, Claude Code, Cursor) using your Skycloak API key.

> **Status:** early release. Tool coverage is growing; see the changelog for what's available.

## Authentication & safety

- Set your API key via the `SKYCLOAK_API_KEY` environment variable (create a key in the [Skycloak dashboard](https://app.skycloak.io)). The connection is scoped to that key's workspace.
- Requests are rate limited according to your Skycloak plan; on a `429` response the server surfaces `Retry-After`.
- **Read-only by default.** Mutating tools are only registered when the server is started with `--allow-writes`.
- **Destructive tools require confirmation** — e.g. deleting a realm requires an explicit `confirm=true` argument.

## Tools

**Read-only** (always available): `list_clusters`, `get_cluster`, `list_realms`, `list_applications`, `list_identity_providers`, `get_logs`, `get_security_logs`, `query_events`, `list_domains`, `get_domain`, `list_themes`, `get_theme_assignment`, `get_login_branding`, `get_email_branding`, `list_extensions`, `list_cluster_extensions`, `list_exports`, `get_export`, `list_realm_roles`, `list_realm_groups`, `list_realm_users`, `get_realm_user`, `list_application_roles`, `list_application_sessions`, `get_realm`, `get_application`, `get_identity_provider`, `list_cluster_locations`, `list_cluster_types`, `list_cluster_features`, `list_cluster_versions`, `list_cluster_upgrades`, `list_identity_provider_templates`, `list_domain_routes`, `get_smtp`, `get_theme`, `get_domain_route`, `get_client_theme_assignment`, `list_user_roles`, `list_user_groups`, `discover_oidc`, `get_cluster_security`, `get_cluster_credentials`, `list_cluster_builds`, `get_cluster_build`, `get_cluster_upgrade_path`, `get_cluster_insights`, `get_realm_role`, `get_realm_group`, `list_realm_group_members`, `export_cluster_events`.

**Write** (require `--allow-writes`): `create_cluster`, `delete_cluster`, `create_realm`, `delete_realm`, `create_application`, `delete_application`, `create_identity_provider` (OIDC), `delete_identity_provider`, `create_domain`, `verify_domain`, `delete_domain`, `set_theme_assignment`, `install_extension`, `upgrade_extension`, `uninstall_extension`, `create_export`, `create_realm_role`, `delete_realm_role`, `create_realm_group`, `delete_realm_group`, `create_realm_user`, `delete_realm_user`, `assign_realm_user_role`, `remove_realm_user_role`, `add_realm_user_to_group`, `remove_realm_user_from_group`, `assign_application_role`, `remove_application_role`, `rotate_application_secret`, `update_realm`, `delete_smtp`, `create_domain_route`, `delete_domain_route`, `set_client_theme_assignment`, `delete_theme`, `delete_extension`, `delete_export`, `test_smtp`, `test_identity_provider`, `cancel_cluster_upgrade`, `update_cluster_security`, `update_realm_role`, `update_realm_group`, `update_realm_user`, `update_application`, `update_identity_provider`, `update_cluster`, `update_extension`, `update_theme`, `update_domain_route`, `upsert_smtp`, `upsert_login_branding`, `upsert_email_branding`, `delete_login_branding`, `delete_email_branding`. Destructive tools (`delete_*`) require `confirm=true`. `create_cluster` is asynchronous — poll `get_cluster` until the cluster is `available`. `create_domain` returns the DNS records the customer must create; `verify_domain` triggers a DNS check. `set_theme_assignment` activates a custom theme per Keycloak theme type (empty string resets to the built-in default).

## Connecting

**Claude Desktop / Cursor** (local, stdio):

```jsonc
{
  "mcpServers": {
    "skycloak": {
      "command": "skycloak-mcp",
      "args": ["--transport", "stdio"],
      "env": { "SKYCLOAK_API_KEY": "sk_sc_..." }
    }
  }
}
```

**Claude Code:**

```bash
claude mcp add skycloak --env SKYCLOAK_API_KEY=sk_sc_... -- skycloak-mcp --transport stdio
```

Add `--allow-writes` only when you intend to make changes (and use a key scoped for it).

The server also supports a streamable-HTTP transport (`--transport http`) for hosted/remote use.

## Configuration

| Env var | Default |
|---|---|
| `SKYCLOAK_API_KEY` | — (required) |
| `SKYCLOAK_ENDPOINT` | `https://api.skycloak.io` |
| `SKYCLOAK_API_VERSION` | current API version |

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

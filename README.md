# skycloak-mcp

Official [Model Context Protocol](https://modelcontextprotocol.io) server for **Skycloak** — manage your managed-Keycloak environment from any MCP client (Claude Desktop, Claude Code, Cursor) using your Skycloak API key.

> **Status:** early release. Tool coverage is growing; see the changelog for what's available.

## Authentication & safety

- Set your API key via the `SKYCLOAK_API_KEY` environment variable (create a key in the [Skycloak dashboard](https://app.skycloak.io)). The connection is scoped to that key's workspace.
- Requests are rate limited according to your Skycloak plan; on a `429` response the server surfaces `Retry-After`.
- **Read-only by default.** Mutating tools are only registered when the server is started with `--allow-writes`.
- **Destructive tools require confirmation** — e.g. deleting a realm requires an explicit `confirm=true` argument.

## Tools

**Read-only** (always available): `list_clusters`, `get_cluster`, `list_realms`, `list_applications`, `list_identity_providers`.

**Write** (require `--allow-writes`): `create_realm`, `delete_realm` (destructive — requires `confirm=true`).

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

## License

[Apache-2.0](./LICENSE).

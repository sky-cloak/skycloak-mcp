# Distribution & discovery

How `skycloak-mcp` is shipped and where it's listed. Beyond being installable, the
public listings are a **marketing surface** — every catalog entry is a place an
AI-assistant user discovers Skycloak.

## Artifacts (produced automatically on each `vX.Y.Z` tag)

| Artifact | Where | How users consume it |
|---|---|---|
| Multi-arch binaries + checksums | GitHub Release | `go install`, or download + point the MCP client at the binary |
| Container image | `ghcr.io/sky-cloak/skycloak-mcp` | `docker run` / reference in client config |

No registry is *required* for the server to work — a user just adds the stdio
command (or hosted URL) to their MCP client config. The channels below are for
**discovery**.

## Discovery channels (do these once the repo + image are public)

1. **Official MCP Registry** — `registry.modelcontextprotocol.io`
   - Listing metadata lives in [`server.json`](./server.json) (namespace `io.skycloak/skycloak-mcp`).
   - Publish with the `mcp-publisher` CLI:
     ```bash
     mcp-publisher validate server.json
     mcp-publisher login dns --domain skycloak.io   # or: login github (namespace io.github.sky-cloak/*)
     mcp-publisher publish
     ```
   - The `io.skycloak/*` namespace requires **DNS ownership verification** of `skycloak.io`. (Alternatively use `io.github.sky-cloak/skycloak-mcp` with GitHub auth — less branded.)

2. **Anthropic / Claude connectors directory** — submit so Claude Desktop/Code users can add it in-app. (Highest-value channel for reach.)

3. **Cursor MCP directory** and **VS Code MCP** lists — submit the stdio config + repo.

4. **Community catalogs** — e.g. `modelcontextprotocol/servers`, `punkpeye/awesome-mcp-servers`. Open a PR adding Skycloak with a one-line pitch.

## Marketing notes
- Keep the `server.json` `description` and each catalog blurb leading with the value prop ("manage managed-Keycloak from your AI assistant") and a link to `https://app.skycloak.io` for signup.
- Bump `version` in `server.json` on each release and re-`publish` so the registry tracks the latest.

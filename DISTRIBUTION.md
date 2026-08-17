# Distribution & discovery

How `skycloak-mcp` reaches users and where it's listed. Beyond being usable, the
public listings are a **marketing surface**: every catalog entry is a place an
AI-assistant user discovers Skycloak.

## What is public today

| Surface | Status |
|---|---|
| Hosted server, `https://mcp.skycloak.io` | **Public and live.** Streamable HTTP, browser OAuth, nothing to install |
| This repository | Private |
| `ghcr.io/sky-cloak/skycloak-mcp` image | Private |
| GitHub Release binaries | Not published |

So the hosted endpoint is the whole public product right now. Every listing, doc
and post should point at the URL, and none should mention Homebrew, the container
image, a downloadable binary, or a stdio config, because a reader cannot obtain any
of them.

## Discovery channels

**None of these are blocked on opening the repo.** The official registry lists
remote servers with no repository and no package at all: of the first 60 entries
returned by the registry API, 49 are remote-only with `repository: null`. That is
the shape [`server.json`](./server.json) now uses.

1. **Official MCP Registry** (`registry.modelcontextprotocol.io`). **Automated.** The
   `publish-registry` job in [`release.yml`](./.github/workflows/release.yml) runs on
   every `v*` tag, after goreleaser succeeds. It pins `server.json` to the tag, so the
   published version can never drift from the release, then signs with DNS auth.

   One-time setup, already done:
   - TXT record on the **apex** of `skycloak.io`: `v=MCPv1; k=ed25519; p=<public key>`
   - Repo secret `MCP_DNS_PRIVATE_KEY` holding the Ed25519 private key as 64 hex chars

   OIDC is not an option here. It only authenticates the `io.github.*` namespace, and
   this server is `io.skycloak/*`, which is DNS-verified.

   To publish by hand:
   ```bash
   mcp-publisher validate server.json
   mcp-publisher login dns --domain skycloak.io --private-key "$PRIV"
   mcp-publisher publish
   ```

2. **Anthropic / Claude connectors directory**. Highest-value channel for reach, and
   a remote URL is exactly what it wants.

3. **Cursor MCP directory**, **VS Code MCP** lists. Submit the hosted URL, not a
   stdio config.

4. **Community catalogs**: `mcp.so`, `glama.ai/mcp/servers`, `smithery.ai`,
   `PulseMCP`, `punkpeye/awesome-mcp-servers`. Open a PR or fill the form with a
   one-line pitch and the hosted URL.

Where a form demands a repository or GitHub link, use `https://skycloak.io/docs/mcp/`.
Do not link this repo until it is public.

## Loose end

The server advertises `resource_documentation: https://github.com/sky-cloak/skycloak-mcp`
in its OAuth protected-resource metadata, which is a public 404 today. Either open the
repo or repoint that field at the docs page.

## When the repo and image go public

Re-add to `server.json` the `repository` block and a `packages` entry for the OCI image
(`registryType: oci`, `transport: stdio`), keeping `remotes` alongside them so clients can
pick either. Then re-publish. Nothing else in this document changes.

## Marketing notes

- Lead every blurb with the value prop ("manage managed-Keycloak from your AI assistant")
  and link `https://app.skycloak.io` for signup.
- Bump `version` in `server.json` on each release and re-publish so the registry tracks
  the latest.

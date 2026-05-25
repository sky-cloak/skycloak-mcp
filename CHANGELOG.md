# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MCP server with stdio and streamable-HTTP transports, built on the official Go MCP SDK.
- API-key authentication (`SKYCLOAK_API_KEY`) scoped to the key's workspace.
- `--allow-writes` gate (default off) separating the read-only and mutating tool surfaces.
- Read-only tools: `list_clusters`, `get_cluster`, `list_realms`, `list_applications`, `list_identity_providers`.
- Write tools (behind `--allow-writes`): `create_realm`, `delete_realm` (destructive; requires `confirm=true`).
- Typed API client generated from the Skycloak OpenAPI specification (oapi-codegen) with a `make generate` workflow.
- Unit tests, CI, a container image, and a release pipeline.
- Automatic `Retry-After`-aware retries on `429`/`5xx` responses.
- `spec-sync` workflow + `scripts/check-api-coverage.sh` that detect upstream OpenAPI drift and report API operations not yet exposed as tools.

[Unreleased]: https://github.com/sky-cloak/skycloak-mcp/commits/main

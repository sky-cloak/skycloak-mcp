# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Observability read tools: `get_logs`, `get_security_logs`, `query_events`.
- Custom-domain tools: `list_domains`, `get_domain` (read); `create_domain`, `verify_domain`, `delete_domain` (write). `create_domain` returns the DNS records to create; `delete_domain` requires `confirm=true`.
- Branding & theme tools: `list_themes`, `get_theme_assignment`, `get_login_branding`, `get_email_branding` (read); `set_theme_assignment` (write — activates a custom theme per Keycloak theme type, empty string resets to the built-in default).
- Extension tools: `list_extensions` (catalog), `list_cluster_extensions` (read); `install_extension`, `upgrade_extension`, `uninstall_extension` (write). Install/upgrade are asynchronous; `uninstall_extension` requires `confirm=true`.
- Database export tools: `list_exports`, `get_export` (read); `create_export` (write, asynchronous — poll `get_export` for the download URL). Including credentials requires an `encryption_password`.
- Realm RBAC tools: `list_realm_roles`, `list_realm_groups`, `list_realm_users`, `get_realm_user` (read); `create_realm_role`, `delete_realm_role`, `create_realm_group`, `delete_realm_group`, `create_realm_user`, `delete_realm_user`, `assign_realm_user_role`, `remove_realm_user_role`, `add_realm_user_to_group`, `remove_realm_user_from_group` (write). Destructive `delete_*` tools require `confirm=true`.
- Application role & session tools: `list_application_roles`, `list_application_sessions` (read); `assign_application_role`, `remove_application_role` (write).

## [0.1.0] - 2026-05-25

### Added
- MCP server with stdio and streamable-HTTP transports, built on the official Go MCP SDK.
- API-key authentication (`SKYCLOAK_API_KEY`) scoped to the key's workspace.
- `--allow-writes` gate (default off) separating the read-only and mutating tool surfaces.
- Read-only tools: `list_clusters`, `get_cluster`, `list_realms`, `list_applications`, `list_identity_providers`.
- Write tools (behind `--allow-writes`): `create_cluster`, `delete_cluster`, `create_realm`, `delete_realm`, `create_application`, `delete_application`, `create_identity_provider` (OIDC), `delete_identity_provider`. Destructive tools (`delete_*`) require `confirm=true`.
- `list_applications` follows pagination across all pages.
- `server.json` (MCP Registry listing metadata) and `DISTRIBUTION.md` (discovery/marketing channels).
- Typed API client generated from the Skycloak OpenAPI specification (oapi-codegen) with a `make generate` workflow.
- Unit tests, CI, a container image, and a release pipeline.
- Automatic `Retry-After`-aware retries on `429`/`5xx` responses.
- `spec-sync` workflow + `scripts/check-api-coverage.sh` that detect upstream OpenAPI drift and report API operations not yet exposed as tools.

[Unreleased]: https://github.com/sky-cloak/skycloak-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sky-cloak/skycloak-mcp/releases/tag/v0.1.0

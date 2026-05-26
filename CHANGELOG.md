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
- Read-parity tools: `get_realm`, `get_application`, `get_identity_provider`, `list_cluster_locations`, `list_cluster_types`, `list_cluster_features`, `list_cluster_versions`, `list_cluster_upgrades`, `list_identity_provider_templates`, `list_domain_routes`.
- Write/read parity tools: `get_smtp`, `get_theme`, `get_domain_route`, `get_client_theme_assignment`, `list_user_roles`, `list_user_groups` (read); `rotate_application_secret`, `update_realm`, `delete_smtp`, `create_domain_route`, `delete_domain_route`, `set_client_theme_assignment`, `delete_theme`, `delete_extension`, `delete_export` (write). Destructive deletes require `confirm=true`.
- Action tools: `discover_oidc` (read); `test_smtp`, `test_identity_provider`, `cancel_cluster_upgrade` (write). `cancel_cluster_upgrade` requires `confirm=true`.
- Cluster security tools: `get_cluster_security` (read); `update_cluster_security` (write) — IP allow-listing, rate limiting, WAF, geo-blocking, bot management (CAPTCHA preserved).
- Read-parity tools: `get_cluster_credentials`, `list_cluster_builds`, `get_cluster_build`, `get_cluster_upgrade_path`, `get_cluster_insights`, `get_realm_role`, `get_realm_group`, `list_realm_group_members`.
- Update/upsert tools: `update_realm_role`, `update_realm_group`, `update_realm_user`, `update_application`, `update_identity_provider`, `update_cluster`, `update_extension`, `update_theme`, `update_domain_route`, `upsert_smtp`, `upsert_login_branding`, `upsert_email_branding`, `delete_login_branding`, `delete_email_branding`, `export_cluster_events`.

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

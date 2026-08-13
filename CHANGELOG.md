# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-08-13

### Added
- `init --allow-credentials` requests `clusters:credentials:read`, the scope `get_cluster_credentials` needs. It stays out of the default grant, because a key that carries it lets an assistant read a cluster's Keycloak admin credentials.

### Changed
- `get_cluster_credentials` answers a `403` by naming the scope it needs and how to get a key that carries it, instead of a bare "forbidden". It was previously the only tool a signed-in user could never call, with nothing to say why. The message covers both transports and notes that `SKYCLOAK_API_KEY` outranks the stored key.

## [0.4.0] - 2026-08-13

### Added
- Realm import/export tools: `create_realm_export`, `get_realm_export`, `create_realm_import`, `get_realm_import`, `create_realm_import_upload_url`. Both jobs are asynchronous; the archive is always encrypted, and a realm can be imported from an existing export without re-uploading it. Import creates a realm and refuses a name collision rather than overwriting, and requires `confirm=true` because it brings users and credentials with it.
- `download_theme_content` returns a theme's archive as an MCP resource blob, with size and SHA-256 always reported and the bytes inlined only when small enough to be worth it.
- This completes the API surface: all 134 generated operations are now used.

### Fixed
- A `5xx` response to a non-idempotent request is no longer retried. A gateway `504` on a `POST` often means the origin did accept it, so replaying it could start a second realm import or export. A `429` is still retried on any method: it means the request was refused, not performed.
- `--allow-writes` requested seven scope names the API does not define (`users:read`, `users:write`, `cluster-logs:read`, `cluster-insights:read`, `cluster-events:read`, `cluster-security:read`, `cluster-security:write`), and omitted every scope for domains, themes, branding, extensions, SMTP, SIEM, webhooks, exports and imports. A minted key therefore 403'd on those tools. The list now matches the scopes declared in the OpenAPI spec, and a test checks it against the spec so a new tool area cannot silently miss one.
- The container image declares its user numerically (`65532:65532`) instead of by name. Under a `runAsNonRoot` policy the kubelet has to verify the user is not root, cannot do that from a name, and refuses to start the container with `CreateContainerConfigError`.

## [0.3.0] - 2026-08-13

### Added
- Browser sign-in: `skycloak-mcp init` runs the OAuth 2.0 device authorization flow (RFC 8628) against the Skycloak realm, mints a workspace-scoped API key, and stores it in the OS keychain. `skycloak-mcp run` loads it; `skycloak-mcp logout` removes it. No API key to copy or paste.
- `--workspace`, `--allow-writes`, and `--ttl-days` flags on `init`; `SKYCLOAK_ISSUER`, `SKYCLOAK_CLIENT_ID`, and `SKYCLOAK_DASHBOARD_URL` env vars to target dev / self-hosted control planes.
- `init` opens your browser to the verification page automatically (code pre-filled), and still prints the URL/code as a fallback. `--no-browser` disables the auto-open for SSH / headless terminals.
- Hosted HTTP transport (`run --transport http`): every request authenticates on its own via `Authorization: Bearer <key>` or `API-Key: <key>`, so one process serves many workspaces without holding a key of its own. `?readonly=true` narrows a session to read-only tools.
- Unauthenticated `GET /healthz` and `GET /readyz` for container probes, and a graceful drain on `SIGTERM`.

### Changed
- `SKYCLOAK_API_KEY` is now optional: it is the headless/CI path (and still used by the container image) and takes precedence over the keychain when set. Invoking the binary with no subcommand still serves stdio, so existing configurations keep working.
- `skycloak-mcp run` signs you in automatically (device flow) when started interactively in a terminal with no stored key. When an MCP client launches it over a pipe it stays non-interactive and surfaces the actionable `run skycloak-mcp init` message instead.
- The HTTP transport runs stateless: it no longer caches an MCP session (and the server built for it) under the client-supplied `Mcp-Session-Id`. Previously a caller replaying another caller's session id was served with that caller's API key. Replicas now need no session affinity.
- An unauthenticated HTTP request is answered with `401` and a `WWW-Authenticate` challenge instead of `400`.
- Request retries are bounded per attempt rather than by one overall client deadline, so a `Retry-After` longer than a single attempt's timeout is honored instead of failing the call. The caller's context still bounds the whole operation.
- The client no longer installs its retry transport onto an `http.Client` supplied via `WithHTTPClient`; it copies the client first.
- A server-supplied `Retry-After` is capped at 60s, and the backoff a single call may accumulate is capped at 2 minutes, so a gateway incident cannot park a tool call indefinitely.
- A query string containing `;` is rejected rather than silently parsed as absent, so `?readonly=true;x=1` can no longer fall back to the write-capable default.

### Removed
- list_cluster_builds / get_cluster_build tools: the cluster-builds endpoints were removed from the Skycloak public API.

## [0.2.0] - 2026-05-26

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

[Unreleased]: https://github.com/sky-cloak/skycloak-mcp/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/sky-cloak/skycloak-mcp/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sky-cloak/skycloak-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/sky-cloak/skycloak-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sky-cloak/skycloak-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sky-cloak/skycloak-mcp/releases/tag/v0.1.0

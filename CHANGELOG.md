# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Four MCP skills served over the draft SEP-2640 Skills extension: the server
  declares `io.modelcontextprotocol/skills`, answers `skills/list` and
  `skills/get` with per-file sha256 digests, and serves each `SKILL.md` as a
  resource at `skill://<name>/SKILL.md`, which is the shape OpenAI's plugin
  directory imports. The skills are operational playbooks rather than tool
  summaries: triaging an authentication incident (read-only), rolling out an
  enterprise SSO integration end to end, assessing Keycloak upgrade
  readiness with rollout sequencing, and preflighting or diagnosing Keycloak
  exports, imports and migrations, built from the failure modes support
  tickets actually show and centered on reading a failed job's
  `error_message`, which the API records but the dashboard notice does not
  surface. They follow the same gating as the tools they name: the three
  write workflows are withheld from read-only sessions,
  and tests fail if a served skill names a tool its session does not have,
  if a listing digest stops matching the served bytes, or if an entry's
  frontmatter drifts from the file's.

### Changed
- MCP Go SDK upgraded from v1.6.1 to v1.7.0, which adds the custom JSON-RPC
  method registration that `skills/list` and `skills/get` are built on.
- Eight MCP prompts, one per workflow users actually start with: auditing
  self-registration, reviewing upgrades, triaging failed logins, reviewing
  identity providers, reviewing admin changes, provisioning an environment,
  setting up a custom domain, and rotating a client secret. Each takes
  arguments and names the exact tools to use in order, so a client that
  surfaces prompts offers a starting point instead of a bare 129-tool list.
  Prompts follow the same gating as the tools they name: the three mutating
  workflows are withheld from read-only sessions, and a test fails if a
  prompt names a tool its session cannot have, lacks a description, or does
  not require the scopes of every tool it references.

## [0.8.0] - 2026-08-18

### Added
- Every tool now declares `openWorldHint`, and the thirteen write tools that had
  no `destructiveHint` now carry one. Both are required by OpenAI's plugin
  directory, which validates them during its tool scan, and the first is a
  correctness fix in its own right: the MCP spec defaults `openWorldHint` to
  true, so all 129 tools were telling clients they might act on the open
  internet while operating on a single tenant. Six are genuinely open-world:
  the SMTP, SIEM, webhook and identity-provider test tools, OIDC discovery, and
  domain verification.
- `OPENAI_APPS_CHALLENGE_TOKEN` serves that directory's domain verification
  token at `/.well-known/openai-apps-challenge`. Unset, the route is not
  registered.
- A test that fails if any registered tool reaches the wire without a title,
  `openWorldHint`, or, for write tools, `destructiveHint`.

## [0.7.2] - 2026-08-18

### Fixed
- The registry description fits the registry. 0.7.1 shipped a 444-character one and
  the publish step rejected it with `expected length <= 100`, so the tag produced a
  GitHub release and a container image but never reached the registry. The longer
  copy belongs in directory listings that have their own description field, not
  here.

## [0.7.1] - 2026-08-18

### Changed
- The registry entry carries a description worth indexing. The previous one was 98
  characters and said little beyond the product name, which is what every directory
  mirroring the registry was displaying.

### Added
- The registry entry points at the source repository, so directories can show the
  licence and the code rather than only an endpoint. Uses GitHub's numeric
  repository id, which survives a rename and changes if a repository is deleted and
  recreated.

## [0.7.0] - 2026-08-18

### Changed
- This repository is now open source under Apache-2.0. The pre-release history was squashed into a single initial
  commit, so the commit log starts here; the changelog above remains the record of what changed in each earlier release.
- The README leads with a quick start and example prompts instead of authentication internals, and states plainly that
  the hosted server is write-capable with writes bounded by your credential's scopes. The previous "read-only by
  default" wording described the local binary only and read as if it covered the hosted server.

### Added
- `SECURITY.md` with a private disclosure address, and a `NOTICE` clarifying that the bundled OpenAPI description is
  (c) Skycloak rather than Apache-2.0.

### Removed
- The internal distribution playbook, which was a go-to-market document rather than something a user of this server
  needs.

## [0.6.6] - 2026-08-18

### Changed
- The MCP Registry entry carries a 512x512 icon and a display title, so the server renders properly in registry and
  directory listings rather than falling back to a bare package name.

## [0.6.5] - 2026-08-17

### Fixed
- `resource_documentation` in the protected-resource metadata points at the published documentation rather than a
  placeholder, so a client following the RFC 9728 pointer lands somewhere useful.

### Added
- Releases publish to the MCP Registry automatically, authenticated by DNS against `skycloak.io`, so a tagged release no
  longer needs a manual registry step.

## [0.6.4] - 2026-08-15

### Fixed
- Every tool parameter that maps to an API enum accepts any case, not just the two #31 reached. Thirty-one more were forwarding the model's spelling untouched, so `create_cluster(size="Large")`, `create_export(format="SQL")`, `upsert_smtp(encryption="STARTTLS")`, the SIEM destination transports and the WAF, geo-blocking and bot-management modes all answered `422 Validation Failed: Invalid parameter` with nothing in it pointing at the case. Each parameter is folded to the case its own enum uses, which cannot be a blanket lowercase because `UserEventType`, `AdminOperationType` and `DnsRecordType` are uppercase. A value the enum does not list is still passed through untouched, so a value the API grows after this release reaches it and the API's own error is what the caller sees.
- `get_cluster_insights` refuses a `type` it does not recognise instead of answering with the overview document. The five insight kinds are five endpoints, so the client picks the path and the value never reaches the API: a typo, or the right word in the wrong case, used to return a different document than the one asked for, successfully. Correct values in any case still work; anything else now names the five that are valid.
- The affected tool descriptions state the values they accept and that case does not matter, across all of them rather than the two that already did. Two of fifteen advertising case-insensitivity was worse than none: a model generalising from those two hit an opaque failure everywhere else. `create_identity_provider` described its `provider_id` as a free-form alias when the spec declares it the `SkycloakProviderId` enum; the description now says so and points at `skycloak_list_identity_provider_templates` for the values. The provider alias in the other four identity-provider tools is a free-form string in the spec, so it stays case-sensitive and its description says so.

### Added
- The enum inventory is checked against the committed `openapi.yaml`, so it cannot drift back. A value spelled differently from the spec, an enum that gains or loses one, a normalised parameter whose description stops naming what it accepts, and a newly added tool parameter that carries an API enum with no normalisation each fail the build instead of a user's call. The checks drive the registered tools by name over an in-memory MCP session, so a tool wired to a handler that skips the normalisation fails too.

## [0.6.3] - 2026-08-14

### Fixed
- `get_logs` accepts a log level in any case, so `level="ERROR"` stops failing with `422 Invalid parameter: level`. The API's enum is lowercase (`info`, `warn`, `error`, `debug`) but the tool's own description advertised `ERROR, WARN, INFO`, so a model that followed the documentation got a validation error with nothing in it to suggest the case was the problem. The value is now lowercased and trimmed before the request, and the description names the four values the API actually accepts. `query_events` takes its `category` (`user`, `admin`) the same way.

## [0.6.2] - 2026-08-14

### Fixed
- The hosted OAuth sign-in advertises the scopes it needs, so it stops failing at the token exchange with `stage=exchange status=403 dashboard_status=401`. The protected-resource metadata carried no `scopes_supported` and the `WWW-Authenticate` challenge carried no `scope`, so a client following RFC 9728 had nothing to ask for and requested none. Keycloak then issued a token without `openid`, which verifies and passes introspection but makes Keycloak's userinfo endpoint answer `403` when the dashboard validates it, so a sign-in that looked correct at every earlier step died at the last one. Both the document and the challenge now name `openid profile email`.
- A token granted without `openid` is refused at verification, as `no_openid_scope`, instead of being carried to an exchange that cannot succeed. Advertising the scopes only helps a client that has yet to sign in: one that connected before holds a refresh token from the old grant, and every access token minted from it inherits the gap. Those requests used to end in a `403` with nothing to act on, so the client retried the same doomed token until its realm session lapsed. They are now answered with a `401` and the challenge, which is what makes a client authorize again and come back with the right scopes.

## [0.6.1] - 2026-08-14

### Added
- The hosted HTTP transport logs every request it refuses on the OAuth path, so "credentials rejected" stops being a report with four possible causes and no evidence. Each rejection is one line naming the stage that failed (token verification, the dashboard exchange, or the empty-grant check), the status the caller got, and the underlying error, capped in length because part of that error is the key id from an unverified token header and an uncapped line would let one request write a log entry its own size. A verification failure names the check that rejected the token (expired, wrong issuer, bad signature, unknown key id, wrong token type, and the rest) rather than collapsing to "invalid token"; an exchange failure names the dashboard's own status and the host being called. The caller is identified by the token's subject, and only once it is verified. Nothing that is a credential is logged: not the access token or any part of it, not the `Authorization` header, and not the minted API key. Accepted requests stay silent.
- The HTTP transport logs the configuration it resolved at startup: whether OAuth is on, the issuer, the dashboard URL, the public URL and the API endpoint. Both of the last two production problems were a value nobody could read back from a running pod, a public URL advertising `http` for an `https` endpoint and a dev deployment exchanging tokens against the production dashboard. Values only, no secrets.

## [0.6.0] - 2026-08-14

### Added
- The hosted HTTP transport accepts OAuth, so a client can connect with no credential in its configuration: `claude mcp add --transport http skycloak https://mcp.skycloak.io` now opens a browser, the user approves in the Skycloak login realm, and the tools appear. The server publishes RFC 9728 protected-resource metadata at `/.well-known/oauth-protected-resource` and names it in the `WWW-Authenticate` challenge, which is what a first-time client follows to find the authorization server. Skycloak API keys keep working exactly as before, on both `Authorization: Bearer sk_sc_...` and `API-Key:`.
- A verified realm access token is exchanged, at the dashboard, for a short-lived workspace-scoped API key, and the session runs on that. The exchange is cached per user and workspace and refreshed before the key lapses, and concurrent first requests share one mint rather than racing to rotate each other's key. Naming your only workspace explicitly resolves to the same session as not naming it, so the two spellings cannot mint over one another. Neither the token nor the key is ever logged.
- The realm's signing keys are cached, refreshed when a key id is unfamiliar and again once the set is ten minutes old, so a key the realm withdraws stops verifying tokens instead of living on until the process restarts. Refreshes are coalesced and rate limited, counting failed attempts, so neither a flood of junk tokens nor an unreachable realm turns into one outbound request per inbound one. Only tokens the realm labels as access tokens are accepted, and signing keys below 2048 bits are ignored.
- Tools are tailored to what the session may actually do. A read-only workspace member no longer sees dozens of write tools that would answer 403; a workspace owner sees the full surface. `get_cluster_credentials` stays hidden unless the credential carries `clusters:credentials:read`, which no OAuth session is granted. Stdio and API-key callers are unchanged: their grant is not enumerable, so every tool is registered as before.
- `?workspace=<uuid>` on the hosted URL picks which workspace an OAuth session acts on, alongside the existing `?readonly=true`. A user who belongs to several workspaces and names none gets a `400` that lists them and says how to choose.
- `SKYCLOAK_PUBLIC_URL` overrides the resource identifier published in the OAuth metadata. It is only needed when the URL clients use differs from the `Host` they send.

### Fixed
- An OAuth session that the dashboard grants no scopes is no longer cached. Connecting before your workspace role was granted used to pin you to that empty answer for the key's whole life: the server refused with a `403`, every retry hit the cached session, and an admin granting the role changed nothing until the key lapsed nearly an hour later. The next request now asks the dashboard again, so the grant takes effect immediately.
- `update_cluster_security` reads the cluster's current configuration so the sections it does not manage, CAPTCHA among them, survive the update. A refused read used to fall through to an empty body, so the update silently wiped them. It now fails instead of writing.

### Changed
- The realm issuer and dashboard URL (`SKYCLOAK_ISSUER`, `SKYCLOAK_DASHBOARD_URL`) now configure the HTTP transport as well as the CLI sign-in. Blanking either turns the OAuth path off, and the server goes back to advertising nothing but the API-key challenge.

## [0.5.1] - 2026-08-13

### Fixed
- The hosted HTTP transport answered every unknown path with `401` and the credential challenge, including the OAuth discovery paths. A client that got a `401` on connect then probed `/.well-known/oauth-protected-resource`, read the `401` there as "this server does OAuth", attempted Dynamic Client Registration, and told the user registration had been rejected, when all the server ever wanted was an API key. Only the MCP endpoint is credential-gated now; anything else is a plain `404` with no challenge. The endpoint still serves the bare origin, `/mcp` and `/mcp/`, and `/healthz` and `/readyz` stay unauthenticated.

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
- The HTTP transport runs stateless: it no longer caches an MCP session (and the server built for it) under the client-supplied `Mcp-Session-Id`. This closes a session-handling issue and means every request is served strictly on its own credential. Replicas now need no session affinity.
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

<!-- Version-comparison links were removed when this repository was opened up: the pre-release history was
squashed into a single initial commit, so there are no earlier tags to compare against. The entries above
are the record of what changed. -->

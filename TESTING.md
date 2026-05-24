# Testing & versioning

How every change to `skycloak-mcp` is verified and released. **No change merges red.**

## The rule for every change

Every PR that adds or changes behavior MUST include, in the same PR:

1. **Tests** — a new/updated unit test that exercises the change.
   - New tool → a handler test (success + at least one error path) **and** it is covered by `TestRegister` (which proves JSON-schema inference doesn't panic at startup).
   - Client change → an `httptest`-backed test asserting headers, query, and response/error decoding.
2. **Checklist** — tick or add the relevant line in [`CHECKLIST.md`](./CHECKLIST.md).
3. **Changelog** — an entry under `## [Unreleased]` in [`CHANGELOG.md`](./CHANGELOG.md).
4. **Green gates** — `make lint test-race build` pass locally; CI re-runs them on the PR.

## Test layers

| Layer | What | Command | Gate |
|---|---|---|---|
| Unit | Tool handlers (mocked `API`), client (httptest) | `make test` / `make test-race` | CI on every push/PR |
| Schema | `TestRegister` — every tool's input/output schema infers cleanly | `go test ./internal/tools` | CI |
| Lint | govet, staticcheck, revive, errcheck, … | `make lint` | CI |
| Tidy | `go.mod`/`go.sum` committed & tidy | `go mod tidy && git diff --exit-code` | CI |
| Inspector | Manual protocol/annotation check | `make inspector` | pre-release |
| Integration | Smoke vs a dev workspace (read-only by default) | `SKYCLOAK_API_KEY=… make run` + Inspector | pre-release |

The mocked-`API` interface in `internal/tools` is the key to fast, deterministic tool tests — handlers never hit the network in unit tests.

## Running locally

```bash
make test-race                 # unit tests + race + coverage
make lint                      # golangci-lint
SKYCLOAK_API_KEY=sk_sc_... make run        # stdio, against the real API
make inspector                 # MCP Inspector against the local binary
```

## Versioning

- **SemVer** (`vMAJOR.MINOR.PATCH`), pre-1.0 while the tool surface is unstable.
  - PATCH: fixes, no tool contract change. MINOR: new tools / new optional args. MAJOR: removed/renamed tools or changed required args.
- **Conventional commits** (`feat:`, `fix:`, `docs:`, `chore:`…) drive the generated release notes.
- **API surface** is pinned separately via the Skycloak `API-Version` header (`SKYCLOAK_API_VERSION`); a server release notes which API version it targets.
- **Releasing:** move `## [Unreleased]` entries under a new version heading in `CHANGELOG.md`, then tag:
  ```bash
  git tag v0.1.0 && git push origin v0.1.0
  ```
  The `release` workflow runs `goreleaser` → GitHub release with binaries, checksums, and the GHCR image `ghcr.io/sky-cloak/skycloak-mcp:v0.1.0`.

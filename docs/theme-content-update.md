# Replacing theme content from MCP

How `skycloak_update_theme_content` works, and why it is shaped this way.

## The problem it removes

Until the API grew a content endpoint, the only way to change a deployed theme's
files was to delete it and upload the replacement. That path is worse than it
looks:

- `DELETE /themes/{id}` answers `409 Conflict` while the theme is assigned, so a
  caller first has to detach it from every realm and application.
- Between the detach and the re-assignment the realm falls back to Keycloak's
  built-in look, so the sign-in page is visibly unbranded for real users.
- The re-upload is a new theme with a new ID, so anything holding the old ID
  (Terraform state, a saved runbook, another MCP session) is now stale.

`PUT /clusters/{cluster_id}/themes/{theme_id}/content` replaces the archive in
place instead: the theme keeps its ID and name, every realm and application
assignment keeps pointing at it, and the new content deploys immediately. The
MCP tool is a thin cover over that call, so a programmatic caller gets the same
fix the dashboard and the Terraform provider get.

## The call

`internal/tools/branding.go` holds the tool. It sits in the `branding writes`
area, whose only scope is `themes:write`, which is exactly what the endpoint
requires, so a scoped session that can write themes sees it and no other session
does.

The archive arrives base64-encoded in `content_base64`, mirroring
`skycloak_download_theme_content`, which hands the archive back as a base64
blob: download, edit, update round-trips through the same encoding. Before
anything is sent, `decodeThemeArchive`:

- strips whitespace, because base64 from a shell pipeline or a model arrives
  wrapped, and a line break is not worth a failed call;
- refuses anything over 50 MB, the endpoint's body limit, so an oversized
  archive costs a message rather than the upload;
- reads the archive's central directory with `archive/zip`, refusing anything
  that is not a real ZIP (a JAR is one by format) or that holds no entries. A
  prefix check would pass a payload that merely starts with `PK`, so the
  structure is what gets read, which catches a mis-encoded or truncated body
  before it becomes a remote `400`.

The replacement is destructive: the archive it overwrites is gone afterwards,
the way `rotate_application_secret` discards the old secret. So the tool takes
`confirm`, and refuses without `confirm=true`, like every other destructive tool
on this server. What survives is the theme's identity: its ID, its name and its
assignments, which is the point of the endpoint.

`filename` is what decides the media type: a `.jar` name is sent as
`application/java-archive` (Keycloakify's packaging), anything else as
`application/zip`. Those are the only two the endpoint accepts, and since a JAR
is a ZIP by format, the name is the only thing that can tell them apart. An
omitted filename defaults to `theme.zip`.

`version` is optional and omitted from the body when empty, so a content
replacement does not blank the recorded version label.

## The client method

`skycloak.Client.UpdateThemeContent` (`internal/skycloak/realms_transfer.go`,
next to `DownloadThemeContent`) builds the `multipart/form-data` body by hand
rather than through the generated typed body, because the `theme_file` part
needs its own `Content-Type` header.

The body is buffered into a `*bytes.Reader` rather than streamed. That is not
incidental: `http.NewRequest` derives `GetBody` from a `*bytes.Reader`, and the
retry transport replays a `PUT` on `503` only when `GetBody` is set. A streamed
body would be replayed empty, and an empty body means replacing the live theme
with nothing. `TestUpdateThemeContentReplaysTheBodyOnRetry` pins that.

## What the tool does not do

It never calls `DeleteTheme`, `UpdateTheme` or `SetThemeAssignment`: the whole
point is that the assignments are untouched, and
`TestUpdateThemeContentReplacesInPlace` asserts those calls are absent as well
as asserting the content call happened. The existing detach, rename and delete
tools are unchanged, since other flows still use them.

Two API behaviors surface to the caller as-is rather than being worked around:
an archive that drops a theme type the theme currently provides is a `400`, and
a theme created by a platform migration has pinned content and answers `409`.
Both come back as the API's own message, which is what tells the caller that a
rename-and-re-upload is the only route for a pinned theme.

## Tests

| Layer | File | What it covers |
|---|---|---|
| Client (httptest) | `internal/skycloak/realms_transfer_test.go` | multipart wire shape, part media type for ZIP vs JAR, omitted version, `409` surfacing, body replay on retry |
| Tool handler | `internal/tools/branding_test.go` | in-place update with no detach or reassignment, filename default, the `confirm=true` gate, input validation (non-archive, `PK`-prefixed junk, truncated and empty archives), wrapped base64, API errors |
| Registration | `internal/tools/annotations_test.go`, `internal/tools/scopes_test.go` | schema inference, annotations, `themes:write` gating |

#!/usr/bin/env bash
# Usage: sync-platform-spec.sh <commit-sha> <fetched-spec> [<target-dir>]
# Installs a fetched copy of the second spec as <target-dir>/openapi.yaml and
# records the commit it was taken from in <target-dir>/SOURCE_COMMIT. The
# target defaults to internal/platformclient.
#
# Refuses, leaving the target untouched, when the commit is not a full hash,
# the file is not an OpenAPI document, or it still has a /v1/staff/ path. Staff
# paths are removed where the public copy is made; this is the second fence, so
# a copy taken from the wrong file can never reach this repository.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
sha=$("$here/resolve-platform-ref.sh" "${1:-}")
spec=${2:-}
target=${3:-internal/platformclient}

if [[ -z "$spec" || ! -f "$spec" ]]; then
  echo "refusing to sync: no spec file at '$spec'" >&2
  exit 2
fi
if ! head -1 "$spec" | grep -q '^openapi:'; then
  echo "refusing to sync: $spec is not an OpenAPI document" >&2
  exit 2
fi
if grep -Eq '^[[:space:]]*"?/v1/staff(/|"?:|$)' "$spec"; then
  echo "refusing to sync: $spec has a /v1/staff/ path; it is not the public copy" >&2
  exit 2
fi

cp "$spec" "$target/openapi.yaml"
echo "$sha" > "$target/SOURCE_COMMIT"

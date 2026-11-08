#!/usr/bin/env bash
# Usage: resolve-platform-ref.sh <commit-sha>
# Echoes the commit if it is a full 40-character commit hash, else refuses. The
# second spec follows commits on main, so the workflow resolves main to a hash
# first and the fetch is pinned to it: a branch name or a tag would let the
# bytes change between the lookup and the read, and the recorded commit would
# no longer say what the copy was taken from.
set -euo pipefail
ref=${1:-}
if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
  echo "refusing to sync from '$ref': not a full commit hash" >&2
  exit 2
fi
echo "$ref"

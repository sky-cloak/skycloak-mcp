#!/usr/bin/env bash
# Usage: filter-spec.sh <spec.json> <path-prefix>
# Echoes the spec as JSON with the given path and every path under it removed
# (for example "/v1/area" drops "/v1/area" and "/v1/area/..."), and nothing
# else changed. The result is what gets compared or written.
# Exit codes: 2 bad usage or a file that is not a JSON object.
set -euo pipefail
spec=${1:-}
prefix=${2:-}
prefix=${prefix%/}
if [[ -z "$spec" || ! -f "$spec" || -z "$prefix" ]]; then
  echo "usage: filter-spec.sh <spec.json> <path-prefix>" >&2
  exit 2
fi
if ! jq -e 'type == "object"' "$spec" >/dev/null 2>&1; then
  echo "'$spec' is not a JSON object" >&2
  exit 2
fi
jq --arg p "$prefix" 'if has("paths") and (.paths | type == "object")
    then .paths |= with_entries(select((.key == $p or (.key | startswith($p + "/"))) | not))
    else . end' "$spec"

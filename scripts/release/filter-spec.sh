#!/usr/bin/env bash
# Usage: filter-spec.sh <spec.json|spec.yaml> <path-prefix>
# Echoes the spec as JSON with the given path and every path under it removed
# (for example "/v1/area" drops "/v1/area" and "/v1/area/..."), and nothing
# else changed. Components and tags are kept as they are, even when only a
# removed path used them. YAML input is converted with yq, which must be on
# PATH for that case. The result is what gets compared or written.
# Exit codes: 2 bad usage or a file that is not a JSON or YAML object.
set -euo pipefail
spec=${1:-}
prefix=${2:-}
prefix=${prefix%/}
if [[ -z "$spec" || ! -f "$spec" || -z "$prefix" ]]; then
  echo "usage: filter-spec.sh <spec.json|spec.yaml> <path-prefix>" >&2
  exit 2
fi
json=$(mktemp)
trap 'rm -f "$json"' EXIT
if ! jq -e 'type == "object"' "$spec" >/dev/null 2>&1; then
  if ! command -v yq >/dev/null 2>&1 || ! yq -o=json '.' "$spec" >"$json" 2>/dev/null; then
    echo "'$spec' is not a JSON or YAML object" >&2
    exit 2
  fi
  if ! jq -e 'type == "object"' "$json" >/dev/null 2>&1; then
    echo "'$spec' is not a JSON or YAML object" >&2
    exit 2
  fi
  spec=$json
fi
jq --arg p "$prefix" 'if has("paths") and (.paths | type == "object")
    then .paths |= with_entries(select((.key == $p or (.key | startswith($p + "/"))) | not))
    else . end' "$spec"

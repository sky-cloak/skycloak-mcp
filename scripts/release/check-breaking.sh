#!/usr/bin/env bash
# Usage: check-breaking.sh <old-spec> <new-spec>
# Compares two filtered specs with oasdiff and lists the breaking changes:
# a removed path or operation, a removed response field (required or optional)
# and a new required request input (parameter, body or body property).
# oasdiff must be on PATH; CI installs a pinned release.
# Exit codes: 0 no breaking change, 2 bad usage or the comparison could not run,
# 3 breaking changes found (listed on stdout).
set -euo pipefail
old=${1:-}
new=${2:-}
if [[ -z "$old" || -z "$new" || ! -f "$old" || ! -f "$new" ]]; then
  echo "usage: check-breaking.sh <old-spec> <new-spec>" >&2
  exit 2
fi
if ! command -v oasdiff >/dev/null 2>&1; then
  echo "oasdiff is not installed; refusing to pass a spec unchecked" >&2
  exit 2
fi

# oasdiff reports an optional response property that disappears as info only,
# but a client reading it breaks the same way, so it counts here.
levels=$(mktemp)
out=$(mktemp)
trap 'rm -f "$levels" "$out"' EXIT
echo "response-optional-property-removed err" >"$levels"

code=0
oasdiff breaking "$old" "$new" --severity-levels "$levels" --fail-on ERR >"$out" 2>&1 || code=$?
case $code in
  0)
    cat "$out"
    echo "no breaking changes"
    ;;
  1)
    cat "$out"
    exit 3
    ;;
  *)
    cat "$out" >&2
    echo "oasdiff could not compare the specs (exit $code)" >&2
    exit 2
    ;;
esac

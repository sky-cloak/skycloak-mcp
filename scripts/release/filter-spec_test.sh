#!/usr/bin/env bash
# Run: bash scripts/release/filter-spec_test.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# A made-up spec: two public routes and three under the filtered prefix.
cat >"$tmp/spec.json" <<'J'
{"openapi":"3.0.3","info":{"title":"Sample","version":"1"},
 "paths":{
  "/v1/widgets":{"get":{"responses":{"200":{"description":"ok"}}}},
  "/v1/widgets/{id}":{"get":{"responses":{"200":{"description":"ok"}}}},
  "/v1/hidden/gizmos":{"get":{"responses":{"200":{"description":"ok"}}}},
  "/v1/hidden/gizmos/{id}":{"delete":{"responses":{"204":{"description":"gone"}}}},
  "/v1/hiddenly":{"get":{"responses":{"200":{"description":"ok"}}}}
 }}
J

out=$("$here/filter-spec.sh" "$tmp/spec.json" /v1/hidden); code=$?
[[ $code -eq 0 ]] && ok "a valid spec is filtered" || bad "a valid spec is filtered (exit $code)"

got=$(jq -c '.paths | keys' <<<"$out")
want='["/v1/hiddenly","/v1/widgets","/v1/widgets/{id}"]'
[[ "$got" == "$want" ]] && ok "no path under the prefix is left, similar paths stay" || bad "paths: got $got, want $want"

got=$(jq -c 'del(.paths)' <<<"$out")
want=$(jq -c 'del(.paths)' "$tmp/spec.json")
[[ "$got" == "$want" ]] && ok "everything outside paths is unchanged" || bad "non-path content changed"

got=$(jq -c '.paths["/v1/widgets"]' <<<"$out")
want=$(jq -c '.paths["/v1/widgets"]' "$tmp/spec.json")
[[ "$got" == "$want" ]] && ok "a kept path is unchanged" || bad "a kept path changed"

echo '{"openapi":"3.0.3","info":{"title":"Sample","version":"1"}}' >"$tmp/nopaths.json"
out=$("$here/filter-spec.sh" "$tmp/nopaths.json" /v1/hidden); code=$?
[[ $code -eq 0 && "$(jq -c 'has("paths")' <<<"$out")" == "false" ]] && ok "a spec without paths passes through" || bad "a spec without paths (exit $code)"

"$here/filter-spec.sh" >/dev/null 2>&1; code=$?
[[ $code -eq 2 ]] && ok "no file is refused" || bad "no file: exit $code, want 2"

"$here/filter-spec.sh" "$tmp/missing.json" /v1/hidden >/dev/null 2>&1; code=$?
[[ $code -eq 2 ]] && ok "a missing file is refused" || bad "missing file: exit $code, want 2"

echo 'not json' >"$tmp/bad.json"
"$here/filter-spec.sh" "$tmp/bad.json" /v1/hidden >/dev/null 2>&1; code=$?
[[ $code -eq 2 ]] && ok "a file that is not JSON is refused" || bad "not json: exit $code, want 2"

exit $fail

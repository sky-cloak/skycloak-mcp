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
if [[ $code -eq 0 ]]; then ok "a valid spec is filtered"; else bad "a valid spec is filtered (exit $code)"; fi

got=$(jq -c '.paths | keys' <<<"$out")
want='["/v1/hiddenly","/v1/widgets","/v1/widgets/{id}"]'
if [[ "$got" == "$want" ]]; then ok "no path under the prefix is left, similar paths stay"; else bad "paths: got $got, want $want"; fi

got=$(jq -c 'del(.paths)' <<<"$out")
want=$(jq -c 'del(.paths)' "$tmp/spec.json")
if [[ "$got" == "$want" ]]; then ok "everything outside paths is unchanged"; else bad "non-path content changed"; fi

got=$(jq -c '.paths["/v1/widgets"]' <<<"$out")
want=$(jq -c '.paths["/v1/widgets"]' "$tmp/spec.json")
if [[ "$got" == "$want" ]]; then ok "a kept path is unchanged"; else bad "a kept path changed"; fi

echo '{"openapi":"3.0.3","info":{"title":"Sample","version":"1"}}' >"$tmp/nopaths.json"
out=$("$here/filter-spec.sh" "$tmp/nopaths.json" /v1/hidden); code=$?
if [[ $code -eq 0 && "$(jq -c 'has("paths")' <<<"$out")" == "false" ]]; then ok "a spec without paths passes through"; else bad "a spec without paths (exit $code)"; fi

"$here/filter-spec.sh" >/dev/null 2>&1; code=$?
if [[ $code -eq 2 ]]; then ok "no file is refused"; else bad "no file: exit $code, want 2"; fi

"$here/filter-spec.sh" "$tmp/missing.json" /v1/hidden >/dev/null 2>&1; code=$?
if [[ $code -eq 2 ]]; then ok "a missing file is refused"; else bad "missing file: exit $code, want 2"; fi

echo 'not json' >"$tmp/bad.json"
"$here/filter-spec.sh" "$tmp/bad.json" /v1/hidden >/dev/null 2>&1; code=$?
if [[ $code -eq 2 ]]; then ok "a file that is not JSON is refused"; else bad "not json: exit $code, want 2"; fi

exit $fail

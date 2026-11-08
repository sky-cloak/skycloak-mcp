#!/usr/bin/env bash
# Run: bash scripts/release/sync-platform-spec_test.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fail=0
sha=0123456789abcdef0123456789abcdef01234567

# check NAME WANT_EXIT ARGS...: runs the script into a fresh target.
check() {
  local name=$1 want=$2; shift 2
  rm -rf "$work/t"; mkdir "$work/t"; echo old > "$work/t/openapi.yaml"
  "$here/sync-platform-spec.sh" "$@" "$work/t" >/dev/null 2>&1
  local code=$?
  if [[ $code -ne $want ]]; then
    echo "FAIL $name: exit $code, want $want"; fail=1; return
  fi
  if [[ $want -ne 0 && "$(cat "$work/t/openapi.yaml")" != old ]]; then
    echo "FAIL $name: a refused sync changed the target"; fail=1; return
  fi
  echo "ok   $name"
}

printf 'openapi: 3.0.0\npaths:\n  /v1/tenants:\n    get: {}\n' > "$work/good.yaml"
printf 'openapi: 3.0.0\npaths:\n  /v1/tenants:\n    get: {}\n  /v1/staff/overview:\n    get: {}\n' > "$work/staff.yaml"
printf 'openapi: 3.0.0\npaths:\n  "/v1/staff":\n    get: {}\n' > "$work/staff-quoted.yaml"
printf 'openapi: 3.0.0\npaths:\n  /v1/staffing:\n    get: {}\n' > "$work/staffing.yaml"
printf '<html></html>\n' > "$work/html.yaml"

check "a public copy is installed" 0 "$sha" "$work/good.yaml"
check "a staff path is refused" 2 "$sha" "$work/staff.yaml"
check "a quoted staff path is refused" 2 "$sha" "$work/staff-quoted.yaml"
check "a path that only starts with staff is not a staff path" 0 "$sha" "$work/staffing.yaml"
check "a non-OpenAPI file is refused" 2 "$sha" "$work/html.yaml"
check "a missing file is refused" 2 "$sha" "$work/none.yaml"
check "a branch name is refused" 2 main "$work/good.yaml"
check "a short hash is refused" 2 0123456 "$work/good.yaml"

rm -rf "$work/t"; mkdir "$work/t"
"$here/sync-platform-spec.sh" "$sha" "$work/good.yaml" "$work/t" >/dev/null 2>&1
if [[ "$(cat "$work/t/SOURCE_COMMIT")" == "$sha" ]]; then echo "ok   the commit is recorded"; else echo "FAIL the commit is not recorded"; fail=1; fi

exit $fail

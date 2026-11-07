#!/usr/bin/env bash
# Run: bash scripts/release/resolve-platform-ref_test.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fail=0

# check NAME WANT_STDOUT WANT_EXIT REF
check() {
  local name=$1 want=$2 want_code=$3 ref=$4
  local got code
  got=$("$here/resolve-platform-ref.sh" "$ref" 2>/dev/null)
  code=$?
  if [[ "$got" != "$want" || $code -ne $want_code ]]; then
    echo "FAIL $name: got '$got' (exit $code), want '$want' (exit $want_code)"
    fail=1
  else
    echo "ok   $name"
  fi
}

h=0123456789abcdef0123456789abcdef01234567
check "a full commit hash is accepted" "$h" 0 "$h"
check "no ref is refused" "" 2 ""
check "a branch name is refused" "" 2 main
check "a release tag is refused" "" 2 v1.2.3
check "a short hash is refused" "" 2 0123456
check "an upper-case hash is refused" "" 2 "${h^^}"
check "a hash with trailing text is refused" "" 2 "${h}x"
check "a hash with a leading ref path is refused" "" 2 "refs/heads/$h"

exit $fail

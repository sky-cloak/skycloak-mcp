#!/usr/bin/env bash
# Run: bash scripts/release/check-breaking_test.sh
# Needs oasdiff on PATH.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fail=0
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if ! command -v oasdiff >/dev/null 2>&1; then
  echo "FAIL oasdiff is not installed"
  exit 1
fi

# A made-up base spec with invented routes.
cat >"$tmp/base.json" <<'J'
{"openapi":"3.0.3","info":{"title":"Sample","version":"1"},
 "paths":{
  "/v1/widgets":{
   "get":{"operationId":"listWidgets","responses":{"200":{"description":"ok",
     "content":{"application/json":{"schema":{"type":"object",
       "properties":{"id":{"type":"string"},"label":{"type":"string"}}}}}}}},
   "post":{"operationId":"createWidget","responses":{"201":{"description":"made"}}}},
  "/v1/gadgets":{"get":{"operationId":"listGadgets","responses":{"200":{"description":"ok"}}}}
 }}
J

# check NAME WANT_EXIT WANT_TEXT NEW_SPEC_FILE
check() {
  local name=$1 want_code=$2 want_text=$3 new=$4
  local got code
  got=$("$here/check-breaking.sh" "$tmp/base.json" "$new" 2>&1)
  code=$?
  if [[ $code -ne $want_code || "$got" != *"$want_text"* ]]; then
    echo "FAIL $name: exit $code, want $want_code; output: $got"
    fail=1
  else
    echo "ok   $name"
  fi
}

mut() { jq "$1" "$tmp/base.json" >"$tmp/$2.json"; }

mut '.' same
mut '.paths["/v1/gadgets"].get.description = "Lists gadgets"
  | .paths["/v1/widgets"].get.responses["200"].content["application/json"].schema.properties.color = {"type":"string"}
  | .paths["/v1/doodads"] = {"get":{"operationId":"listDoodads","responses":{"200":{"description":"ok"}}}}' additive
mut 'del(.paths["/v1/gadgets"])' removed-path
mut 'del(.paths["/v1/widgets"].post)' removed-operation
mut '.paths["/v1/widgets"].get.responses["200"].content["application/json"].schema.properties |= del(.label)' removed-response-field
mut '.paths["/v1/widgets"].get.parameters = [{"name":"q","in":"query","required":true,"schema":{"type":"string"}}]' required-param
mut '.paths["/v1/widgets"].get.parameters = [{"name":"q","in":"query","required":false,"schema":{"type":"string"}}]' optional-param
mut '.paths["/v1/widgets"].post.requestBody = {"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"n":{"type":"string"}}}}}}' required-body

check "identical specs have no breaking change" 0 "no breaking changes" "$tmp/same.json"
check "added routes, fields and docs are not breaking" 0 "no breaking changes" "$tmp/additive.json"
check "an optional new input is not breaking" 0 "no breaking changes" "$tmp/optional-param.json"
check "a removed path is breaking" 3 "removed" "$tmp/removed-path.json"
check "a removed operation is breaking" 3 "POST /v1/widgets" "$tmp/removed-operation.json"
check "a removed response field is breaking" 3 "label" "$tmp/removed-response-field.json"
check "a new required parameter is breaking" 3 "new-required-request-parameter" "$tmp/required-param.json"
check "a new required request body is breaking" 3 "request-body-added-required" "$tmp/required-body.json"

# A new required property inside an existing body.
jq '.paths["/v1/widgets"].post.requestBody = {"content":{"application/json":{"schema":{"type":"object","properties":{"n":{"type":"string"}}}}}}' "$tmp/base.json" >"$tmp/body-base.json"
jq '.paths["/v1/widgets"].post.requestBody.content["application/json"].schema |= (.properties.m = {"type":"string"} | .required = ["m"])' "$tmp/body-base.json" >"$tmp/required-prop.json"
got=$("$here/check-breaking.sh" "$tmp/body-base.json" "$tmp/required-prop.json" 2>&1); code=$?
if [[ $code -eq 3 && "$got" == *"new-required-request-property"* ]]; then echo "ok   a new required body property is breaking"; else echo "FAIL required body property: exit $code; $got"; fail=1; fi

"$here/check-breaking.sh" "$tmp/base.json" >/dev/null 2>&1; code=$?
[[ $code -eq 2 ]] && echo "ok   a missing argument is refused" || { echo "FAIL missing argument: exit $code, want 2"; fail=1; }

"$here/check-breaking.sh" "$tmp/base.json" "$tmp/missing.json" >/dev/null 2>&1; code=$?
[[ $code -eq 2 ]] && echo "ok   a missing file is refused" || { echo "FAIL missing file: exit $code, want 2"; fail=1; }

echo 'not a spec' >"$tmp/junk.json"
"$here/check-breaking.sh" "$tmp/base.json" "$tmp/junk.json" >/dev/null 2>&1; code=$?
[[ $code -eq 2 ]] && echo "ok   an unreadable spec is an error, not a pass" || { echo "FAIL unreadable spec: exit $code, want 2"; fail=1; }

exit $fail

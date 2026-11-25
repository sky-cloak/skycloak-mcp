#!/usr/bin/env bash
# Run: bash scripts/release/added-files_test.sh
# The filter and check scripts and their tests are public: their names and text
# must stay neutral.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
fail=0
# Built in two halves so this file does not contain the word it looks for.
word="plat""form"

for f in filter-spec.sh filter-spec_test.sh check-breaking.sh check-breaking_test.sh added-files_test.sh; do
  if [[ ! -f "$here/$f" ]]; then
    echo "FAIL $f is missing"
    fail=1
  elif [[ "$f" == *"$word"* ]] || grep -qi -- "$word" "$here/$f"; then
    echo "FAIL $f mentions the forbidden word"
    fail=1
  else
    echo "ok   $f is neutral"
  fi
done

exit $fail

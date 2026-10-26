#!/bin/sh
# Checks that ClamAV loads every rule in the given .yar files. ClamAV skips
# rules it cannot handle (modules, global rules) and still exits 0, so the
# number of loaded signatures must equal the number of rules, and the debug
# output must show no parse error.
set -eu
empty=$(mktemp)
trap 'rm -f "$empty"' EXIT
fail=0
for f in "$@"; do
  want=$(grep -cE '^rule[[:space:]]' "$f")
  out=$(clamscan --debug --database="$f" "$empty" 2>&1) || true
  got=$(printf '%s\n' "$out" | sed -n 's/^Known viruses: //p')
  echo "$f: $want rules, ClamAV loaded ${got:-none}"
  if printf '%s\n' "$out" | grep -E 'yyerror|failed to parse'; then
    fail=1
  fi
  [ "$got" = "$want" ] || fail=1
done
exit $fail

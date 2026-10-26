#!/bin/sh
# Checks that YARA-X compiles the given .yar files. yr check exits non-zero
# on warnings too (e.g. duplicate patterns in the original rules, which we
# keep unchanged), so the warnings are shown and only errors fail.
# Usage: check-yarax.sh <yr binary> <file.yar>...
set -u
yr=$1
shift
fail=0
for f in "$@"; do
  out=$("$yr" check "$f" 2>&1)
  printf '%s\n' "$out"
  if ! printf '%s\n' "$out" | grep -qE "^\[ (OK|WARN) \] $f\$"; then
    echo "$f: YARA-X does not compile it"
    fail=1
  fi
done
exit $fail

#!/bin/bash
# Scans the release images before they are published: with meles against a
# clamd with the full signature database and the chart's YARA rules, and with
# Trivy for known vulnerabilities. Any finding, skipped file or error fails the
# release. Runs in .github/workflows/release.yml.
#
#   CLAMAV_IMAGE=... hack/ci/self-scan.sh <meles binary> <OCI layout>...
set -euo pipefail
usage="usage: self-scan.sh <meles binary> <OCI layout>..."
meles=${1:?$usage}
shift
[ $# -gt 0 ] || { echo "$usage" >&2; exit 2; }
: "${CLAMAV_IMAGE:?}"
here=$(cd "$(dirname "$0")" && pwd)
export MELES_CLAMD=tcp://127.0.0.1:3310

# The mini setup brings the limits and the rules; the signatures come from
# Cisco Talos. No cache: this job must not depend on anything an earlier run
# left behind, and it only runs for releases.
dir=$(mktemp -d)
"$here/mini-clamd.sh" "$dir" 3310
sed -i "s#$dir#/clamd#" "$dir/clamd.conf"
chmod -R a+rwX "$dir"
docker run --rm -v "$dir/db:/var/lib/clamav" --entrypoint freshclam "$CLAMAV_IMAGE" --foreground --stdout
docker run -d --name clamd -p 127.0.0.1:3310:3310 -v "$dir:/clamd:ro" \
  --entrypoint clamd "$CLAMAV_IMAGE" --config-file=/clamd/clamd.conf
trap 'docker logs clamd 2>&1 | tail -30; docker rm -f clamd >/dev/null' EXIT
for i in $(seq 120); do
  (exec 3<>/dev/tcp/127.0.0.1/3310 && printf 'zPING\0' >&3 && head -c4 <&3 | grep -q PONG) 2>/dev/null && break
  [ "$i" -lt 120 ] || { echo "clamd did not start" >&2; exit 1; }
  sleep 2
done

# A chain that detects nothing would pass every image.
"$meles" selftest --yara
for layout in "$@"; do
  "$meles" image --input "$layout"
  # Fixed vulnerabilities only: nothing can be done about the others here.
  trivy image --input "$layout" --platform linux/amd64 --scanners vuln \
    --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress
done

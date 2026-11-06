#!/usr/bin/env bash
# Scans the images in images.txt through the API of a running meles server and
# writes one report per image plus results.tsv to an output directory.
#
#   kubectl -n meles port-forward svc/meles-server 8080:80 &
#   hack/popular-images/run.sh http://localhost:8080 /tmp/popular-images
#
# Runs are queued first and collected afterwards, so a dropped port-forward
# only needs a restart of this script: it continues with runs.tsv.
# MELES_PLATFORMS sets the platforms to scan (default linux/amd64).
set -euo pipefail

url=${1:?usage: run.sh <server url> <output dir>}
out=${2:?usage: run.sh <server url> <output dir>}
platforms=${MELES_PLATFORMS:-linux/amd64}
list=$(dirname "$0")/images.txt
mkdir -p "$out/reports"
touch "$out/runs.tsv"

while read -r ref; do
	case $ref in '' | '#'*) continue ;; esac
	grep -q -F "$ref"$'\t' "$out/runs.tsv" && continue
	body=$(jq -n --arg r "$ref" --arg p "$platforms" '{imageRef: $r, platforms: $p}')
	id=$(curl -fsS -X POST -H 'Content-Type: application/json' -d "$body" "$url/api/runs" | jq -r .id)
	printf '%s\t%s\n' "$ref" "$id" >>"$out/runs.tsv"
done <"$list"

while read -r ref id; do
	until run=$(curl -fsS "$url/api/runs/$id") && [ "$(jq -r '.finishedAt // empty' <<<"$run")" ]; do
		sleep 15
	done
	name=${ref//[\/:]/_}
	echo "$run" >"$out/reports/$name.run.json"
	curl -fsS "$url/api/runs/$id/report" -o "$out/reports/$name.report.json" || true
	jq -r '[.imageRef, .status] | @tsv' <<<"$run"
done <"$out/runs.tsv"

{
	printf 'image\tstatus\tseconds\tfiles\tfindings\tskipped\tdigest\terror\n'
	while read -r ref _; do
		jq -r '[.imageRef, .status,
			(((.finishedAt[:19] + "Z" | fromdate) - (.startedAt[:19] + "Z" | fromdate))),
			.files, .findings, .skipped, .digest, (.error // "" | gsub("[\t\n]"; " "))] | @tsv' \
			"$out/reports/${ref//[\/:]/_}.run.json"
	done <"$out/runs.tsv"
} >"$out/results.tsv"

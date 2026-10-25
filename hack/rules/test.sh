#!/bin/sh
# Renders the chart's PrometheusRule and runs its unit tests with promtool
# (from the Prometheus release or image; PROMTOOL overrides the path).
set -eu
cd "$(dirname "$0")"
PROMTOOL=${PROMTOOL:-promtool}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
helm template meles ../../charts/meles \
	--set operator.enabled=true,operator.gate.enabled=true,operator.prometheusRule.enabled=true \
	--show-only templates/operator-rules.yaml |
	sed -n '/^spec:/,$p' | sed '1d; s/^  //' >"$out/rules.yaml"
cp rules_test.yaml "$out/"
"$PROMTOOL" check rules "$out/rules.yaml"
"$PROMTOOL" test rules "$out/rules_test.yaml"

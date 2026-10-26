# Development

Building, testing and releasing meles. How it works inside is described in
[architecture.md](architecture.md).

## Requirements

- Go (see `go.mod`), no CGO
- a running clamd for the integration tests and the selftest, e.g.
  `apt install clamav-daemon`
- no Docker: images are built with [ko](https://ko.build), the operator
  tests run against envtest's API server and etcd, and test images come from
  an in-memory registry

## Make targets

```sh
make build              # bin/meles
make test               # unit tests (race detector)
make test-integration   # against a real clamd (CLAMD=unix:///run/clamav/clamd.ctl)
make test-envtest       # operator and cluster-report tests against a real API server and etcd (downloads them)
make test-rules         # the chart's Prometheus alerts with promtool (PROMTOOL=<path>)
make generate           # deepcopy functions and the CRD after changing api/v1alpha1
make lint               # gofmt and go vet
make selftest           # EICAR test images against $(CLAMD)
make run-server         # web UI on http://127.0.0.1:8080, database meles.db
make image              # build and push the multi-arch image with ko
make image-tarball      # build the image into dist/meles.tar, no push
```

## Tests

- **Unit tests** are table tests. The engine is replaced by
  `internal/engine/fake`, which can report signatures, refuse sizes and hold
  scans (to test queues and timeouts).
- **Integration tests** carry the build tag `integration` and run against
  the clamd in `MELES_TEST_CLAMD` (`make test-integration` sets it from
  `CLAMD`). There is no testcontainers, because the development machine has
  no Docker.
- **envtest**: `internal/operator` and `internal/server` start a real API
  server and etcd (`KUBEBUILDER_ASSETS`, set by `make test-envtest`;
  Kubernetes version in `ENVTEST_K8S`). Without it these tests are skipped by
  `make test`. CI runs them.
- **Alert rules**: `make test-rules` renders the chart's PrometheusRule and
  runs `promtool check rules` and the unit tests in
  `hack/rules/rules_test.yaml`. CI runs it in its own job with helm and
  promtool from their releases, pinned by version and sha256 in
  `.gitea/workflows/ci.yml`; update both there together.

### EICAR

EICAR test files are generated at runtime and never stored in the
repository; they would trigger scanners on developer machines and in CI.
`internal/testimage` builds test images (clean, EICAR present, EICAR deleted
by a whiteout, optionally behind basic auth) and serves them from an
in-memory registry. To try the UI with them:

```sh
go run ./hack/testregistry &      # EICAR test images on 127.0.0.1:5055
bin/meles server --insecure-registry --db demo.db
# then scan 127.0.0.1:5055/selftest/eicar-whiteout:latest
```

## Repository layout

```
api/v1alpha1/           CRD types (MalwareReport, ignore rules, group meles.io)
cmd/meles/              main and cobra commands
internal/source/        image sources (registry), platform filter
internal/extract/       reading layers, whiteouts, limits
internal/engine/        engine interface; clamd/, fake/
internal/clamdproxy/    clamd-proxy: TLS, token, command filter
internal/scan/          scanner: pipeline, layer cache, report types, ignore application
internal/ignore/        ignore rules
internal/report/        CLI output: table, json
internal/store/         SQLite: scans, runs, findings, cluster history
internal/runner/        queue and workers for the server's runs
internal/schedule/      cron schedules
internal/server/        web UI (web/templates, web/static) and JSON API
internal/operator/      operator: pods, workloads, scan queue, reports, pruning
internal/harbor/        Harbor scanner adapter
internal/yararules/     index of the default YARA rules (author, license), generated
internal/testimage/     EICAR test images, in-memory registry
hack/testregistry/      test images on a fixed port (UI demo)
hack/yaraindex/         generator of internal/yararules/index.json
hack/yara/              ClamAV load check of YARA rules (CI)
charts/meles/           Helm chart; crds/ is generated; rules/ holds the default YARA rules
spike/                  throw-away prototype (own module), reference only
```

## Conventions

- Code, comments, commit messages and documentation in English.
- [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix:`, `docs:` ...): the changelog is made from them. Versions follow
  SemVer.
- Wrap errors with context (`fmt.Errorf("pull %s: %w", ref, err)`); no
  panics in library code.
- Logging with `log/slog`, structured. Scan results go to stdout, logs to
  stderr.
- Unpacking is security code: check paths against traversal, keep the limits
  for total size, file size and number of files, never require root.

## CRDs

After changing `api/v1alpha1` run `make generate`; it writes the deepcopy
functions and `charts/meles/crds/`. Helm installs CRDs with the chart but
never updates them, so after an upgrade:

```sh
kubectl apply -f charts/meles/crds/
```

## YARA rules

The default rules live in `charts/meles/rules/` (selection and licenses in
its README). After changing them:

```sh
go generate ./internal/yararules                    # rule index embedded in meles
hack/yara/check-clamav.sh charts/meles/rules/*.yar  # every rule loads in ClamAV (needs clamscan)
yr check charts/meles/rules/                        # compiles in YARA-X
```

CI runs all three (the ClamAV check in the deployed `clamav/clamav` image).

## Images and releases

`make image` builds `meles` for linux/amd64 and linux/arm64 with ko on
`cgr.dev/chainguard/static` (non-root) and pushes it to `KO_DOCKER_REPO`
with the tags `$(VERSION)` and `latest`. Build from a clean checkout of the
commit (e.g. a `git worktree`), so that the version is not `-dirty`, and
then set `appVersion` in `charts/meles/Chart.yaml` in a follow-up commit.

Planned for releases: GoReleaser (linux/darwin, amd64/arm64), multi-arch
images on ghcr.io, keyless cosign signatures, SBOM and SLSA provenance, and
a scan of the own image with Trivy and meles.

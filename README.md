# meles

**meles** is a malware scanner for container images. It works like Trivy, but
looks for malware instead of CVEs: one command on an image reference, no
Docker daemon, CI-friendly exit codes. A web UI runs scheduled scans and keeps
reports.

The name comes from *Meles meles*, the European badger – it digs through the
layers.

## Why

- Trivy, Grype & co. find vulnerabilities, misconfigurations and secrets – not malware.
- meles scans **every layer separately**, not just the final filesystem. A file
  that a later layer deletes (whiteout) is still shipped with the image and is
  still found, with the layer that added it and the one that deleted it.
- **All platforms** of a multi-arch image are scanned by default: an amd64 CI
  runner would otherwise miss malware in the arm64 variant.
- No Docker socket: images are pulled straight from the registry.
- Scanning is done by ClamAV's `clamd` over its socket protocol. meles does not
  link against libclamav and stays Apache-2.0 licensed.

meles reports; it does not block or delete anything. It is no substitute for
image signing, SBOMs or runtime detection.

## Quick start

You need a running clamd (e.g. `apt install clamav-daemon`, or the
`clamav/clamav` image).

```sh
make build
bin/meles selftest                     # checks the whole chain with EICAR test images
bin/meles image alpine:3.20
bin/meles image --format json --platform linux/amd64 ghcr.io/org/app:1.2
```

```
alpine:3.20 (d9e853e87e55)
engine: ClamAV 1.4.3, signatures 28159, scanned in 2.6s

PLATFORM        LAYERS  FILES  FINDINGS  SKIPPED
linux/amd64     1       87     0         0
linux/arm64/v8  1       87     0         0

No malware found.
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | clean (or findings with `--exit-code 0`, report-only mode) |
| `1` | malware found (change with `--exit-code`) |
| `2` | error: pull, engine or configuration. **Never** reported as clean. |

Unlike Trivy, meles fails the pipeline on findings by default.

Files that were not scanned (above `--max-file-size`, or above one of clamd's
scan limits) are listed as skipped, and the report is marked incomplete: the
table says "Scan INCOMPLETE" instead of "No malware found.", the JSON report
has `"complete": false`. By default this does not change the exit code. Use
`--skipped-exit-code 2` to treat an incomplete scan as an error, or
`--skipped-exit-code 1` to treat it like a finding.

### Configuration

Every flag can also be set as an environment variable `MELES_<FLAG>`, e.g.
`MELES_CLAMD=tcp://clamd:3310` or `MELES_PLATFORM=host`. Flags win over
environment variables, which win over defaults.

| Flag | Default | |
|---|---|---|
| `--clamd` | `unix:///run/clamav/clamd.ctl` | `unix:///path` or `tcp://host:3310` |
| `--platform` | `all` | `all`, `host` or a list like `linux/amd64,linux/arm64` |
| `--format` | `table` | `table`, `json` |
| `--exit-code` | `1` | exit code on findings; `2` is reserved for errors |
| `--skipped-exit-code` | `0` | exit code when files were not scanned; `0` = report only |
| `--max-file-size` | `25M` | larger files are skipped **and reported**; keep ≤ clamd's `StreamMaxLength` |
| `--max-layer-size` | `4G` | hard limit per layer (uncompressed); exceeding it is an error |
| `--max-files` | `500000` | hard limit of entries per layer |
| `--concurrency` | `4` | parallel clamd sessions |

Registry credentials come from the Docker config (`~/.docker/config.json` or
`$DOCKER_CONFIG`).

### CI

GitHub Actions / Gitea Actions:

```yaml
- name: Scan image for malware
  run: meles image --clamd tcp://clamd:3310 "$IMAGE"
```

GitLab CI:

```yaml
malware-scan:
  image: git.itknecht.de/sugras/meles:latest
  services:
    - name: clamav/clamav:1.4
      alias: clamd
  variables:
    MELES_CLAMD: tcp://clamd:3310
  script:
    - meles image "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
```

## Web UI

`meles server` serves a web UI and JSON API:

- **Dashboard** – quick scan, images that need attention, upcoming and recent runs
- **Scans** – image references with an optional cron schedule (`@daily`,
  `0 3 * * 1-5`, `@every 6h`, `CRON_TZ=Europe/Berlin …`)
- **Runs** – every run with its result; the run page shows each finding with
  path, signature, platform, layer, Dockerfile instruction and whether a later
  layer deleted it
- **Reports** – runs per day, image status, top signatures, CSV export

```sh
make run-server          # http://127.0.0.1:8080, database in meles.db
```

Runs and reports are stored in SQLite. The server has **no login of its own**:
keep it internal or put an authenticating proxy in front of it.

To try it with infected test images locally:

```sh
go run ./hack/testregistry &      # serves EICAR test images on 127.0.0.1:5055
bin/meles server --insecure-registry --db demo.db
# then scan 127.0.0.1:5055/selftest/eicar-whiteout:latest
```

API: `GET/POST /api/scans`, `GET/PUT/DELETE /api/scans/{id}`,
`POST /api/scans/{id}/run`, `GET/POST /api/runs`, `GET /api/runs/{id}`,
`GET /api/runs/{id}/report`, `/healthz`, `/readyz` (clamd reachable).

## Kubernetes

`deploy/base` is a Kustomize base with three roles in the namespace `meles`:

| Component | Purpose |
|---|---|
| `meles-mirror` | cvdupdate + nginx. The only component that downloads signatures from Cisco Talos (at most hourly). |
| `meles-clamd` | clamd workers; get signatures from the mirror via freshclam `PrivateMirror`. |
| `meles-server` | web UI, scheduler, run history (SQLite on a PVC). |

Plus a suspended CronJob `meles-selftest` to check the chain on demand.

```sh
kubectl apply -k deploy/base
kubectl -n meles create job --from=cronjob/meles-selftest selftest-1
kubectl -n meles port-forward svc/meles-server 8080:80
```

The `meles` image is private: create a pull secret `meles-pull` in the
namespace. For private images to scan, put a Docker config into the secret
`meles-registry-auth` (type `kubernetes.io/dockerconfigjson`).

clamd needs about 1.5 GB of memory with the full database and briefly almost
twice that during a reload.

## Development

```sh
make test               # unit tests (race detector)
make test-integration   # against a real clamd (CLAMD=unix:///run/clamav/clamd.ctl)
make lint
make image              # build and push the image with ko, no Docker daemon
```

EICAR test files are generated at runtime and never stored in the repository.

## License

Apache-2.0. The `clamav/clamav` image used for the workers contains ClamAV,
which is licensed under GPLv2.

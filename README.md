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
- Besides ClamAV's signatures, the Helm chart ships about 140 curated YARA
  rules for cryptominers, Linux malware, webshells and attacks on
  containers, run by clamd as well.

By default meles only reports, and it never deletes anything. It is no
substitute for image signing, SBOMs or runtime detection.

## Documentation

- this README: using meles (CLI, web UI, Kubernetes, Harbor)
- [docs/architecture.md](docs/architecture.md): how it works, where state
  lives, security model, design decisions
- [docs/development.md](docs/development.md): building, testing, releasing
- [docs/architecture.md#planned-improvements](docs/architecture.md#planned-improvements): what is planned but not built yet
- [ROADMAP.md](ROADMAP.md): plans and progress (German)

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
| `1` | malware found, or files were not scanned (change with `--exit-code` and `--skipped-exit-code`) |
| `2` | error: pull, engine or configuration. **Never** reported as clean. |

Unlike Trivy, meles fails the pipeline on findings by default.

Files that were not scanned (above `--max-file-size`, or above one of clamd's
limits) are listed as skipped, and the report is marked incomplete: the table
says "Scan INCOMPLETE" instead of "No malware found.", the JSON report has
`"complete": false`, and meles exits with `1` like on a finding. Any size
limit can be dodged by making a file larger than it, so an unscanned file
must not pass a security gate. Use `--skipped-exit-code 0` to only report
skipped files, or `2` to treat them as an error.

`--max-file-size` defaults to `768M` and can be raised up to ClamAV's own
limit of `2047M`. Files above 4 MiB are streamed to clamd, so a high limit
costs no memory in meles; clamd keeps each stream in a temporary file while
it scans it. clamd's `StreamMaxLength`, `MaxFileSize` and `MaxScanSize` must
be at least as large (the Helm chart sets them to at least
`scan.maxFileSize`, see [Limits in clamd](docs/architecture.md#limits-in-clamd);
clamd's own default `StreamMaxLength` is only `100M`). Files that clamd
refuses as too large are reported as skipped. Larger files, such as big ML
models, cannot be scanned by ClamAV at all.

### Configuration

Every flag can also be set as an environment variable `MELES_<FLAG>`, e.g.
`MELES_CLAMD=tcp://clamd:3310` or `MELES_PLATFORM=host`. Flags win over
environment variables, which win over defaults.

| Flag | Default | |
|---|---|---|
| `--clamd` | `unix:///run/clamav/clamd.ctl` | `unix:///path`, `tcp://host:3310` or `tls://host:3310` (clamd-proxy) |
| `--clamd-token` | | token for `meles clamd-proxy`; set it as `MELES_CLAMD_TOKEN`, a flag shows up in the process list |
| `--clamd-ca` | system roots | CA certificate of `meles clamd-proxy` |
| `--clamd-timeout` | `5m` | wait for clamd's verdict on a file; keep it above clamd's `MaxScanTime` |
| `--platform` | `all` | `all`, `host` or a list like `linux/amd64,linux/arm64` |
| `--format` | `table` | `table`, `json`, `sarif` (SARIF 2.1.0, e.g. for GitHub code scanning) |
| `--exit-code` | `1` | exit code on findings; `2` is reserved for errors |
| `--skipped-exit-code` | `1` | exit code when files were not scanned; `0` = report only |
| `--max-file-size` | `768M` | larger files are skipped **and reported**; at most `2047M`, keep ≤ clamd's `StreamMaxLength` |
| `--max-layer-size` | `4G` | hard limit per layer (uncompressed); exceeding it is an error |
| `--max-files` | `500000` | hard limit of entries per layer |
| `--concurrency` | `4` | parallel clamd sessions |
| `--ignorefile` | | YAML file with ignore rules, see below |
| `--input` | | read the image from a local OCI layout or `docker save` archive instead of a registry, see below |
| `--registry-mirror` | | pull a registry's images from a mirror first, e.g. `docker.io=harbor.example.com/dockerhub`; repeatable |

Registry credentials come from the Docker config (`~/.docker/config.json` or
`$DOCKER_CONFIG`).

`--registry-mirror registry=host[/path]` pulls images of `registry` from
`host/path/<repository>` first, e.g. from a Harbor proxy cache project:
`docker.io=harbor.example.com/dockerhub` pulls `nginx:1.27` as
`harbor.example.com/dockerhub/library/nginx:1.27`. The registry itself is
the fallback when the mirror fails, as in containerd, and reports keep the
original reference. A mirror is trusted for tags; for digests meles checks
that the mirror serves exactly that digest. Registries that are only other
names for Docker Hub (such as `cr.smallstep.com`) need their own entry.

### Ignore rules

False positives (a miner detector's test data, a network tool) and files
the engine cannot scan for a known harmless reason would otherwise turn a
pipeline red for good. An ignore file lists them, each with a reason and an
expiry date at most a year ahead:

```yaml
# meles-ignore.yaml
rules:
  - name: php-phar-test-quine
    # Every php:* image ships the PHP sources. ext/phar/tests/bug81726.gz
    # unpacks to itself, so clamd stops at MaxRecursion whatever the limit.
    path: /usr/src/php.tar.xz
    signature: Heuristics.Limits.Exceeded.MaxRecursion
    reason: PHP test file bug81726.gz is a gzip that contains itself
    expires: "2027-06-30"
  - name: monitor-miner-samples
    signature: "*.Coinminer.*"
    image: ghcr.io/acme/monitor
    path: /opt/monitor/testdata/**
    reason: detection samples of our miner monitor, reviewed 2026-10
    expires: "2027-01-31"
```

```sh
meles image --ignorefile meles-ignore.yaml nextcloud:33
```

A rule matches when all of its set fields match; it needs at least one of
`path`, `signature` and `sha256`. `path` and `signature` are globs (`*` and
`?` within a path segment, `**` across segments), `image` is a repository
glob or an image digest `sha256:…`, `sha256` names exactly one file content
(the JSON output has the hash of every finding and skipped file). Skipped
files have signatures too: clamd's `Heuristics.Limits.Exceeded.*`, or
`Meles.Limits.MaxFileSize`, `Meles.Limits.StreamMaxLength` and
`Meles.Unsupported.TarEntry`.

Ignored entries stay in the report, marked with the rule and its reason;
they only no longer count for the verdict and the exit code. Once a rule has
expired, the entry counts again and the report says so. An invalid rule
(no reason, no date, a date more than a year ahead, an unknown field) fails
the run. Scan errors can never be ignored.

### Local images

`--input` scans an image that is not in a registry yet, so that a pipeline
can check it before pushing it:

```sh
docker save app:1.4 -o app.tar && meles image --input app.tar
docker buildx build --output type=oci,dest=app.tar . && meles image --input app.tar app:1.4
podman save --format oci-archive -o app.tar app:1.4 && meles image --input app.tar
meles image --input oci-layout/          # an OCI image layout directory
```

meles reads OCI image layouts (a directory or a tar of one, as written by
`docker save` since Docker 25, buildx `type=oci`, `podman save --format
oci-archive`, skopeo `oci-archive:`) and the `docker save` format of older
Docker versions and of plain `podman save`. Tars may be gzip or zstd
compressed; a compressed tar is unpacked into one temporary file first
(`TMPDIR`), an uncompressed one is read in place. If the input holds several
images, name the one to scan: `meles image --input all.tar app:1.4`. The
report names the image as the archive does; for an archive without names
(e.g. `crane pull --format=oci`), the name you give is used, so that ignore
rules with `image:` match. Layer contents are checked against their digests
while they are read, as for a registry.

### CI

GitHub Actions / Gitea Actions:

```yaml
- name: Scan image for malware
  run: meles image --clamd tcp://clamd:3310 "$IMAGE"
```

Scan before pushing:

```yaml
- run: docker build -t app:${{ github.sha }} . && docker save app:${{ github.sha }} -o app.tar
- name: Scan image for malware
  run: meles image --clamd tcp://clamd:3310 --input app.tar
- run: docker push app:${{ github.sha }}
```

With GitHub code scanning, write SARIF and upload it even when meles fails
the job:

```yaml
- name: Scan image for malware
  run: meles image --clamd tcp://clamd:3310 --format sarif "$IMAGE" > meles.sarif
- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: meles.sarif
    category: meles
```

In SARIF, findings are errors and skipped files warnings (the scan is
incomplete). Entries an ignore rule takes out of the verdict are kept as
suppressed results with the rule's reason. The location is the path in the
image; image, platform, layer and Dockerfile instruction are in the result's
properties. The fingerprint leaves out the digest, so an alert stays the
same alert in the next version of the image. A failed scan marks the run
unsuccessful instead of producing an empty, clean-looking report.

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

The UI follows the system's light or dark mode; the switch in the header
overrides it for the browser (stored in its local storage).

Runs and reports are stored in SQLite. The server has **no login of its own**:
keep it internal or put an authenticating proxy in front of it.

`meles server --ignorefile meles-ignore.yaml` applies ignore rules (format
below) to its runs; the file is read at every run. A run keeps the verdict
of its time: a new rule applies from the next run on.

To try it with infected test images locally, see
[development.md](docs/development.md#eicar).

API: `GET/POST /api/scans`, `GET/PUT/DELETE /api/scans/{id}`,
`POST /api/scans/{id}/run`, `GET/POST /api/runs`, `GET /api/runs/{id}`,
`GET /api/runs/{id}/report`, `/healthz`, `/readyz` (clamd reachable).

## Kubernetes

The Helm chart in `charts/meles` installs these roles:

| Component | Purpose |
|---|---|
| `<release>-mirror` | cvdupdate + nginx. The only component that downloads signatures from Cisco Talos (at most hourly); also serves the YARA rules. |
| `<release>-clamd` | clamd workers; get signatures from the mirror via freshclam `PrivateMirror`. |
| `<release>-server` | web UI, scheduler, run history (SQLite on a PVC). |
| `<release>-operator` | scans the image of every pod in the cluster, writes MalwareReports (off by default, see below). |

Plus a suspended CronJob `<release>-selftest` to check the chain on demand.
Each role can be turned off; with `clamd.enabled=false` set `clamd.address`
to an existing clamd.

```sh
kubectl create namespace meles
kubectl label namespace meles pod-security.kubernetes.io/enforce=baseline
helm install meles charts/meles -n meles -f my-values.yaml
kubectl -n meles create job --from=cronjob/meles-selftest selftest-1
kubectl -n meles port-forward svc/meles-server 8080:80
```

The clamd image starts as root and drops privileges itself, so the namespace
needs the `baseline` Pod Security level, not `restricted`.

Important values (see `charts/meles/values.yaml`):

| Value | Default | |
|---|---|---|
| `imagePullSecrets` | `[]` | pull secrets for the meles image |
| `scan.maxFileSize` | `768M` | `--max-file-size` of meles and clamd's `StreamMaxLength` (`MaxScanSize`/`MaxFileSize` at least this); at most `2047M` |
| `clamd.maxScanSize` | `100M` | clamd's `MaxScanSize` and `MaxFileSize`: data scanned per file including unpacked content; at least `scan.maxFileSize` |
| `clamd.maxScanTime` | `120000` | clamd's `MaxScanTime` in milliseconds; larger compressed archives may need more. `--clamd-timeout` of the meles clients follows it (plus a minute, at least 5 minutes) |
| `clamd.maxFiles` | `10000` | clamd's `MaxFiles`: files scanned per archive |
| `clamd.maxRecursion` | `17` | clamd's `MaxRecursion`: nesting of archives |
| `clamd.detectPUA` | `false` | ClamAV's `PUA.*` signatures (potentially unwanted applications); mostly false positives in container images |
| `yara.defaultRules` | `true` | the chart's YARA rules (see below) |
| `yara.extra` | `[]` | own YARA rules from ConfigMaps, e.g. `[{configMap: team-rules, files: [team.yar]}]` |
| `server.timezone` | `UTC` | time zone of cron schedules |
| `server.clusterReports.enabled` | with `operator.enabled` | page "Cluster" with the operator's MalwareReports (ClusterRole: read `malwarereports`) |
| `server.clusterReports.rescan` | `true` | "Rescan" button in the UI (adds `patch` on `malwarereports`) |
| `server.clusterReports.ignore` | `false` | "Ignore…" button and page "Ignore rules" (adds `create`/`delete` on `malwareignores` and `clustermalwareignores`), see below |
| `server.clusterReports.historyDays` | `365` | keep the history of the reports this many days |
| `server.registryAuthSecret` | `""` | `kubernetes.io/dockerconfigjson` secret for private images to scan |
| `scan.registryMirrors` | `[]` | mirrors the server and the operator pull from first, e.g. `docker.io=harbor.example.com/dockerhub` (see `--registry-mirror`) |
| `scan.registryCA.configMap` | `""` | ConfigMap with an additional CA (`key`, default `ca.crt`) for registries and mirrors, e.g. a private CA of Harbor |
| `server.httpRoute.*`, `server.ingress.*` | off | expose the UI (Gateway API or Ingress) |
| `clamd.auth.enabled` | `true` | TLS + token in front of clamd (see below) |
| `clamd.auth.existingSecret` | `""` | secret with key `token`; empty: generated and kept |
| `clamd.auth.tls.*` | self-signed | `existingSecret`, `certManager.enabled` + `issuerRef`, `extraDnsNames` |
| `networkPolicy.enabled` | `true` | clamd only for pods of the release, the mirror only for clamd |
| `networkPolicy.clamdExtraFrom` | `[]` | further clients of clamd, e.g. CI runners in other namespaces |
| `networkPolicy.serverFrom` | `[]` | restrict access to the UI, e.g. to the ingress controller |
| `operator.enabled` | `false` | run the operator |
| `operator.platform` | `nodes` | `nodes` (architectures of the cluster's nodes), `all`, or a list |
| `operator.retryAfter` | `1h` | retry of failed scans |
| `operator.retryIncompleteAfter` | `12h` | rescan of images with skipped files |
| `operator.pullSecrets.clusterWide` | `false` | read the pods' `imagePullSecrets` in all namespaces; otherwise per namespace with a RoleBinding (see below) |
| `operator.registryAuthSecret` | `""` | `kubernetes.io/dockerconfigjson` secret the operator always uses, e.g. a Docker Hub account |
| `operator.pruneInterval` | `30m` | delete reports of ReplicaSets, StatefulSets and DaemonSets without pods; `0` disables |
| `operator.rescanInterval` | `24h` | rescan after a signature update at most this often; `0` disables |
| `operator.serviceMonitor.enabled` | `false` | ServiceMonitor for the operator's `/metrics` (`labels`, `interval`) |
| `operator.prometheusRule.enabled` | `false` | alerts as a PrometheusRule (`labels`, `alertLabels`, `disabled`, `errorFor`, `gateHeldFor`, `uiURL`) |
| `operator.grafanaDashboard.enabled` | `false` | Grafana dashboard as a ConfigMap for the sidecar (`labels`, default `grafana_dashboard: "1"`; `namespace`, `annotations`) |
| `networkPolicy.operatorMetricsFrom` | `[]` | further peers allowed to reach the operator's `/metrics` and `/status`, e.g. Prometheus |
| `operator.gate.enabled` | `false` | scan gate: hold new pods in labelled namespaces until their images are scanned (see below) |
| `operator.gate.failOpen` | `true` | release held pods when the scan failed in clamd |
| `operator.gate.failurePolicy` | `Ignore` | webhook failure policy; `Fail` blocks pod creation in gated namespaces while the operator is down |
| `operator.gate.tls.certManager.*` | off | webhook certificate from cert-manager instead of a self-signed one |

### YARA rules

`charts/meles/rules/meles.yar` holds about 140 YARA rules from open sources
(signature-base, Volexity, ditekSHen, SEKOIA and others), selected for
containers: cryptominers, Linux malware, webshells and attacks on Docker
and Kubernetes. They were checked against the images of a typical cluster
without a false positive. The mirror serves them, freshclam loads them into
every clamd pod, and clamd runs them with ClamAV's YARA support; findings
look like `YARA.SIGNATURE_BASE_XMRIG_Monero_Miner.UNOFFICIAL`.

Every finding of such a rule names the rule's author, license and source
(CLI, JSON, MalwareReports, web UI, Harbor): the Detection Rule License of
some sources requires it. Sources and licenses:
[charts/meles/rules/README.md](charts/meles/rules/README.md).

Own rules go into ConfigMaps of the release namespace and `yara.extra`; the
mirror serves them next to the default ones. ClamAV supports a subset of
YARA (no modules, no `global` rules) and skips other rules silently, so
check them first: `clamscan -d team.yar /dev/null` must report as many
"Known viruses" as the file has rules.

Changed rules reach clamd with freshclam's next check
(`clamd.freshclam.checksPerDay`, default hourly). The clamd-proxy appends a
hash of the loaded rules to the signature version (`28164+rules.3f2a…`), so
the operator and the layer caches rescan as after a signature update.
Without `clamd.auth` (no proxy) new rules do not trigger rescans.

With the CLI against your own clamd, put `meles.yar` into clamd's database
directory and reload clamd.

### Operator

With `operator.enabled=true`, meles watches all pods of the cluster and scans
the image every container (including init containers) runs, by digest. The
result is a `MalwareReport` (`meles.io/v1alpha1`) in the pod's namespace, one
per workload and container, owned by the workload and deleted with it:

```
$ kubectl get malwarereports -A
NAMESPACE   NAME                         WORKLOAD     CONTAINER   IMAGE                     STATUS     FINDINGS
shop        replicaset-web-5d8f7c-app    ReplicaSet   app         docker.io/acme/web        Clean      0
tools       cronjob-backup-rclone        CronJob      rclone      docker.io/rclone/rclone   Infected   1
```

- A workload is the pod's controller (ReplicaSet, StatefulSet, DaemonSet,
  Job), the CronJob of a Job, or the pod itself.
- Every digest is scanned once; other workloads with the same image get a
  copy of the result.
- `Status` is `Clean`, `Infected`, `Incomplete` (files skipped) or `Error`
  (not scanned, e.g. a private registry or an image imported into the node).
  `Error` and `Incomplete` are never clean.
- `Error` is retried after `operator.retryAfter` (1h), `Incomplete` after
  `operator.retryIncompleteAfter` (12h), for example once clamd's limits
  (`clamd.maxScanSize`, `clamd.maxScanTime`) were raised. Other results are
  rescanned when
  the signature database changed, at most once per `operator.rescanInterval`
  (24h; each rescan pulls the image again).
- Reports of ReplicaSets, StatefulSets and DaemonSets without pods, such as
  the old ReplicaSets a Deployment keeps for rollbacks, are deleted every
  `operator.pruneInterval`. A CronJob keeps its report between runs.
- A deleted report is written again right away. To rescan an image now,
  e.g. after raising clamd's limits, annotate one of its reports; all
  reports of the image get the new result:

  ```sh
  kubectl annotate malwarereport -n nextcloud replicaset-nextcloud-7d9f-app meles.io/rescan=1
  ```
- Images of private registries are pulled with the `imagePullSecrets` of the
  pods that run them and of their service accounts, as the kubelet does,
  where the operator may read them. That is opt-in per namespace: the team
  that owns it binds the ClusterRole `<release>-pull-secret-reader` (`get`
  on `secrets` and `serviceaccounts`, no `list` or `watch`) to the
  operator, and nobody has to give it every secret of the cluster:

  ```sh
  kubectl -n shop create rolebinding meles-pull-secrets \
    --clusterrole=meles-pull-secret-reader --serviceaccount=meles:meles-operator
  ```

  A team that wants to expose only its pull secret writes its own Role with
  `resourceNames`. Until then, private images are reported as `Error`,
  never as `Clean`, and the error names the command for its namespace.
  `operator.pullSecrets.clusterWide` binds the role in all namespaces
  instead. `operator.registryAuthSecret` adds one Docker config the
  operator always uses, e.g. a Docker Hub account against its pull rate
  limit or a registry mirror, without any permission on other secrets.
  Credentials that exist only on the nodes (kubelet credential providers)
  are not covered. Mirrors configured on the nodes (containerd,
  `registries.yaml` of k3s) are not seen either: set the same ones in
  `scan.registryMirrors`, or the operator pulls from the upstream registry
  and spends its pull rate limit, e.g. Docker Hub's for anonymous pulls,
  which it shares with the kubelet (see
  [Registry rate limits and a pull-through cache](#registry-rate-limits-and-a-pull-through-cache)).

Ignore rules (see [Ignore rules](#ignore-rules)) live in two resources:
`MalwareIgnore` for the reports of its namespace, so that teams manage the
exceptions for their own workloads, and the cluster-scoped
`ClusterMalwareIgnore` for administrators. Who may create them is up to
Kubernetes RBAC. Changed rules apply to the reports right away, without a
rescan; ignored entries stay in the report, marked with the rule
(`<object>#<n>` or `<object>/<name>`), and the summary counts them as
`ignored`. Invalid and expired rules are listed in the object's status:

```yaml
apiVersion: meles.io/v1alpha1
kind: ClusterMalwareIgnore
metadata:
  name: known-harmless
spec:
  rules:
    - name: php-phar-test-quine
      path: /usr/src/php.tar.xz
      signature: Heuristics.Limits.Exceeded.MaxRecursion
      reason: PHP test file ext/phar/tests/bug81726.gz unpacks to itself
      expires: "2027-06-30"
```

```
$ kubectl get clustermalwareignores
NAME             RULES   PROBLEMS   AGE
known-harmless   1                  2m
```

With `server.clusterReports.ignore=true` rules can also be created in the
web UI: the button **Ignore…** at a finding or skipped file opens a form
prefilled with path, signature, image and the file's sha256. Reason and
expiry (default 90 days, at most a year) are required, and the rule applies
either to the report's namespace (a `MalwareIgnore`) or to the whole
cluster (a `ClusterMalwareIgnore`). Every rule becomes an object of its own,
labelled `app.kubernetes.io/managed-by: meles-server`, with the user from
oauth2-proxy (`X-Forwarded-Email`) in the annotation `meles.io/created-by`.
The page **Ignore rules** lists all rules with their origin: created in the
UI (by whom), or applied by Argo CD, Flux, Helm, or kubectl/Git. The UI
deletes only the rules it created. The server's own runs apply the
`ClusterMalwareIgnore`s too.

This is **off by default**: everyone who can open the UI could then take
findings out of the verdict and, with the scan gate on, let an image run.
Limit who may log in first (`server.oauth2Proxy.allowedGroups`).

The web UI shows the reports on the page **Cluster** (filter by result,
namespace or image; details with findings and skipped files; a "Rescan"
button) and as JSON under `/api/cluster/reports`. The server reads them
from the Kubernetes API, the reports stay the only source. Every change of a
report (a new result, a deletion) is also recorded in the server's database:
the report page shows the history of the workload, across rollouts for the
ReplicaSets of a Deployment, and the Cluster page since when each status
holds (JSON: `/api/cluster/reports/<namespace>/<name>/history`). Everyone who
can open the UI sees the reports of all namespaces.

Above the reports, the Cluster page shows what the operator does: scans
running and waiting (by priority), the oldest waiting scan, recent scans
with errors, and the pods the scan gate holds (JSON:
`/api/cluster/operator`). The operator serves this at `/status` and
Prometheus metrics at `/metrics` on port 8080, behind the headless service
`<release>-operator-metrics`:

| Metric | |
|---|---|
| `meles_operator_scan_queue{priority}` | scans waiting: `gated`, `new`, `rescan` |
| `meles_operator_scans_running` | scans running |
| `meles_operator_scans_total{status}` | finished scans: `Clean`, `Infected`, `Incomplete`, `Error` |
| `meles_operator_scan_duration_seconds` | histogram of scan durations |
| `meles_operator_gate_held_pods` | pods the scan gate holds |
| `meles_operator_gate_released_total{scan}` | released pods: `complete` or `unscanned` |
| `meles_operator_leader` | 1 on the replica that scans |
| `meles_operator_reports{namespace,status}` | MalwareReports in the cluster (leader only) |
| `meles_operator_infected{namespace,report,workload_kind,workload,container,image}` | findings of each Infected report (leader only) |

`operator.serviceMonitor.enabled` creates a ServiceMonitor (with
`honorLabels`, so `namespace` of `meles_operator_reports` stays the
report's); with network policies on, allow Prometheus in
`networkPolicy.operatorMetricsFrom`. `operator.grafanaDashboard.enabled`
adds a Grafana dashboard (reports, queue, scans, scan gate) as a ConfigMap
for Grafana's dashboard sidecar, as in kube-prometheus-stack; the JSON is
in `charts/meles/dashboards/` for importing it by hand.

`operator.prometheusRule.enabled` adds alerts as a PrometheusRule:

| Alert | Severity | When |
|---|---|---|
| `MelesInfectedWorkload` | critical | a workload's container runs an Infected image; one alert each, naming workload, container and image |
| `MelesScanErrors` | warning | reports stay Error for `errorFor` (6h): images not scanned |
| `MelesScansIncomplete` | info | reports stay Incomplete for `errorFor`: files skipped |
| `MelesOperatorDown` | warning, critical with the scan gate | no operator replica reachable for 10 minutes |
| `MelesOperatorNoLeader` | warning | no replica holds the leader lease for 10 minutes |
| `MelesScanQueueStuck` | warning | scans queued, none finished for 30 minutes |
| `MelesGatePodsHeld` | warning | the scan gate holds pods for `gateHeldFor` (30m) |
| `MelesGateReleasedUnscanned` | warning | the scan gate released pods without a complete scan |

Each alert carries a `url` annotation into the web UI (the report, or the
Cluster page filtered by namespace and status), from `server.ingress`,
`server.httpRoute` or `operator.prometheusRule.uiURL`. The gate's alerts
exist only with `operator.gate.enabled`; leave out others
with `operator.prometheusRule.disabled`, e.g. `{MelesScansIncomplete: true}`.

```yaml
operator:
  serviceMonitor: {enabled: true}
  grafanaDashboard: {enabled: true}
  prometheusRule: {enabled: true}
networkPolicy:
  operatorMetricsFrom:
    - namespaceSelector:
        matchLabels: {kubernetes.io/metadata.name: monitoring}
      podSelector:
        matchLabels: {app.kubernetes.io/name: prometheus}
```

The CRD is in `charts/meles/crds/`. Helm installs it with the chart but never
updates or deletes it; after an upgrade apply it again:

```sh
kubectl apply -f charts/meles/crds/
```

### Scan gate

By default meles only reports: a pod runs while its image is scanned, and
the operator has no permission to change pods. With `operator.gate.enabled`
an administrator holds new pods until their images are scanned, per
namespace:

```sh
kubectl label namespace shop meles.io/gate=enforce   # or audit
```

| Mode | Released when |
|---|---|
| `enforce` | every image is `Clean` (ignored findings do not count) |
| `audit` | no image is `Infected` |

A held pod is `SchedulingGated`; `kubectl describe pod` shows why in an
event (`ScanGateHeld`), and its MalwareReport has the details. Once
released, the pod runs exactly the scanned image: the operator pins it to
the digest (`busybox:1.37@sha256:…`). Infected images never start, and a
rollout of an infected version leaves the old pods running. An image that
was scanned before is released at once; rescans never hold a pod.

- A workload opts out with the annotation `meles.io/gate: skip` on its pod
  template.
- `kube-system`, the release namespace and `operator.gate.excludeNamespaces`
  are never gated. Pods that exist already are not affected.
- If clamd fails, held pods are released with a warning event
  (`ScanGateReleasedUnscanned`) unless `operator.gate.failOpen=false`.
  Images that cannot be pulled or resolved stay held.
- If the operator is down, new pods start ungated
  (`operator.gate.failurePolicy: Ignore`); `Fail` refuses to create pods in
  gated namespaces until it is back. The chart runs two operator replicas
  while the gate is on, so that a rollout of the operator does not open the
  gate.
- With the gate the operator may `patch` pods and create events in all
  namespaces. Kubernetes 1.30 or later is required.

How it works and why it uses a webhook rather than a
`MutatingAdmissionPolicy`: [architecture.md](docs/architecture.md#scan-gate).

### Harbor

With `harborAdapter.enabled=true`, meles runs as a
[pluggable scanner](https://github.com/goharbor/pluggable-scanner-spec) for
Harbor (`meles harbor-adapter`): Harbor sends every pushed image to meles
and shows the result, before the image runs anywhere. Register it under
**Administration → Interrogation Services**:

- Endpoint: `http://<release>-harbor-adapter.<namespace>:8080`
- Authorization: `Bearer`, token from
  `kubectl -n <namespace> get secret <release>-harbor-adapter-token -o jsonpath='{.data.token}' | base64 -d`

Harbor knows vulnerability and SBOM reports only, so meles reports a finding
as an entry of severity `Critical` (the signature as ID, the file path as
package; layer, status and sha256 under `vendor_attributes`) and a file that
was not scanned as an entry of `harborAdapter.skippedSeverity` (`Critical` by
default). With the project setting *Prevent vulnerable images from running*
at `Critical`, Harbor refuses to hand out infected images.

A Harbor project uses one scanner. To keep the CVE scan, chain Harbor's
Trivy adapter with `harborAdapter.upstream.url` (e.g.
`http://harbor-trivy.harbor:8080`): every scan goes to both, the report
contains the CVEs and the malware findings, and SBOM requests are passed
through. Ignore rules go into `harborAdapter.ignoreRules`; Harbor's CVE
allowlist works on the signature IDs as well.

### Registry rate limits and a pull-through cache

The operator pulls the manifests and layers of every image it scans, and
again for each rescan, independently of the kubelet: a second pull per
image. meles does not throttle these pulls on its own, since that would only
delay the scans. Without credentials it pulls from the same address
as the nodes, so both share the registry's limit for anonymous pulls
(Docker Hub: 100 per hour per IP address); a cluster with many Docker Hub
images runs into `TOOMANYREQUESTS`, in the operator's reports and in the
kubelet's image pulls. Credentials in `operator.registryAuthSecret` raise
the limit for meles only. A pull-through cache helps both: every image is
fetched from Docker Hub once, and later pulls come from the cache.

With Harbor:

1. **Administration → Registries:** a new endpoint of provider *Docker
   Hub*, anonymous or with an access token (read-only) for a higher limit.
2. **Projects:** a new project, e.g. `dockerhub`, with *Proxy Cache* on that
   endpoint. Harbor deletes cached images that were not pulled for 7 days
   (the project's retention rule); the space is freed only by a garbage
   collection, so give it a schedule under **Administration → Clean Up**.
3. **meles:**

   ```yaml
   scan:
     registryMirrors:
       - docker.io=harbor.example.com/dockerhub
       # Registries that are only other names for Docker Hub need their own entry.
       - cr.smallstep.com=harbor.example.com/dockerhub
     registryCA:
       configMap: my-root-ca   # only if Harbor's certificate is from a private CA
   ```

4. **Nodes:** the container runtime needs the same mirrors, e.g. in
   `/etc/rancher/k3s/registries.yaml` on every k3s node (restart `k3s` or
   `k3s-agent` afterwards; running pods keep running), or in containerd's
   `hosts.toml` elsewhere:

   ```yaml
   mirrors:
     docker.io:
       endpoint: ["https://harbor.example.com"]
       rewrite:
         "^(.*)$": "dockerhub/$1"
   configs:
     harbor.example.com:
       tls:
         ca_file: /etc/rancher/k3s/my-root-ca.crt
   ```

meles and containerd both fall back to the registry itself when the mirror
fails, so an outage of Harbor costs time, not pulls; Harbor's own images
usually come from Docker Hub as well. meles trusts the mirror for tags and
checks digests (see `--registry-mirror`), and reports keep the original
image reference.

### Login for the web UI

meles has no login of its own. Without one, anyone who reaches the UI can
create and start scans and read all reports. The chart can run
[oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/) as a sidecar
in front of the UI: only users logged in with your OIDC provider (Keycloak,
GitHub, Entra ID, ...) get through, optionally only members of certain
groups. The server then listens on 127.0.0.1, so the login cannot be bypassed
from inside the cluster either.

1. Create an OIDC client (confidential, standard flow) with the redirect URI
   `https://<ui-host>/oauth2/callback`. For `allowedGroups` the ID token needs
   a `groups` claim (Keycloak: group membership mapper).
2. Store its secret: `kubectl -n meles create secret generic meles-oidc --from-literal=client-secret=...`
3. Set the values:

```yaml
server:
  oauth2Proxy:
    enabled: true
    issuerUrl: https://keycloak.example.com/realms/main
    clientId: meles
    existingSecret: meles-oidc
    allowedGroups: [meles-admins]
    # If the provider's certificate comes from an internal CA: a ConfigMap
    # with the CA certificate in the release namespace.
    providerCA: {configMap: internal-ca, key: ca.crt}
```

oauth2-proxy only accepts users with a verified e-mail address.

Without oauth2-proxy keep the UI internal (port-forward) or put another
authenticating proxy in front of it.

### clamd authentication

clamd has no authentication, and any client could send `SHUTDOWN` or
`SCAN <path>`. With `clamd.auth.enabled` (default) clamd listens only on
127.0.0.1 in its pod; the sidecar `meles clamd-proxy` accepts clients over
TLS with a token and forwards only `PING`, `VERSION`, `IDSESSION`, `INSTREAM`
and `END`. Server and selftest of the release are configured automatically.
Other clients, e.g. CI jobs in another namespace (also allow them with
`networkPolicy.clamdExtraFrom`):

```sh
kubectl -n meles get secret meles-clamd-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > clamd-ca.crt
export MELES_CLAMD_TOKEN=$(kubectl -n meles get secret meles-clamd-token -o jsonpath='{.data.token}' | base64 -d)
meles image --clamd tls://meles-clamd.meles:3310 --clamd-ca clamd-ca.crt "$IMAGE"
```

The token secret may hold several tokens, one per line: add the new one,
switch the clients, remove the old one. The proxy reloads the token file and
the certificate when they change.

The PVCs of mirror and server are kept on `helm uninstall`
(`helm.sh/resource-policy: keep`): the databases count against the Cisco
Talos rate limits, the server holds the run history.

clamd needs about 1.5 GB of memory with the full database and briefly almost
twice that during a reload.

## Development

See [docs/development.md](docs/development.md).

## License

Apache-2.0. The `clamav/clamav` image used for the workers contains ClamAV,
which is licensed under GPLv2. The YARA rules in `charts/meles/rules` keep
the licenses of their sources (Detection Rule License 1.1, BSD-2-Clause,
Apache-2.0), see the README there.

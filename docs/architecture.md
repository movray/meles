# Architecture

How meles works inside, how its parts fit together in a cluster, where state
lives, and why it is built this way. For using meles see the
[README](../README.md), for working on it [development.md](development.md).

## Scan pipeline

CLI, server, operator and Harbor adapter share one pipeline
(`internal/scan`):

```
image source ──▶ puller ──▶ layer extractor ──▶ layer cache ──▶ engine ──▶ report
(registry)      (go-container- (one layer at a    (layer digest +  (clamd      (table, json,
                 registry)      time, whiteouts,   engine + DB      INSTREAM)   CRD, Harbor)
                                limits)            version)
```

- **Daemonless.** Images are pulled straight from the registry with
  [go-containerregistry](https://github.com/google/go-containerregistry);
  no Docker socket, no root. Credentials come from the Docker config, from
  pull secrets (operator) or from the request (Harbor).
- **Every layer on its own**, not the final filesystem. A file that a later
  layer deletes is still shipped and still found. Both whiteout kinds are
  followed: `.wh.<name>` (one file or directory) and the opaque
  `.wh..wh..opq` (a whole directory from lower layers). Each finding carries
  its layer digest, the Dockerfile instruction from the image history where
  available, and a status: `present` (visible in the final filesystem) or
  `deleted` (removed in a later layer, but shipped).
- **All platforms** of an image index by default. A layer shared by several
  platforms is scanned once. Every finding names its platform.
- **Layer cache.** Results are kept per layer digest, engine and signature
  database version; base layers are scanned once. Layers with files that
  clamd refused are not cached, so they are scanned again.
- **Limits** against tar and zip bombs: total size per layer, size per file,
  number of files per layer. Paths are checked against traversal (`../`,
  absolute paths, symlinks out of the target). Files above
  `--max-file-size` are skipped and reported, never silently dropped.
- **Hashes.** Findings and skipped files carry their sha256, so that an
  ignore rule can name exactly one file content.

### clamd protocol

meles talks to clamd over its socket protocol and never links against
libclamav (GPLv2), so meles stays Apache-2.0. Each file is its own
`INSTREAM`; several requests share a connection through `IDSESSION`, and a
pool of connections scans in parallel (`--concurrency`). Files above 4 MiB
are streamed, so a large `--max-file-size` costs no memory in meles.

Sending a whole layer tarball as one stream was rejected: clamd then only
answers `stream: <Sig> FOUND` without a file name, and it runs into
`StreamMaxLength`.

### Incomplete is not clean

Any size limit can be dodged by making a file larger than it. A file that
was not scanned (meles' own limits, clamd's `StreamMaxLength`, `MaxScanSize`,
`MaxFiles`, `MaxRecursion`, `MaxScanTime`, unknown tar entry types) makes the
report incomplete. It is never reported as clean: the CLI exits with `1` by
default, the operator writes `Incomplete`, Harbor gets a `Critical` entry.
Errors are never clean either, whatever `--exit-code` says.

Skipped files have signatures like findings (`Meles.Limits.MaxFileSize`,
`Meles.Limits.StreamMaxLength`, `Meles.Unsupported.TarEntry`, clamd's
`Heuristics.Limits.Exceeded.*`), so ignore rules treat both alike.

### Limits in clamd

The Helm chart derives clamd's limits from a few values:

| clamd setting | Set to | Why |
|---|---|---|
| `StreamMaxLength` | `scan.maxFileSize` | the largest file meles sends |
| `MaxFileSize` | `clamd.maxScanSize` (at most 2 GiB) | it also limits content clamd unpacks from a file: random bytes in a Go binary can look like a ZIP header claiming a gigabyte |
| `MaxScanSize`, `MaxScanTime`, `MaxFiles`, `MaxRecursion` | `clamd.*` | per file including unpacked content |
| `IdleTimeout`, `ReadTimeout` | from `clamd.maxScanTime` plus a minute | clamd closes a silent session while it still scans a large archive |

The clients' `--clamd-timeout` follows `clamd.maxScanTime` as well.

## Components in a cluster

```
Cisco Talos CDN ──▶ mirror (cvdupdate + nginx, once per site)
                       │ freshclam (PrivateMirror)
                       ▼
                   clamd workers (1..n, signatures kept in memory)
                   └ clamd-proxy sidecar: TLS + token + command filter
                       ▲ INSTREAM          ▲                ▲              ▲
                       │                   │                │              │
                 meles server         meles CLI       meles operator   meles harbor-adapter
                 (web UI, schedules,  (CI jobs,       (watches pods,   (Harbor's pluggable
                  history in SQLite)   selftest)       MalwareReports)  scanner API)
```

- **Mirror.** The only component that talks to Cisco Talos, at most hourly
  (rate limits). A Deployment with two containers (cvdupdate loop and nginx)
  on one RWO volume; a CronJob and nginx would need RWX or the same node.
- **clamd workers.** clamd needs well over 1 GB of memory with the full
  database and almost twice that during a reload, so workers run long; no
  clamd per scan. The layer cache belongs to the clients, not the workers.
- **clamd-proxy.** clamd has no authentication and accepts `SHUTDOWN` or
  `SCAN <path>` from anyone. The sidecar accepts clients over TLS, checks a
  token (`zAUTH <token>` → `AUTH OK`) and forwards only `IDSESSION`,
  `INSTREAM`, `VERSION`, `PING` and `END`. clamd itself listens on
  127.0.0.1 in its pod, so the image's probes keep working.
- **Server.** Server-rendered pages (`html/template`, embedded), no JS
  framework, no CDN, strict CSP; JavaScript only as an enhancement. One
  replica, because the database is SQLite on a PVC. No login of its own:
  authentication belongs in the infrastructure (oauth2-proxy sidecar in the
  chart). CSRF protection is built in.
- **Operator.** See [Operator](#operator).
- **Harbor adapter.** See [Harbor adapter](#harbor-adapter).

## Where state lives

Nothing that matters lives only in memory: results are in the Kubernetes API
or are requested again by Harbor. A restart costs work, not results.

| Component | Durable | In memory, lost on restart |
|---|---|---|
| Operator | `MalwareReport`s, ignore rules and the `meles.io/rescan` annotation in the Kubernetes API (etcd) | scan queue and running scans (start over; waiting pods are requested again on start), recent results (restored from the reports), layer cache, informer caches |
| Server | SQLite on a PVC: scans and schedules, runs with reports and findings, history of the cluster reports (`cluster_events`); interrupted runs are marked failed | layer cache, informer cache of the cluster reports |
| Harbor adapter | nothing | queue and finished reports (24 h; Harbor gets `404` and asks again), layer cache |
| clamd | signatures on disk, loaded on start | – |
| Mirror | signature database on its PVC | – |
| CLI | nothing | layer cache for one call |

## Operator

`meles operator` (controller-runtime, same binary) watches all pods and
scans the image of every container, init containers included, by digest.

### Reports

One `MalwareReport` (`meles.io/v1alpha1`) per workload and container in the
namespace of the app, owned by the workload: teams read their reports with
`kubectl`, and deleting a workload deletes its reports. The workload is the
pod's controller (ReplicaSet, StatefulSet, DaemonSet, Job), the CronJob of a
Job, or the pod itself. A report of a ReplicaSet records its Deployment as
`workload.parent`, derived from `pod-template-hash` without further
permissions, so history groups across rollouts.

The API group `meles.io` is a registered domain: renaming a group breaks
installations.

### Reconcile and scan queue

Reconciling a pod is short: find the workload, look at the report, and if a
scan is due, request one. Scans run in their own queue with `--workers`
workers, so a ten-minute scan does not block new pods, deleted reports or
changed rules. Every digest is scanned once; its result is written to all
reports of that digest. Pods waiting for a running scan are reconciled again
when it finishes.

- `Error` is retried after `--retry-after` (1h), `Incomplete` after
  `--retry-incomplete-after` (12h).
- `Clean` and `Infected` are rescanned when engine or signature version
  changed, at most every `--rescan-interval` (24h).
- The annotation `meles.io/rescan` on a report forces a rescan.
- A deleted report is written again right away; terminating pods are skipped
  (otherwise an endless loop with the garbage collector).
- `--prune-interval` deletes reports of ReplicaSets, StatefulSets and
  DaemonSets without pods (old ReplicaSets of a Deployment). CronJobs keep
  their report between runs.
- Platforms: `--platform nodes` scans the architectures of the cluster's
  nodes; only those run here.
- Leader election: only one replica scans.

### Ignore rules

`MalwareIgnore` (namespaced, for teams) and `ClusterMalwareIgnore` (for
administrators); RBAC decides who may write them. Rules apply when reports
are written, without a rescan: the report keeps the raw result, so a changed
rule only re-evaluates it. Ignored entries stay visible, marked with the
rule. Every rule needs a reason and an expiry date at most a year ahead. A
scan error can never be ignored. The status of the rule objects lists
invalid and expired rules.

### Private registries

The operator uses the `imagePullSecrets` of the pod and of its service
account, like the kubelet (go-containerregistry `pkg/authn/kubernetes`, not
`k8schain` with its cloud helpers). Reading secrets cluster-wide is a lot of
power, so it is **opt-in per namespace**: the chart creates the ClusterRole
`<release>-pull-secret-reader` (only `get` on `secrets` and
`serviceaccounts`, no `list` or `watch`, never cached), and a team binds it
with a RoleBinding. `operator.pullSecrets.clusterWide` binds it everywhere.
Without the permission the operator scans anyway and reports `Error` only
when the registry refuses, with the `kubectl create rolebinding` command in
the message. `operator.registryAuthSecret` adds one fixed Docker config.

Rejected alternatives: reading images from the nodes (needs root on every
node) and scanning the running container filesystem (runtime detection, a
non-goal). meles does not talk to the kubelet or the CRI; the price is a
second pull from the registry (rate limits). A registry mirror or Harbor
with the adapter avoids it.

### Scan gate (planned)

Off by default: meles only reports, and the operator has no permission to
change pods. Turned on by the administrator (`operator.gate.enabled`):

- A mutating webhook in the operator adds the scheduling gate `meles.io/scan`
  to new pods in namespaces labelled `meles.io/gate: enforce` or `audit`.
  Never in `kube-system` or the namespace of meles (clamd would wait for its
  own scan). A workload opts out with the annotation `meles.io/gate: skip`
  on its pod template.
- The operator resolves the tag itself (a gated pod has no `imageID` yet),
  scans, and in one patch pins the pod's image to the scanned digest and
  removes the gate. So exactly what was scanned runs, even if the tag moved.
- `Clean` releases (ignored findings do not count). `Infected` holds, with
  an event on the pod; a rollout of an infected version leaves the old pods
  running. `Incomplete` and image or registry errors hold in `enforce`;
  `audit` holds only `Infected`. There is no maximum wait: a held pod is
  visible. Known digests are released at once; rescans never gate.
- Queue order: gated pods first, then new images, then rescans.

Why gate instead of reject: a webhook may take at most 30 seconds, a scan
takes minutes, and rejected pods cause retry loops in the ReplicaSet
controller.

**Webhook, not `MutatingAdmissionPolicy`.** Since Kubernetes 1.36 the gate
can be added without a webhook, by a `MutatingAdmissionPolicy` evaluated in
the API server. It needs no webhook certificate, but it always applies: if
meles is down, nobody removes the gate, and every new pod in a gated
namespace waits (updates, scale-ups, CronJobs, replacements after a node
failure; a rolling update with `maxUnavailable` still stops some old pods).
That is fail-closed only. The webhook runs inside the operator: if the
operator is down, so is the webhook, and with `failurePolicy: Ignore` (the
default) pods start unscanned; `Fail` is available for fail-closed. Failures
of meles' own infrastructure (clamd unreachable, timeouts) follow the same
setting and release the pod with an event "released unscanned"; image and
registry errors hold it. The policy may come later as an option for
administrators who want fail-closed and no webhook certificate.

## Server and cluster reports

The page **Cluster** reads the operator's `MalwareReport`s through an
informer from the Kubernetes API. There is no copy in SQLite: the CRDs stay
the only source, and `kubectl`, policies and kube-state-metrics read the
same data. The server only records each change of a report (new result,
deletion) in SQLite as history, without duplicates after restarts; deletions
missed while it was down are added after the start. `--history-days` (365)
prunes it, keeping the last entry of each report.

Several clusters will be a layer of their own later (a central server
collecting from the servers per cluster); the operator stays cluster-local.
The `cluster` column (`--cluster-name`) prepares that.

## Harbor adapter

`meles harbor-adapter` implements Harbor's
[pluggable scanner API](https://github.com/goharbor/pluggable-scanner-spec)
v1.2. Harbor knows vulnerability and SBOM reports only, so a finding becomes
a vulnerability of severity `Critical` (signature as ID, path as package;
layer, status and sha256 under `vendor_attributes`) and a skipped file one of
`--skipped-severity` (`Critical`). Harbor's *Prevent vulnerable images from
running* then refuses infected images at the registry. Harbor passes
registry credentials with every request; Harbor's internal registry address
(`harbor-core:80`) is completed with `--harbor-namespace`.

A Harbor project uses one scanner, so the adapter can chain another adapter
(`--upstream-url`, e.g. Trivy): every scan goes to both, the reports are
merged, SBOM requests are passed through, and a failing upstream fails the
scan.

## Security model

| Component | Kubernetes permissions | Exposed |
|---|---|---|
| clamd + proxy | none | TLS port 3310 with token; NetworkPolicy: only pods of the release (plus `networkPolicy.clamdExtraFrom`) |
| Mirror | none | HTTP, only for clamd (NetworkPolicy) |
| Server | read `malwarereports` cluster-wide, `patch` for the rescan button (optional) | UI and API without login of its own: oauth2-proxy sidecar or keep internal |
| Operator | read `pods`, `nodes`, `jobs`; write `malwarereports`; read ignore rules, write their status; leases and events in its namespace; `get` on `secrets`/`serviceaccounts` only where a namespace grants it | health port only |
| Harbor adapter | none | HTTP API with bearer token |

- No component needs to run as root; the meles image is non-root on
  `cgr.dev/chainguard/static`. The clamd image starts as root and drops
  privileges, so its namespace needs the `baseline` Pod Security level.
- clamd parses untrusted files from every image; that is its job, and the
  reason it runs in its own pod without permissions and behind the proxy.
- Everyone who can open the UI sees the reports of all namespaces.
- A full review (permissions, pull secrets, clamd's attack surface, network
  paths, tokens, supply chain of the images) is planned before the release.

## Decisions

| Topic | Decision | Reason |
|---|---|---|
| Language | Go | go-containerregistry, controller-runtime, one binary |
| CLI | cobra; every flag also as `MELES_<FLAG>` | like `TRIVY_*` |
| ClamAV | clamd over INSTREAM, no `clamscan` fallback, no libclamav | license, database in memory once |
| YARA | first through ClamAV's YARA support | no CGO |
| Scan unit | layer, not the final filesystem | whiteout findings, cache per digest |
| Multi-arch | all platforms by default | an amd64 runner must not call an infected arm64 variant clean |
| Exit codes | `1` on findings and skipped files, `2` fixed for errors | a security gate; unlike Trivy |
| Web UI | server-rendered, embedded, no CDN | one binary, offline, strict CSP |
| Database | SQLite (`modernc.org/sqlite`, pure Go) on a PVC, one replica | no CGO, no database service |
| Schedules | cron (`robfig/cron`); a run is skipped while the previous one is active | familiar syntax |
| Login | none in the server | authentication belongs in the infrastructure |
| Cluster reports | read from the CRDs, history only in SQLite | one source of truth |
| Operator reports | one per workload and container, owned by the workload | teams see their own, cleanup by garbage collection |
| Pull secrets | opt-in per namespace | cluster-wide secret access is a lot of power |
| Scan gate | off by default; webhook with scheduling gates | admin decides; scans take minutes; fail-open possible |

## Non-goals

- No replacement for supply-chain protection (signatures, SBOMs) or runtime
  detection (Falco, Tetragon).
- No antivirus engine of its own.
- meles never deletes or changes files or image contents. By default it only
  reports; with the scan gate on, it holds new pods until their image is
  scanned.

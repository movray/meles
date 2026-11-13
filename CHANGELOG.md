# Changelog

Notable changes and upgrade notes. The full list of commits is in each
[GitHub release](https://github.com/movray/meles/releases).

## v0.3.4

The Helm chart is listed on [Artifact Hub](https://artifacthub.io/packages/helm/meles/meles).

### Upgrade

Nothing changes for existing installations.

### Changed

- The chart has a README of its own and Artifact Hub metadata: links,
  screenshots, the CRDs with examples.

### Dependencies

- `click` 8.5.1 in the database mirror.

## v0.3.3

Makes the chart upgradable with `--reuse-values` again.

### Upgrade

Upgrading from 0.3.2 or older with `helm upgrade --reuse-values` works again.
Nothing else changes for existing installations.

### Fixed

- `helm upgrade --reuse-values` from an older chart left `scan.maxLayerSize`
  empty, and meles refused to start.

### Dependencies

- `modernc.org/sqlite` 1.62.0, `golang.org/x/sync` 0.25.0,
  `github.com/spf13/pflag` 1.1.0; GitHub Actions updates.

## v0.3.2

Closes three gaps that let content pass unscanned, shows incomplete runs as
such, and is the first release tested against popular and known malicious
images: see [docs/popular-images.md](docs/popular-images.md).

### Upgrade

A client of the API that treats every status other than `infected` and `error`
as clean has to learn the new status `incomplete`. Scans of images with large
archives take longer with the new limits. The operator scans its images again,
because the rules changed. With the CLI against your own clamd, add
`meles-own.yar` to clamd's database, or `meles selftest --yara` fails.

Do not upgrade this version with `helm upgrade --reuse-values`: meles does not
start then. Pass your values with `-f`.

### Security

- The server stored runs with skipped files as `clean` and showed "No malware
  found". They now have the status `incomplete` in the UI and the API, like in
  the CLI and the operator, and count as needing attention. Stored runs are
  corrected at the first start.
- Whiteout entries with content were not scanned: a file named `.wh.<name>`
  or `.wh..wh..opq` could carry malware through a scan as clean. A runtime
  never unpacks such an entry, but the image ships it. Its content is now
  scanned and a finding has the status `deleted`. The selftest has a new case
  for it, `eicar-whiteout-content`.
- Data after the end of a layer's tar archive was read but not scanned. It now
  makes the scan `Incomplete` (`meles.Unsupported.TrailingData`), and it
  counts against `--max-layer-size`.
- Sparse files could expand far beyond `--max-layer-size`, because the limit
  only counted the bytes read. It now counts what the entries declare, across
  the whole layer.
- The mirror installs cvdupdate and its dependencies with pinned hashes
  (`charts/meles/files/mirror/requirements.txt`) instead of the newest
  matching version from PyPI. Dependabot updates the file.

### Added

- Fuzz tests for the layer extractor: `make fuzz`.
- A refresh button with an interval in the header of the web UI. The browser
  remembers the interval; `Auto` refreshes while a run is active, as before.

- Chart value `scan.maxLayerSize` for `--max-layer-size`. Machine learning
  images can have layers above the default of 4G.
- YARA rules of our own in `meles-own.yar`, for xmrig-proxy, ariominer and the
  JSON configuration of XMRig and xmrig-proxy.

### Changed

- Higher default limits in the chart, because popular images stayed
  `Incomplete` with the old ones: `clamd.maxFiles` 100000 (was 10000),
  `clamd.maxScanTime` 600000 (was 120000), `clamd.maxScanSize` 2047M (in effect
  768M before). Images with large archives take up to twice as long, in the
  worst case 3.6 times, and clamd can unpack more into its ephemeral storage.

### Fixed

- A long scan could end with an error: a resumed layer download failed with
  403 once the signed CDN URL had expired, and with 401 once the token of the
  registry had. meles now asks the registry for new access.

## v0.3.1

Shows in the UI whether meles still finds what it must find.

### Upgrade

The selftest CronJob of the chart now runs daily, and the server scans the
test images every 6 hours. With `clamd.enabled=false` and a clamd without the
EICAR signature the UI shows the selftest as failed; set
`server.selftestInterval=0` then.

### Added

- The server runs the selftest every 6 hours and shows the result in the UI
  and at `/api/selftest`: clamd can answer and still have lost its signatures.
  `--selftest-interval`, chart value `server.selftestInterval`, 0 turns it off.

### Changed

- The selftest CronJob of the chart now runs daily. Set
  `selftest.suspend=true` for the old behaviour.

## v0.3.0

Makes meles easier to start with and more robust while clamd restarts.

### Upgrade

1. **`server.ingress` and `server.httpRoute` now need a login.** Without
   `server.oauth2Proxy` the chart refuses to render. If another proxy in
   front of the UI handles the login, or the UI stays on an internal network,
   set `server.allowUnauthenticated=true`.
2. **With `clamd.detectPUA` or `clamd.extraConfig` set,** all images are
   rescanned once: the signature version now carries `+config.<hash>`. With
   the default options nothing changes.

### Added

- `docs/results.md` explains the results, what `Clean` does not guarantee,
  limits and false positives. The README starts with an overview, and its
  TL;DR now covers Kubernetes with the operator.
- The release workflow scans the image with meles and Trivy before it is
  published.

### Changed

- The operator tries a scan again for almost 4 minutes if clamd fails, so a
  clamd that is starting or being replaced no longer leads to `Error` reports,
  and pods held by the scan gate are no longer released unscanned because of
  it.
- A change of `clamd.detectPUA` or `clamd.extraConfig` triggers rescans and
  reaches the layer cache.

## v0.2.0

A security release: it fixes the findings of a review of meles itself
(permissions, admission, network paths, dependencies). It has incompatible
changes; read **Upgrade** before you update.

### Upgrade

1. **Apply the CRDs first.** Helm installs CRDs but never updates them:

   ```sh
   helm pull oci://ghcr.io/movray/charts/meles --version 0.2.0 --untar
   kubectl apply --server-side --force-conflicts -f meles/crds/
   ```

2. **Scan results moved from `.report` to `.status`** of each
   MalwareReport (a status subresource). Results from 0.1.0 are dropped on
   the upgrade, and the operator scans every image in the cluster once
   more (it pulls each image again; about 45 minutes for 100 images in our
   test cluster). Meanwhile reports have no result yet; reports of
   CronJobs get one at their next run. Scripts, `kubectl` JSONPath and
   dashboards that read `.report` have to read `.status`.

3. **Images from registries on private addresses** (10/8, 172.16/12,
   192.168/16, 100.64/10, fc00::/7) are refused by the server, the operator
   and the Harbor adapter unless the registry is a configured mirror or
   proxy, the Harbor that called the adapter, or listed in
   `scan.allowPrivateRegistries` (`--allow-private-registry`). Loopback and
   link-local addresses are always refused, plain HTTP only with
   `--insecure-registry`. The CLI is unchanged.

4. **Scan gate** (only with `operator.gate.enabled`): the new
   `operator.gate.protect` is on by default. In gated namespaces:
   - `meles.io/gate: skip` needs the namespace label
     `meles.io/gate-skip=allowed`; without it, the pod is refused:

     ```sh
     kubectl label namespace <namespace> meles.io/gate-skip=allowed
     ```

   - new pods with `spec.nodeName` are refused (except from the kubelet),
   - the image of a pod can no longer be changed in place; change the
     workload instead.

   To see first what it would refuse, set
   `operator.gate.protect.validationActions: [Warn]`;
   `operator.gate.protect.enabled: false` keeps the behaviour of 0.1.0.

### Security

- **Forged scan results.** The result of a MalwareReport could be written
  by anyone with `patch` on MalwareReports, including the server for its
  rescan button, and the operator trusted existing reports, for reuse also
  those of other namespaces. Results are now in the status subresource,
  which only the operator may write.
- **Scan gate bypass by namespace members.** Anyone who could create or
  update pods in a gated namespace could let an image run unscanned: opt
  out, bind the pod to a node, remove the scheduling gate, switch to audit
  mode or change the image after the release. A ValidatingAdmissionPolicy
  (`operator.gate.protect`) refuses all of these. A pod created with the
  gate and `meles.io/gate-mode: audit` was held in audit mode in an
  `enforce` namespace; the webhook now always sets the mode of the
  namespace.
- **Server-side request forgery.** Image references from pods and UI runs
  could make meles connect to internal services or the cloud metadata
  endpoint and put the answer into reports and events. Every connection is
  now checked after the DNS lookup (redirects and token realms included),
  and error bodies are cut short.
- **Open redirect.** The back link of the ignore form accepted a tab
  (`/\t/evil.example`), which browsers turn into a link to another host.
- **HTTP/2 vulnerabilities in `golang.org/x/net`** reachable from the
  server and the registry client (GO-2026-6603, GO-2026-6610,
  GO-2026-6611, GO-2026-6612, GO-2026-6617): updated to v0.62.0.

### Other changes

- The history views bound the number of days they allocate for.
- CI runs `govulncheck` on every push, weekly and before every release; a
  known vulnerability in a code path meles reaches stops the release.

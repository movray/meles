# Changelog

Notable changes and upgrade notes. The full list of commits is in each
[GitHub release](https://github.com/movray/meles/releases).

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

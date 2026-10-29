# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue: on GitHub,
open the **Security** tab of this repository and choose **Report a
vulnerability**. Only the maintainer sees the report.

Helpful in a report: the meles version (`meles version`) or commit, how
meles runs (CLI, server, operator, Harbor adapter, Helm chart values), what
you did, what happened, and what an attacker gains.

meles is maintained by one person in their spare time. I aim to confirm a
report within a week and to agree on a fix and a disclosure date with you.

## Supported versions

There is no release yet. Fixes go into `main`; from the first release on,
the latest release gets security fixes.

## Scope

In scope, for example:

- an image whose malware meles reports as clean, or a way to make meles
  skip files without marking the report incomplete
- path traversal, decompression bombs or resource exhaustion while
  unpacking layers
- bypassing the clamd-proxy's token or command filter
- the scan gate letting a pod run an image other than the one scanned
- the operator, server or Helm chart granting more rights than documented
- cross-site scripting, CSRF or similar in the web UI

Not in scope here:

- vulnerabilities in ClamAV itself: please report them to
  [Cisco Talos](https://docs.clamav.net/manual/Development/Security.html)
- a signature that misses a sample or flags a harmless file: open a normal
  issue (for YARA rules, the rule's source is named in
  `charts/meles/rules/README.md`)
- findings that need an attacker who already controls the cluster, the
  registry credentials or the machine meles runs on

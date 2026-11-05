# Reading the results

What a result of meles means, what it does not mean, and what to do next.

## The four results

| Result | Meaning | What to do |
|---|---|---|
| `Clean` | Every file was scanned and nothing matched. | Nothing. See [what Clean does not mean](#what-clean-does-not-mean). |
| `Infected` | At least one file matched a signature or YARA rule. | Look at the [finding](#reading-a-finding). Real malware: rebuild the image and find out how it got in. False positive: add an [ignore rule](#false-positives). |
| `Incomplete` | Nothing matched, but at least one file was not scanned. | Look at the skipped files: see [Limits](#limits). |
| `Error` | The image was not scanned. | Read the error. `errorSource` says whether the image (`Image`: registry, pull secret, tag) or the engine (`Engine`: clamd) failed. |

`Infected` wins over `Incomplete`. `Incomplete` and `Error` are never clean:
any size limit could otherwise be dodged by making a file larger than it.

## Where you see them

| Result | CLI output | Exit code | Scan gate, `enforce` | Scan gate, `audit` |
|---|---|---|---|---|
| `Clean` | `No malware found.` | `0` | released | released |
| `Infected` | the findings | `1` (`--exit-code`) | held | held |
| `Incomplete` | `Scan INCOMPLETE`, JSON `"complete": false` | `1` (`--skipped-exit-code`) | held | released |
| `Error`, source `Image` | error message | `2`, fixed | held | released with a warning |
| `Error`, source `Engine` | error message | `2`, fixed | released with a warning unless `operator.gate.failOpen=false` | released with a warning |

`--exit-code 0` turns findings into a report only; errors still exit with
`2`. A warning is the event `ScanGateReleasedUnscanned` on the pod.

In the cluster, `kubectl get malwarereports -A` lists the results and
`kubectl get malwarereport <name> -o yaml` has the details; the web UI shows
the same on the page *Cluster*. Results are retried on their own: see
[Operator](../README.md#operator).

## Reading a finding

A finding names the file, the signature, the platform and the layer that
added the file, if known with the Dockerfile instruction from the image
history. Findings from the chart's YARA rules also name the rule's author.

The status of a finding says where the file is:

- `present`: visible in the final filesystem of the image.
- `deleted`: a later layer removed it, but it is still shipped with the image
  and anyone can read it from that layer. It does not show up in a running
  container, so check how it got there: it may be left over from a build
  step. Deleting a secret or a tool in a later layer never removes it from
  the image.

Each platform of a multi-arch image is scanned, and each finding names its
platform: a finding in `linux/arm64` is a finding, even if you only run
`linux/amd64`. The CLI and the server scan all platforms by default; the
operator scans the architectures of your nodes (`operator.platform`).

## What Clean does not mean

`Clean` means that no signature or rule known to clamd at that time matched.
It does not mean that the image is safe:

- Malware without a signature is not found. New or targeted code can pass
  until a signature exists. That is why the operator rescans when the
  signatures change.
- Content that clamd cannot read, such as encrypted archives, is not
  inspected.
- A scan looks at files. What a process downloads or does at runtime is out
  of reach: that needs runtime detection.
- It says nothing about vulnerabilities, misconfigurations or who built the
  image. Use a vulnerability scanner, image signatures and SBOMs for those.
- It applies to the scanned digest and platforms only. A tag can point to
  something else tomorrow; the scan gate pins the digest for that reason.
- Ignored findings do not count against `Clean`. They stay visible in the
  report with their rule and reason.

## Limits

Files that were not scanned are listed as skipped, with a reason and a
signature you can use in an ignore rule:

| Signature | Cause | What helps |
|---|---|---|
| `meles.Limits.MaxFileSize` | The file is larger than `--max-file-size` (`scan.maxFileSize`, default 768M). | Raise it, up to 2047M. Larger files, such as big ML models, cannot be scanned by ClamAV at all. |
| `meles.Limits.StreamMaxLength` | clamd refused the stream as too large. | Raise `StreamMaxLength` in clamd. The chart keeps it in line with `scan.maxFileSize`. |
| `Heuristics.Limits.Exceeded.*` | clamd could not finish the file within its limits, for example with very large binaries or deeply nested archives. | Raise the limit in the name (`clamd.maxScanSize`, `maxScanTime`, `maxFiles`, `maxRecursion`), then rescan. |
| `meles.Unsupported.TarEntry` | The layer has a tar entry of a type meles does not read. | Look at the file. Ignore it if it is harmless. |

Some files stay `Incomplete` at any limit: a very large binary may exceed
`MaxScanSize` even at the maximum, and a test file that unpacks to itself
always hits `MaxRecursion`. Check that the file is what it should be, then
add an ignore rule with a reason and, ideally, its `sha256`, so that the rule
ends with this content.

## False positives

ClamAV and the YARA rules also flag things that are harmless in your
context: cryptominer detectors' test data, network tools, packed binaries.
`Infected` does not prove bad intent, and a finding is worth a look before
you act on it:

1. Which file is it, and which package or build step brought it in?
2. Does the signature fit the file? `sha256` from the JSON output lets you
   compare it with the file of the upstream package.
3. Harmless: add an [ignore rule](../README.md#ignore-rules) with a reason.
   It expires after a year at most, so that it is looked at again. Prefer
   `sha256` or a narrow `path` over a wide `signature` glob.

`clamd.detectPUA` is off by default for this reason: in our tests it only
produced false positives.

## Next

- [README](../README.md): flags, values and ignore rules
- [getting-started.md](getting-started.md): a tour with a file hidden by a
  later layer
- [architecture.md](architecture.md): how scans, limits and the gate work

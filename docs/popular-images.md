# Scanning popular images

What happens when meles scans the images people actually run, and what it
finds in images known to be malicious. Measured on 6 November 2026.

## Summary

- **47 popular images:** 39 scanned completely, 8 `Incomplete` with one file
  each that could not be scanned, none infected, no false positive.
- **14 known malicious images:** meles detected 9 on the first run. We analysed
  the 5 misses and added rules for 3 of them, so v0.3.2 detects 12 of 14.
- The other 2 are out of scope by design: one hides its miner behind a packer,
  the other only starts an attack when it runs. That is the job of runtime
  tools like Falco or Tetragon. meles has a different purpose: it inspects what
  an image contains before it runs, including files deleted in earlier layers
  that a runtime tool never sees. You need both.

The test also changed meles: the default limits of the chart are higher now,
and a long scan no longer fails when a signed download URL expires. Both are
in v0.3.2.

## Setup

- Scanned through the API of `meles server` in a test cluster (k3s), one image
  at a time, `linux/amd64` only.
- clamd ran on a virtual machine with 4 vCPUs of a generic QEMU CPU model and
  8 GB of RAM, without a CPU limit. **The times below are from this slow
  machine.** Compare them with each other, not with your hardware.
- ClamAV 1.4.6, signatures 28174 and 28175, and the default YARA rules.

The results come from three runs, because each run answered a question the
previous one raised. We did not repeat all images afterwards: the images that
passed run A had already passed with stricter limits.

| Run | meles | Limits | Images |
|---|---|---|---|
| A | 0.3.1 | defaults of 0.3.1 | all 47 |
| B | 0.3.1 | `clamd.maxFiles=100000`, `clamd.maxScanTime=600000`, `clamd.maxScanSize=2047M`, the defaults of v0.3.2 | the 10 images that were `Incomplete` in run A |
| C | development build of v0.3.2 | as B, plus `clamd.maxRecursion=64` and for `pytorch` `--max-layer-size 16G` | 3 images still blocked by `MaxRecursion`, and those that ended with an error |

To repeat the run, see [`hack/popular-images`](../hack/popular-images/run.sh).

## Results

| Image | Result | Seconds | Files | Run |
|---|---|---:|---:|---|
| `alpine:latest` | Clean | 3 | 84 | A |
| `ubuntu:latest` | Clean | 40 | 5491 | A |
| `debian:latest` | Clean | 39 | 4407 | A |
| `busybox:latest` | Clean | 1 | 16 | A |
| `fedora:latest` | Clean | 40 | 3612 | A |
| `amazonlinux:latest` | Clean | 49 | 5173 | A |
| `registry.access.redhat.com/ubi9/ubi:latest` | Clean | 43 | 6547 | A |
| `gcr.io/distroless/static-debian12:latest` | Clean | 11 | 965 | A |
| `cgr.dev/chainguard/static:latest` | Clean | 3 | 723 | A |
| `python:latest` | Clean | 285 | 26314 | A |
| `node:latest` | Clean | 44 | 28752 | A |
| `golang:latest` | Clean | 167 | 30928 | A |
| `eclipse-temurin:latest` | Clean | 361 | 7381 | B |
| `php:latest` | Incomplete | 653 | 9165 | C |
| `ruby:latest` | Clean | 34 | 26930 | A |
| `rust:latest` | Clean | 80 | 24151 | A |
| `mcr.microsoft.com/dotnet/aspnet:9.0` | Clean | 76 | 3826 | A |
| `nginx:latest` | Clean | 10 | 3743 | A |
| `httpd:latest` | Clean | 6 | 3637 | A |
| `traefik:latest` | Clean | 22 | 565 | A |
| `haproxy:latest` | Clean | 6 | 2932 | A |
| `caddy:latest` | Clean | 10 | 237 | A |
| `envoyproxy/envoy:v1.34-latest` | Clean | 36 | 4226 | A |
| `postgres:latest` | Clean | 54 | 7865 | A |
| `mysql:latest` | Clean | 460 | 7519 | B |
| `mariadb:latest` | Clean | 38 | 8734 | A |
| `mongo:latest` | Clean | 118 | 6476 | A |
| `redis:latest` | Clean | 8 | 2714 | A |
| `memcached:latest` | Clean | 2 | 2751 | A |
| `rabbitmq:latest` | Clean | 46 | 8773 | A |
| `elasticsearch:9.5.5` | Clean | 1817 | 2800 | C |
| `wordpress:latest` | Incomplete | 445 | 16008 | C |
| `nextcloud:latest` | Incomplete | 729 | 41879 | C |
| `grafana/grafana:latest` | Clean | 320 | 15644 | B |
| `prom/prometheus:latest` | Clean | 34 | 458 | A |
| `hashicorp/vault:latest` | Incomplete | 74 | 452 | B |
| `quay.io/keycloak/keycloak:latest` | Clean | 620 | 3026 | A |
| `sonarqube:latest` | Incomplete | 3540 | 5679 | C |
| `jenkins/jenkins:lts` | Incomplete | 944 | 9062 | B |
| `gitlab/gitlab-ce:latest` | Clean | 1395 | 105068 | A |
| `registry.k8s.io/pause:3.10` | Clean | 1 | 1 | A |
| `registry.k8s.io/kube-apiserver:v1.33.0` | Clean | 20 | 959 | A |
| `quay.io/argoproj/argocd:latest` | Clean | 125 | 12740 | A |
| `quay.io/prometheus/node-exporter:latest` | Clean | 5 | 453 | A |
| `rancher/mirrored-library-traefik:3.7.4` | Incomplete | 25 | 588 | B |
| `pytorch/pytorch:latest` | Incomplete | 1184 | 50732 | C |
| `ghcr.io/movray/meles:latest` | Clean | 9 | 724 | A |

`Incomplete` means that meles reports the image as not fully scanned, and the
CLI exits with 1 by default: a file that was not scanned must not pass as clean.
In run A, `elasticsearch` had a wrong tag and was scanned as `9.5.5` in run C.

The result of `pytorch` needs a higher limit than the default:
with `scan.maxLayerSize=4G` (`--max-layer-size`) the scan ends with an error,
because one layer is larger than that.

## The 8 files that could not be scanned

| Image | File | Reason | What helps |
|---|---|---|---|
| `php`, `wordpress`, `nextcloud` | `/usr/src/php.tar.xz` | `MaxRecursion` | Nothing we found: still skipped with `clamd.maxRecursion=64`, so the default stays at 17 |
| `hashicorp/vault` | `/bin/vault` (525 MiB) | `MaxScanSize` | No limit we tried. It stays skipped at the highest possible value |
| `traefik` | `/usr/local/bin/traefik` (169 MiB) | `MaxScanSize` | As for Vault. It stops after seconds, so clamd probably takes bytes in the Go binary for an archive header that claims a huge size; we did not confirm this |
| `jenkins/jenkins` | `jenkins.war` (51 MiB) | `MaxScanTime` | A faster CPU or a higher `clamd.maxScanTime` |
| `sonarqube` | `sonar-application-*.jar` (115 MiB) | `MaxScanTime` | As for Jenkins |
| `pytorch/pytorch` | `libtorch_cuda.so` (1028 MiB) | `scan.maxFileSize` (768M) | A higher `scan.maxFileSize`, at most 2047M; not tested |

Large Go binaries and some archives can stay `Incomplete`. Decide per image
whether that is acceptable: [ignore rules](../README.md#ignore-rules) make the exception
visible instead of hiding it.

## Limits

Run A showed that the old defaults were too low for popular images, so run B
tried higher ones. Each run scanned the same image once, on the same machine:

| Image | Seconds with old limits | With new limits | Factor | Not scanned, old | New |
|---|---:|---:|---:|---:|---:|
| `eclipse-temurin` | 185 | 361 | 2.0 | 1 | 0 |
| `mysql` | 258 | 460 | 1.8 | 1 | 0 |
| `grafana/grafana` | 302 | 320 | 1.1 | 1 | 0 |
| `php` | 177 | 633 | 3.6 | 1 | 1 |
| `wordpress` | 225 | 437 | 1.9 | 1 | 1 |
| `nextcloud` | 496 | 746 | 1.5 | 1 | 1 |
| `jenkins/jenkins` | 389 | 944 | 2.4 | 2 | 1 |
| `hashicorp/vault` | 65 | 74 | 1.1 | 1 | 1 |
| `traefik` | 24 | 25 | 1.0 | 1 | 1 |

The new defaults of the chart are `clamd.maxFiles=100000` (was 10000),
`clamd.maxScanTime=600000` (was 120000) and `clamd.maxScanSize=2047M` (768M in
effect before). They are upper bounds, so only large archives take longer.
`clamd` stayed at about 1 GiB of memory.

## Detection of known malicious images

Popular images only show that meles does not raise false alarms. To see what
it finds beyond the EICAR test file, we scanned images that security
researchers documented as malicious on Docker Hub:

- [Unit 42: Cryptojacking images on Docker Hub](https://unit42.paloaltonetworks.com/malicious-cryptojacking-images/)
- [Flare: Cryptomining supply chain abuse on Docker Hub](https://flare.io/learn/resources/blog/cryptomining-supply-chain-abuse-docker-hub-malware/)

Of the 33 repositories named there, 18 still existed. We scanned 16 images from
15 of them, and 14 could be pulled. We do not name the images here.

| | Images |
|---|---:|
| Detected on the first run | 9 of 14 |
| ... by ClamAV signatures | 2 |
| ... only by the YARA rules | 7 |
| Detected with the rules of v0.3.2 | 12 of 14 |

The 5 misses, and why they happened. None of them was a failed scan: every file
was scanned, and no signature or rule matched.

| Images | Why meles missed it | Now |
|---|---|---|
| 1 | xmrig-proxy, a mining proxy: the rules described the miner, not the proxy | Detected, new rules for the binary and its JSON configuration |
| 2 | ariominer, built from public source: there was no rule for it | Detected, new rule |
| 1 | xmrig packed with UPX: the strings that rules look for are not visible | Not detected |
| 1 | A plain Alpine image: the attack is a shell command in `CMD` that adds a cron job on the host, which starts a second image with a miner | Not detected, there is no malicious file. meles detects the second image |

**Read these numbers with care.** The new rules were written after looking at
the misses, so 12 of 14 says what v0.3.2 finds in these images, not what it
would find in images nobody has seen. The first run, 9 of 14, is closer to that,
and with 14 images, all of them cryptominers, it is a rough value at best.
It is no general detection rate.

A complete scan means: every file was checked and nothing known was found. Like
every scanner based on signatures and rules, meles only finds what these
describe, see [What Clean does not mean](results.md#what-clean-does-not-mean).

The new rules are in
[`charts/meles/rules/meles-own.yar`](../charts/meles/rules/meles-own.yar).
They raised no finding in the 47 popular images.

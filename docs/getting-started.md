# Getting started

## TL;DR

On your machine (Linux amd64, Docker, bash):

```sh
curl -fsSL https://github.com/movray/meles/releases/download/v0.1.0/meles_0.1.0_linux_amd64.tar.gz | tar -xz meles
docker run -d --name clamd -p 127.0.0.1:3310:3310 clamav/clamav:1.4
export MELES_CLAMD=tcp://127.0.0.1:3310
until (exec 3<>/dev/tcp/127.0.0.1/3310 && printf 'zPING\0' >&3 && head -c4 <&3 | grep -q PONG) 2>/dev/null; do sleep 5; done
./meles selftest
./meles image alpine:3.20
```

In Kubernetes:

```sh
kubectl create namespace meles
kubectl label namespace meles pod-security.kubernetes.io/enforce=baseline
helm install meles oci://ghcr.io/movray/charts/meles --version 0.1.0 -n meles
kubectl -n meles rollout status deploy/meles-clamd --timeout=15m
kubectl -n meles port-forward svc/meles-server 8080:80   # http://localhost:8080/
```

Everything below explains these steps and goes further: a file hidden by a
later layer, the operator, the scan gate.

## The tour

A step-by-step tour: scan an image on your machine, find a file that a
later layer deleted, then run meles in a Kubernetes cluster with the web UI,
the operator and the scan gate. The [README](../README.md) is the reference
for every flag and value.

1. [On your machine](#1-on-your-machine) (about 10 minutes, needs Docker)
2. [In a CI pipeline](#2-in-a-ci-pipeline)
3. [In Kubernetes](#3-in-kubernetes) (about 20 minutes, needs a cluster)

## 1. On your machine

### Install meles

Take the binary from the latest
[release](https://github.com/movray/meles/releases) (Linux and macOS,
amd64 and arm64):

```sh
VERSION=0.1.0
curl -fsSLO https://github.com/movray/meles/releases/download/v$VERSION/meles_${VERSION}_linux_amd64.tar.gz
tar -xzf meles_${VERSION}_linux_amd64.tar.gz meles
sudo install meles /usr/local/bin/
meles version
```

How to check its signature and build provenance: [Install](../README.md#install).

### Start clamd

meles does not scan by itself: it sends every file to ClamAV's clamd. If
your distribution's `clamav-daemon` is running, meles finds its socket
(`/run/clamav/clamd.ctl`) on its own and you can skip this step. Otherwise
start the official ClamAV image. It downloads the signature database first,
then loads it, which takes a minute or two and about 1.5 GB of memory:

```sh
docker run -d --name clamd -p 127.0.0.1:3310:3310 clamav/clamav:1.4
export MELES_CLAMD=tcp://127.0.0.1:3310

# wait until clamd answers (bash)
until (exec 3<>/dev/tcp/127.0.0.1/3310 && printf 'zPING\0' >&3 && head -c4 <&3 | grep -q PONG) 2>/dev/null; do
  sleep 5
done
```

### Check the chain

`meles selftest` builds images with the harmless
[EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
in memory and scans them. If it passes, meles, the connection and clamd's
signatures work:

```
$ meles selftest
engine: ClamAV 1.4.3/28169/Fri Oct 30 07:26:48 2026
PASS  clean             []
PASS  eicar-present     [/opt/eicar.com present]
PASS  eicar-whiteout    [/tmp/payload/eicar.com deleted]
PASS  eicar-opaque      [/data/eicar.com deleted]
YARA rules not checked (--yara)
selftest passed
```

### Scan an image

```
$ meles image alpine:3.20
alpine:3.20 (d9e853e87e55)
engine: ClamAV 1.4.3, signatures 28169, scanned in 9.7s

PLATFORM        LAYERS  FILES  FINDINGS  SKIPPED
linux/amd64     1       87     0         0
linux/arm/v6    1       87     0         0
...

No malware found.
```

meles pulls the image straight from the registry, without the Docker
daemon, and scans every platform of a multi-arch image. `--platform host`
scans only the one of your machine. The exit code is `0` here; it would be
`1` for a finding and `2` for an error.

### Find a file that was deleted

A file that a later layer deletes is gone from the running container, but
it is still part of the image. Build an image that does exactly that with
the EICAR test file:

```sh
mkdir meles-demo && cd meles-demo
cat > Dockerfile <<'EOF'
FROM busybox:1.37
# The EICAR test string, in two parts so that this Dockerfile itself
# does not trigger a virus scanner.
RUN printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-' 'ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
RUN rm /tmp/eicar.com
EOF
docker build -t meles-demo .
docker run --rm meles-demo ls /tmp     # empty: the file is "deleted"
```

The image was built but not pushed, so let meles read it from a
`docker save` archive:

```
$ docker save meles-demo -o meles-demo.tar
$ meles image --input meles-demo.tar
...
PLATFORM     LAYERS  FILES  FINDINGS  SKIPPED
linux/amd64  3       17     1         0

Findings (1):
PLATFORM     LAYER             PATH            SIGNATURE             STATUS                         CREATED BY
linux/amd64  2 (0404fcc71627)  /tmp/eicar.com  Eicar-Test-Signature  deleted in layer 3 (whiteout)  RUN /bin/sh -c printf ...
```

The finding names the layer that added the file, the instruction that
created that layer, and that layer 3 deleted it. The exit code is `1`. Try
`--format json` or `--format sarif` for the same result as data.

## 2. In a CI pipeline

The [CI section](../README.md#ci) of the README has a complete GitHub
Actions job: it starts clamd in the job, keeps the signature database in the
Actions cache, and fails the pipeline on a finding. Scanning an image before
it is pushed works as above, with `meles image --input`.

## 3. In Kubernetes

You need:

- a cluster with Kubernetes 1.30 or later (the scan gate needs it), for
  example k3s, kind or a test cluster
- about 2 GB of free memory on one node for clamd (it requests 1.5 GiB)
- a default StorageClass (two volumes: 2 GiB for the signature database,
  1 GiB for the web UI's database)
- outbound HTTPS to the ClamAV database (`database.clamav.net`), to PyPI
  (the mirror installs `cvdupdate` at start) and to the registries of your
  images
- `helm` 3.8 or later

### Install

```sh
kubectl create namespace meles
# The clamd image starts as root and drops privileges itself.
kubectl label namespace meles pod-security.kubernetes.io/enforce=baseline
helm install meles oci://ghcr.io/movray/charts/meles --version 0.1.0 -n meles
```

The defaults install three roles: a mirror that downloads the signatures
(the only component that talks to Cisco Talos), clamd behind a small proxy
with TLS and a token, and the web UI. Wait for clamd:

```sh
kubectl -n meles rollout status deploy/meles-clamd --timeout=15m
```

On a test cluster this took about a minute; it depends on the download.

### Check the chain

The chart has a suspended CronJob for the selftest. Run it once:

```
$ kubectl -n meles create job --from=cronjob/meles-selftest selftest-1
$ kubectl -n meles wait --for=condition=complete job/selftest-1 --timeout=5m
$ kubectl -n meles logs job/selftest-1
engine: ClamAV 1.4.6/28169+rules.205f6808c38a/Fri Oct 30 06:26:48 2026
PASS  clean             []
PASS  eicar-present     [/opt/eicar.com present]
PASS  eicar-whiteout    [/tmp/payload/eicar.com deleted]
PASS  eicar-opaque      [/data/eicar.com deleted]
PASS  yara-xmrig-config [/opt/miner/config.json present]
selftest passed
```

The last line checks the YARA rules the chart ships; `+rules.…` in the
signature version is their hash.

### The web UI

```sh
kubectl -n meles port-forward svc/meles-server 8080:80
```

Open http://localhost:8080/, enter `alpine:3.20` under *Quick scan*, and
follow the run. Under *Scans* you can add images with a cron schedule.
The UI has no login of its own: keep it internal, or put a login in front
of it ([Login for the web UI](../README.md#login-for-the-web-ui)) before you
expose it.

### The operator

The operator scans the image of every pod in the cluster and writes the
result next to the workload:

```sh
helm upgrade meles oci://ghcr.io/movray/charts/meles --version 0.1.0 -n meles \
  --reuse-values --set operator.enabled=true
kubectl get malwarereports -A
```

```
NAMESPACE     NAME                                          WORKLOAD     CONTAINER    IMAGE                                        STATUS       FINDINGS   AGE
kube-system   daemonset-svclb-traefik-14e131a3-lb-tcp-443   DaemonSet    lb-tcp-443   docker.io/rancher/klipper-lb                 Clean        0          9m
kube-system   job-helm-install-traefik-helm                 Job          helm         docker.io/rancher/klipper-helm               Clean        0          8m
kube-system   replicaset-traefik-6cd8c7cd89-traefik         ReplicaSet   traefik      docker.io/rancher/mirrored-library-traefik   Incomplete   0          9m
...
```

Reports appear as the scans finish, within a few minutes for a small
cluster. `Incomplete` means that a file could not be scanned completely;
`kubectl get malwarereport -o yaml` names the file and the reason (see
[Troubleshooting](#troubleshooting)). The page *Cluster* in the web UI
shows the same reports.

### The scan gate

With the scan gate, a new pod in a labelled namespace waits until its image
is scanned. Turn it on and label a test namespace:

```sh
helm upgrade meles oci://ghcr.io/movray/charts/meles --version 0.1.0 -n meles \
  --reuse-values --set operator.gate.enabled=true
kubectl -n meles rollout status deploy/meles-operator

kubectl create namespace gate-demo
kubectl label namespace gate-demo meles.io/gate=enforce
kubectl -n gate-demo create deployment web --image=nginx:1.29-alpine
kubectl -n gate-demo get pods -w
```

The pod is `SchedulingGated` until the scan is done (under a minute for
nginx), then it starts, pinned to the digest that was scanned:

```
$ kubectl -n gate-demo get pod -l app=web -o jsonpath='{.items[0].spec.containers[0].image}'
nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de
```

An image that meles cannot scan is held, too. Make a typo in the tag:

```
$ kubectl -n gate-demo run typo --image=nginx:1.299-alpine
$ kubectl -n gate-demo describe pod typo
...
  Warning  ScanGateHeld  39s   meles-operator  held by the meles scan gate (enforce): typo: resolve nginx:1.299-alpine: GET https://index.docker.io/v2/library/nginx/manifests/1.299-alpine: MANIFEST_UNKNOWN: manifest unknown; unknown tag=1.299-alpine
```

To see an infected image held, push the demo image from step 1 to a
registry the cluster can pull from. [ttl.sh](https://ttl.sh) takes
anonymous images that expire after the given time:

```sh
IMAGE=ttl.sh/meles-demo-$(date +%s):1h
docker tag meles-demo "$IMAGE" && docker push "$IMAGE"
kubectl -n gate-demo run infected --image="$IMAGE"
kubectl -n gate-demo describe pod infected     # held: 1 finding
kubectl -n gate-demo get malwarereports
```

The gate is off by default. It fails open: if meles or clamd is down, pods
start anyway. What it covers and what it does not:
[Scan gate](../README.md#scan-gate).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `meles selftest`: connection refused | clamd is still loading the signatures; wait (see [Start clamd](#start-clamd)), or point `MELES_CLAMD` at the right address |
| clamd pod restarts with `OOMKilled` | clamd needs about 1.5 GiB, and almost twice that while it reloads the database; give the node more memory or raise `clamd.resources` |
| clamd pod stays in `Init` | `wait-for-mirror`: the mirror has not downloaded the database yet; `kubectl -n meles logs deploy/meles-mirror -c cvdupdate` shows the download, including rate limits of Cisco Talos |
| pods of the release are rejected by Pod Security | the namespace needs `pod-security.kubernetes.io/enforce=baseline` |
| report `Incomplete`, reason `Heuristics.Limits.Exceeded.*` | clamd could not scan a file completely within its limits (`clamd.maxScanSize`, `maxScanTime`, `maxFiles`, `maxRecursion`). Raising the named limit may help; rescan with `kubectl annotate malwarereport <name> meles.io/rescan=1`. Some large binaries stay `Incomplete` even at the maximum (k3s's traefik on a test cluster). meles reports this rather than calling the image clean |
| report `Error` for a private image | the operator needs the pull secret: [Operator](../README.md#operator) |

## Clean up

```sh
docker rm -f clamd
kubectl delete namespace gate-demo
helm uninstall meles -n meles
kubectl delete namespace meles
kubectl get crd -o name | grep meles.io | xargs kubectl delete
```

Helm keeps the CRDs on uninstall; the last line removes them, and with them
all MalwareReports and ignore rules.

## Next

- [README](../README.md): every flag, value and output format, ignore rules,
  Harbor, registry mirrors
- [architecture.md](architecture.md): how it works and the security model

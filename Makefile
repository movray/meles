VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
CLAMD   ?= unix:///run/clamav/clamd.ctl
# Image repository for `make image` (full name, ko runs with --bare)
KO_DOCKER_REPO ?= ghcr.io/movray/meles
KO_VERSION     ?= v0.18.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.22.0
# Kubernetes version of the API server and etcd that envtest runs.
ENVTEST_K8S    ?= 1.36.x
SETUP_ENVTEST  ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.2
PROMTOOL       ?= promtool

.PHONY: build test test-integration test-envtest test-rules generate lint run-server selftest image image-tarball clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/meles ./cmd/meles

test:
	go test -race ./...

# Needs a running clamd.
test-integration:
	MELES_TEST_CLAMD=$(CLAMD) go test -race -tags integration ./...

# The operator and cluster-report tests need a real API server and etcd (no Docker); without
# KUBEBUILDER_ASSETS they are skipped by `make test`.
test-envtest:
	KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use -p path $(ENVTEST_K8S))" go test -race ./internal/operator/... ./internal/server/...

# The chart's alerts against hack/rules/rules_test.yaml; needs helm and
# promtool (PROMTOOL=<path>).
test-rules:
	PROMTOOL=$(PROMTOOL) hack/rules/test.sh

# Deepcopy functions and the CRD of api/v1alpha1.
generate:
	$(CONTROLLER_GEN) object paths=./api/...
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:artifacts:config=charts/meles/crds

lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }
	go vet ./...

selftest: build
	bin/meles selftest --clamd $(CLAMD)

run-server: build
	bin/meles server --clamd $(CLAMD) --db meles.db --listen 127.0.0.1:8080

# Builds and pushes the meles image without a Docker daemon.
image:
	KO_DOCKER_REPO=$(KO_DOCKER_REPO) VERSION=$(VERSION) \
		go run github.com/google/ko@$(KO_VERSION) build --bare --platform=linux/amd64,linux/arm64 \
		--tags=$(VERSION),latest ./cmd/meles

# Builds the image into a local tarball only (no push).
image-tarball:
	mkdir -p dist
	KO_DOCKER_REPO=local.invalid/meles VERSION=$(VERSION) \
		go run github.com/google/ko@$(KO_VERSION) build --bare --platform=linux/amd64 \
		--push=false --tarball=dist/meles.tar ./cmd/meles

clean:
	rm -rf bin dist

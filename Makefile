VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
CLAMD   ?= unix:///run/clamav/clamd.ctl
# Image repository for `make image`, e.g. git.itknecht.de/sugras
KO_DOCKER_REPO ?= git.itknecht.de/sugras
KO_VERSION     ?= v0.18.0

.PHONY: build test test-integration lint run-server selftest image image-tarball clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/meles ./cmd/meles

test:
	go test -race ./...

# Needs a running clamd.
test-integration:
	MELES_TEST_CLAMD=$(CLAMD) go test -race -tags integration ./...

lint:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }
	go vet ./...

selftest: build
	bin/meles selftest --clamd $(CLAMD)

run-server: build
	bin/meles server --clamd $(CLAMD) --db meles.db --listen 127.0.0.1:8080

# Builds and pushes the meles image without a Docker daemon.
image:
	KO_DOCKER_REPO=$(KO_DOCKER_REPO) GOFLAGS="-ldflags=-X=main.version=$(VERSION)" \
		go run github.com/google/ko@$(KO_VERSION) build --bare --platform=linux/amd64,linux/arm64 \
		--tags=$(VERSION) ./cmd/meles

# Builds the image into a local tarball only (no push).
image-tarball:
	mkdir -p dist
	KO_DOCKER_REPO=ko.local/meles GOFLAGS="-ldflags=-X=main.version=$(VERSION)" \
		go run github.com/google/ko@$(KO_VERSION) build --bare --platform=linux/amd64 \
		--push=false --tarball=dist/meles.tar ./cmd/meles

clean:
	rm -rf bin dist

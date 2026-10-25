package source

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

func TestParseMirror(t *testing.T) {
	tests := []struct {
		in   string
		want Mirror
		err  bool
	}{
		{"docker.io=harbor.example.com/dockerhub", Mirror{"docker.io", "harbor.example.com/dockerhub"}, false},
		{" quay.io = harbor.example.com/quay/ ", Mirror{"quay.io", "harbor.example.com/quay"}, false},
		{"docker.io", Mirror{}, true},
		{"docker.io=", Mirror{}, true},
		{"docker.io/library=harbor.example.com", Mirror{}, true},
		{"docker.io=https://harbor.example.com", Mirror{}, true},
	}
	for _, tt := range tests {
		got, err := ParseMirror(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("ParseMirror(%q) = %+v, %v", tt.in, got, err)
		}
	}
}

func TestMirrored(t *testing.T) {
	m := Mirror{"docker.io", "harbor.example.com/dockerhub"}
	tests := []struct{ ref, want string }{
		{"nginx:1.27", "harbor.example.com/dockerhub/library/nginx:1.27"},
		{"docker.io/grafana/grafana:12.0.2", "harbor.example.com/dockerhub/grafana/grafana:12.0.2"},
		{"index.docker.io/library/busybox@sha256:" + strings.Repeat("a", 64), "harbor.example.com/dockerhub/library/busybox@sha256:" + strings.Repeat("a", 64)},
		{"quay.io/prometheus/prometheus:v3.4.2", ""},
	}
	for _, tt := range tests {
		r, err := name.ParseReference(tt.ref)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := m.mirrored(r, nil)
		if err != nil || ok != (tt.want != "") || (ok && got.String() != tt.want) {
			t.Errorf("mirrored(%s) = %v, %v, %v; want %q", tt.ref, got, ok, err, tt.want)
		}
	}
}

// countingRegistry is an in-memory registry that counts manifest requests.
type countingRegistry struct {
	*httptest.Server
	manifests atomic.Int32
}

func newRegistry(t *testing.T) *countingRegistry {
	t.Helper()
	r := &countingRegistry{}
	h := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/manifests/") && req.Method == http.MethodGet {
			r.manifests.Add(1)
		}
		h.ServeHTTP(w, req)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *countingRegistry) host() string { return strings.TrimPrefix(r.URL, "http://") }

func push(t *testing.T, ref string, img v1.Image) {
	t.Helper()
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
}

func TestFetchMirror(t *testing.T) {
	img, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := random.Image(256, 1)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	upstream, mirror := newRegistry(t), newRegistry(t)
	push(t, upstream.host()+"/team/app:1", img)
	push(t, mirror.host()+"/proxy/team/app:1", img)
	// The mirror serves another image under a tag only it has.
	push(t, mirror.host()+"/proxy/team/app:evil", other)
	push(t, upstream.host()+"/team/app:evil", img)

	var logs bytes.Buffer
	opts := Options{
		Insecure: true,
		Mirrors:  []Mirror{{Registry: upstream.host(), Prefix: mirror.host() + "/proxy"}},
		Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
	}
	ctx := context.Background()
	fetch := func(ref string) (*Image, error) {
		t.Helper()
		upstream.manifests.Store(0)
		mirror.manifests.Store(0)
		logs.Reset()
		return Fetch(ctx, ref, opts)
	}

	// From the mirror only.
	got, err := fetch(upstream.host() + "/team/app:1")
	if err != nil || got.Digest != digest.String() || upstream.manifests.Load() != 0 || mirror.manifests.Load() == 0 {
		t.Fatalf("mirrored fetch: %v, %+v, upstream %d, mirror %d", err, got, upstream.manifests.Load(), mirror.manifests.Load())
	}
	if got.Ref != upstream.host()+"/team/app:1" {
		t.Errorf("ref = %s, want the original reference", got.Ref)
	}

	// Not on the mirror: from the registry, and the mirror is logged.
	push(t, upstream.host()+"/team/only:1", img)
	if got, err = fetch(upstream.host() + "/team/only:1"); err != nil || got.Digest != digest.String() || upstream.manifests.Load() == 0 {
		t.Fatalf("fallback: %v, %+v", err, got)
	}
	if !strings.Contains(logs.String(), "registry mirror failed") {
		t.Errorf("fallback not logged: %s", logs.String())
	}

	// A mirror that serves other content for a digest is not believed:
	// the image comes from the registry.
	evilDigest, err := other.Digest()
	if err != nil {
		t.Fatal(err)
	}
	evilManifest, err := other.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	liar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.Contains(req.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", digest.String())
			w.Write(evilManifest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer liar.Close()
	lying := opts
	lying.Mirrors = []Mirror{{Registry: upstream.host(), Prefix: strings.TrimPrefix(liar.URL, "http://") + "/proxy"}}
	logs.Reset()
	upstream.manifests.Store(0)
	if got, err = Fetch(ctx, upstream.host()+"/team/app@"+digest.String(), lying); err != nil || got.Digest != digest.String() || upstream.manifests.Load() == 0 {
		t.Fatalf("lying mirror: %v, %+v", err, got)
	}
	if !strings.Contains(logs.String(), "registry mirror failed") {
		t.Errorf("lying mirror not logged: %s", logs.String())
	}

	// Neither has it: the error names both.
	_, err = fetch(upstream.host() + "/team/missing:1")
	if err == nil || !strings.Contains(err.Error(), "mirror "+mirror.host()+"/proxy/team/missing:1") {
		t.Fatalf("missing everywhere: %v", err)
	}

	// Resolve takes the mirror's answer for a tag (trusted for tags).
	_, d, err := Resolve(ctx, upstream.host()+"/team/app:evil", opts)
	if err != nil || d != evilDigest.String() {
		t.Errorf("resolve via mirror = %s, %v; want %s", d, err, evilDigest)
	}
}

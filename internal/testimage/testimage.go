// Package testimage builds images with EICAR test files at runtime and
// serves them from an in-memory registry. It backs the tests and
// `meles selftest`, which checks the whole chain (registry pull, layer
// extraction, engine) without an EICAR image in any real registry.
package testimage

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// EICAR returns the EICAR test string. It is assembled at runtime so that
// source files and binaries do not trigger virus scanners themselves.
func EICAR() string {
	return strings.Join([]string{`X5O!P%@AP[4\PZX54(P^)7CC)7}$`, "EICAR-STANDARD-ANTIVIRUS-", "TEST-FILE!$H+H*"}, "")
}

// Layer is one layer of a test image.
type Layer struct {
	CreatedBy string
	Files     map[string]string
}

// Case is a test image and the result meles must report for it.
type Case struct {
	Name   string
	Layers []Layer
	// Want lists the expected findings as "path status", e.g.
	// "/opt/eicar.com present". Empty means clean.
	Want []string
}

var base = Layer{"COPY hello.txt /etc/", map[string]string{"/etc/hello.txt": "hello\n"}}

// Cases returns the standard test images.
func Cases() []Case {
	return []Case{
		{Name: "clean", Layers: []Layer{base}},
		{Name: "eicar-present", Layers: []Layer{base,
			{"COPY eicar.com /opt/", map[string]string{"/opt/eicar.com": EICAR()}},
		}, Want: []string{"/opt/eicar.com present"}},
		{Name: "eicar-whiteout", Layers: []Layer{base,
			{"COPY eicar.com /tmp/payload/", map[string]string{"/tmp/payload/eicar.com": EICAR()}},
			{"RUN echo noop", map[string]string{"/etc/motd": "hi\n"}},
			{"RUN rm /tmp/payload/eicar.com", map[string]string{"/tmp/payload/.wh.eicar.com": ""}},
		}, Want: []string{"/tmp/payload/eicar.com deleted"}},
		{Name: "eicar-opaque", Layers: []Layer{base,
			{"COPY eicar.com /data/", map[string]string{"/data/eicar.com": EICAR()}},
			{"RUN rm -rf /data && mkdir /data && echo replaced > /data/readme.txt",
				map[string]string{"/data/.wh..wh..opq": "", "/data/readme.txt": "replaced\n"}},
		}, Want: []string{"/data/eicar.com deleted"}},
	}
}

// YaraCases returns test images for the default YARA rules
// (charts/meles/rules); clamd must have loaded them. The file is a harmless
// XMRig configuration that SIGNATURE_BASE_XMRIG_Monero_Miner_Config
// matches.
func YaraCases() []Case {
	config := "{\n    \"algo\": \"cryptonight\",  // cryptonight (default) or cryptonight-lite\n    \"threads\": 1\n}\n"
	return []Case{
		{Name: "yara-xmrig-config", Layers: []Layer{base,
			{"COPY config.json /opt/miner/", map[string]string{"/opt/miner/config.json": config}},
		}, Want: []string{"/opt/miner/config.json present"}},
	}
}

// Registry is an in-memory registry with the test images.
type Registry struct {
	srv  *httptest.Server
	Host string
	// auth holds "user:password" once RequireAuth was called.
	auth atomic.Pointer[[2]string]
}

// RequireAuth makes the registry refuse requests without these basic auth
// credentials, like a private registry. Push before calling it.
func (r *Registry) RequireAuth(user, password string) {
	r.auth.Store(&[2]string{user, password})
}

func (r *Registry) checkAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if want := r.auth.Load(); want != nil {
			if u, p, ok := req.BasicAuth(); !ok || u != want[0] || p != want[1] {
				w.Header().Set("WWW-Authenticate", `Basic realm="testimage"`)
				http.Error(w, `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}`, http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

// Close stops the registry.
func (r *Registry) Close() { r.srv.Close() }

// Ref returns the reference of a test image in the registry.
func (r *Registry) Ref(name string) string {
	return r.Host + "/selftest/" + name + ":latest"
}

// Serve starts an in-memory registry and pushes the given cases to it.
// References must be parsed with name.Insecure (plain HTTP).
func Serve(cases []Case) (*Registry, error) {
	reg := &Registry{}
	reg.srv = httptest.NewServer(reg.checkAuth(registry.New(registry.Logger(log.New(io.Discard, "", 0)))))
	reg.Host = strings.TrimPrefix(reg.srv.URL, "http://")
	for _, c := range cases {
		img, err := Build(c.Layers)
		if err != nil {
			reg.Close()
			return nil, fmt.Errorf("build %s: %w", c.Name, err)
		}
		if err := reg.Push(c.Name, img); err != nil {
			reg.Close()
			return nil, err
		}
	}
	return reg, nil
}

// Push stores an image or index under the given name.
func (r *Registry) Push(name string, img remote.Taggable) error {
	ref, err := nameRef(r.Ref(name))
	if err != nil {
		return err
	}
	switch v := img.(type) {
	case v1.ImageIndex:
		err = remote.WriteIndex(ref, v)
	case v1.Image:
		err = remote.Write(ref, v)
	default:
		return fmt.Errorf("push %s: unsupported type %T", name, img)
	}
	if err != nil {
		return fmt.Errorf("push %s: %w", name, err)
	}
	return nil
}

func nameRef(s string) (name.Reference, error) {
	r, err := name.ParseReference(s, name.Insecure)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", s, err)
	}
	return r, nil
}

// Build creates a linux/amd64 image from layers.
func Build(layers []Layer) (v1.Image, error) {
	return BuildPlatform(layers, v1.Platform{OS: "linux", Architecture: "amd64"})
}

// BuildPlatform creates an image for platform p from layers.
func BuildPlatform(layers []Layer, p v1.Platform) (v1.Image, error) {
	img := empty.Image
	for _, tl := range layers {
		b, err := tarBytes(tl.Files)
		if err != nil {
			return nil, err
		}
		l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(b)), nil
		})
		if err != nil {
			return nil, fmt.Errorf("layer: %w", err)
		}
		img, err = mutate.Append(img, mutate.Addendum{Layer: l, History: v1.History{CreatedBy: tl.CreatedBy}})
		if err != nil {
			return nil, fmt.Errorf("append layer: %w", err)
		}
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Variant = p.OS, p.Architecture, p.Variant
	return mutate.ConfigFile(img, cf)
}

func tarBytes(files map[string]string) ([]byte, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		content := files[n]
		h := &tar.Header{Name: strings.TrimPrefix(n, "/"), Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(h); err != nil {
			return nil, fmt.Errorf("tar header %s: %w", n, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("tar write %s: %w", n, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("tar close: %w", err)
	}
	return buf.Bytes(), nil
}

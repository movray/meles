package scan

// Regression tests for ways an image with malware could pass as clean.

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/movray/meles/internal/engine"
	"github.com/movray/meles/internal/engine/fake"
	"github.com/movray/meles/internal/extract"
	"github.com/movray/meles/internal/source"
	"github.com/movray/meles/internal/testimage"
)

func eicarImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "evil", Files: map[string]string{"/opt/eicar.com": testimage.EICAR()}}})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func cleanImage(t *testing.T) v1.Image {
	t.Helper()
	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "base", Files: map[string]string{"/etc/hello.txt": "hello\n"}}})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func serve(t *testing.T, imgs map[string]any) *testimage.Registry {
	t.Helper()
	reg, err := testimage.Serve(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	for n, img := range imgs {
		if err := reg.Push(n, img.(remote.Taggable)); err != nil {
			t.Fatal(err)
		}
	}
	return reg
}

// forgedLayer reports a diffID that does not match its content.
type forgedLayer struct {
	v1.Layer
	diffID v1.Hash
}

func (f forgedLayer) DiffID() (v1.Hash, error) { return f.diffID, nil }

// A layer whose config claims the diffID of an already scanned clean layer
// must not be served from the cache.
func TestForgedDiffID(t *testing.T) {
	cl, _ := cleanImage(t).Layers()
	cleanDiffID, _ := cl[0].DiffID()
	el, _ := eicarImage(t).Layers()
	forged, err := mutate.Append(empty.Image, mutate.Addendum{Layer: forgedLayer{el[0], cleanDiffID}})
	if err != nil {
		t.Fatal(err)
	}
	reg := serve(t, map[string]any{"clean": cleanImage(t), "forged": forged})

	for _, warm := range []bool{false, true} {
		s := newScanner(&fake.Engine{}, NewCache(100))
		if warm {
			if _, err := s.Scan(context.Background(), reg.Ref("clean"), source.PlatformFilter{}, nil); err != nil {
				t.Fatal(err)
			}
		}
		rep, err := s.Scan(context.Background(), reg.Ref("forged"), source.PlatformFilter{}, nil)
		if err == nil && !rep.Infected() {
			t.Errorf("warm cache %v: image with EICAR reported clean", warm)
		}
		if err == nil {
			t.Errorf("warm cache %v: want diffID mismatch error", warm)
		}
	}
}

// A registry that serves other bytes for a blob digest (split view) must
// cause an error.
func TestBlobContentMismatch(t *testing.T) {
	evil := eicarImage(t)
	clean, err := testimage.Build([]testimage.Layer{{CreatedBy: "clean", Files: map[string]string{"/opt/eicar.com": strings.Repeat("x", len(testimage.EICAR()))}}})
	if err != nil {
		t.Fatal(err)
	}
	el, _ := evil.Layers()
	evilDigest, _ := el[0].Digest()
	evilSize, _ := el[0].Size()
	cl, _ := clean.Layers()
	rc, _ := cl[0].Compressed()
	cleanBytes, _ := io.ReadAll(rc)
	// Same size as the real blob.
	body := append(cleanBytes, make([]byte, int(evilSize)-len(cleanBytes))...)

	inner := registry.New(registry.Logger(log.New(io.Discard, "", 0)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/blobs/"+evilDigest.String()) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(body)
			return
		}
		inner.ServeHTTP(w, r)
	}))
	defer srv.Close()
	ref := strings.TrimPrefix(srv.URL, "http://") + "/split/evil:latest"
	nref, _ := name.ParseReference(ref, name.Insecure)
	if err := remote.Write(nref, evil); err != nil {
		t.Fatal(err)
	}

	if _, err := newScanner(&fake.Engine{}, nil).Scan(context.Background(), ref, source.PlatformFilter{}, nil); err == nil {
		t.Error("blob with wrong content for its digest was accepted")
	}
}

// Index entries without a platform are resolved via their config, like
// containerd does, instead of being skipped.
func TestIndexEntryWithoutPlatform(t *testing.T) {
	arm := v1.Platform{OS: "linux", Architecture: "arm64"}
	clean, err := testimage.BuildPlatform([]testimage.Layer{{CreatedBy: "base", Files: map[string]string{"/etc/hello.txt": "hello\n"}}}, arm)
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.IndexMediaType(empty.Index, types.OCIImageIndex)
	idx = mutate.AppendManifests(idx,
		mutate.IndexAddendum{Add: clean, Descriptor: v1.Descriptor{Platform: &arm}},
		mutate.IndexAddendum{Add: eicarImage(t)}, // no platform
	)
	reg := serve(t, map[string]any{"multi": idx})

	tests := []struct {
		filter       string
		wantInfected bool
	}{
		{"all", true},
		{"linux/amd64", true},
		{"linux/arm64", false},
	}
	for _, tt := range tests {
		pf, err := source.ParsePlatforms(tt.filter)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := newScanner(&fake.Engine{}, nil).Scan(context.Background(), reg.Ref("multi"), pf, nil)
		if err != nil {
			t.Fatalf("%s: %v", tt.filter, err)
		}
		if rep.Infected() != tt.wantInfected {
			t.Errorf("%s: Infected = %v, want %v", tt.filter, rep.Infected(), tt.wantInfected)
		}
	}
}

// Files above the size limit make the report incomplete.
func TestOversizedFileIncomplete(t *testing.T) {
	big := testimage.EICAR() + strings.Repeat("A", 2<<20)
	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "evil", Files: map[string]string{"/opt/big.bin": big}}})
	if err != nil {
		t.Fatal(err)
	}
	reg := serve(t, map[string]any{"big": img, "clean": cleanImage(t)})

	s := newScanner(&fake.Engine{}, nil)
	rep, err := s.Scan(context.Background(), reg.Ref("big"), source.PlatformFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Complete || len(rep.Skipped()) != 1 {
		t.Errorf("Complete = %v, skipped = %v; want incomplete with 1 skipped file", rep.Complete, rep.Skipped())
	}
	rep, err = s.Scan(context.Background(), reg.Ref("clean"), source.PlatformFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Complete {
		t.Error("clean image reported incomplete")
	}
}

// limitEngine answers like clamd with AlertExceedsMax for every file.
type limitEngine struct{ fake.Engine }

func (e *limitEngine) Open(context.Context) (engine.Session, error) { return limitSession{}, nil }

type limitSession struct{}

func (limitSession) Scan(context.Context, io.Reader) (string, error) {
	return "Heuristics.Limits.Exceeded.MaxScanSize", nil
}
func (limitSession) Close() error { return nil }

// clamd limit alerts are skipped files, not findings.
func TestEngineLimitIsSkipped(t *testing.T) {
	reg := serve(t, map[string]any{"clean": cleanImage(t)})
	s := &Scanner{Engine: &limitEngine{}, Concurrency: 1, Source: source.Options{Insecure: true}, Limits: extract.Limits{MaxFileSize: 1 << 20}}
	rep, err := s.Scan(context.Background(), reg.Ref("clean"), source.PlatformFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Infected() || rep.Complete || len(rep.Skipped()) != 1 {
		t.Errorf("Infected = %v, Complete = %v, skipped = %v; want 1 skipped file and no finding", rep.Infected(), rep.Complete, rep.Skipped())
	}
}

func TestCacheMaxPaths(t *testing.T) {
	layer := func(n int) *layerResult {
		m := map[string]bool{}
		for i := range n {
			m[string(rune('a'+i))] = true
		}
		return &layerResult{meta: &extract.Layer{Entries: m}}
	}
	c := NewCache(100)
	c.MaxPaths = 5
	c.put("a", layer(2))
	c.put("b", layer(2))
	c.put("c", layer(2)) // 6 paths: evicts a
	if _, ok := c.get("a"); ok || c.Len() != 2 {
		t.Errorf("after 6 paths: a cached = %v, Len = %d; want a evicted, 2 left", ok, c.Len())
	}
	c.put("d", layer(9)) // larger than the budget on its own
	if c.Len() != 0 {
		t.Errorf("Len = %d, want 0", c.Len())
	}
}

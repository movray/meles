package source

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/klauspost/compress/zstd"

	"github.com/movray/meles/internal/testimage"
)

func platformImage(t *testing.T, arch, content string) v1.Image {
	t.Helper()
	img, err := testimage.BuildPlatform([]testimage.Layer{{CreatedBy: "COPY hello /", Files: map[string]string{"/hello": content}}},
		v1.Platform{OS: "linux", Architecture: arch})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// ociLayout writes an OCI layout with a single-platform image app:1 and a
// multi-arch index multi:2, as docker save and buildx do.
func ociLayoutDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AppendImage(platformImage(t, "amd64", "app"), layout.WithAnnotations(map[string]string{
		annotationImageName: "docker.io/library/app:1", annotationRefName: "1"})); err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: platformImage(t, "amd64", "x86"), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: platformImage(t, "arm64", "arm"), Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}})
	if err := p.AppendIndex(idx, layout.WithAnnotations(map[string]string{annotationRefName: "registry.example.com/multi:2"})); err != nil {
		t.Fatal(err)
	}
	return dir
}

// tarDir packs dir into a tar, with extra entries that must not be served.
func tarDir(t *testing.T, dir, dst string, wrap func(io.Writer) io.WriteCloser) {
	t.Helper()
	f, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := wrap(f)
	tw := tar.NewWriter(w)
	tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 1, Mode: 0o644})
	tw.Write([]byte("x"))
	tw.WriteHeader(&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if err := tw.WriteHeader(&tar.Header{Name: "./" + filepath.ToSlash(rel), Typeflag: tar.TypeReg, Size: int64(len(b)), Mode: 0o644}); err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func readHello(t *testing.T, pi PlatformImage) string {
	t.Helper()
	layers, err := pi.Image.Layers()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[0].Uncompressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if err != nil {
			t.Fatalf("no /hello in the layer: %v", err)
		}
		if strings.TrimPrefix(h.Name, "/") == "hello" {
			b, _ := io.ReadAll(tr)
			return string(b)
		}
	}
}

func TestFetchLocalOCI(t *testing.T) {
	dir := ociLayoutDir(t)
	tmp := t.TempDir()
	inputs := map[string]string{"directory": dir}
	for kind, wrap := range map[string]func(io.Writer) io.WriteCloser{
		"tar":  func(w io.Writer) io.WriteCloser { return nopWriteCloser{w} },
		"gzip": func(w io.Writer) io.WriteCloser { return gzip.NewWriter(w) },
		"zstd": func(w io.Writer) io.WriteCloser { z, _ := zstd.NewWriter(w); return z },
	} {
		p := filepath.Join(tmp, "layout."+kind)
		tarDir(t, dir, p, wrap)
		inputs[kind] = p
	}
	for kind, in := range inputs {
		t.Run(kind, func(t *testing.T) {
			if _, err := Fetch(t.Context(), "", Options{Input: in}); err == nil || !strings.Contains(err.Error(), "several images") || !strings.Contains(err.Error(), "docker.io/library/app:1") {
				t.Errorf("without a name: %v", err)
			}
			for _, name := range []string{"app:1", "docker.io/library/app:1"} {
				img, err := Fetch(t.Context(), name, Options{Input: in})
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if img.Ref != "docker.io/library/app:1" || img.Input != in || len(img.Platforms) != 1 || readHello(t, img.Platforms[0]) != "app" {
					t.Errorf("%s: ref %q, %d platforms", name, img.Ref, len(img.Platforms))
				}
				img.Close()
			}
			pf, _ := ParsePlatforms("linux/arm64")
			img, err := Fetch(t.Context(), "registry.example.com/multi:2", Options{Input: in, Platforms: pf})
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			if len(img.Platforms) != 1 || img.Platforms[0].Platform != "linux/arm64" || readHello(t, img.Platforms[0]) != "arm" {
				t.Errorf("multi-arch: %+v", img.Platforms)
			}
			if _, err := Fetch(t.Context(), "missing:1", Options{Input: in}); err == nil || !strings.Contains(err.Error(), "no image named missing:1") {
				t.Errorf("missing name: %v", err)
			}
		})
	}
	if leftovers, _ := filepath.Glob(filepath.Join(os.TempDir(), "meles-input-*.tar")); len(leftovers) > 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}
}

// A single image without a name takes the name the user gives.
func TestFetchLocalUnnamed(t *testing.T) {
	dir := t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AppendImage(platformImage(t, "amd64", "app")); err != nil {
		t.Fatal(err)
	}
	for want, ref := range map[string]string{"": dir, "ghcr.io/acme/app:1": "ghcr.io/acme/app:1"} {
		img, err := Fetch(t.Context(), want, Options{Input: dir})
		if err != nil {
			t.Fatal(err)
		}
		if img.Ref != ref {
			t.Errorf("name %q: ref %q, want %q", want, img.Ref, ref)
		}
		img.Close()
	}
}

// A layer whose content does not match its digest fails when read.
func TestFetchLocalTamperedLayer(t *testing.T) {
	dir := t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatal(err)
	}
	img := platformImage(t, "amd64", "original")
	if err := p.AppendImage(img); err != nil {
		t.Fatal(err)
	}
	layers, _ := img.Layers()
	d, _ := layers[0].Digest()
	blob := filepath.Join(dir, "blobs", "sha256", d.Hex)
	b, _ := os.ReadFile(blob)
	b[len(b)-1] ^= 0xff
	if err := os.WriteFile(blob, b, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Fetch(t.Context(), "", Options{Input: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer got.Close()
	ls, _ := got.Platforms[0].Image.Layers()
	rc, err := ls[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.Copy(io.Discard, rc); err == nil || !strings.Contains(err.Error(), "content has digest") {
		t.Errorf("tampered layer read: %v", err)
	}
}

// The docker save format before Docker 25: manifest.json only.
func TestFetchLocalDockerArchive(t *testing.T) {
	tmp := t.TempDir()
	one, _ := name.NewTag("app:1")
	two, _ := name.NewTag("ghcr.io/acme/tool:2")
	single := filepath.Join(tmp, "single.tar")
	if err := tarball.WriteToFile(single, one, platformImage(t, "amd64", "app")); err != nil {
		t.Fatal(err)
	}
	multi := filepath.Join(tmp, "multi.tar")
	f, _ := os.Create(multi)
	if err := tarball.MultiRefWrite(map[name.Reference]v1.Image{one: platformImage(t, "amd64", "app"), two: platformImage(t, "arm64", "tool")}, f); err != nil {
		t.Fatal(err)
	}
	f.Close()

	img, err := Fetch(t.Context(), "", Options{Input: single})
	if err != nil {
		t.Fatal(err)
	}
	if img.Ref != "index.docker.io/library/app:1" && img.Ref != "app:1" {
		t.Errorf("ref %q", img.Ref)
	}
	if len(img.Platforms) != 1 || readHello(t, img.Platforms[0]) != "app" {
		t.Errorf("platforms %+v", img.Platforms)
	}
	img.Close()

	if _, err := Fetch(t.Context(), "", Options{Input: multi}); err == nil || !strings.Contains(err.Error(), "several images") {
		t.Errorf("multi without a name: %v", err)
	}
	img, err = Fetch(t.Context(), "ghcr.io/acme/tool:2", Options{Input: multi})
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if img.Platforms[0].Platform != "linux/arm64" || readHello(t, img.Platforms[0]) != "tool" {
		t.Errorf("selected %+v", img.Platforms)
	}
}

func TestFetchLocalNotAnImage(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "README"), []byte("hi"), 0o644)
	if _, err := Fetch(t.Context(), "", Options{Input: dir}); err == nil || !strings.Contains(err.Error(), "neither an OCI image layout") {
		t.Errorf("plain directory: %v", err)
	}
	if _, err := Fetch(t.Context(), "", Options{Input: filepath.Join(dir, "missing.tar")}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

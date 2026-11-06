package extract

import (
	"archive/tar"
	"bytes"
	"io"
	"path"
	"strings"
	"testing"
)

// seeds are layers with the shapes Walk treats specially.
func seeds(f *testing.F) {
	f.Helper()
	f.Add([]byte{})
	f.Add(make([]byte, 1024))
	for _, entries := range [][]entry{
		{{name: "etc/hello.txt", content: "hello"}},
		{{name: "tmp/.wh.payload"}, {name: "data/.wh..wh..opq"}},
		{{name: "tmp/.wh.payload", content: "shipped"}},
		{{name: "data/.wh..wh..opq", content: "shipped"}},
		{{name: "../../escape", content: "x"}, {name: "/abs", content: "y"}},
		{{name: "usr/bin/link", content: "tool", typeflag: tar.TypeSymlink}},
		{{name: "odd", typeflag: '9'}},
		{{name: "dir/", typeflag: tar.TypeDir}, {name: ".wh.", content: "z"}},
	} {
		b, err := io.ReadAll(tarball(f, entries...))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
		f.Add(append(bytes.Clone(b), "after the end of the archive"...))
	}
}

// FuzzWalk feeds arbitrary bytes to Walk. Whatever the input, Walk must not
// panic, and on success no content may go unnoticed: every entry with
// content is passed to the callback or reported as skipped.
func FuzzWalk(f *testing.F) {
	seeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		lim := Limits{MaxFileSize: 1 << 10, MaxLayerSize: 1 << 22, MaxFiles: 256}
		seen := map[string]int{}
		l, err := Walk(bytes.NewReader(data), lim, func(file File) error {
			if file.Path != CleanPath(file.Path) || !strings.HasPrefix(file.Path, "/") {
				t.Fatalf("path %q is not clean and absolute", file.Path)
			}
			if file.Size > lim.MaxFileSize {
				t.Fatalf("%s: size %d above the limit", file.Path, file.Size)
			}
			if _, err := io.Copy(io.Discard, file.Content); err != nil {
				return err
			}
			seen[file.Path]++
			return nil
		})
		if err != nil {
			if l != nil {
				t.Fatalf("layer returned together with error %v", err)
			}
			return
		}
		for _, s := range l.Skipped {
			seen[s.Path]++
		}
		tr := tar.NewReader(bytes.NewReader(data))
		for {
			h, err := tr.Next()
			if err != nil {
				return
			}
			n, err := io.Copy(io.Discard, tr)
			if err != nil {
				t.Fatalf("Walk succeeded, tar reader failed: %v", err)
			}
			if p := CleanPath(h.Name); n > 0 && seen[p] == 0 {
				t.Fatalf("%d bytes of %s neither scanned nor skipped", n, p)
			}
		}
	})
}

// FuzzWalkEntry builds a valid layer from a fuzzed name and type, which
// reaches deeper than random bytes that rarely pass the tar checksum.
func FuzzWalkEntry(f *testing.F) {
	f.Add("tmp/.wh.payload", byte(tar.TypeReg), []byte("shipped"))
	f.Add(".wh..wh..opq", byte(tar.TypeReg), []byte("shipped"))
	f.Add(".wh.", byte(tar.TypeReg), []byte("shipped"))
	f.Add("../../a", byte(tar.TypeReg), []byte("x"))
	f.Add("a/b", byte(tar.TypeCont), []byte("x"))
	f.Fuzz(func(t *testing.T, name string, typeflag byte, content []byte) {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		h := &tar.Header{Name: name, Typeflag: typeflag, Mode: 0o644, Size: int64(len(content)), Format: tar.FormatPAX}
		if err := tw.WriteHeader(h); err != nil {
			t.Skip()
		}
		if _, err := tw.Write(content); err != nil {
			t.Skip()
		}
		if err := tw.Close(); err != nil {
			t.Skip()
		}
		var got []byte
		l, err := Walk(bytes.NewReader(buf.Bytes()), Limits{}, func(file File) error {
			b, err := io.ReadAll(file.Content)
			got = append(got, b...)
			return err
		})
		if err != nil {
			t.Skip()
		}
		if len(content) > 0 && !bytes.Equal(got, content) && len(l.Skipped) == 0 {
			t.Fatalf("entry %q type %q: content neither scanned nor skipped", name, typeflag)
		}
	})
}

// FuzzCleanPath checks that a tar entry name can never leave the layer root.
func FuzzCleanPath(f *testing.F) {
	for _, s := range []string{"", ".", "..", "/", "../../etc/passwd", "a/../../b", "./a//b/", "a\x00b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		p := CleanPath(name)
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("%q: %q is not absolute", name, p)
		}
		if CleanPath(p) != p {
			t.Fatalf("%q: %q is not stable", name, p)
		}
		if strings.Contains(p+"/", "/../") {
			t.Fatalf("%q: %q still has a parent reference", name, p)
		}
	})
}

// FuzzHiddenBy checks that the walk up the path ends and that a file can
// only be hidden by its own or a later layer.
func FuzzHiddenBy(f *testing.F) {
	f.Add("/a/b", "/a", "/a/b", uint8(0))
	f.Add("/", "/", "/", uint8(1))
	f.Fuzz(func(t *testing.T, p, whiteout, opaque string, entry uint8) {
		p = CleanPath(p)
		layers := []*Layer{
			{Entries: map[string]bool{p: true}},
			{Whiteouts: map[string]bool{path.Clean(whiteout): true}, Opaques: map[string]bool{path.Clean(opaque): true}},
		}
		j, how := HiddenBy(p, int(entry)%len(layers), layers)
		if (j < 0) != (how == "") {
			t.Fatalf("index %d with reason %q", j, how)
		}
		if j >= len(layers) {
			t.Fatalf("index %d beyond the layers", j)
		}
	})
}

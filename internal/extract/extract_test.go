package extract

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

type entry struct {
	name     string
	content  string
	typeflag byte
}

func tarball(t testing.TB, entries ...entry) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: tf, Mode: 0o644}
		if tf == tar.TypeReg {
			h.Size = int64(len(e.content))
		}
		if tf == tar.TypeSymlink {
			h.Linkname = e.content
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg {
			if _, err := tw.Write([]byte(e.content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestWalk(t *testing.T) {
	r := tarball(t,
		entry{name: "etc/", typeflag: tar.TypeDir},
		entry{name: "etc/hello.txt", content: "hello"},
		entry{name: "./usr/bin/tool", content: "binary"},
		entry{name: "usr/bin/link", content: "tool", typeflag: tar.TypeSymlink},
		entry{name: "tmp/.wh.payload", content: ""},
		entry{name: "data/.wh..wh..opq", content: ""},
		entry{name: "../../escape", content: "x"},
		entry{name: "big", content: "0123456789"},
		entry{name: "odd", typeflag: '9'},
	)

	var got []string
	l, err := Walk(r, Limits{MaxFileSize: 8}, func(f File) error {
		b, err := io.ReadAll(f.Content)
		if err != nil {
			return err
		}
		got = append(got, f.Path+"="+string(b))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"/etc/hello.txt=hello", "/usr/bin/tool=binary", "/escape=x"}
	if len(got) != len(want) {
		t.Fatalf("files = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("file %d = %q, want %q", i, got[i], want[i])
		}
	}
	if !l.Whiteouts["/tmp/payload"] {
		t.Errorf("whiteout /tmp/payload not recorded: %v", l.Whiteouts)
	}
	if !l.Opaques["/data"] {
		t.Errorf("opaque /data not recorded: %v", l.Opaques)
	}
	if !l.Entries["/usr/bin/link"] {
		t.Errorf("symlink not recorded as entry")
	}
	if l.Entries["/etc"] {
		t.Errorf("directory recorded as entry")
	}
	if len(l.Skipped) != 2 || l.Skipped[0].Path != "/big" || l.Skipped[1].Path != "/odd" {
		t.Errorf("skipped = %v, want /big and /odd (unsupported type)", l.Skipped)
	}
	// sha256("0123456789"): skipped files are hashed for ignore rules.
	if sk := l.Skipped[0]; sk.Signature != SigMaxFileSize || sk.SHA256 != "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882" {
		t.Errorf("skipped /big: signature %q, sha256 %q", sk.Signature, sk.SHA256)
	}
	if l.Skipped[1].Signature != SigUnsupported {
		t.Errorf("skipped /odd: signature %q", l.Skipped[1].Signature)
	}
	if l.Files != 3 {
		t.Errorf("Files = %d, want 3", l.Files)
	}
}

func TestWalkLimits(t *testing.T) {
	tests := []struct {
		name string
		lim  Limits
	}{
		{"max files", Limits{MaxFiles: 2}},
		{"max layer size", Limits{MaxLayerSize: 10}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tarball(t, entry{name: "a", content: "aaaaaa"}, entry{name: "b", content: "bbbbbb"}, entry{name: "c", content: "c"})
			_, err := Walk(r, tt.lim, func(File) error { return nil })
			if !errors.Is(err, ErrLimitExceeded) {
				t.Fatalf("err = %v, want ErrLimitExceeded", err)
			}
		})
	}
}

func TestHiddenBy(t *testing.T) {
	layer := func(entries, whiteouts, opaques []string) *Layer {
		l := &Layer{Entries: map[string]bool{}, Whiteouts: map[string]bool{}, Opaques: map[string]bool{}}
		for _, p := range entries {
			l.Entries[p] = true
		}
		for _, p := range whiteouts {
			l.Whiteouts[p] = true
		}
		for _, p := range opaques {
			l.Opaques[p] = true
		}
		return l
	}

	tests := []struct {
		name    string
		layers  []*Layer
		path    string
		wantIdx int
		wantHow string
	}{
		{"visible", []*Layer{layer([]string{"/a/f"}, nil, nil), layer([]string{"/b"}, nil, nil)}, "/a/f", -1, ""},
		{"file whiteout", []*Layer{layer([]string{"/a/f"}, nil, nil), layer(nil, []string{"/a/f"}, nil)}, "/a/f", 1, "whiteout"},
		{"parent whiteout", []*Layer{layer([]string{"/a/f"}, nil, nil), layer(nil, nil, nil), layer(nil, []string{"/a"}, nil)}, "/a/f", 2, "whiteout"},
		{"opaque parent", []*Layer{layer([]string{"/a/f"}, nil, nil), layer([]string{"/a/g"}, nil, []string{"/a"})}, "/a/f", 1, "opaque"},
		{"opaque on file itself does not hide", []*Layer{layer([]string{"/a"}, nil, nil), layer(nil, nil, []string{"/a"})}, "/a", -1, ""},
		{"overwritten", []*Layer{layer([]string{"/a/f"}, nil, nil), layer([]string{"/a/f"}, nil, nil)}, "/a/f", 1, "overwritten"},
		{"parent replaced by file", []*Layer{layer([]string{"/a/f"}, nil, nil), layer([]string{"/a"}, nil, nil)}, "/a/f", 1, "overwritten"},
		{"whiteout of sibling", []*Layer{layer([]string{"/a/f"}, nil, nil), layer(nil, []string{"/a/g"}, nil)}, "/a/f", -1, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, how := HiddenBy(tt.path, 0, tt.layers)
			if idx != tt.wantIdx || how != tt.wantHow {
				t.Errorf("HiddenBy = (%d, %q), want (%d, %q)", idx, how, tt.wantIdx, tt.wantHow)
			}
		})
	}
}

func TestWalkWhiteoutContent(t *testing.T) {
	tests := []struct {
		name, entry string
		wantScanned bool
	}{
		{"empty whiteout", "tmp/.wh.a", false},
		{"whiteout with content", "tmp/.wh.a", true},
		{"opaque with content", "tmp/.wh..wh..opq", true},
		{"bare prefix with content", "tmp/.wh.", true},
		{"metadata with content", "tmp/.wh..wh.plnk", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := ""
			if tc.wantScanned {
				content = "payload"
			}
			var got []string
			l, err := Walk(tarball(t, entry{name: tc.entry, content: content}), Limits{}, func(f File) error {
				got = append(got, f.Path)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			p := CleanPath(tc.entry)
			if scanned := len(got) == 1 && got[0] == p; scanned != tc.wantScanned {
				t.Errorf("scanned = %v, want %v", got, tc.wantScanned)
			}
			if l.Entries[p] {
				t.Errorf("%s counts as a file of the final filesystem", p)
			}
			if j, how := HiddenBy(p, 0, []*Layer{l}); tc.wantScanned && (j != 0 || how != "whiteout") {
				t.Errorf("HiddenBy = %d, %q", j, how)
			}
		})
	}
}

func TestWalkTrailingData(t *testing.T) {
	archive := func(t *testing.T) []byte {
		b, err := io.ReadAll(tarball(t, entry{name: "a", content: "x"}))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	tests := []struct {
		name  string
		extra []byte
		want  int
	}{
		{"none", nil, 0},
		{"zero padding", make([]byte, 10240), 0},
		{"data", []byte("hidden"), 1},
		{"data after padding", append(make([]byte, 40000), 'x'), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := bytes.NewReader(append(archive(t), tc.extra...))
			l, err := Walk(r, Limits{}, func(File) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			if len(l.Skipped) != tc.want {
				t.Fatalf("skipped = %+v, want %d", l.Skipped, tc.want)
			}
			if tc.want == 1 && (l.Skipped[0].Signature != SigTrailingData || l.Skipped[0].SHA256 == "") {
				t.Errorf("skipped = %+v", l.Skipped[0])
			}
			if r.Len() != 0 {
				t.Errorf("%d bytes left unread", r.Len())
			}
		})
	}
}

func TestWalkTrailingDataLimit(t *testing.T) {
	b, err := io.ReadAll(tarball(t, entry{name: "a", content: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	r := io.MultiReader(bytes.NewReader(b), io.LimitReader(zeros{}, 1<<20))
	if _, err := Walk(r, Limits{MaxLayerSize: 1 << 16}, func(File) error { return nil }); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v", err)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// A GNU sparse file declares far more than the layer holds; the limit has to
// count what the entries expand to, across all entries.
func TestWalkSparseLimit(t *testing.T) {
	var buf bytes.Buffer
	for _, name := range []string{"a", "b", "c"} {
		buf.Write(sparseHeader(t, name, 1<<20))
	}
	buf.Write(make([]byte, 1024))
	var read int64
	_, err := Walk(bytes.NewReader(buf.Bytes()), Limits{MaxLayerSize: 3 << 19}, func(f File) error {
		n, err := io.Copy(io.Discard, f.Content)
		read += n
		return err
	})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("err = %v after %d bytes", err, read)
	}
	if read > 3<<19 {
		t.Errorf("read %d bytes, above the limit", read)
	}
}

// sparseHeader is an old GNU format header of a file that is one big hole.
func sparseHeader(t *testing.T, name string, size int64) []byte {
	t.Helper()
	b := make([]byte, 512)
	copy(b, name)
	copy(b[100:], "0000644\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], "00000000000\x00") // no data in the archive
	copy(b[136:], "00000000000\x00")
	b[156] = tar.TypeGNUSparse
	copy(b[257:], "ustar  \x00")
	// One sparse entry that ends at the real size: offset size, length 0.
	copy(b[386:], fmt.Sprintf("%011o\x00", size))
	copy(b[398:], "00000000000\x00")
	copy(b[483:], fmt.Sprintf("%011o\x00", size))
	copy(b[148:], "        ")
	var sum int
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

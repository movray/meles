package extract

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"testing"
)

type entry struct {
	name     string
	content  string
	typeflag byte
}

func tarball(t *testing.T, entries ...entry) *bytes.Reader {
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

//go:build integration

package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"git.itknecht.de/sugras/meles/internal/engine/clamd"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

// TestRealClamdStreamsLargeFile scans an archive above bufferLimit, which is
// streamed from the layer to clamd. clamd's StreamMaxLength, MaxFileSize and
// MaxScanSize must be at least 16M.
func TestRealClamdStreamsLargeFile(t *testing.T) {
	c := realClamd(t)

	// clamd detects EICAR by the hash of the whole file, so it goes into an
	// archive next to padding instead of being appended to it.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"padding.bin": strings.Repeat("meles", 2*bufferLimit/5),
		"eicar.com":   testimage.EICAR(),
	} {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() <= bufferLimit {
		t.Fatalf("archive has %d bytes, want more than bufferLimit", buf.Len())
	}

	reg, err := testimage.Serve(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "COPY big.zip /", Files: map[string]string{"/big.zip": buf.String()}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Push("big", img); err != nil {
		t.Fatal(err)
	}

	s := &Scanner{Engine: c, Limits: extract.Limits{MaxFileSize: 16 << 20}, Concurrency: 2, Source: source.Options{Insecure: true}}
	rep, err := s.Scan(context.Background(), reg.Ref("big"), source.PlatformFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Findings()
	if len(f) != 1 || f[0].Path != "/big.zip" || !strings.Contains(strings.ToUpper(f[0].Signature), "EICAR") || !rep.Complete {
		t.Errorf("findings = %+v, complete = %v", f, rep.Complete)
	}
}

// TestRealClamdYaraRules needs a clamd with the default YARA rules
// (MELES_TEST_YARA=1): a match carries the rule's author and license.
func TestRealClamdYaraRules(t *testing.T) {
	if os.Getenv("MELES_TEST_YARA") == "" {
		t.Skip("MELES_TEST_YARA not set")
	}
	c := realClamd(t)
	cases := testimage.YaraCases()
	reg, err := testimage.Serve(cases)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	s := &Scanner{Engine: c, Concurrency: 2, Source: source.Options{Insecure: true}}
	for _, tc := range cases {
		rep, err := s.Scan(context.Background(), reg.Ref(tc.Name), source.PlatformFilter{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		f := rep.Findings()
		if len(f) != len(tc.Want) {
			t.Fatalf("%s: findings = %+v, want %v", tc.Name, f, tc.Want)
		}
		for i, want := range tc.Want {
			if got := f[i].Path + " " + f[i].Status; got != want || f[i].Rule == nil || f[i].Rule.Author == "" || f[i].Rule.License == "" {
				t.Errorf("%s: finding %q (rule %+v), want %q with rule author and license", tc.Name, got, f[i].Rule, want)
			}
		}
		if !strings.Contains(rep.Engine.Signatures, "+rules.") && os.Getenv("MELES_CLAMD_TOKEN") != "" {
			t.Errorf("signature version %q without the rules hash of the clamd-proxy", rep.Engine.Signatures)
		}
	}
}

func realClamd(t *testing.T) *clamd.Client {
	t.Helper()
	addr := os.Getenv("MELES_TEST_CLAMD")
	if addr == "" {
		t.Skip("MELES_TEST_CLAMD not set")
	}
	c, err := clamd.New(addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Token = os.Getenv("MELES_CLAMD_TOKEN")
	if ca := os.Getenv("MELES_CLAMD_CA"); ca != "" {
		if c.TLSConfig, err = clamd.LoadCA(ca); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

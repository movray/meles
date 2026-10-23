package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"git.itknecht.de/sugras/meles/internal/engine/fake"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

func newScanner(e *fake.Engine, c *Cache) *Scanner {
	return &Scanner{
		Engine:      e,
		Limits:      extract.Limits{MaxFileSize: 1 << 20},
		Concurrency: 3,
		Cache:       c,
		Source:      source.Options{Insecure: true},
	}
}

func findings(r *Report) []string {
	var out []string
	for _, f := range r.Findings() {
		out = append(out, f.Path+" "+f.Status)
	}
	return out
}

func TestScanCases(t *testing.T) {
	cases := testimage.Cases()
	reg, err := testimage.Serve(cases)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	s := newScanner(&fake.Engine{}, NewCache(100))
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			rep, err := s.Scan(context.Background(), reg.Ref(c.Name), source.PlatformFilter{}, nil)
			if err != nil {
				t.Fatal(err)
			}
			got := findings(rep)
			if fmt.Sprint(got) != fmt.Sprint(c.Want) {
				t.Errorf("findings = %v, want %v", got, c.Want)
			}
			if rep.Infected() != (len(c.Want) > 0) {
				t.Errorf("Infected = %v", rep.Infected())
			}
		})
	}
}

func TestScanWhiteoutDetails(t *testing.T) {
	reg, err := testimage.Serve(testimage.Cases())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	rep, err := newScanner(&fake.Engine{}, nil).Scan(context.Background(), reg.Ref("eicar-whiteout"), source.PlatformFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := rep.Findings()[0]
	if f.Layer != 2 || f.HiddenByLayer != 4 || f.HiddenHow != "whiteout" || f.CreatedBy != "COPY eicar.com /tmp/payload/" {
		t.Errorf("finding = %+v", f)
	}
}

func TestScanMultiArch(t *testing.T) {
	reg, err := testimage.Serve(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// The arm64 variant is infected, amd64 is clean: scanning only the host
	// platform of a typical CI runner would miss it.
	amd, err := testimage.BuildPlatform([]testimage.Layer{{CreatedBy: "COPY a /", Files: map[string]string{"/a": "clean"}}}, v1.Platform{OS: "linux", Architecture: "amd64"})
	if err != nil {
		t.Fatal(err)
	}
	arm, err := testimage.BuildPlatform([]testimage.Layer{{CreatedBy: "COPY a /", Files: map[string]string{"/a": testimage.EICAR()}}}, v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"})
	if err != nil {
		t.Fatal(err)
	}
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: arm, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}}},
		mutate.IndexAddendum{Add: amd, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "unknown", Architecture: "unknown"}}},
	)
	if err := reg.Push("multi", idx); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		platforms     string
		wantPlatforms int
		wantInfected  bool
		wantErr       error
	}{
		{"all", 2, true, nil},
		{"linux/amd64", 1, false, nil},
		{"linux/arm64", 1, true, nil},
		{"linux/amd64,linux/arm64", 2, true, nil},
		{"linux/s390x", 0, false, source.ErrNoPlatform},
	}
	s := newScanner(&fake.Engine{}, nil)
	for _, tt := range tests {
		t.Run(tt.platforms, func(t *testing.T) {
			pf, err := source.ParsePlatforms(tt.platforms)
			if err != nil {
				t.Fatal(err)
			}
			rep, err := s.Scan(context.Background(), reg.Ref("multi"), pf, nil)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Platforms) != tt.wantPlatforms || rep.Infected() != tt.wantInfected {
				t.Errorf("platforms = %d, infected = %v", len(rep.Platforms), rep.Infected())
			}
		})
	}
}

func TestScanCache(t *testing.T) {
	reg, err := testimage.Serve(testimage.Cases())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	e := &fake.Engine{}
	s := newScanner(e, NewCache(100))
	ctx := context.Background()
	ref := reg.Ref("eicar-whiteout")

	if _, err := s.Scan(ctx, ref, source.PlatformFilter{}, nil); err != nil {
		t.Fatal(err)
	}
	first := e.Scans.Load()
	rep, err := s.Scan(ctx, ref, source.PlatformFilter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if e.Scans.Load() != first {
		t.Errorf("second scan used the engine %d times, want cache", e.Scans.Load()-first)
	}
	if len(rep.Findings()) != 1 || !rep.Platforms[0].Layers[1].Cached {
		t.Errorf("cached report wrong: %v", findings(rep))
	}

	// A signature update invalidates the cache.
	e.Signatures = "2"
	if _, err := s.Scan(ctx, ref, source.PlatformFilter{}, nil); err != nil {
		t.Fatal(err)
	}
	if e.Scans.Load() == first {
		t.Error("signature update did not cause a rescan")
	}
}

func TestScanEngineError(t *testing.T) {
	reg, err := testimage.Serve(testimage.Cases())
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	e := &fake.Engine{Err: errors.New("engine down")}
	if _, err := newScanner(e, nil).Scan(context.Background(), reg.Ref("clean"), source.PlatformFilter{}, nil); err == nil {
		t.Fatal("want error; an engine failure must never look clean")
	}
}

// Files above bufferLimit are streamed from the layer to the engine instead
// of being read into memory first.
func TestScanStreamsLargeFiles(t *testing.T) {
	reg, err := testimage.Serve(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	big := strings.Repeat("a", bufferLimit+1)
	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "COPY . /", Files: map[string]string{
		"/a-small":     "clean",
		"/b-big-clean": big,
		"/c-big-evil":  big + testimage.EICAR(),
		"/d-small":     testimage.EICAR(),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Push("big", img); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		engine  *fake.Engine
		want    []string
		wantErr bool
	}{
		{"findings", &fake.Engine{}, []string{"/c-big-evil present", "/d-small present"}, false},
		{"engine error", &fake.Engine{Err: errors.New("engine down")}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScanner(tt.engine, nil)
			s.Limits.MaxFileSize = 4 * bufferLimit
			rep, err := s.Scan(context.Background(), reg.Ref("big"), source.PlatformFilter{}, nil)
			if tt.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := findings(rep); fmt.Sprint(got) != fmt.Sprint(tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
			if !rep.Complete || rep.Platforms[0].Files != 4 {
				t.Errorf("complete = %v, files = %d", rep.Complete, rep.Platforms[0].Files)
			}
		})
	}
}

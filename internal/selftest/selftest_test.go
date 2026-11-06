package selftest

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/movray/meles/internal/engine"
	"github.com/movray/meles/internal/engine/fake"
	"github.com/movray/meles/internal/extract"
	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/source"
)

func scanner(eng engine.Engine) *scan.Scanner {
	return &scan.Scanner{Engine: eng, Limits: extract.Limits{MaxFileSize: 1 << 20}, Concurrency: 2}
}

// blind answers like an engine that lost its signatures.
type blind struct{ engine.Engine }

func (b blind) Open(ctx context.Context) (engine.Session, error) {
	s, err := b.Engine.Open(ctx)
	return blindSession{s}, err
}

type blindSession struct{ engine.Session }

func (s blindSession) Scan(ctx context.Context, r io.Reader) (string, error) {
	_, err := s.Session.Scan(ctx, r)
	return "", err
}

func TestRun(t *testing.T) {
	tests := []struct {
		name   string
		eng    engine.Engine
		yara   bool
		checks int
		failed int
		err    bool
	}{
		{name: "engine finds everything", eng: &fake.Engine{}, checks: 5},
		{name: "engine without signatures", eng: blind{&fake.Engine{}}, checks: 5, failed: 4},
		// The fake engine has no YARA rules, like a clamd without them.
		{name: "rules not loaded", eng: &fake.Engine{}, yara: true, checks: 9, failed: 4},
		{name: "engine fails", eng: &fake.Engine{Err: errors.New("connection lost")}, err: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := Run(t.Context(), scanner(tt.eng), tt.yara)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want error: %v", err, tt.err)
			}
			if len(res.Checks) != tt.checks || len(res.Failed()) != tt.failed {
				t.Errorf("%d checks, %d failed, want %d, %d: %v", len(res.Checks), len(res.Failed()), tt.checks, tt.failed, res.Checks)
			}
		})
	}
}

// A cached layer would pass without asking the engine, so a second run must
// reach the engine again even if the scanner has a cache.
func TestRunIgnoresCache(t *testing.T) {
	eng := &fake.Engine{}
	s := scanner(eng)
	s.Cache = scan.NewCache(100)
	if _, err := Run(t.Context(), s, false); err != nil {
		t.Fatal(err)
	}
	first := eng.Scans.Load()
	if first == 0 {
		t.Fatal("the engine was not asked")
	}
	if _, err := Run(t.Context(), s, false); err != nil {
		t.Fatal(err)
	}
	if got := eng.Scans.Load(); got != 2*first {
		t.Errorf("scans after two runs = %d, want %d", got, 2*first)
	}
}

// The server refuses loopback addresses for registries; the test images
// live there.
func TestRunWithRestrictedNetwork(t *testing.T) {
	s := scanner(&fake.Engine{})
	s.Source.Network = source.Network{Restrict: true}
	res, err := Run(t.Context(), s, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Failed()) != 0 {
		t.Errorf("failed: %v", res.Failed())
	}
	if !s.Source.Network.Restrict {
		t.Error("Run changed the scanner of the caller")
	}
}

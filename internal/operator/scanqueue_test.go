package operator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/source"
)

// flakyScanner returns errs in turn and then a report.
type flakyScanner struct {
	errs  []error
	calls int
	hook  func(ctx context.Context)
}

func (s *flakyScanner) Scan(ctx context.Context, _ string, _ source.PlatformFilter, _ func(scan.Progress), _ ...scan.Option) (*scan.Report, error) {
	s.calls++
	if s.hook != nil {
		s.hook(ctx)
	}
	if len(s.errs) == 0 {
		return &scan.Report{}, nil
	}
	err := s.errs[0]
	s.errs = s.errs[1:]
	return nil, err
}

func TestScanRetrying(t *testing.T) {
	engineErr := &scan.EngineError{Err: errors.New("connection refused")}
	imageErr := errors.New("manifest unknown")
	waits := []time.Duration{time.Millisecond, time.Millisecond}
	tests := []struct {
		name         string
		errs         []error
		down         bool
		wantCalls    int
		wantErr      error
		wantDownNext bool
	}{
		{name: "clean run", wantCalls: 1},
		{name: "engine back on the second try", errs: []error{engineErr}, wantCalls: 2},
		{name: "engine back on the last try", errs: []error{engineErr, engineErr}, wantCalls: 3},
		{name: "retries used up", errs: []error{engineErr, engineErr, engineErr, engineErr}, wantCalls: 3, wantErr: engineErr, wantDownNext: true},
		{name: "image errors are not retried", errs: []error{imageErr}, wantCalls: 1, wantErr: imageErr},
		{name: "engine known down: no retries", errs: []error{engineErr, engineErr}, down: true, wantCalls: 1, wantErr: engineErr, wantDownNext: true},
		{name: "engine answers again", down: true, wantCalls: 1},
		{name: "image error shows the engine is back", errs: []error{imageErr}, down: true, wantCalls: 1, wantErr: imageErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &flakyScanner{errs: tt.errs}
			r := &Reconciler{Scanner: s, ScanTimeout: time.Minute, engineWaits: waits}
			r.engineDown.Store(tt.down)
			_, err := r.scanRetrying(t.Context(), image{ref: "example.com/app"}, source.PlatformFilter{}, authn.DefaultKeychain)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
			if s.calls != tt.wantCalls {
				t.Errorf("calls = %d, want %d", s.calls, tt.wantCalls)
			}
			if got := r.engineDown.Load(); got != tt.wantDownNext {
				t.Errorf("engineDown = %v, want %v", got, tt.wantDownNext)
			}
		})
	}
}

// A scan that ran out of time is not tried again: it would only take as long
// once more, and says nothing about the engine.
func TestScanRetryingTimeout(t *testing.T) {
	s := &flakyScanner{
		errs: []error{&scan.EngineError{Err: errors.New("read reply: timeout")}},
		hook: func(ctx context.Context) { <-ctx.Done() },
	}
	r := &Reconciler{Scanner: s, ScanTimeout: time.Millisecond, engineWaits: []time.Duration{time.Millisecond}}
	if _, err := r.scanRetrying(t.Context(), image{ref: "example.com/app"}, source.PlatformFilter{}, authn.DefaultKeychain); err == nil {
		t.Fatal("want error")
	}
	if s.calls != 1 {
		t.Errorf("calls = %d, want 1", s.calls)
	}
	if r.engineDown.Load() {
		t.Error("a timeout marked the engine as down")
	}
}

// Shutting down ends the wait for the next try.
func TestScanRetryingCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	s := &flakyScanner{errs: []error{&scan.EngineError{Err: errors.New("EOF")}}, hook: func(context.Context) { cancel() }}
	r := &Reconciler{Scanner: s, ScanTimeout: time.Minute, engineWaits: []time.Duration{time.Hour}}
	done := make(chan error, 1)
	go func() {
		_, err := r.scanRetrying(ctx, image{ref: "example.com/app"}, source.PlatformFilter{}, authn.DefaultKeychain)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("want error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("still waiting after the context was canceled")
	}
}

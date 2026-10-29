// Package fake provides an in-process scan engine for tests. It reports the
// EICAR test string and nothing else.
package fake

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/movray/meles/internal/engine"
	"github.com/movray/meles/internal/testimage"
)

// Engine detects EICAR. Scans counts the streams scanned.
type Engine struct {
	Signatures string
	Scans      atomic.Int64
	// Err, if set, is returned by every scan.
	Err error
	// MaxSize, if set, rejects larger streams like clamd's StreamMaxLength.
	MaxSize int
	// Hold, if set, makes scans of streams containing it wait until Release
	// is closed, like a long scan.
	Hold    []byte
	Release chan struct{}

	// mu guards Signatures and MaxSize once the engine is in use.
	mu sync.Mutex
}

// SetSignatures changes the signature version, as after a database update.
func (e *Engine) SetSignatures(sig string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Signatures = sig
}

// SetMaxSize changes MaxSize, as after a change of clamd's limits.
func (e *Engine) SetMaxSize(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.MaxSize = n
}

var _ engine.Engine = (*Engine)(nil)

func (e *Engine) Open(context.Context) (engine.Session, error) { return session{e}, nil }

func (e *Engine) Version(context.Context) (engine.Version, error) {
	e.mu.Lock()
	sig := e.Signatures
	e.mu.Unlock()
	if sig == "" {
		sig = "1"
	}
	return engine.Version{Engine: "fake", Signatures: sig, Raw: "fake/" + sig}, nil
}

type session struct{ e *Engine }

func (s session) Scan(ctx context.Context, r io.Reader) (string, error) {
	s.e.Scans.Add(1)
	if s.e.Err != nil {
		return "", s.e.Err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	if len(s.e.Hold) > 0 && bytes.Contains(b, s.e.Hold) {
		select {
		case <-s.e.Release:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	s.e.mu.Lock()
	maxSize := s.e.MaxSize
	s.e.mu.Unlock()
	if maxSize > 0 && len(b) > maxSize {
		return "", fmt.Errorf("fake: size limit exceeded: %w", engine.ErrTooLarge)
	}
	if bytes.Contains(b, []byte(testimage.EICAR())) {
		return "Eicar-Test-Signature", nil
	}
	return "", nil
}

func (session) Close() error { return nil }

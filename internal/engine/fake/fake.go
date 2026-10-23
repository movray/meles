// Package fake provides an in-process scan engine for tests. It reports the
// EICAR test string and nothing else.
package fake

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync/atomic"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

// Engine detects EICAR. Scans counts the streams scanned.
type Engine struct {
	Signatures string
	Scans      atomic.Int64
	// Err, if set, is returned by every scan.
	Err error
	// MaxSize, if set, rejects larger streams like clamd's StreamMaxLength.
	MaxSize int
}

var _ engine.Engine = (*Engine)(nil)

func (e *Engine) Open(context.Context) (engine.Session, error) { return session{e}, nil }

func (e *Engine) Version(context.Context) (engine.Version, error) {
	sig := e.Signatures
	if sig == "" {
		sig = "1"
	}
	return engine.Version{Engine: "fake", Signatures: sig, Raw: "fake/" + sig}, nil
}

type session struct{ e *Engine }

func (s session) Scan(_ context.Context, r io.Reader) (string, error) {
	s.e.Scans.Add(1)
	if s.e.Err != nil {
		return "", s.e.Err
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	if s.e.MaxSize > 0 && len(b) > s.e.MaxSize {
		return "", fmt.Errorf("fake: size limit exceeded: %w", engine.ErrTooLarge)
	}
	if bytes.Contains(b, []byte(testimage.EICAR())) {
		return "Eicar-Test-Signature", nil
	}
	return "", nil
}

func (session) Close() error { return nil }

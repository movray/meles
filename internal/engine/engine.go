// Package engine defines the interface between meles and malware scan
// engines such as clamd.
package engine

import (
	"context"
	"errors"
	"io"
)

// ErrTooLarge is returned (wrapped) by Session.Scan when the engine refused a
// stream because of its size, e.g. above clamd's StreamMaxLength. The file
// counts as skipped, not as an error; the session must not be reused.
var ErrTooLarge = errors.New("stream too large for the engine")

// Engine opens scan sessions.
type Engine interface {
	// Open starts a session. Each concurrent worker uses its own session.
	Open(ctx context.Context) (Session, error)
	// Version reports the engine and signature database version. It is part
	// of the cache key, so results are rescanned after a signature update.
	Version(ctx context.Context) (Version, error)
}

// Session scans one stream at a time. It is not safe for concurrent use.
type Session interface {
	// Scan returns the name of the matching signature, or "" if the stream
	// is clean.
	Scan(ctx context.Context, r io.Reader) (string, error)
	Close() error
}

// Version identifies an engine and its signature database.
type Version struct {
	Engine     string `json:"engine"`
	Signatures string `json:"signatures"`
	// Raw is the version string as reported by the engine.
	Raw string `json:"raw"`
}

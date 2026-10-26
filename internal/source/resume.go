package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// maxResumeFailures bounds the attempts to resume a download in a row
// without receiving any new bytes.
const maxResumeFailures = 3

// resumingTransport continues a response body that breaks off midway with
// an HTTP Range request from the byte where it stopped. meles stops reading
// a layer while clamd scans a large file of it, sometimes for minutes, and
// proxies reset such a connection: ingress-nginx in front of Harbor after
// 60 s (send_timeout). go-containerregistry sees one continuous body and
// still verifies the digest at its end.
//
// It sits below go-containerregistry's auth transport: a resumed request is
// a clone of the original one, with its Authorization header. After a
// redirect (e.g. to a CDN) the redirected request is resumed.
type resumingTransport struct {
	inner http.RoundTripper
	log   *slog.Logger
	// backoff is the pause before the n-th attempt in a row (n >= 1).
	backoff func(n int) time.Duration
}

func newResumingTransport(inner http.RoundTripper, log *slog.Logger) *resumingTransport {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &resumingTransport{inner: inner, log: log, backoff: func(n int) time.Duration { return time.Duration(n) * time.Second }}
}

func (t *resumingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := t.inner.RoundTrip(req)
	if err != nil || req.Method != http.MethodGet || req.Header.Get("Range") != "" ||
		res.StatusCode != http.StatusOK || res.ContentLength <= 0 {
		return res, err
	}
	res.Body = &resumingBody{t: t, req: req, body: res.Body, size: res.ContentLength}
	return res, nil
}

type resumingBody struct {
	t    *resumingTransport
	req  *http.Request
	body io.ReadCloser
	size int64
	off  int64
	// broken is the error that ended the current body; the next Read
	// resumes.
	broken   error
	failures int
}

func (b *resumingBody) Read(p []byte) (int, error) {
	for {
		if b.broken != nil {
			if err := b.resume(); err != nil {
				return 0, err
			}
		}
		n, err := b.body.Read(p)
		b.off += int64(n)
		if n > 0 {
			b.failures = 0
		}
		switch {
		case err == nil:
			return n, nil
		case errors.Is(err, io.EOF) && b.off >= b.size:
			return n, io.EOF
		case errors.Is(err, io.EOF):
			err = io.ErrUnexpectedEOF
		}
		b.broken = err
		if n > 0 {
			return n, nil
		}
	}
}

// resume requests the rest of the body. It gives up on a cancelled request
// and after maxResumeFailures attempts without new bytes, returning the
// error that broke the body.
func (b *resumingBody) resume() error {
	ctx := b.req.Context()
	b.body.Close()
	// Not the query: signed CDN URLs carry credentials there.
	where := b.req.URL.Host + b.req.URL.Path
	if b.failures == 0 {
		b.t.log.Info("download broke off, resuming", "url", where, "offset", b.off, "size", b.size, "err", b.broken)
	}
	cause := b.broken
	for {
		if ctx.Err() != nil || b.failures >= maxResumeFailures {
			return cause
		}
		b.failures++
		if b.failures > 1 {
			select {
			case <-time.After(b.t.backoff(b.failures - 1)):
			case <-ctx.Done():
				return cause
			}
		}
		body, err := b.reopen(ctx)
		if err == nil {
			b.body, b.broken = body, nil
			return nil
		}
		b.t.log.Warn("resuming download failed", "url", where, "offset", b.off, "attempt", b.failures, "err", err)
		cause = fmt.Errorf("%w (resuming at byte %d: %v)", b.broken, b.off, err)
	}
}

// reopen requests the body from b.off. A server that ignores the Range
// header sends it whole; the bytes already read are skipped.
func (b *resumingBody) reopen(ctx context.Context) (io.ReadCloser, error) {
	req := b.req.Clone(ctx)
	// With an explicit end: some registries reject "bytes=N-".
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", b.off, b.size-1))
	res, err := b.t.inner.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusPartialContent:
		if want := fmt.Sprintf("bytes %d-%d/", b.off, b.size-1); !strings.HasPrefix(res.Header.Get("Content-Range"), want) {
			res.Body.Close()
			return nil, fmt.Errorf("unexpected Content-Range %q", res.Header.Get("Content-Range"))
		}
		return res.Body, nil
	case http.StatusOK:
		if res.ContentLength != b.size {
			res.Body.Close()
			return nil, fmt.Errorf("size changed from %d to %d", b.size, res.ContentLength)
		}
		if _, err := io.CopyN(io.Discard, res.Body, b.off); err != nil {
			res.Body.Close()
			return nil, fmt.Errorf("skip %d bytes: %w", b.off, err)
		}
		return res.Body, nil
	}
	res.Body.Close()
	return nil, fmt.Errorf("HTTP %s", res.Status)
}

func (b *resumingBody) Close() error { return b.body.Close() }

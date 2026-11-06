package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/movray/meles/internal/testimage"
)

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(b)
	return b
}

// abortAfter lets the first breaks responses end after cut bytes, like a
// proxy resetting the connection; with zeroAfterFirst every later response
// ends before its first byte.
type abortAfter struct {
	cut            int64
	breaks         int32
	zeroAfterFirst bool
	served         atomic.Int32
}

// limit returns how many body bytes the next response may write, -1 for all.
func (a *abortAfter) limit() int64 {
	n := a.served.Add(1)
	switch {
	case n <= a.breaks && n == 1:
		return a.cut
	case n <= a.breaks && a.zeroAfterFirst:
		return 0
	case n <= a.breaks:
		return a.cut
	}
	return -1
}

// limitedWriter aborts the handler once more than limit bytes are written.
type limitedWriter struct {
	http.ResponseWriter
	limit, written int64
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.limit >= 0 && w.written+int64(len(p)) > w.limit {
		n, _ := w.ResponseWriter.Write(p[:w.limit-w.written])
		w.written += int64(n)
		if f, ok := w.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	}
	n, err := w.ResponseWriter.Write(p)
	w.written += int64(n)
	return n, err
}

func TestResumingTransport(t *testing.T) {
	content := randomBytes(3 << 20)
	tests := []struct {
		name    string
		http2   bool
		ranges  bool
		abort   *abortAfter
		wantErr bool
	}{
		{"complete", false, true, &abortAfter{}, false},
		{"HTTP/1.1, breaks once", false, true, &abortAfter{cut: 1 << 20, breaks: 1}, false},
		{"HTTP/2, breaks three times", true, true, &abortAfter{cut: 700 << 10, breaks: 3}, false},
		{"server ignores Range", true, false, &abortAfter{cut: 1 << 20, breaks: 2}, false},
		{"no progress after the break", false, true, &abortAfter{cut: 1 << 20, breaks: 100, zeroAfterFirst: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			abort := tt.abort
			var requests atomic.Int32
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body := content
				status := http.StatusOK
				if rg := r.Header.Get("Range"); tt.ranges && rg != "" {
					from, to, _ := strings.Cut(strings.TrimPrefix(rg, "bytes="), "-")
					off, err := strconv.ParseInt(from, 10, 64)
					if err != nil || to != strconv.Itoa(len(content)-1) {
						http.Error(w, "bad range", http.StatusBadRequest)
						return
					}
					body, status = content[off:], http.StatusPartialContent
					w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, len(content)-1, len(content)))
				}
				limit := abort.limit()
				if limit == 0 {
					panic(http.ErrAbortHandler)
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
				w.WriteHeader(status)
				lw := &limitedWriter{ResponseWriter: w, limit: limit}
				io.Copy(lw, bytes.NewReader(body))
			})
			srv := httptest.NewUnstartedServer(h)
			srv.EnableHTTP2 = tt.http2
			srv.Config.ErrorLog = nil
			srv.StartTLS()
			defer srv.Close()

			rt := newResumingTransport(srv.Client().Transport, nil)
			rt.backoff = func(int) time.Duration { return 0 }
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/blob", nil)
			res, err := rt.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			if tt.http2 && res.ProtoMajor != 2 {
				t.Fatalf("protocol %s, want HTTP/2", res.Proto)
			}
			got, err := io.ReadAll(res.Body)
			res.Body.Close()
			if tt.wantErr {
				if err == nil {
					t.Fatal("read succeeded, want an error")
				}
				if n := requests.Load(); n != 1+maxResumeFailures {
					t.Errorf("%d requests, want %d", n, 1+maxResumeFailures)
				}
				return
			}
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if sha256.Sum256(got) != sha256.Sum256(content) {
				t.Fatalf("got %d bytes that differ from the %d sent", len(got), len(content))
			}
			if want := 1 + int32(tt.abort.breaks); requests.Load() != want {
				t.Errorf("%d requests, want %d", requests.Load(), want)
			}
		})
	}
}

// A layer whose blob download breaks off is read completely, and
// go-containerregistry's digest checks still pass.
func TestFetchResumesLayer(t *testing.T) {
	reg := registry.New()
	var blobGets atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") && blobGets.Add(1) == 2 {
			// The first blob is the config, the second the layer.
			reg.ServeHTTP(&limitedWriter{ResponseWriter: w, limit: 300 << 10}, r)
			return
		}
		reg.ServeHTTP(w, r)
	}))
	defer srv.Close()

	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "COPY big /", Files: map[string]string{"/big": string(randomBytes(2 << 20))}}})
	if err != nil {
		t.Fatal(err)
	}
	ref := strings.TrimPrefix(srv.URL, "http://") + "/resume/test:latest"
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	blobGets.Store(0)

	fetched, err := Fetch(context.Background(), ref, Options{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	layers, err := fetched.Platforms[0].Image.Layers()
	if err != nil {
		t.Fatal(err)
	}
	rc, err := layers[0].Compressed()
	if err != nil {
		t.Fatal(err)
	}
	// go-containerregistry checks the blob digest at EOF.
	n, err := io.Copy(io.Discard, rc)
	if err != nil {
		t.Fatalf("read layer: %v", err)
	}
	if want, _ := layers[0].Size(); n != want {
		t.Errorf("read %d bytes, want %d", n, want)
	}
	if blobGets.Load() < 3 {
		t.Errorf("%d blob requests: the download did not break off", blobGets.Load())
	}
}

// TestFetchRenewsAccess reads a layer whose download breaks off after the
// access to it expired: a signed CDN URL, or the token of a registry that
// serves the blob itself.
func TestFetchRenewsAccess(t *testing.T) {
	img, err := testimage.Build([]testimage.Layer{{CreatedBy: "COPY big /", Files: map[string]string{"/big": string(randomBytes(2 << 20))}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		redirect bool
	}{
		{"signed CDN URL", true},
		{"registry token", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reg := registry.New()
			// generation invalidates tokens and signed URLs issued before.
			var generation, blobGets, broken atomic.Int32
			var issued atomic.Int32
			valid := func(v string) bool { return v == strconv.Itoa(int(generation.Load())) }
			// serve breaks off the first read of the layer and expires the
			// access with it.
			serve := func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Range") == "" && blobGets.Add(1) == 2 && broken.CompareAndSwap(0, 1) {
					defer generation.Add(1)
					reg.ServeHTTP(&limitedWriter{ResponseWriter: w, limit: 300 << 10}, r)
					return
				}
				reg.ServeHTTP(w, r)
			}
			cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !valid(r.URL.Query().Get("sig")) {
					http.Error(w, "expired", http.StatusForbidden)
					return
				}
				r2 := r.Clone(r.Context())
				r2.URL.RawQuery = ""
				serve(w, r2)
			}))
			defer cdn.Close()
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/token" {
					issued.Add(1)
					fmt.Fprintf(w, `{"token":%q}`, strconv.Itoa(int(generation.Load())))
					return
				}
				if !valid(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="test"`, srv.URL+"/token"))
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/") {
					if tt.redirect {
						http.Redirect(w, r, cdn.URL+r.URL.Path+"?sig="+strconv.Itoa(int(generation.Load())), http.StatusTemporaryRedirect)
						return
					}
					serve(w, r)
					return
				}
				reg.ServeHTTP(w, r)
			}))
			defer srv.Close()

			ref := strings.TrimPrefix(srv.URL, "http://") + "/renew/test:latest"
			r, err := name.ParseReference(ref, name.Insecure)
			if err != nil {
				t.Fatal(err)
			}
			if err := remote.Write(r, img); err != nil {
				t.Fatal(err)
			}
			blobGets.Store(0)
			issued.Store(0)

			fetched, err := Fetch(context.Background(), ref, Options{Insecure: true})
			if err != nil {
				t.Fatal(err)
			}
			layers, err := fetched.Platforms[0].Image.Layers()
			if err != nil {
				t.Fatal(err)
			}
			rc, err := layers[0].Compressed()
			if err != nil {
				t.Fatal(err)
			}
			defer rc.Close()
			n, err := io.Copy(io.Discard, rc)
			if err != nil {
				t.Fatalf("read layer: %v", err)
			}
			if want, _ := layers[0].Size(); n != want {
				t.Errorf("read %d bytes, want %d", n, want)
			}
			if generation.Load() == 0 {
				t.Error("the download did not break off")
			}
			if issued.Load() < 2 {
				t.Errorf("%d tokens issued, want a new one after the break", issued.Load())
			}
		})
	}
}

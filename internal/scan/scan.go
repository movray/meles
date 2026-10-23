// Package scan scans container images layer by layer: it pulls an image,
// streams every file of every layer to a scan engine and works out which
// findings are visible in the final filesystem and which were deleted by a
// later layer but are still shipped with the image.
package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/errgroup"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/source"
)

// Scanner scans images. It is safe for concurrent use if its Engine is.
type Scanner struct {
	Engine engine.Engine
	Limits extract.Limits
	// Concurrency is the number of parallel engine sessions per scan.
	Concurrency int
	// Cache is optional. It is shared between scans.
	Cache  *Cache
	Source source.Options
	Logger *slog.Logger
}

// Progress is reported while a scan runs.
type Progress struct {
	Platform    string
	Layer       int // 1-based
	Layers      int
	FilesQueued int
}

// layerResult is the engine result for one layer, independent of the image
// it belongs to.
type layerResult struct {
	meta *extract.Layer
	mu   sync.Mutex
	hits []hit
	// limited holds files the engine could not scan completely.
	limited []extract.Skipped
}

// limitSignaturePrefix marks clamd results for files that exceeded one of
// its scan limits (with AlertExceedsMax). They are not malware findings, but
// the files were not fully scanned.
const limitSignaturePrefix = "Heuristics.Limits.Exceeded"

type hit struct {
	path, signature string
}

// bufferLimit is the largest file that is read into memory and queued, so
// that small files are scanned in parallel while the layer is read on.
// Larger files are streamed from the layer straight to one engine session;
// reading the layer waits meanwhile. Memory per scan therefore stays at
// about (Concurrency+1) x bufferLimit, whatever the maximum file size.
const bufferLimit = 4 << 20

type scanJob struct {
	res  *layerResult
	path string
	size int64
	data []byte
	// stream is set instead of data for files above bufferLimit. The worker
	// reports on done once it stopped reading from it.
	stream io.Reader
	done   chan error
}

// Scan scans the platforms of ref selected by platforms. Progress is
// optional. An error means the image was not fully scanned; it must never be
// treated as clean.
func (s *Scanner) Scan(ctx context.Context, ref string, platforms source.PlatformFilter, progress func(Progress)) (*Report, error) {
	log := s.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	started := time.Now()

	version, err := s.Engine.Version(ctx)
	if err != nil {
		return nil, fmt.Errorf("engine version: %w", err)
	}
	opts := s.Source
	opts.Platforms = platforms
	img, err := source.Fetch(ctx, ref, opts)
	if err != nil {
		return nil, err
	}

	rep := &Report{
		Ref:       ref,
		Digest:    img.Digest,
		Engine:    version,
		Platform:  platforms.String(),
		StartedAt: started,
	}

	workers := max(s.Concurrency, 1)
	jobs := make(chan scanJob, workers)
	g, gctx := errgroup.WithContext(ctx)

	type platformLayers struct {
		results []*layerResult
		layers  []LayerReport
	}
	plats := make([]platformLayers, len(img.Platforms))
	fresh := map[string]*layerResult{} // layers scanned by this run, by cache key

	g.Go(func() error {
		defer close(jobs)
		for pi, p := range img.Platforms {
			layers, err := p.Image.Layers()
			if err != nil {
				return fmt.Errorf("%s: list layers: %w", p.Platform, err)
			}
			createdBy, err := history(p)
			if err != nil {
				return err
			}
			plats[pi].results = make([]*layerResult, len(layers))
			plats[pi].layers = make([]LayerReport, len(layers))
			for li, l := range layers {
				diffID, err := l.DiffID()
				if err != nil {
					return fmt.Errorf("%s: layer %d diffID: %w", p.Platform, li+1, err)
				}
				digest, err := l.Digest()
				if err != nil {
					return fmt.Errorf("%s: layer %d digest: %w", p.Platform, li+1, err)
				}
				lr := LayerReport{Index: li + 1, DiffID: diffID.String(), Digest: digest.String()}
				if li < len(createdBy) {
					lr.CreatedBy = createdBy[li]
				}
				// The key includes the blob digest: the diffID comes from the
				// image config and is only trusted once the layer was read
				// and verified against it.
				key := cacheKey(digest.String(), diffID.String(), version, s.Limits)
				res, cached := s.Cache.get(key)
				if !cached {
					res, cached = fresh[key]
				}
				if !cached {
					if progress != nil {
						progress(Progress{Platform: p.Platform, Layer: li + 1, Layers: len(layers)})
					}
					res = &layerResult{}
					if err := s.walkLayer(gctx, l, diffID, res, jobs); err != nil {
						return fmt.Errorf("%s: layer %d (%s): %w", p.Platform, li+1, diffID, err)
					}
					fresh[key] = res
					log.Debug("layer read", "platform", p.Platform, "layer", li+1, "files", res.meta.Files)
				}
				lr.Cached = cached
				lr.Files = res.meta.Files
				lr.Bytes = res.meta.Bytes
				plats[pi].results[li] = res
				plats[pi].layers[li] = lr
			}
		}
		return nil
	})

	for range workers {
		g.Go(func() error {
			var sess engine.Session
			defer func() {
				if sess != nil {
					sess.Close()
				}
			}()
			for j := range jobs {
				err := s.scanFile(gctx, &sess, j)
				if j.done != nil {
					j.done <- err
				}
				if err != nil {
					return err
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	for key, res := range fresh {
		// Files the engine could not scan may be scanned after a change of
		// its limits, which is not part of the key.
		if len(res.limited) == 0 {
			s.Cache.put(key, res)
		}
	}

	for pi, p := range img.Platforms {
		rep.Platforms = append(rep.Platforms, buildPlatformReport(p, plats[pi].layers, plats[pi].results))
	}
	rep.Complete = len(rep.Skipped()) == 0
	rep.FinishedAt = time.Now()
	return rep, nil
}

// scanFile scans one queued file on *sess, opening the session first if
// needed, and records the result in the file's layer.
func (s *Scanner) scanFile(ctx context.Context, sess *engine.Session, j scanJob) error {
	if *sess == nil {
		var err error
		if *sess, err = s.Engine.Open(ctx); err != nil {
			return err
		}
	}
	r := j.stream
	if r == nil {
		r = bytes.NewReader(j.data)
	}
	sig, err := (*sess).Scan(ctx, r)
	if errors.Is(err, engine.ErrTooLarge) {
		// Not scanned, like a file above MaxFileSize. The engine dropped
		// the session; the next file gets a new one.
		(*sess).Close()
		*sess = nil
		j.res.mu.Lock()
		j.res.limited = append(j.res.limited, extract.Skipped{Path: j.path, Size: j.size, Reason: "refused by the engine as too large (clamd: StreamMaxLength below --max-file-size)"})
		j.res.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("scan %s: %w", j.path, err)
	}
	switch {
	case strings.HasPrefix(sig, limitSignaturePrefix):
		j.res.mu.Lock()
		j.res.limited = append(j.res.limited, extract.Skipped{Path: j.path, Size: j.size, Reason: "engine limit exceeded (" + sig + ")"})
		j.res.mu.Unlock()
	case sig != "":
		j.res.mu.Lock()
		j.res.hits = append(j.res.hits, hit{j.path, sig})
		j.res.mu.Unlock()
	}
	return nil
}

// walkLayer reads layer l and queues its files. It returns once all files
// are queued, not when they are scanned (except streamed large files). It reads the layer to the end, so
// that the blob digest is verified, and checks the uncompressed content
// against diffID from the image config.
func (s *Scanner) walkLayer(ctx context.Context, l v1.Layer, diffID v1.Hash, res *layerResult, jobs chan<- scanJob) error {
	if diffID.Algorithm != "sha256" {
		return fmt.Errorf("unsupported diffID algorithm %q", diffID.Algorithm)
	}
	rc, err := l.Uncompressed()
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer rc.Close()
	h := sha256.New()
	r := io.TeeReader(rc, h)
	meta, err := extract.Walk(r, s.Limits, func(f extract.File) error {
		job := scanJob{res: res, path: f.Path, size: f.Size}
		if f.Size > bufferLimit {
			job.stream, job.done = f.Content, make(chan error, 1)
		} else {
			data, err := io.ReadAll(f.Content)
			if err != nil {
				return fmt.Errorf("read %s: %w", f.Path, err)
			}
			job.data, job.size = data, int64(len(data))
		}
		select {
		case jobs <- job:
		case <-ctx.Done():
			return ctx.Err()
		}
		if job.done == nil {
			return nil
		}
		// The worker reads from the layer: wait until it is done. It always
		// answers, and quickly once ctx is cancelled.
		return <-job.done
	})
	if err != nil {
		return err
	}
	// The tar reader stops at the end-of-archive marker. Read the rest so
	// that go-containerregistry verifies the blob digest at EOF.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != diffID.Hex {
		return fmt.Errorf("content does not match diffID (got sha256:%s)", got)
	}
	res.meta = meta
	return nil
}

func buildPlatformReport(p source.PlatformImage, layers []LayerReport, results []*layerResult) PlatformReport {
	metas := make([]*extract.Layer, len(results))
	for i, r := range results {
		metas[i] = r.meta
	}
	pr := PlatformReport{Platform: p.Platform, Digest: p.Digest, Layers: layers}
	for i, r := range results {
		pr.Files += r.meta.Files
		for _, h := range r.hits {
			f := Finding{
				Platform:  p.Platform,
				Layer:     i + 1,
				DiffID:    layers[i].DiffID,
				Path:      h.path,
				Signature: h.signature,
				Status:    StatusPresent,
				CreatedBy: layers[i].CreatedBy,
			}
			if j, how := extract.HiddenBy(h.path, i, metas); j >= 0 {
				f.HiddenByLayer = j + 1
				f.HiddenHow = how
				f.Status = StatusDeleted
				if how == "overwritten" {
					f.Status = StatusOverwritten
				}
			}
			pr.Findings = append(pr.Findings, f)
		}
		for _, sk := range append(r.meta.Skipped, r.limited...) {
			pr.Skipped = append(pr.Skipped, SkippedFile{Platform: p.Platform, Layer: i + 1, Skipped: sk})
		}
	}
	sort.Slice(pr.Findings, func(a, b int) bool {
		fa, fb := pr.Findings[a], pr.Findings[b]
		if fa.Layer != fb.Layer {
			return fa.Layer < fb.Layer
		}
		return fa.Path < fb.Path
	})
	return pr
}

// history returns the CreatedBy instruction of each non-empty layer.
func history(p source.PlatformImage) ([]string, error) {
	cf, err := p.Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("%s: read config: %w", p.Platform, err)
	}
	var out []string
	for _, h := range cf.History {
		if !h.EmptyLayer {
			out = append(out, h.CreatedBy)
		}
	}
	return out, nil
}

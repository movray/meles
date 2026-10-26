// Package runner executes scan runs from a queue with a fixed number of
// workers and stores their results.
package runner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/store"
)

// ErrQueueFull is returned when too many runs are waiting.
var ErrQueueFull = errors.New("run queue is full")

// Runner queues and executes runs.
type Runner struct {
	store   *store.Store
	scanner *scan.Scanner
	workers int
	// Timeout bounds a single run.
	timeout time.Duration
	log     *slog.Logger

	queue chan int64
	wg    sync.WaitGroup
	// ignore returns the ignore rules for a finished scan.
	ignore IgnoreFunc
}

// IgnoreFunc returns the ignore rules in effect. On an error the rules it
// still returns are applied; everything else counts.
type IgnoreFunc func(ctx context.Context) (*ignore.Rules, error)

// SetIgnore sets the source of ignore rules; call it before Start.
func (r *Runner) SetIgnore(fn IgnoreFunc) { r.ignore = fn }

// New returns a runner. Call Start to process the queue.
func New(st *store.Store, sc *scan.Scanner, workers int, timeout time.Duration, log *slog.Logger) *Runner {
	return &Runner{
		store:   st,
		scanner: sc,
		workers: max(workers, 1),
		timeout: timeout,
		log:     log,
		queue:   make(chan int64, 1000),
	}
}

// Start runs the workers until ctx is canceled. Wait waits for them.
func (r *Runner) Start(ctx context.Context) {
	for range r.workers {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case id := <-r.queue:
					r.execute(ctx, id)
				}
			}
		}()
	}
}

// Wait blocks until all workers have stopped.
func (r *Runner) Wait() { r.wg.Wait() }

// Enqueue creates a queued run of ref. sc is the configured scan, or nil
// for an ad-hoc run.
func (r *Runner) Enqueue(ctx context.Context, sc *store.Scan, ref, platforms, trigger string) (*store.Run, error) {
	if _, err := source.ParsePlatforms(platforms); err != nil {
		return nil, err
	}
	run := &store.Run{ImageRef: ref, Platforms: platforms, Trigger: trigger}
	if sc != nil {
		run.ScanID = &sc.ID
	}
	if err := r.store.CreateRun(ctx, run); err != nil {
		return nil, err
	}
	select {
	case r.queue <- run.ID:
		return run, nil
	default:
		r.store.FinishRun(context.WithoutCancel(ctx), run.ID, nil, ErrQueueFull)
		return nil, ErrQueueFull
	}
}

// QueueLen returns the number of runs waiting for a worker.
func (r *Runner) QueueLen() int { return len(r.queue) }

func (r *Runner) execute(ctx context.Context, id int64) {
	// Results are stored even if the server is shutting down.
	dbctx := context.WithoutCancel(ctx)
	run, err := r.store.GetRun(dbctx, id)
	if err != nil {
		r.log.Error("load run", "run", id, "err", err)
		return
	}
	if err := r.store.StartRun(dbctx, id); err != nil {
		r.log.Error("start run", "run", id, "err", err)
		return
	}
	log := r.log.With("run", id, "ref", run.ImageRef)
	log.Info("scan started", "trigger", run.Trigger, "platforms", run.Platforms)

	rep, err := r.scan(ctx, run, func(p scan.Progress) {
		msg := fmt.Sprintf("%s: layer %d of %d", p.Platform, p.Layer, p.Layers)
		if err := r.store.SetProgress(dbctx, id, msg); err != nil {
			log.Warn("set progress", "err", err)
		}
	})
	if err != nil {
		log.Error("scan failed", "err", err)
	} else {
		r.applyIgnore(dbctx, rep, log)
		log.Info("scan finished", "infected", rep.Infected(), "findings", len(rep.ActiveFindings()), "ignored", len(rep.Findings())-len(rep.ActiveFindings()), "files", rep.Files())
	}
	if err := r.store.FinishRun(dbctx, id, rep, err); err != nil {
		log.Error("store result", "err", err)
	}
}

// applyIgnore marks what the rules in effect now ignore. A run keeps the
// verdict of its time: later rules apply from the next run on.
func (r *Runner) applyIgnore(ctx context.Context, rep *scan.Report, log *slog.Logger) {
	if r.ignore == nil {
		return
	}
	rules, err := r.ignore(ctx)
	if err != nil {
		// Without the rules more counts, never less.
		log.Warn("ignore rules not loaded, the run counts what they would ignore", "err", err)
	}
	rep.ApplyIgnore(rules, time.Now())
}

func (r *Runner) scan(ctx context.Context, run *store.Run, progress func(scan.Progress)) (*scan.Report, error) {
	pf, err := source.ParsePlatforms(run.Platforms)
	if err != nil {
		return nil, err
	}
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	rep, err := r.scanner.Scan(ctx, run.ImageRef, pf, progress)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, fmt.Errorf("run timed out after %s: %w", r.timeout, err)
	}
	return rep, err
}

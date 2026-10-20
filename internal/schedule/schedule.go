// Package schedule triggers configured scans on their cron schedules.
package schedule

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"git.itknecht.de/sugras/meles/internal/runner"
	"git.itknecht.de/sugras/meles/internal/store"
)

// parser accepts standard five-field expressions ("0 3 * * *"), descriptors
// such as "@daily" or "@every 6h" and a "CRON_TZ=Europe/Berlin " prefix.
var parser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)

// Validate checks a cron expression. Empty means "no schedule".
func Validate(expr string) error {
	if expr == "" {
		return nil
	}
	if _, err := parser.Parse(expr); err != nil {
		return fmt.Errorf("invalid schedule %q: %w", expr, err)
	}
	return nil
}

// Next returns the next activation of expr after t, or the zero time.
func Next(expr string, t time.Time) time.Time {
	if expr == "" {
		return time.Time{}
	}
	s, err := parser.Parse(expr)
	if err != nil {
		return time.Time{}
	}
	return s.Next(t)
}

// Scheduler enqueues runs of scheduled scans.
type Scheduler struct {
	store  *store.Store
	runner *runner.Runner
	log    *slog.Logger
	cron   *cron.Cron

	mu      sync.Mutex
	entries map[int64]cron.EntryID
}

// New returns a scheduler using loc for expressions without CRON_TZ.
func New(st *store.Store, r *runner.Runner, loc *time.Location, log *slog.Logger) *Scheduler {
	return &Scheduler{
		store:   st,
		runner:  r,
		log:     log,
		cron:    cron.New(cron.WithParser(parser), cron.WithLocation(loc)),
		entries: map[int64]cron.EntryID{},
	}
}

// Start starts the scheduler; Stop stops it.
func (s *Scheduler) Start() { s.cron.Start() }

// Stop stops the scheduler and waits for running triggers.
func (s *Scheduler) Stop() { <-s.cron.Stop().Done() }

// Sync reloads all scans from the store. Call it after every change.
func (s *Scheduler) Sync(ctx context.Context) error {
	scans, err := s.store.ListScans(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, e := range s.entries {
		s.cron.Remove(e)
		delete(s.entries, id)
	}
	for _, sc := range scans {
		if !sc.Enabled || sc.Schedule == "" {
			continue
		}
		id := sc.ID
		e, err := s.cron.AddFunc(sc.Schedule, func() { s.trigger(id) })
		if err != nil {
			s.log.Error("invalid schedule", "scan", id, "schedule", sc.Schedule, "err", err)
			continue
		}
		s.entries[id] = e
	}
	return nil
}

// NextRun returns the next scheduled run of a scan, or the zero time.
func (s *Scheduler) NextRun(scanID int64) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[scanID]
	if !ok {
		return time.Time{}
	}
	return s.cron.Entry(e).Next
}

func (s *Scheduler) trigger(scanID int64) {
	ctx := context.Background()
	sc, err := s.store.GetScan(ctx, scanID)
	if err != nil {
		s.log.Error("scheduled scan", "scan", scanID, "err", err)
		return
	}
	if !sc.Enabled {
		return
	}
	// Do not pile up runs when a scan takes longer than its interval.
	if active, err := s.store.HasActiveRun(ctx, scanID); err != nil || active {
		if err != nil {
			s.log.Error("scheduled scan", "scan", scanID, "err", err)
		} else {
			s.log.Info("scheduled scan skipped, previous run still active", "scan", scanID)
		}
		return
	}
	if _, err := s.runner.Enqueue(ctx, sc, sc.ImageRef, sc.Platforms, store.TriggerSchedule); err != nil {
		s.log.Error("enqueue scheduled scan", "scan", scanID, "err", err)
	}
}

package store

import (
	"context"
	"fmt"
	"time"
)

// Stats summarises the database for the dashboard.
type Stats struct {
	Scans          int
	ScheduledScans int
	Runs           int
	Clean          int
	Infected       int
	Errors         int
	// InfectedImages counts images whose latest finished run found malware.
	InfectedImages int
	// Images counts distinct image references with a finished run.
	Images int
}

// Stats returns counts; run counts cover runs queued since since.
func (s *Store) Stats(ctx context.Context, since time.Time) (Stats, error) {
	var st Stats
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(enabled = 1 AND schedule <> ''), 0) FROM scans`).Scan(&st.Scans, &st.ScheduledScans)
	if err != nil {
		return st, fmt.Errorf("stats: %w", err)
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*),
		COALESCE(SUM(status = 'clean'), 0), COALESCE(SUM(status = 'infected'), 0), COALESCE(SUM(status = 'error'), 0)
		FROM runs WHERE queued_at >= ?`, unix(since)).Scan(&st.Runs, &st.Clean, &st.Infected, &st.Errors)
	if err != nil {
		return st, fmt.Errorf("stats: %w", err)
	}
	images, err := s.ImageStatus(ctx)
	if err != nil {
		return st, err
	}
	st.Images = len(images)
	for _, r := range images {
		if r.Status == StatusInfected {
			st.InfectedImages++
		}
	}
	return st, nil
}

// ImageStatus returns the latest finished run of every image reference,
// infected images first.
func (s *Store) ImageStatus(ctx context.Context) ([]Run, error) {
	return s.queryRuns(ctx, `SELECT `+runColumns+` FROM runs r LEFT JOIN scans s ON s.id = r.scan_id
		WHERE r.id IN (SELECT MAX(id) FROM runs WHERE status IN ('clean', 'infected', 'error') GROUP BY image_ref)
		ORDER BY CASE r.status WHEN 'infected' THEN 0 WHEN 'error' THEN 1 ELSE 2 END, r.image_ref`)
}

// Day counts finished runs of one day.
type Day struct {
	Date     time.Time
	Clean    int
	Infected int
	Errors   int
}

// Total returns the number of runs of the day.
func (d Day) Total() int { return d.Clean + d.Infected + d.Errors }

// Daily returns one entry per day for the last days days (oldest first),
// grouped by the day the run finished in loc.
func (s *Store) Daily(ctx context.Context, days int, loc *time.Location) ([]Day, error) {
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	first := today.AddDate(0, 0, -(days - 1))
	out := make([]Day, days)
	for i := range out {
		out[i].Date = first.AddDate(0, 0, i)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT finished_at, status FROM runs WHERE finished_at >= ? AND status IN ('clean', 'infected', 'error')`, unix(first))
	if err != nil {
		return nil, fmt.Errorf("daily runs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var finished int64
		var status string
		if err := rows.Scan(&finished, &status); err != nil {
			return nil, fmt.Errorf("daily runs: %w", err)
		}
		t := time.UnixMilli(finished).In(loc)
		i := int(time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc).Sub(first).Hours()+12) / 24
		if i < 0 || i >= days {
			continue
		}
		switch status {
		case StatusClean:
			out[i].Clean++
		case StatusInfected:
			out[i].Infected++
		case StatusError:
			out[i].Errors++
		}
	}
	return out, rows.Err()
}

// SignatureCount aggregates findings of one signature.
type SignatureCount struct {
	Signature string
	Findings  int
	Images    int
	LastSeen  time.Time
}

// TopSignatures returns the most frequent signatures of runs finished since
// since.
func (s *Store) TopSignatures(ctx context.Context, since time.Time, limit int) ([]SignatureCount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.signature, COUNT(*), COUNT(DISTINCT r.image_ref), MAX(r.finished_at)
		FROM findings f JOIN runs r ON r.id = f.run_id
		WHERE r.finished_at >= ?
		GROUP BY f.signature ORDER BY COUNT(*) DESC, f.signature LIMIT ?`, unix(since), limit)
	if err != nil {
		return nil, fmt.Errorf("top signatures: %w", err)
	}
	defer rows.Close()
	var out []SignatureCount
	for rows.Next() {
		var c SignatureCount
		var last int64
		if err := rows.Scan(&c.Signature, &c.Findings, &c.Images, &last); err != nil {
			return nil, fmt.Errorf("top signatures: %w", err)
		}
		c.LastSeen = time.UnixMilli(last)
		out = append(out, c)
	}
	return out, rows.Err()
}

// FindingRow is a finding with its run, for exports.
type FindingRow struct {
	RunID      int64
	FinishedAt time.Time
	ImageRef   string
	Digest     string
	Platform   string
	Layer      int
	Path       string
	Signature  string
	Status     string
}

// Findings returns all findings of runs finished since since, newest first.
func (s *Store) Findings(ctx context.Context, since time.Time) ([]FindingRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id, r.finished_at, r.image_ref, r.digest, f.platform, f.layer, f.path, f.signature, f.status
		FROM findings f JOIN runs r ON r.id = f.run_id
		WHERE r.finished_at >= ? ORDER BY r.id DESC, f.platform, f.layer, f.path`, unix(since))
	if err != nil {
		return nil, fmt.Errorf("findings: %w", err)
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		var finished int64
		if err := rows.Scan(&f.RunID, &finished, &f.ImageRef, &f.Digest, &f.Platform, &f.Layer, &f.Path, &f.Signature, &f.Status); err != nil {
			return nil, fmt.Errorf("findings: %w", err)
		}
		f.FinishedAt = time.UnixMilli(finished)
		out = append(out, f)
	}
	return out, rows.Err()
}

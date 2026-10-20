// Package store keeps configured scans, scan runs and their findings in
// SQLite (pure Go driver, no CGO).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"git.itknecht.de/sugras/meles/internal/scan"
)

// ErrNotFound is returned when a scan or run does not exist.
var ErrNotFound = errors.New("not found")

// Run statuses. Only clean means the image was fully scanned without
// findings.
const (
	StatusQueued   = "queued"
	StatusRunning  = "running"
	StatusClean    = "clean"
	StatusInfected = "infected"
	StatusError    = "error"
)

// Run triggers.
const (
	TriggerManual   = "manual"
	TriggerSchedule = "schedule"
	TriggerAPI      = "api"
)

// Scan is a configured scan of an image reference.
type Scan struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ImageRef  string `json:"imageRef"`
	Platforms string `json:"platforms"`
	// Schedule is a cron expression; empty means manual runs only.
	Schedule  string    `json:"schedule"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	// LastRun is the most recent run, if any (not stored with the scan).
	LastRun *Run `json:"lastRun,omitempty"`
}

// Run is one execution of a scan or an ad-hoc scan.
type Run struct {
	ID         int64      `json:"id"`
	ScanID     *int64     `json:"scanId,omitempty"`
	ScanName   string     `json:"scanName,omitempty"`
	ImageRef   string     `json:"imageRef"`
	Platforms  string     `json:"platforms"`
	Trigger    string     `json:"trigger"`
	Status     string     `json:"status"`
	QueuedAt   time.Time  `json:"queuedAt"`
	StartedAt  *time.Time `json:"startedAt,omitempty"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Digest     string     `json:"digest,omitempty"`
	Engine     string     `json:"engine,omitempty"`
	Signatures string     `json:"signatures,omitempty"`
	Files      int        `json:"files"`
	Findings   int        `json:"findings"`
	Skipped    int        `json:"skipped"`
	Progress   string     `json:"progress,omitempty"`
	Error      string     `json:"error,omitempty"`
}

// Done reports whether the run has finished.
func (r *Run) Done() bool {
	return r.Status == StatusClean || r.Status == StatusInfected || r.Status == StatusError
}

// Duration returns how long the run took or has been running.
func (r *Run) Duration() time.Duration {
	if r.StartedAt == nil {
		return 0
	}
	end := time.Now()
	if r.FinishedAt != nil {
		end = *r.FinishedAt
	}
	return end.Sub(*r.StartedAt)
}

// Store is a SQLite database.
type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS scans (
	id         INTEGER PRIMARY KEY,
	name       TEXT    NOT NULL,
	image_ref  TEXT    NOT NULL,
	platforms  TEXT    NOT NULL DEFAULT 'all',
	schedule   TEXT    NOT NULL DEFAULT '',
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
	id          INTEGER PRIMARY KEY,
	scan_id     INTEGER REFERENCES scans(id) ON DELETE SET NULL,
	image_ref   TEXT    NOT NULL,
	platforms   TEXT    NOT NULL,
	trigger     TEXT    NOT NULL,
	status      TEXT    NOT NULL,
	queued_at   INTEGER NOT NULL,
	started_at  INTEGER,
	finished_at INTEGER,
	digest      TEXT    NOT NULL DEFAULT '',
	engine      TEXT    NOT NULL DEFAULT '',
	signatures  TEXT    NOT NULL DEFAULT '',
	files       INTEGER NOT NULL DEFAULT 0,
	findings    INTEGER NOT NULL DEFAULT 0,
	skipped     INTEGER NOT NULL DEFAULT 0,
	progress    TEXT    NOT NULL DEFAULT '',
	error       TEXT    NOT NULL DEFAULT '',
	report      TEXT
);
CREATE INDEX IF NOT EXISTS runs_scan_id ON runs(scan_id, id);
CREATE INDEX IF NOT EXISTS runs_queued_at ON runs(queued_at);
CREATE TABLE IF NOT EXISTS findings (
	run_id    INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
	platform  TEXT    NOT NULL,
	layer     INTEGER NOT NULL,
	path      TEXT    NOT NULL,
	signature TEXT    NOT NULL,
	status    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_run_id ON findings(run_id);
`

// Open opens or creates the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// SQLite allows one writer; a single connection avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks the database connection.
func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Times are stored as Unix milliseconds.
func unix(t time.Time) int64 { return t.UnixMilli() }

func fromUnix(n sql.NullInt64) *time.Time {
	if !n.Valid {
		return nil
	}
	t := time.UnixMilli(n.Int64)
	return &t
}

// --- scans ---

// CreateScan stores a new scan and sets its ID.
func (s *Store) CreateScan(ctx context.Context, sc *Scan) error {
	now := time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (name, image_ref, platforms, schedule, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sc.Name, sc.ImageRef, sc.Platforms, sc.Schedule, sc.Enabled, unix(now), unix(now))
	if err != nil {
		return fmt.Errorf("create scan: %w", err)
	}
	sc.ID, _ = res.LastInsertId()
	sc.CreatedAt, sc.UpdatedAt = now, now
	return nil
}

// UpdateScan saves the configuration of an existing scan.
func (s *Store) UpdateScan(ctx context.Context, sc *Scan) error {
	sc.UpdatedAt = time.Now()
	res, err := s.db.ExecContext(ctx,
		`UPDATE scans SET name = ?, image_ref = ?, platforms = ?, schedule = ?, enabled = ?, updated_at = ? WHERE id = ?`,
		sc.Name, sc.ImageRef, sc.Platforms, sc.Schedule, sc.Enabled, unix(sc.UpdatedAt), sc.ID)
	if err != nil {
		return fmt.Errorf("update scan %d: %w", sc.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("update scan %d: %w", sc.ID, ErrNotFound)
	}
	return nil
}

// DeleteScan deletes a scan. Its runs are kept as ad-hoc runs.
func (s *Store) DeleteScan(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM scans WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete scan %d: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("delete scan %d: %w", id, ErrNotFound)
	}
	return nil
}

const scanColumns = `s.id, s.name, s.image_ref, s.platforms, s.schedule, s.enabled, s.created_at, s.updated_at`

func scanScan(row interface{ Scan(...any) error }) (*Scan, error) {
	var sc Scan
	var created, updated int64
	if err := row.Scan(&sc.ID, &sc.Name, &sc.ImageRef, &sc.Platforms, &sc.Schedule, &sc.Enabled, &created, &updated); err != nil {
		return nil, err
	}
	sc.CreatedAt, sc.UpdatedAt = time.UnixMilli(created), time.UnixMilli(updated)
	return &sc, nil
}

// GetScan returns a scan with its last run.
func (s *Store) GetScan(ctx context.Context, id int64) (*Scan, error) {
	sc, err := scanScan(s.db.QueryRowContext(ctx, `SELECT `+scanColumns+` FROM scans s WHERE s.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("scan %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get scan %d: %w", id, err)
	}
	runs, err := s.ListRuns(ctx, RunFilter{ScanID: id, Limit: 1})
	if err != nil {
		return nil, err
	}
	if len(runs) > 0 {
		sc.LastRun = &runs[0]
	}
	return sc, nil
}

// ListScans returns all scans by name, each with its last run.
func (s *Store) ListScans(ctx context.Context) ([]Scan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scanColumns+` FROM scans s ORDER BY s.name COLLATE NOCASE, s.id`)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		sc, err := scanScan(rows)
		if err != nil {
			return nil, fmt.Errorf("list scans: %w", err)
		}
		out = append(out, *sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	rows.Close()

	last, err := s.lastRuns(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if r, ok := last[out[i].ID]; ok {
			out[i].LastRun = &r
		}
	}
	return out, nil
}

func (s *Store) lastRuns(ctx context.Context) (map[int64]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+runColumns+` FROM runs r LEFT JOIN scans s ON s.id = r.scan_id
		WHERE r.id IN (SELECT MAX(id) FROM runs WHERE scan_id IS NOT NULL GROUP BY scan_id)`)
	if err != nil {
		return nil, fmt.Errorf("last runs: %w", err)
	}
	defer rows.Close()
	out := map[int64]Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("last runs: %w", err)
		}
		out[*r.ScanID] = *r
	}
	return out, rows.Err()
}

// --- runs ---

// CreateRun queues a run and sets its ID.
func (s *Store) CreateRun(ctx context.Context, r *Run) error {
	r.Status = StatusQueued
	r.QueuedAt = time.Now()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO runs (scan_id, image_ref, platforms, trigger, status, queued_at) VALUES (?, ?, ?, ?, ?, ?)`,
		r.ScanID, r.ImageRef, r.Platforms, r.Trigger, r.Status, unix(r.QueuedAt))
	if err != nil {
		return fmt.Errorf("create run: %w", err)
	}
	r.ID, _ = res.LastInsertId()
	return nil
}

// StartRun marks a queued run as running.
func (s *Store) StartRun(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET status = ?, started_at = ? WHERE id = ?`, StatusRunning, unix(time.Now()), id)
	if err != nil {
		return fmt.Errorf("start run %d: %w", id, err)
	}
	return nil
}

// SetProgress updates the progress text of a running run.
func (s *Store) SetProgress(ctx context.Context, id int64, progress string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET progress = ? WHERE id = ?`, progress, id)
	if err != nil {
		return fmt.Errorf("set progress of run %d: %w", id, err)
	}
	return nil
}

// FinishRun stores the result of a run: the report, or the error that
// stopped it. A run with an error is never stored as clean.
func (s *Store) FinishRun(ctx context.Context, id int64, rep *scan.Report, runErr error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("finish run %d: %w", id, err)
	}
	defer tx.Rollback()

	now := unix(time.Now())
	if runErr != nil || rep == nil {
		msg := "no report"
		if runErr != nil {
			msg = runErr.Error()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, finished_at = ?, error = ?, progress = '' WHERE id = ?`,
			StatusError, now, msg, id); err != nil {
			return fmt.Errorf("finish run %d: %w", id, err)
		}
		return tx.Commit()
	}

	status := StatusClean
	if rep.Infected() {
		status = StatusInfected
	}
	js, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("encode report of run %d: %w", id, err)
	}
	fs := rep.Findings()
	if _, err := tx.ExecContext(ctx, `UPDATE runs SET status = ?, finished_at = ?, digest = ?, engine = ?, signatures = ?,
		files = ?, findings = ?, skipped = ?, progress = '', error = '', report = ? WHERE id = ?`,
		status, now, rep.Digest, rep.Engine.Engine, rep.Engine.Signatures,
		rep.Files(), len(fs), len(rep.Skipped()), string(js), id); err != nil {
		return fmt.Errorf("finish run %d: %w", id, err)
	}
	for _, f := range fs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings (run_id, platform, layer, path, signature, status) VALUES (?, ?, ?, ?, ?, ?)`,
			id, f.Platform, f.Layer, f.Path, f.Signature, f.Status); err != nil {
			return fmt.Errorf("store finding of run %d: %w", id, err)
		}
	}
	return tx.Commit()
}

// FailUnfinished marks runs left queued or running by a previous process
// as failed. Call it once at startup.
func (s *Store) FailUnfinished(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE runs SET status = ?, error = ?, finished_at = ?, progress = '' WHERE status IN (?, ?)`,
		StatusError, "interrupted: meles server stopped before the run finished", unix(time.Now()), StatusQueued, StatusRunning)
	if err != nil {
		return 0, fmt.Errorf("fail unfinished runs: %w", err)
	}
	return res.RowsAffected()
}

// HasActiveRun reports whether a scan has a queued or running run.
func (s *Store) HasActiveRun(ctx context.Context, scanID int64) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs WHERE scan_id = ? AND status IN (?, ?)`, scanID, StatusQueued, StatusRunning).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("active runs of scan %d: %w", scanID, err)
	}
	return n > 0, nil
}

const runColumns = `r.id, r.scan_id, COALESCE(s.name, ''), r.image_ref, r.platforms, r.trigger, r.status, r.queued_at, r.started_at,
	r.finished_at, r.digest, r.engine, r.signatures, r.files, r.findings, r.skipped, r.progress, r.error`

func scanRun(row interface{ Scan(...any) error }) (*Run, error) {
	var r Run
	var scanID, started, finished sql.NullInt64
	var queued int64
	if err := row.Scan(&r.ID, &scanID, &r.ScanName, &r.ImageRef, &r.Platforms, &r.Trigger, &r.Status, &queued, &started,
		&finished, &r.Digest, &r.Engine, &r.Signatures, &r.Files, &r.Findings, &r.Skipped, &r.Progress, &r.Error); err != nil {
		return nil, err
	}
	if scanID.Valid {
		r.ScanID = &scanID.Int64
	}
	r.QueuedAt = time.UnixMilli(queued)
	r.StartedAt, r.FinishedAt = fromUnix(started), fromUnix(finished)
	return &r, nil
}

// GetRun returns a run without its report.
func (s *Store) GetRun(ctx context.Context, id int64) (*Run, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runColumns+` FROM runs r LEFT JOIN scans s ON s.id = r.scan_id WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("run %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get run %d: %w", id, err)
	}
	return r, nil
}

// GetReport returns the scan report of a finished run, or nil if the run
// has none (still running or failed).
func (s *Store) GetReport(ctx context.Context, id int64) (*scan.Report, error) {
	var js sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT report FROM runs WHERE id = ?`, id).Scan(&js)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("run %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get report of run %d: %w", id, err)
	}
	if !js.Valid {
		return nil, nil
	}
	var rep scan.Report
	if err := json.Unmarshal([]byte(js.String), &rep); err != nil {
		return nil, fmt.Errorf("decode report of run %d: %w", id, err)
	}
	return &rep, nil
}

// RunFilter selects runs. Zero values mean no restriction.
type RunFilter struct {
	ScanID   int64
	Status   string
	ImageRef string
	Since    time.Time
	Limit    int
	Offset   int
}

func (f RunFilter) where() (string, []any) {
	var where []string
	var args []any
	if f.ScanID != 0 {
		where, args = append(where, "r.scan_id = ?"), append(args, f.ScanID)
	}
	if f.Status != "" {
		where, args = append(where, "r.status = ?"), append(args, f.Status)
	}
	if f.ImageRef != "" {
		where, args = append(where, "r.image_ref = ?"), append(args, f.ImageRef)
	}
	if !f.Since.IsZero() {
		where, args = append(where, "r.queued_at >= ?"), append(args, unix(f.Since))
	}
	if len(where) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// ListRuns returns runs, newest first.
func (s *Store) ListRuns(ctx context.Context, f RunFilter) ([]Run, error) {
	where, args := f.where()
	q := `SELECT ` + runColumns + ` FROM runs r LEFT JOIN scans s ON s.id = r.scan_id` + where + ` ORDER BY r.id DESC`
	if f.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d OFFSET %d", f.Limit, max(f.Offset, 0))
	}
	return s.queryRuns(ctx, q, args...)
}

func (s *Store) queryRuns(ctx context.Context, q string, args ...any) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, fmt.Errorf("list runs: %w", err)
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// CountRuns counts runs matching f (Limit and Offset are ignored).
func (s *Store) CountRuns(ctx context.Context, f RunFilter) (int, error) {
	where, args := f.where()
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM runs r`+where, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count runs: %w", err)
	}
	return n, nil
}

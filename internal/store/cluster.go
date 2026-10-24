package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ClusterEvent is a change of a MalwareReport of the meles operator: a new
// scan result, or the deletion of the report.
type ClusterEvent struct {
	ID int64 `json:"id"`
	// Cluster is the name of the cluster (empty for a single cluster).
	Cluster   string `json:"cluster,omitempty"`
	Namespace string `json:"namespace"`
	Report    string `json:"report"`
	// Group identifies the workload and container across rollouts:
	// "Deployment/web/app" for the ReplicaSets of a Deployment, otherwise
	// "<kind>/<name>/<container>".
	Group        string `json:"group"`
	WorkloadKind string `json:"workloadKind"`
	WorkloadName string `json:"workloadName"`
	Container    string `json:"container"`
	Repository   string `json:"repository"`
	Reference    string `json:"reference,omitempty"`
	Digest       string `json:"digest"`
	// Status of the report (Clean, Infected, Incomplete, Error); empty for a
	// deletion.
	Status     string    `json:"status,omitempty"`
	Deleted    bool      `json:"deleted,omitempty"`
	Findings   int       `json:"findings"`
	Skipped    int       `json:"skipped"`
	Files      int       `json:"files"`
	Engine     string    `json:"engine,omitempty"`
	Signatures string    `json:"signatures,omitempty"`
	Error      string    `json:"error,omitempty"`
	ScannedAt  time.Time `json:"scannedAt"`
	RecordedAt time.Time `json:"recordedAt"`
	// StatusSince is when the group got its current status.
	StatusSince time.Time `json:"statusSince"`
}

const clusterSchema = `
CREATE TABLE IF NOT EXISTS cluster_events (
	id            INTEGER PRIMARY KEY,
	cluster       TEXT    NOT NULL DEFAULT '',
	namespace     TEXT    NOT NULL,
	report        TEXT    NOT NULL,
	grp           TEXT    NOT NULL,
	workload_kind TEXT    NOT NULL,
	workload_name TEXT    NOT NULL,
	container     TEXT    NOT NULL,
	repository    TEXT    NOT NULL DEFAULT '',
	reference     TEXT    NOT NULL DEFAULT '',
	digest        TEXT    NOT NULL DEFAULT '',
	status        TEXT    NOT NULL DEFAULT '',
	deleted       INTEGER NOT NULL DEFAULT 0,
	findings      INTEGER NOT NULL DEFAULT 0,
	skipped       INTEGER NOT NULL DEFAULT 0,
	files         INTEGER NOT NULL DEFAULT 0,
	engine        TEXT    NOT NULL DEFAULT '',
	signatures    TEXT    NOT NULL DEFAULT '',
	error         TEXT    NOT NULL DEFAULT '',
	scanned_at    INTEGER NOT NULL,
	recorded_at   INTEGER NOT NULL,
	status_since  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cluster_events_report ON cluster_events(cluster, namespace, report, id);
CREATE INDEX IF NOT EXISTS cluster_events_group ON cluster_events(cluster, namespace, grp, id);
CREATE INDEX IF NOT EXISTS cluster_events_recorded_at ON cluster_events(recorded_at);
`

const clusterColumns = `id, cluster, namespace, report, grp, workload_kind, workload_name, container,
	repository, reference, digest, status, deleted, findings, skipped, files, engine, signatures, error,
	scanned_at, recorded_at, status_since`

func scanClusterEvent(row interface{ Scan(...any) error }) (ClusterEvent, error) {
	var e ClusterEvent
	var scanned, recorded, since int64
	err := row.Scan(&e.ID, &e.Cluster, &e.Namespace, &e.Report, &e.Group, &e.WorkloadKind, &e.WorkloadName, &e.Container,
		&e.Repository, &e.Reference, &e.Digest, &e.Status, &e.Deleted, &e.Findings, &e.Skipped, &e.Files, &e.Engine, &e.Signatures, &e.Error,
		&scanned, &recorded, &since)
	e.ScannedAt, e.RecordedAt, e.StatusSince = time.UnixMilli(scanned), time.UnixMilli(recorded), time.UnixMilli(since)
	return e, err
}

// lastClusterEvent returns the newest event matching where, or nil.
func lastClusterEvent(ctx context.Context, tx *sql.Tx, where string, args ...any) (*ClusterEvent, error) {
	e, err := scanClusterEvent(tx.QueryRowContext(ctx, `SELECT `+clusterColumns+` FROM cluster_events WHERE `+where+` ORDER BY id DESC LIMIT 1`, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// RecordClusterEvent stores e unless it repeats the last event of the
// report: the same scan (status, digest, scan time), or a second deletion.
// Reports seen again after a restart therefore add nothing. If the group of
// the report changed (e.g. its Deployment became known), its earlier events
// move to the new group. It sets e.ID and e.StatusSince and reports whether
// e was stored.
func (s *Store) RecordClusterEvent(ctx context.Context, e *ClusterEvent) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("record cluster event: %w", err)
	}
	defer tx.Rollback()

	last, err := lastClusterEvent(ctx, tx, `cluster = ? AND namespace = ? AND report = ?`, e.Cluster, e.Namespace, e.Report)
	if err != nil {
		return false, fmt.Errorf("last event of %s/%s: %w", e.Namespace, e.Report, err)
	}
	if last != nil && last.Group != e.Group && !e.Deleted {
		if _, err := tx.ExecContext(ctx, `UPDATE cluster_events SET grp = ? WHERE cluster = ? AND namespace = ? AND report = ?`,
			e.Group, e.Cluster, e.Namespace, e.Report); err != nil {
			return false, fmt.Errorf("move events of %s/%s to %s: %w", e.Namespace, e.Report, e.Group, err)
		}
		if !last.Deleted && last.Status == e.Status && last.Digest == e.Digest && last.ScannedAt.Equal(e.ScannedAt) {
			return false, tx.Commit()
		}
	}
	switch {
	case e.Deleted && (last == nil || last.Deleted):
		return false, nil
	case !e.Deleted && last != nil && !last.Deleted && last.Status == e.Status && last.Digest == e.Digest && last.ScannedAt.Equal(e.ScannedAt):
		return false, nil
	}

	e.RecordedAt = time.Now()
	e.StatusSince = e.ScannedAt
	prev, err := lastClusterEvent(ctx, tx, `cluster = ? AND namespace = ? AND grp = ? AND deleted = 0`, e.Cluster, e.Namespace, e.Group)
	if err != nil {
		return false, fmt.Errorf("last event of %s/%s: %w", e.Namespace, e.Group, err)
	}
	if prev != nil && (e.Deleted || prev.Status == e.Status) {
		e.StatusSince = prev.StatusSince
	}
	if e.Deleted {
		e.Status = ""
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO cluster_events (cluster, namespace, report, grp, workload_kind, workload_name, container,
		repository, reference, digest, status, deleted, findings, skipped, files, engine, signatures, error, scanned_at, recorded_at, status_since)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Cluster, e.Namespace, e.Report, e.Group, e.WorkloadKind, e.WorkloadName, e.Container,
		e.Repository, e.Reference, e.Digest, e.Status, e.Deleted, e.Findings, e.Skipped, e.Files, e.Engine, e.Signatures, e.Error,
		unix(e.ScannedAt), unix(e.RecordedAt), unix(e.StatusSince))
	if err != nil {
		return false, fmt.Errorf("insert cluster event: %w", err)
	}
	e.ID, _ = res.LastInsertId()
	return true, tx.Commit()
}

// ClusterHistory returns the newest events of a workload group, newest
// first.
func (s *Store) ClusterHistory(ctx context.Context, cluster, namespace, group string, limit int) ([]ClusterEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clusterColumns+` FROM cluster_events
		WHERE cluster = ? AND namespace = ? AND grp = ? ORDER BY id DESC LIMIT ?`, cluster, namespace, group, limit)
	if err != nil {
		return nil, fmt.Errorf("cluster history: %w", err)
	}
	defer rows.Close()
	var out []ClusterEvent
	for rows.Next() {
		e, err := scanClusterEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("cluster history: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ClusterKey identifies a workload group in a namespace.
type ClusterKey struct{ Namespace, Group string }

// ClusterStatusSince returns, per workload group, since when its current
// status holds.
func (s *Store) ClusterStatusSince(ctx context.Context, cluster string) (map[ClusterKey]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT namespace, grp, status_since FROM cluster_events WHERE id IN (
		SELECT MAX(id) FROM cluster_events WHERE cluster = ? AND deleted = 0 GROUP BY namespace, grp)`, cluster)
	if err != nil {
		return nil, fmt.Errorf("cluster status since: %w", err)
	}
	defer rows.Close()
	out := map[ClusterKey]time.Time{}
	for rows.Next() {
		var k ClusterKey
		var since int64
		if err := rows.Scan(&k.Namespace, &k.Group, &since); err != nil {
			return nil, fmt.Errorf("cluster status since: %w", err)
		}
		out[k] = time.UnixMilli(since)
	}
	return out, rows.Err()
}

// ClusterReportKey identifies a report.
type ClusterReportKey struct{ Namespace, Report string }

// LiveClusterReports returns the reports whose last event is not a deletion,
// with that event, to record deletions missed while the server was down.
func (s *Store) LiveClusterReports(ctx context.Context, cluster string) (map[ClusterReportKey]ClusterEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clusterColumns+` FROM cluster_events WHERE id IN (
		SELECT MAX(id) FROM cluster_events WHERE cluster = ? GROUP BY namespace, report) AND deleted = 0`, cluster)
	if err != nil {
		return nil, fmt.Errorf("live cluster reports: %w", err)
	}
	defer rows.Close()
	out := map[ClusterReportKey]ClusterEvent{}
	for rows.Next() {
		e, err := scanClusterEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("live cluster reports: %w", err)
		}
		out[ClusterReportKey{e.Namespace, e.Report}] = e
	}
	return out, rows.Err()
}

// PruneClusterEvents deletes events recorded before t, except the last
// event of each report: it holds the current state and its StatusSince.
func (s *Store) PruneClusterEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM cluster_events WHERE recorded_at < ? AND id NOT IN (
		SELECT MAX(id) FROM cluster_events GROUP BY cluster, namespace, report)`, unix(before))
	if err != nil {
		return 0, fmt.Errorf("prune cluster events: %w", err)
	}
	return res.RowsAffected()
}

// ClusterDay counts the cluster's reports by status at the end of a day
// (for today: now).
type ClusterDay struct {
	Date       time.Time `json:"date"`
	Clean      int       `json:"clean"`
	Infected   int       `json:"infected"`
	Incomplete int       `json:"incomplete"`
	Errors     int       `json:"errors"`
}

// Total returns the number of reports of the day.
func (d ClusterDay) Total() int { return d.Clean + d.Infected + d.Incomplete + d.Errors }

// ClusterDaily replays the history to the state at the end of each of the
// last days days (oldest first) in loc. Days before the history began count
// nothing.
func (s *Store) ClusterDaily(ctx context.Context, cluster string, days int, loc *time.Location) ([]ClusterDay, error) {
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	first := today.AddDate(0, 0, -(days - 1))
	out := make([]ClusterDay, days)
	for i := range out {
		out[i].Date = first.AddDate(0, 0, i)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT namespace, report, status, deleted, recorded_at FROM cluster_events
		WHERE cluster = ? ORDER BY id`, cluster)
	if err != nil {
		return nil, fmt.Errorf("cluster daily: %w", err)
	}
	defer rows.Close()

	state := map[ClusterReportKey]string{}
	day := 0
	// snapshot counts the state into out[day].
	snapshot := func() {
		for _, st := range state {
			switch st {
			case "Clean":
				out[day].Clean++
			case "Infected":
				out[day].Infected++
			case "Incomplete":
				out[day].Incomplete++
			default:
				out[day].Errors++
			}
		}
	}
	for rows.Next() {
		var k ClusterReportKey
		var status string
		var deleted bool
		var at int64
		if err := rows.Scan(&k.Namespace, &k.Report, &status, &deleted, &at); err != nil {
			return nil, fmt.Errorf("cluster daily: %w", err)
		}
		t := time.UnixMilli(at)
		// Close the days that ended before this event.
		for day < days && !t.Before(out[day].Date.AddDate(0, 0, 1)) {
			snapshot()
			day++
		}
		if day == days {
			break
		}
		if deleted {
			delete(state, k)
		} else {
			state[k] = status
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cluster daily: %w", err)
	}
	for ; day < days; day++ {
		snapshot()
	}
	return out, nil
}

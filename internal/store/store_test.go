package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/scan"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "meles.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func infectedReport() *scan.Report {
	return &scan.Report{
		Ref:    "registry.example/app:1",
		Digest: "sha256:abc",
		Engine: engine.Version{Engine: "ClamAV 1.4.3", Signatures: "28159"},
		Platforms: []scan.PlatformReport{{
			Platform: "linux/amd64",
			Files:    10,
			Findings: []scan.Finding{{Platform: "linux/amd64", Layer: 2, Path: "/opt/eicar.com", Signature: "Eicar-Test-Signature", Status: scan.StatusDeleted}},
		}},
	}
}

func TestScanCRUD(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	sc := &Scan{Name: "app", ImageRef: "registry.example/app:1", Platforms: "all", Schedule: "@daily", Enabled: true}
	if err := s.CreateScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	sc.Name = "app nightly"
	if err := s.UpdateScan(ctx, sc); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetScan(ctx, sc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "app nightly" || got.Schedule != "@daily" || !got.Enabled || got.LastRun != nil {
		t.Errorf("scan = %+v", got)
	}

	r := &Run{ScanID: &sc.ID, ImageRef: sc.ImageRef, Platforms: sc.Platforms, Trigger: TriggerManual}
	if err := s.CreateRun(ctx, r); err != nil {
		t.Fatal(err)
	}
	if active, _ := s.HasActiveRun(ctx, sc.ID); !active {
		t.Error("queued run not active")
	}

	scans, err := s.ListScans(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 || scans[0].LastRun == nil || scans[0].LastRun.ID != r.ID {
		t.Errorf("ListScans = %+v", scans)
	}

	if err := s.DeleteScan(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetScan(ctx, sc.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted scan: err = %v", err)
	}
	// Runs survive the deletion of their scan.
	if run, err := s.GetRun(ctx, r.ID); err != nil || run.ScanID != nil {
		t.Errorf("run after scan deletion = %+v, %v", run, err)
	}
}

func TestRunLifecycle(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	ok := &Run{ImageRef: "registry.example/app:1", Platforms: "all", Trigger: TriggerAPI}
	failed := &Run{ImageRef: "registry.example/other:1", Platforms: "all", Trigger: TriggerAPI}
	left := &Run{ImageRef: "registry.example/left:1", Platforms: "all", Trigger: TriggerAPI}
	for _, r := range []*Run{ok, failed, left} {
		if err := s.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.StartRun(ctx, ok.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishRun(ctx, ok.ID, infectedReport(), nil); err != nil {
		t.Fatal(err)
	}
	// Even with a report, an error must make the run fail.
	if err := s.FinishRun(ctx, failed.ID, infectedReport(), errors.New("pull failed")); err != nil {
		t.Fatal(err)
	}
	if n, err := s.FailUnfinished(ctx); err != nil || n != 1 {
		t.Errorf("FailUnfinished = %d, %v", n, err)
	}

	got, err := s.GetRun(ctx, ok.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusInfected || got.Findings != 1 || got.Files != 10 || got.Signatures != "28159" || got.FinishedAt == nil {
		t.Errorf("run = %+v", got)
	}
	rep, err := s.GetReport(ctx, ok.ID)
	if err != nil || rep == nil || rep.Findings()[0].Path != "/opt/eicar.com" {
		t.Errorf("report = %+v, %v", rep, err)
	}
	if got, _ := s.GetRun(ctx, failed.ID); got.Status != StatusError || got.Error != "pull failed" {
		t.Errorf("failed run = %+v", got)
	}
	if rep, err := s.GetReport(ctx, failed.ID); rep != nil || err != nil {
		t.Errorf("failed run report = %v, %v", rep, err)
	}

	since := time.Now().Add(-time.Hour)
	st, err := s.Stats(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	if st.Runs != 3 || st.Infected != 1 || st.Errors != 2 || st.InfectedImages != 1 || st.Images != 3 {
		t.Errorf("stats = %+v", st)
	}
	n, err := s.CountRuns(ctx, RunFilter{Status: StatusError})
	if err != nil || n != 2 {
		t.Errorf("CountRuns(error) = %d, %v", n, err)
	}
	sigs, err := s.TopSignatures(ctx, since, 10)
	if err != nil || len(sigs) != 1 || sigs[0].Signature != "Eicar-Test-Signature" || sigs[0].Images != 1 {
		t.Errorf("TopSignatures = %+v, %v", sigs, err)
	}
	days, err := s.Daily(ctx, 7, time.Local)
	if err != nil || len(days) != 7 || days[6].Infected != 1 || days[6].Errors != 2 {
		t.Errorf("Daily = %+v, %v", days, err)
	}
	rows, err := s.Findings(ctx, since)
	if err != nil || len(rows) != 1 {
		t.Errorf("Findings = %+v, %v", rows, err)
	}
}

func TestClusterEvents(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	t0 := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	ev := func(report, status string, scanned time.Time) *ClusterEvent {
		return &ClusterEvent{Namespace: "shop", Report: report, Group: "Deployment/web/app", WorkloadKind: "ReplicaSet", WorkloadName: report,
			Container: "app", Digest: "sha256:1", Status: status, ScannedAt: scanned}
	}
	steps := []struct {
		e         *ClusterEvent
		stored    bool
		wantSince time.Time
	}{
		{&ClusterEvent{Namespace: "shop", Report: "web-1", Group: "ReplicaSet/web-1/app", Digest: "sha256:1", Status: "Clean", ScannedAt: t0}, true, t0},
		{ev("web-1", "Clean", t0), false, t0},                 // Deployment now known: moved to its group
		{ev("web-1", "Clean", t0), false, t0},                 // seen again after a restart
		{ev("web-1", "Clean", t0.Add(time.Hour)), true, t0},   // rescan, still clean
		{ev("web-2", "Clean", t0.Add(2*time.Hour)), true, t0}, // rollout: new ReplicaSet, same group
		{&ClusterEvent{Namespace: "shop", Report: "web-1", Group: "Deployment/web/app", Deleted: true, ScannedAt: t0}, true, t0},
		{&ClusterEvent{Namespace: "shop", Report: "web-1", Group: "Deployment/web/app", Deleted: true, ScannedAt: t0}, false, t0},
		{ev("web-2", "Infected", t0.Add(3*time.Hour)), true, t0.Add(3 * time.Hour)},
	}
	for i, st := range steps {
		stored, err := s.RecordClusterEvent(ctx, st.e)
		if err != nil {
			t.Fatal(err)
		}
		if stored != st.stored || (stored && !st.e.StatusSince.Equal(st.wantSince)) {
			t.Errorf("step %d: stored %v, since %v; want %v, %v", i, stored, st.e.StatusSince, st.stored, st.wantSince)
		}
	}

	hist, err := s.ClusterHistory(ctx, "", "shop", "Deployment/web/app", 10)
	if err != nil || len(hist) != 5 || hist[0].Status != "Infected" || !hist[1].Deleted {
		t.Errorf("history = %d events, %v", len(hist), err)
	}
	since, err := s.ClusterStatusSince(ctx, "")
	if err != nil || !since[ClusterKey{"shop", "Deployment/web/app"}].Equal(t0.Add(3*time.Hour)) {
		t.Errorf("status since = %v, %v", since, err)
	}
	live, err := s.LiveClusterReports(ctx, "")
	if _, ok := live[ClusterReportKey{"shop", "web-2"}]; err != nil || len(live) != 1 || !ok {
		t.Errorf("live reports = %v, %v", live, err)
	}

	// Pruning keeps the last event of every report.
	if _, err := s.PruneClusterEvents(ctx, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if hist, _ := s.ClusterHistory(ctx, "", "shop", "Deployment/web/app", 10); len(hist) != 2 {
		t.Errorf("after pruning: %d events, want the last of web-1 and web-2", len(hist))
	}
}

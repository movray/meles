package server

import (
	"context"
	"time"

	"github.com/movray/meles/api/v1alpha1"
	"github.com/movray/meles/internal/store"
)

// historyGroup identifies a workload and container across rollouts: the
// ReplicaSets of a Deployment share "Deployment/<name>/<container>".
func historyGroup(w v1alpha1.Workload) string {
	if w.Parent != "" {
		return "Deployment/" + w.Parent + "/" + w.Container
	}
	return w.Kind + "/" + w.Name + "/" + w.Container
}

func clusterEvent(cluster string, rep *v1alpha1.MalwareReport, deleted bool) *store.ClusterEvent {
	d := rep.Report
	return &store.ClusterEvent{
		Cluster: cluster, Namespace: rep.Namespace, Report: rep.Name, Group: historyGroup(d.Workload),
		WorkloadKind: d.Workload.Kind, WorkloadName: d.Workload.Name, Container: d.Workload.Container,
		Repository: d.Image.Repository, Reference: d.Image.Reference, Digest: d.Image.Digest,
		Status: d.Summary.Status, Deleted: deleted,
		Findings: d.Summary.Findings, Skipped: d.Summary.Skipped, Files: d.Summary.Files,
		Engine: d.Scanner.Engine, Signatures: d.Scanner.Signatures, Error: d.Error,
		ScannedAt: d.ScannedAt.Time,
	}
}

func (s *Server) recordReport(rep *v1alpha1.MalwareReport, deleted bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := s.store.RecordClusterEvent(ctx, clusterEvent(s.clusterName, rep, deleted)); err != nil {
		s.log.Warn("record cluster history", "namespace", rep.Namespace, "report", rep.Name, "err", err)
	}
}

// RunClusterHistory records every change of the cluster's reports in the
// database until ctx is canceled: new results and deletions, including those
// missed while the server was down. Events older than keep are deleted
// daily, except the last one of each report.
func (s *Server) RunClusterHistory(ctx context.Context, k *KubeReports, keep time.Duration) error {
	if err := k.OnChange(ctx, s.recordReport); err != nil {
		return err
	}
	if !k.WaitSynced(ctx) {
		return nil
	}
	if err := s.recordMissedDeletions(ctx); err != nil {
		s.log.Warn("record deletions missed while the server was down", "err", err)
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		if n, err := s.store.PruneClusterEvents(ctx, time.Now().Add(-keep)); err != nil {
			s.log.Warn("prune cluster history", "err", err)
		} else if n > 0 {
			s.log.Info("cluster history pruned", "events", n)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// recordMissedDeletions marks reports deleted that the history still has
// but the cluster no longer.
func (s *Server) recordMissedDeletions(ctx context.Context) error {
	live, err := s.store.LiveClusterReports(ctx, s.clusterName)
	if err != nil {
		return err
	}
	reps, err := s.cluster.List(ctx)
	if err != nil {
		return err
	}
	for _, r := range reps {
		delete(live, store.ClusterReportKey{Namespace: r.Namespace, Report: r.Name})
	}
	for _, e := range live {
		e.Deleted = true
		if _, err := s.store.RecordClusterEvent(ctx, &e); err != nil {
			return err
		}
	}
	return nil
}

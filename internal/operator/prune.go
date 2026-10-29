package operator

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/movray/meles/api/v1alpha1"
)

// prunable are the workload kinds whose reports are deleted once they have
// no pods: an old ReplicaSet that a Deployment keeps for rollbacks, or a
// StatefulSet or DaemonSet scaled to zero. A CronJob has no pods between
// runs and keeps its report; reports of Jobs and bare pods are garbage
// collected with them.
var prunable = map[string]bool{"ReplicaSet": true, "StatefulSet": true, "DaemonSet": true}

// RunPrune deletes reports of workloads without pods every interval until
// ctx is canceled. Scaled up again, a workload gets its report back from the
// next pod event.
func (r *Reconciler) RunPrune(ctx context.Context, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.prune(ctx); err != nil {
			r.log().Warn("prune reports", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (r *Reconciler) prune(ctx context.Context) error {
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods); err != nil {
		return fmt.Errorf("list pods: %w", err)
	}
	live := map[types.UID]bool{}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if pod.DeletionTimestamp != nil {
			continue
		}
		owner, err := resolveWorkload(ctx, r.Client, pod)
		if err != nil {
			return err
		}
		live[owner.UID] = true
	}

	var reps v1alpha1.MalwareReportList
	if err := r.Client.List(ctx, &reps, client.MatchingLabels{"app.kubernetes.io/managed-by": "meles-operator"}); err != nil {
		return fmt.Errorf("list reports: %w", err)
	}
	for i := range reps.Items {
		rep := &reps.Items[i]
		owners := rep.OwnerReferences
		if len(owners) == 0 || !prunable[owners[0].Kind] || live[owners[0].UID] {
			continue
		}
		if err := r.Client.Delete(ctx, rep); client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("delete report %s/%s: %w", rep.Namespace, rep.Name, err)
		}
		r.log().Info("report of a workload without pods deleted", "namespace", rep.Namespace, "report", rep.Name, "workload", owners[0].Kind+"/"+owners[0].Name)
	}
	return nil
}

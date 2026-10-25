package operator

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
)

func TestStatus(t *testing.T) {
	r := &Reconciler{Version: "test", Workers: 2, Gate: true, IsLeader: func() bool { return true }}
	r.queue = newScanQueue()
	pod := client.ObjectKey{Namespace: "shop", Name: "web-1"}
	for _, key := range []string{"a", "b", "c"} {
		if err := r.queue.request(key, "all", image{ref: "reg/" + key + "@sha256:1"}, prioNew, pod); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.queue.request("g", "all", image{ref: "reg/g@sha256:1"}, prioGated, pod); err != nil {
		t.Fatal(err)
	}
	j := r.queue.next()
	r.recordScan(j, resultFromError(errors.New("pull refused"), "test"))
	r.queue.done(j.key)
	running := r.queue.next()
	r.recordHeld(pod, v1alpha1.GateEnforce, []string{"app: 1 findings in reg/g"})
	r.recordHeld(client.ObjectKey{Namespace: "shop", Name: "gone"}, v1alpha1.GateEnforce, []string{"x"})
	r.recordHeld(client.ObjectKey{Namespace: "shop", Name: "gone"}, "", nil)
	r.recordReleased(true)

	st := r.Status()
	if !st.Leader || st.Queued["new"] != 2 || st.Queued["gated"] != 0 || st.OldestQueued == nil {
		t.Errorf("queue = %+v, oldest %v", st.Queued, st.OldestQueued)
	}
	if len(st.Running) != 1 || st.Running[0].Image != running.img.ref || st.Running[0].Pods != 1 {
		t.Errorf("running = %+v", st.Running)
	}
	if len(st.Recent) != 1 || st.Recent[0].Image != "reg/g@sha256:1" || st.Recent[0].Status != v1alpha1.StatusError || st.Recent[0].Priority != "gated" || st.Totals[v1alpha1.StatusError] != 1 {
		t.Errorf("recent = %+v, totals %v", st.Recent, st.Totals)
	}
	if len(st.Gate.Held) != 1 || st.Gate.Held[0].Pod != "web-1" || st.Gate.Released.Unscanned != 1 {
		t.Errorf("gate = %+v", st.Gate)
	}
	if got := testutil.ToFloat64(metricQueued.WithLabelValues("new")); got != 2 {
		t.Errorf("queue metric = %v", got)
	}
	if got := testutil.ToFloat64(metricHeld); got != 1 {
		t.Errorf("held metric = %v", got)
	}
}

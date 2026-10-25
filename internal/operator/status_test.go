package operator

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

func TestReportMetrics(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	rep := func(ns, name, status string) *v1alpha1.MalwareReport {
		return &v1alpha1.MalwareReport{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Report:     v1alpha1.ReportData{Summary: v1alpha1.Summary{Status: status}},
		}
	}
	infected := rep("shop", "c", v1alpha1.StatusInfected)
	infected.Report.Summary.Findings = 2
	infected.Report.Workload = v1alpha1.Workload{Kind: "ReplicaSet", Name: "web-5d8f", Parent: "web", Container: "app"}
	infected.Report.Image = v1alpha1.Image{Repository: "reg/web", Reference: "reg/web:1.2"}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		rep("shop", "a", v1alpha1.StatusClean), rep("shop", "b", v1alpha1.StatusClean),
		infected, rep("db", "d", v1alpha1.StatusError),
	).Build()
	leader := true
	col := reportCollector{c, func() bool { return leader }}
	want := `
# HELP meles_operator_reports MalwareReports by namespace and status (Clean, Infected, Incomplete, Error); only the leader reports them.
# TYPE meles_operator_reports gauge
meles_operator_reports{namespace="db",status="Error"} 1
meles_operator_reports{namespace="shop",status="Clean"} 2
meles_operator_reports{namespace="shop",status="Infected"} 1
# HELP meles_operator_infected Findings (not ignored) of each Infected MalwareReport, by report, workload, container and image, for alerts that name them; only the leader reports them.
# TYPE meles_operator_infected gauge
meles_operator_infected{container="app",image="reg/web:1.2",namespace="shop",report="c",workload="web",workload_kind="Deployment"} 2
`
	if err := testutil.CollectAndCompare(col, strings.NewReader(want)); err != nil {
		t.Error(err)
	}
	leader = false
	if n := testutil.CollectAndCount(col); n != 0 {
		t.Errorf("follower reports %d series", n)
	}
}

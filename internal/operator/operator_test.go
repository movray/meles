package operator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/engine/fake"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

// env is a real API server and etcd (envtest), the test registry with the
// EICAR images and a running operator with the fake engine.
type env struct {
	r      *Reconciler
	c      client.Client
	reg    *testimage.Registry
	engine *fake.Engine
}

// setup needs the envtest binaries (make test-envtest); without
// KUBEBUILDER_ASSETS the test is skipped. configure, if set, adjusts the
// reconciler and engine before the operator starts.
func setup(t *testing.T, configure func(*env)) *env {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run make test-envtest")
	}
	te := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "charts", "meles", "crds")}, ErrorIfCRDPathMissing: true}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { te.Stop() })

	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	v1alpha1.AddToScheme(scheme)
	// Every test starts its own manager with the same controller.
	skipNameValidation := true
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		Controller: config.Controller{SkipNameValidation: &skipNameValidation},
	})
	if err != nil {
		t.Fatal(err)
	}
	reg, err := testimage.Serve(testimage.Cases())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	e := &env{c: mgr.GetClient(), reg: reg, engine: &fake.Engine{}}
	e.r = &Reconciler{
		Client: mgr.GetClient(),
		Scanner: &scan.Scanner{
			Engine: e.engine, Limits: extract.Limits{MaxFileSize: 1 << 20}, Concurrency: 2,
			Source: source.Options{Insecure: true},
		},
		Engine:  e.engine,
		Version: "test", Platforms: "all", Workers: 2,
		ScanTimeout: time.Minute, RetryAfter: time.Hour, RetryIncompleteAfter: time.Hour, RescanInterval: 24 * time.Hour,
	}
	if configure != nil {
		configure(e)
	}
	if err := e.r.SetupWithManager(mgr); err != nil {
		t.Fatal(err)
	}
	for _, cluster := range []bool{false, true} {
		if err := (&IgnoreStatusReconciler{Client: mgr.GetClient(), Cluster: cluster}).SetupWithManager(mgr); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("manager: %v", err)
		}
	})
	return e
}

// imageID returns what the kubelet reports for a test image: repo@digest.
func (e *env) imageID(t *testing.T, image string) string {
	t.Helper()
	ref, err := name.ParseReference(e.reg.Ref(image), name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := remote.Head(ref)
	if err != nil {
		t.Fatal(err)
	}
	return ref.Context().Name() + "@" + desc.Digest.String()
}

func (e *env) create(t *testing.T, obj client.Object) {
	t.Helper()
	if err := e.c.Create(context.Background(), obj); err != nil {
		t.Fatalf("create %T %s: %v", obj, obj.GetName(), err)
	}
}

// runPod creates a pod owned by owner (nil: none) and sets the status the
// kubelet would report once its single container "app" runs imageID.
func (e *env) runPod(t *testing.T, ns, podName string, owner client.Object, imageID string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: podName},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:latest"}}},
	}
	if owner != nil {
		gvk, err := e.c.GroupVersionKindFor(owner)
		if err != nil {
			t.Fatal(err)
		}
		pod.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(owner, gvk)}
	}
	e.create(t, pod)
	pod.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", Image: "app:latest", ImageID: imageID}}
	if err := e.c.Status().Update(context.Background(), pod); err != nil {
		t.Fatalf("update pod status: %v", err)
	}
}

// report waits for a report to appear.
func (e *env) report(t *testing.T, ns, reportName string) *v1alpha1.MalwareReport {
	t.Helper()
	return e.reportWhere(t, ns, reportName, "", func(*v1alpha1.MalwareReport) bool { return true })
}

// reportWhere waits for a report that satisfies ok.
func (e *env) reportWhere(t *testing.T, ns, reportName, what string, ok func(*v1alpha1.MalwareReport) bool) *v1alpha1.MalwareReport {
	t.Helper()
	var rep v1alpha1.MalwareReport
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: reportName}, &rep)
		if err == nil && ok(&rep) {
			return &rep
		}
		if time.Now().After(deadline) {
			t.Fatalf("report %s/%s %s: %v, last %+v", ns, reportName, what, err, rep.Report)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func replicaSet(ns, rsName string) *appsv1.ReplicaSet {
	labels := map[string]string{"app": rsName}
	return &appsv1.ReplicaSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: rsName},
		Spec: appsv1.ReplicaSetSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "app:latest"}}},
			},
		},
	}
}

func TestOperator(t *testing.T) {
	e := setup(t, nil)
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})

	// A ReplicaSet running an image with a file deleted by a whiteout.
	web := replicaSet(ns, "web-1")
	e.create(t, web)
	evil := e.imageID(t, "eicar-whiteout")
	e.runPod(t, ns, "web-1-a", web, evil)
	rep := e.report(t, ns, "replicaset-web-1-app")
	d := rep.Report
	if d.Summary.Status != v1alpha1.StatusInfected || d.Summary.Findings != 1 || d.Findings[0].Path != "/tmp/payload/eicar.com" || d.Findings[0].Status != scan.StatusDeleted {
		t.Errorf("report = %+v", d)
	}
	if d.Workload.Kind != "ReplicaSet" || d.Workload.Name != "web-1" || d.Image.Digest == "" || len(rep.OwnerReferences) != 1 || rep.OwnerReferences[0].UID != web.UID {
		t.Errorf("workload/owner = %+v / %+v", d.Workload, rep.OwnerReferences)
	}
	scans := e.engine.Scans.Load()

	// A second workload with the same image reuses the result, here from the
	// first report, as after a restart of the operator.
	e.r.mu.Lock()
	e.r.results, e.r.order = nil, nil
	e.r.mu.Unlock()
	e.runPod(t, ns, "solo", nil, evil)
	if got := e.report(t, ns, "pod-solo-app").Report.Summary.Status; got != v1alpha1.StatusInfected {
		t.Errorf("reused report status = %s", got)
	}
	if e.engine.Scans.Load() != scans {
		t.Errorf("same digest scanned again: %d engine scans", e.engine.Scans.Load()-scans)
	}

	// A CronJob's job pods report to the CronJob.
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "backup"},
		Spec: batchv1.CronJobSpec{Schedule: "@daily", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "app", Image: "app:latest"}}}},
		}}},
	}
	e.create(t, cj)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "backup-1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cj, batchv1.SchemeGroupVersion.WithKind("CronJob"))}},
		Spec:       cj.Spec.JobTemplate.Spec,
	}
	e.create(t, job)
	e.runPod(t, ns, "backup-1-x", job, e.imageID(t, "clean"))
	if got := e.report(t, ns, "cronjob-backup-app").Report; got.Summary.Status != v1alpha1.StatusClean || got.Workload.Kind != "CronJob" {
		t.Errorf("cronjob report = %+v", got)
	}

	// An image imported into the node has no registry: Error, never Clean.
	e.runPod(t, ns, "imported", nil, "sha256:3f1a6d3b84d0b5e8c0a2f0f5a1f0e0a8b9c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3")
	if got := e.report(t, ns, "pod-imported-app").Report; got.Summary.Status != v1alpha1.StatusError || got.Error == "" {
		t.Errorf("imported image report = %+v", got)
	}

	// A deleted report is written again right away, from the remembered
	// result, without waiting for a pod event.
	if err := e.c.Delete(context.Background(), rep); err != nil {
		t.Fatal(err)
	}
	scans = e.engine.Scans.Load()
	again := e.reportWhere(t, ns, "replicaset-web-1-app", "written again", func(r *v1alpha1.MalwareReport) bool { return r.UID != rep.UID })
	if again.Report.Summary.Status != v1alpha1.StatusInfected || e.engine.Scans.Load() != scans {
		t.Errorf("report written again = %+v after %d engine scans", again.Report, e.engine.Scans.Load()-scans)
	}
}

// The PHP case: an incomplete report becomes clean through a cluster rule,
// without a rescan, keeps the skipped file marked, and is incomplete again
// once the rule is gone. Invalid rules are reported in the status.
func TestIgnoreRules(t *testing.T) {
	e := setup(t, func(e *env) { e.engine.MaxSize = 1 }) // every file is skipped
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	e.runPod(t, ns, "app", nil, e.imageID(t, "clean"))
	if got := e.report(t, ns, "pod-app-app").Report; got.Summary.Status != v1alpha1.StatusIncomplete || len(got.Skipped) != 1 || got.Skipped[0].Signature == "" || got.Skipped[0].SHA256 == "" {
		t.Fatalf("report = %+v", got)
	}
	scans := e.engine.Scans.Load()

	expires := time.Now().AddDate(0, 6, 0).Format("2006-01-02")
	rules := &v1alpha1.ClusterMalwareIgnore{
		ObjectMeta: metav1.ObjectMeta{Name: "known"},
		Spec: v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{
			{Name: "hello", Path: "/etc/hello.txt", Reason: "test file", Expires: expires},
			{Path: "/never", Reason: "too long", Expires: time.Now().AddDate(2, 0, 0).Format("2006-01-02")},
		}},
	}
	e.create(t, rules)
	clean := e.reportWhere(t, ns, "pod-app-app", "clean by the rule", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.Summary.Status == v1alpha1.StatusClean
	})
	s := clean.Report.Summary
	if s.Skipped != 0 || s.IgnoredSkipped != 1 || s.Ignored != 1 || clean.Report.Skipped[0].Ignored == nil || clean.Report.Skipped[0].Ignored.Rule != "known/hello" {
		t.Errorf("summary %+v, skipped %+v", s, clean.Report.Skipped)
	}
	if n := e.engine.Scans.Load(); n != scans {
		t.Errorf("rescanned for a rule change: %d engine scans", n-scans)
	}

	// The invalid rule is not in effect, and the status says why.
	deadline := time.Now().Add(30 * time.Second)
	for {
		var got v1alpha1.ClusterMalwareIgnore
		if err := e.c.Get(context.Background(), client.ObjectKey{Name: "known"}, &got); err != nil {
			t.Fatal(err)
		}
		if got.Status.Rules == 1 && len(got.Status.Problems) == 1 && strings.Contains(got.Status.Problems[0], "more than a year ahead") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status = %+v", got.Status)
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := e.c.Delete(context.Background(), rules); err != nil {
		t.Fatal(err)
	}
	e.reportWhere(t, ns, "pod-app-app", "incomplete again", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.Summary.Status == v1alpha1.StatusIncomplete && r.Report.Summary.Ignored == 0 && r.Report.Skipped[0].Ignored == nil
	})
}

// A long scan holds one scan worker, not the reconcilers: meanwhile a
// deleted report comes back. Before, both workers waited for the slow image
// (one scanning, one for the same digest) and nothing else moved.
func TestLongScanDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	e := setup(t, func(e *env) {
		e.engine.Hold, e.engine.Release = []byte(testimage.EICAR()), release
		e.r.Workers = 2
	})
	defer close(release)
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	clean := e.imageID(t, "clean")
	e.runPod(t, ns, "before", nil, clean)
	before := e.report(t, ns, "pod-before-app")

	// Two pods of the same slow image: one scan, both wait.
	slow := e.imageID(t, "eicar-present")
	e.runPod(t, ns, "slow-1", nil, slow)
	e.runPod(t, ns, "slow-2", nil, slow)
	time.Sleep(time.Second)

	if err := e.c.Delete(context.Background(), before); err != nil {
		t.Fatal(err)
	}
	e.reportWhere(t, ns, "pod-before-app", "back while the slow scan runs", func(r *v1alpha1.MalwareReport) bool { return r.UID != before.UID })
	var rep v1alpha1.MalwareReport
	if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "pod-slow-1-app"}, &rep); err == nil {
		t.Fatal("slow image reported before its scan finished")
	}

	release <- struct{}{}
	for _, n := range []string{"pod-slow-1-app", "pod-slow-2-app"} {
		if got := e.report(t, ns, n).Report.Summary.Status; got != v1alpha1.StatusInfected {
			t.Errorf("%s: %s", n, got)
		}
	}
}

func TestPrune(t *testing.T) {
	e := setup(t, nil)
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	clean := e.imageID(t, "clean")
	old, current := replicaSet(ns, "web-1"), replicaSet(ns, "web-2")
	e.create(t, old)
	e.create(t, current)
	e.runPod(t, ns, "web-1-a", old, clean)
	e.runPod(t, ns, "web-2-a", current, clean)
	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "backup"},
		Spec: batchv1.CronJobSpec{Schedule: "@daily", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{RestartPolicy: corev1.RestartPolicyNever, Containers: []corev1.Container{{Name: "app", Image: "app:latest"}}}},
		}}},
	}
	e.create(t, cj)
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "backup-1", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(cj, batchv1.SchemeGroupVersion.WithKind("CronJob"))}},
		Spec:       cj.Spec.JobTemplate.Spec,
	}
	e.create(t, job)
	e.runPod(t, ns, "backup-1-x", job, clean)
	for _, n := range []string{"replicaset-web-1-app", "replicaset-web-2-app", "cronjob-backup-app"} {
		e.report(t, ns, n)
	}

	// The old ReplicaSet and the CronJob lose their pods.
	for _, p := range []string{"web-1-a", "backup-1-x"} {
		if err := e.c.Delete(context.Background(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: p}}, client.GracePeriodSeconds(0)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := e.r.prune(context.Background()); err != nil {
			t.Fatal(err)
		}
		var rep v1alpha1.MalwareReport
		err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: "replicaset-web-1-app"}, &rep)
		if apierrors.IsNotFound(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("report of the ReplicaSet without pods not pruned: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, n := range []string{"replicaset-web-2-app", "cronjob-backup-app"} {
		var rep v1alpha1.MalwareReport
		if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: n}, &rep); err != nil {
			t.Errorf("report %s: %v", n, err)
		}
	}
}

func TestRescan(t *testing.T) {
	// clamd rejects every file, as with too small limits.
	e := setup(t, func(e *env) {
		e.engine.MaxSize = 1
		e.r.RetryIncompleteAfter, e.r.RescanInterval, e.r.versionTTL = 2*time.Second, 2*time.Second, time.Nanosecond
	})
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	e.runPod(t, ns, "app", nil, e.imageID(t, "clean"))
	first := e.report(t, ns, "pod-app-app")
	if first.Report.Summary.Status != v1alpha1.StatusIncomplete {
		t.Fatalf("status with too small limits = %s", first.Report.Summary.Status)
	}

	// Incomplete is retried after RetryIncompleteAfter: with raised limits it
	// is clean.
	e.engine.SetMaxSize(0)
	clean := e.reportWhere(t, ns, "pod-app-app", "clean after retry", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.Summary.Status == v1alpha1.StatusClean
	})
	if clean.Report.Scanner.Signatures != "1" {
		t.Errorf("signatures = %q", clean.Report.Scanner.Signatures)
	}

	// Without a database update a clean result is kept past RescanInterval.
	scans := e.engine.Scans.Load()
	time.Sleep(5 * time.Second)
	if n := e.engine.Scans.Load(); n != scans {
		t.Errorf("rescanned without a database update: %d engine scans", n-scans)
	}

	// After an update it is rescanned with the new signatures.
	e.engine.SetSignatures("2")
	rescanned := e.reportWhere(t, ns, "pod-app-app", "rescanned", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.Scanner.Signatures == "2" && r.Report.Summary.Status == v1alpha1.StatusClean
	})

	// A second workload with the image gets a copy of the result.
	e.runPod(t, ns, "copy", nil, e.imageID(t, "clean"))
	if got := e.report(t, ns, "pod-copy-app").Report; !got.ScannedAt.Equal(&rescanned.Report.ScannedAt) {
		t.Errorf("copy scanned at %v, want %v", got.ScannedAt, rescanned.Report.ScannedAt)
	}

	// meles.io/rescan scans again although the result is current, removes
	// the annotation and updates the copy too.
	time.Sleep(1100 * time.Millisecond) // ScannedAt has seconds
	scans = e.engine.Scans.Load()
	rescanned.Annotations = map[string]string{v1alpha1.AnnotationRescan: "1"}
	if err := e.c.Update(context.Background(), rescanned); err != nil {
		t.Fatal(err)
	}
	forced := e.reportWhere(t, ns, "pod-app-app", "rescanned on request", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.ScannedAt.After(rescanned.Report.ScannedAt.Time)
	})
	if rescanRequested(forced) || e.engine.Scans.Load() == scans {
		t.Errorf("annotations %v after %d engine scans", forced.Annotations, e.engine.Scans.Load()-scans)
	}
	e.reportWhere(t, ns, "pod-copy-app", "updated", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.ScannedAt.Equal(&forced.Report.ScannedAt)
	})
}

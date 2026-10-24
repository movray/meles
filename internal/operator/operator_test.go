package operator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
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
	e.reportWhere(t, ns, "pod-app-app", "rescanned", func(r *v1alpha1.MalwareReport) bool {
		return r.Report.Scanner.Signatures == "2" && r.Report.Summary.Status == v1alpha1.StatusClean
	})
}

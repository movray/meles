package operator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/movray/meles/api/v1alpha1"
)

// gatedPod creates a pod as the webhook leaves it: held by the scan gate,
// with the mode of its namespace, and not pulled yet.
func (e *env) gatedPod(t *testing.T, ns, podName, image, mode string) {
	t.Helper()
	e.create(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: podName, Annotations: map[string]string{v1alpha1.AnnotationGateMode: mode}},
		Spec: corev1.PodSpec{
			Containers:      []corev1.Container{{Name: "app", Image: e.reg.Ref(image)}},
			SchedulingGates: []corev1.PodSchedulingGate{{Name: v1alpha1.SchedulingGateScan}},
		},
	})
}

// podWhere waits for a pod that satisfies ok.
func (e *env) podWhere(t *testing.T, ns, podName, what string, ok func(*corev1.Pod) bool) *corev1.Pod {
	t.Helper()
	var pod corev1.Pod
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: podName}, &pod)
		if err == nil && ok(&pod) {
			return &pod
		}
		if time.Now().After(deadline) {
			t.Fatalf("pod %s/%s %s: %v, last %+v", ns, podName, what, err, pod.Spec)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func released(p *corev1.Pod) bool { return !gated(p) }

// stillGated waits until the pod's report exists and checks that the pod
// stays held.
func (e *env) stillGated(t *testing.T, ns, podName, reportName, status string) {
	t.Helper()
	e.reportWhere(t, ns, reportName, status, func(r *v1alpha1.MalwareReport) bool { return r.Report.Summary.Status == status })
	time.Sleep(time.Second)
	var pod corev1.Pod
	if err := e.c.Get(context.Background(), client.ObjectKey{Namespace: ns, Name: podName}, &pod); err != nil {
		t.Fatal(err)
	}
	if !gated(&pod) {
		t.Errorf("pod %s released with a %s image", podName, status)
	}
}

func TestScanGate(t *testing.T) {
	e := setup(t, func(e *env) { e.r.Gate = true; e.r.Insecure = true })
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})

	// A clean image is released, pinned to the scanned digest.
	e.gatedPod(t, ns, "web", "clean", v1alpha1.GateEnforce)
	pod := e.podWhere(t, ns, "web", "released", released)
	digest := e.imageID(t, "clean")[strings.Index(e.imageID(t, "clean"), "@"):]
	if want := e.reg.Ref("clean") + digest; pod.Spec.Containers[0].Image != want {
		t.Errorf("image = %s, want %s", pod.Spec.Containers[0].Image, want)
	}
	if rep := e.report(t, ns, "pod-web-app").Report; rep.Summary.Status != v1alpha1.StatusClean || "@"+rep.Image.Digest != digest {
		t.Errorf("report = %+v", rep)
	}

	// An infected image is held, in audit mode as well.
	for _, mode := range []string{v1alpha1.GateEnforce, v1alpha1.GateAudit} {
		e.gatedPod(t, ns, "evil-"+mode, "eicar-present", mode)
		e.stillGated(t, ns, "evil-"+mode, "pod-evil-"+mode+"-app", v1alpha1.StatusInfected)
	}

	// An ignore rule for the finding releases it.
	e.create(t, &v1alpha1.MalwareIgnore{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "test-file"},
		Spec: v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{{
			Signature: "Eicar-Test-Signature", Reason: "test file", Expires: time.Now().AddDate(0, 1, 0).Format("2006-01-02"),
		}}},
	})
	e.podWhere(t, ns, "evil-enforce", "released by the rule", released)
}

// Skipped files hold a pod in enforce mode only.
func TestScanGateIncomplete(t *testing.T) {
	e := setup(t, func(e *env) { e.r.Gate = true; e.r.Insecure = true; e.engine.MaxSize = 1 })
	ns := "shop"
	e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
	e.gatedPod(t, ns, "strict", "clean", v1alpha1.GateEnforce)
	e.stillGated(t, ns, "strict", "pod-strict-app", v1alpha1.StatusIncomplete)
	e.gatedPod(t, ns, "lax", "clean", v1alpha1.GateAudit)
	e.podWhere(t, ns, "lax", "released in audit mode", released)
}

// A failure of clamd releases pods only with fail-open; an image that cannot
// be resolved holds them either way.
func TestScanGateEngineDown(t *testing.T) {
	for _, failOpen := range []bool{true, false} {
		t.Run(map[bool]string{true: "fail-open", false: "fail-closed"}[failOpen], func(t *testing.T) {
			e := setup(t, func(e *env) {
				e.r.Gate, e.r.GateFailOpen, e.r.Insecure = true, failOpen, true
				e.engine.Err = errors.New("clamd: connection refused")
			})
			ns := "shop"
			e.create(t, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})
			e.gatedPod(t, ns, "web", "clean", v1alpha1.GateEnforce)
			if failOpen {
				e.podWhere(t, ns, "web", "released despite clamd", released)
			} else {
				e.stillGated(t, ns, "web", "pod-web-app", v1alpha1.StatusError)
			}
			if rep := e.report(t, ns, "pod-web-app").Report; rep.ErrorSource != v1alpha1.ErrorSourceEngine {
				t.Errorf("report = %+v", rep)
			}

			e.gatedPod(t, ns, "missing", "does-not-exist", v1alpha1.GateEnforce)
			e.stillGated(t, ns, "missing", "pod-missing-app", v1alpha1.StatusError)
			if rep := e.report(t, ns, "pod-missing-app").Report; rep.ErrorSource != v1alpha1.ErrorSourceImage {
				t.Errorf("report = %+v", rep)
			}
		})
	}
}

func TestGateWebhook(t *testing.T) {
	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	w := &GateWebhook{Mode: v1alpha1.GateAudit, Decoder: admission.NewDecoder(scheme)}
	tests := []struct {
		name  string
		pod   corev1.Pod
		op    admissionv1.Operation
		gated bool
	}{
		{"new pod", corev1.Pod{}, admissionv1.Create, true},
		{"opted out", corev1.Pod{ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{v1alpha1.AnnotationGate: v1alpha1.GateSkip}}}, admissionv1.Create, false},
		{"bound to a node", corev1.Pod{Spec: corev1.PodSpec{NodeName: "n1"}}, admissionv1.Create, false},
		{"already gated", corev1.Pod{Spec: corev1.PodSpec{SchedulingGates: []corev1.PodSchedulingGate{{Name: v1alpha1.SchedulingGateScan}}}}, admissionv1.Create, false},
		{"update", corev1.Pod{}, admissionv1.Update, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.pod.Name = "p"
			tt.pod.Spec.Containers = append(tt.pod.Spec.Containers, corev1.Container{Name: "app", Image: "nginx:1.29"})
			raw, _ := json.Marshal(&tt.pod)
			req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: tt.op, Object: runtime.RawExtension{Raw: raw}}}
			resp := w.Handle(context.Background(), req)
			if !resp.Allowed {
				t.Fatalf("not allowed: %+v", resp.Result)
			}
			if got := len(resp.Patches) > 0; got != tt.gated {
				t.Fatalf("patched = %v, patches %+v", got, resp.Patches)
			}
			if !tt.gated {
				return
			}
			var gate, mode bool
			for _, p := range resp.Patches {
				b, _ := json.Marshal(p.Value)
				gate = gate || strings.Contains(string(b), v1alpha1.SchedulingGateScan)
				mode = mode || strings.Contains(p.Path, "annotations") && strings.Contains(string(b), v1alpha1.GateAudit)
			}
			if !gate || !mode {
				t.Errorf("patches = %+v", resp.Patches)
			}
		})
	}
}

func TestScanQueuePriority(t *testing.T) {
	q := newScanQueue()
	pod := client.ObjectKey{Namespace: "ns", Name: "p"}
	for _, r := range []struct {
		key  string
		prio priority
	}{{"rescan", prioRescan}, {"new", prioNew}, {"bumped", prioRescan}, {"gated", prioGated}, {"bumped", prioGated}} {
		if err := q.request(r.key, "all", image{}, r.prio, pod); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for j := q.next(); j != nil; j = q.next() {
		got = append(got, j.key)
	}
	if want := "gated bumped new rescan"; strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

package operator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/movray/meles/api/v1alpha1"
)

// The chart's ValidatingAdmissionPolicy against bypassing the scan gate,
// rendered with helm and enforced by a real API server. Every bypass is
// tried as a member of a gated namespace, then the same change as the
// operator or the kubelet, and outside gated namespaces.
func TestGateProtect(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS not set; run make test-envtest")
	}
	helm, err := exec.LookPath("helm")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("helm is needed to render the policy")
		}
		t.Skip("helm not in PATH")
	}
	out, err := exec.Command(helm, "template", "meles", filepath.Join("..", "..", "charts", "meles"),
		"--namespace", "meles", "--set", "operator.enabled=true", "--set", "operator.gate.enabled=true",
		"--show-only", "templates/operator-gate-protect.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	te := &envtest.Environment{}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { te.Stop() })
	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	ctx := context.Background()
	as := func(user string, groups ...string) client.Client {
		c := rest.CopyConfig(cfg)
		if user != "" {
			c.Impersonate = rest.ImpersonationConfig{UserName: user, Groups: groups}
		}
		cl, err := client.New(c, client.Options{Scheme: scheme})
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	admin := as("")
	const operatorSA = "system:serviceaccount:meles:meles-operator"
	member, operator, node := as("alice"), as(operatorSA), as("system:node:n1", "system:nodes", "system:authenticated")

	dec := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(out), 4096)
	for {
		var u unstructured.Unstructured
		if err := dec.Decode(&u.Object); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if len(u.Object) == 0 {
			continue
		}
		if err := admin.Create(ctx, &u); err != nil {
			t.Fatalf("create %s: %v", u.GetKind(), err)
		}
	}
	// RBAC lets everyone do everything: what is refused, the policy refuses.
	if err := admin.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-all"},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: "alice"},
			{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "system:nodes"},
			{Kind: rbacv1.ServiceAccountKind, Name: "meles-operator", Namespace: "meles"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for name, labels := range map[string]map[string]string{
		"enforce": {v1alpha1.LabelGate: v1alpha1.GateEnforce},
		"audit":   {v1alpha1.LabelGate: v1alpha1.GateAudit},
		"skipok":  {v1alpha1.LabelGate: v1alpha1.GateEnforce, v1alpha1.LabelGateSkip: v1alpha1.GateSkipAllowed},
		"free":    nil,
		"meles":   {v1alpha1.LabelGate: v1alpha1.GateEnforce}, // the release namespace is never gated
	} {
		if err := admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}); err != nil {
			t.Fatal(err)
		}
	}

	n := 0
	pod := func(ns string, mutate ...func(*corev1.Pod)) *corev1.Pod {
		n++
		p := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: fmt.Sprintf("p%d", n)},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx:1.29"}}},
		}
		for _, m := range mutate {
			m(p)
		}
		return p
	}
	gate := func(mode string) func(*corev1.Pod) {
		return func(p *corev1.Pod) {
			p.Spec.SchedulingGates = []corev1.PodSchedulingGate{{Name: v1alpha1.SchedulingGateScan}}
			p.Annotations = map[string]string{v1alpha1.AnnotationGateMode: mode}
		}
	}
	skip := func(p *corev1.Pod) { p.Annotations = map[string]string{v1alpha1.AnnotationGate: v1alpha1.GateSkip} }
	onNode := func(p *corev1.Pod) { p.Spec.NodeName = "n1" }
	check := func(t *testing.T, what string, err error, refused bool) {
		t.Helper()
		switch {
		case refused && err == nil:
			t.Errorf("%s: allowed", what)
		case refused && !apierrors.IsInvalid(err) && !apierrors.IsForbidden(err):
			t.Errorf("%s: %v", what, err)
		case !refused && err != nil:
			t.Errorf("%s: %v", what, err)
		}
	}

	// The policy takes effect a moment after it is created.
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := member.Create(ctx, pod("enforce", onNode))
		if err != nil && strings.Contains(err.Error(), "nodeName") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("policy not in effect after 30s")
		}
		time.Sleep(200 * time.Millisecond)
	}

	t.Run("create", func(t *testing.T) {
		for _, tt := range []struct {
			what    string
			c       client.Client
			p       *corev1.Pod
			refused bool
		}{
			{"skip", member, pod("enforce", skip), true},
			{"skip in audit", member, pod("audit", skip), true},
			{"skip where allowed", member, pod("skipok", skip), false},
			{"skip outside gated namespaces", member, pod("free", skip), false},
			{"skip in the release namespace", member, pod("meles", skip), false},
			{"nodeName", member, pod("enforce", onNode), true},
			{"nodeName by the kubelet", node, pod("enforce", onNode), false},
			{"nodeName with skip where allowed", member, pod("skipok", skip, onNode), false},
			{"nodeName outside gated namespaces", member, pod("free", onNode), false},
			{"gated, audit in enforce (webhook down)", member, pod("enforce", gate(v1alpha1.GateAudit)), true},
			{"gated, audit in audit", member, pod("audit", gate(v1alpha1.GateAudit)), false},
			{"gated, enforce in audit", member, pod("audit", gate(v1alpha1.GateEnforce)), false},
			{"plain pod", member, pod("enforce"), false},
		} {
			check(t, tt.what, tt.c.Create(ctx, tt.p), tt.refused)
		}
	})

	// update creates a held pod in ns as the admin, applies change as c and
	// reports the error.
	update := func(ns string, c client.Client, create func(*corev1.Pod), change func(*corev1.Pod)) error {
		p := pod(ns, create)
		if err := admin.Create(ctx, p); err != nil {
			t.Fatal(err)
		}
		orig := p.DeepCopy()
		change(p)
		return c.Patch(ctx, p, client.MergeFrom(orig))
	}
	ungate := func(p *corev1.Pod) { p.Spec.SchedulingGates = nil }
	release := func(p *corev1.Pod) { ungate(p); p.Spec.Containers[0].Image += "@sha256:" + strings.Repeat("a", 64) }
	newImage := func(p *corev1.Pod) { p.Spec.Containers[0].Image = "evil:latest" }
	toAudit := func(p *corev1.Pod) { p.Annotations[v1alpha1.AnnotationGateMode] = v1alpha1.GateAudit }
	label := func(p *corev1.Pod) { p.Labels = map[string]string{"team": "shop"} }
	enforce := gate(v1alpha1.GateEnforce)

	t.Run("update", func(t *testing.T) {
		for _, tt := range []struct {
			what    string
			ns      string
			c       client.Client
			create  func(*corev1.Pod)
			change  func(*corev1.Pod)
			refused bool
		}{
			{"remove the gate", "enforce", member, enforce, ungate, true},
			{"release by the operator", "enforce", operator, enforce, release, false},
			{"remove the gate outside gated namespaces", "free", member, enforce, ungate, false},
			{"mode to audit", "enforce", member, enforce, toAudit, true},
			{"mode to audit by the operator", "enforce", operator, enforce, toAudit, false},
			{"mode to audit in audit", "audit", member, enforce, toAudit, false},
			{"remove the mode (enforce applies)", "enforce", member, enforce, func(p *corev1.Pod) { p.Annotations = nil }, false},
			{"change the image", "enforce", member, func(*corev1.Pod) {}, newImage, true},
			{"change the image of a held pod", "enforce", member, enforce, newImage, true},
			{"change the image where skip is allowed", "skipok", member, skip, newImage, false},
			{"change the image outside gated namespaces", "free", member, func(*corev1.Pod) {}, newImage, false},
			{"label a held pod", "enforce", member, enforce, label, false},
		} {
			check(t, tt.what, update(tt.ns, tt.c, tt.create, tt.change), tt.refused)
		}
	})
}

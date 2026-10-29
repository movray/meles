package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/movray/meles/api/v1alpha1"
	"github.com/movray/meles/internal/store"
)

// TestKubeReports needs the envtest binaries (make test-envtest).
func TestKubeReports(t *testing.T) {
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
	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop"}}); err != nil {
		t.Fatal(err)
	}
	rep := malwareReport("shop", "web", v1alpha1.StatusClean)
	if err := c.Create(ctx, &rep); err != nil {
		t.Fatal(err)
	}

	k, err := NewKubeReports(cfg, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.List(ctx); !errors.Is(err, errNotSynced) {
		t.Errorf("List before sync: %v, want errNotSynced", err)
	}
	go k.Start(ctx)
	var list []v1alpha1.MalwareReport
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if list, err = k.List(ctx); err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil || len(list) != 1 || list[0].Report.Workload.Name != "web" {
		t.Fatalf("List = %d reports, %v", len(list), err)
	}

	if err := k.RequestRescan(ctx, "shop", rep.Name); err != nil {
		t.Fatal(err)
	}
	var got v1alpha1.MalwareReport
	if err := c.Get(ctx, client.ObjectKeyFromObject(&rep), &got); err != nil || !rescanPending(&got) {
		t.Errorf("annotations after RequestRescan: %v, %v", got.Annotations, err)
	}
	if _, err := k.Get(ctx, "shop", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get missing: %v", err)
	}
	if err := k.RequestRescan(ctx, "shop", "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RequestRescan missing: %v", err)
	}

	// Ignore rules: one applied with kubectl, two created from the UI.
	expires := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	external := &v1alpha1.ClusterMalwareIgnore{ObjectMeta: metav1.ObjectMeta{Name: "known-harmless"},
		Spec: v1alpha1.IgnoreSpec{Rules: []v1alpha1.IgnoreRule{{Path: "/usr/src/php.tar.xz", Reason: "PHP test quine", Expires: expires}}}}
	if err := c.Create(ctx, external); err != nil {
		t.Fatal(err)
	}
	ign := k.Ignores()
	rule := v1alpha1.IgnoreRule{Path: "/usr/bin/xmrig", Reason: "miner detector test data", Expires: expires}
	local, err := ign.Create(ctx, "shop", rule, "ops@example.com")
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := ign.Create(ctx, "", rule, "ops@example.com")
	if err != nil || !strings.HasPrefix(cluster, uiPrefix) {
		t.Fatalf("create cluster-wide: %q, %v", cluster, err)
	}
	var objs []IgnoreObject
	for deadline := time.Now().Add(30 * time.Second); len(objs) < 3 && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		objs, _ = ign.List(ctx)
	}
	if len(objs) != 3 || objs[0].Namespace != "" || objs[2].Namespace != "shop" || objs[2].Name != local || !objs[2].Managed() || objs[2].CreatedBy() != "ops@example.com" {
		t.Fatalf("List = %+v", objs)
	}
	rules, err := ign.ClusterRules(ctx)
	if err != nil || rules.Len() != 2 {
		t.Errorf("ClusterRules: %d rules, %v; want the two ClusterMalwareIgnores", rules.Len(), err)
	}

	if err := ign.Delete(ctx, "", "known-harmless"); !errors.Is(err, errNotManaged) {
		t.Errorf("delete external: %v", err)
	}
	if err := ign.Delete(ctx, "shop", local); err != nil {
		t.Errorf("delete: %v", err)
	}
	if err := c.Get(ctx, client.ObjectKey{Namespace: "shop", Name: local}, &v1alpha1.MalwareIgnore{}); !apierrors.IsNotFound(err) {
		t.Errorf("MalwareIgnore still there: %v", err)
	}
	if err := ign.Delete(ctx, "shop", local); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete again: %v", err)
	}
}

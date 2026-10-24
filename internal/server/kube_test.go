package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/store"
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

	k, err := NewKubeReports(cfg)
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
}

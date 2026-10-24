package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/store"
)

// ClusterReports gives the server the MalwareReports the operator writes.
type ClusterReports interface {
	List(ctx context.Context) ([]v1alpha1.MalwareReport, error)
	// Get returns store.ErrNotFound (wrapped) for a missing report.
	Get(ctx context.Context, namespace, name string) (*v1alpha1.MalwareReport, error)
	// RequestRescan sets the meles.io/rescan annotation.
	RequestRescan(ctx context.Context, namespace, name string) error
}

// errNotSynced is returned until the reports were read from the API server.
var errNotSynced = errors.New("the MalwareReports of the cluster are not loaded yet (is the CRD installed and may the server list them?)")

// KubeReports reads MalwareReports from the Kubernetes API through an
// informer cache.
type KubeReports struct {
	cache  cache.Cache
	client client.Client
	synced atomic.Bool
}

// NewKubeReports creates the cache; Start fills it.
func NewKubeReports(cfg *rest.Config) (*KubeReports, error) {
	scheme := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	c, err := cache.New(cfg, cache.Options{Scheme: scheme, DefaultTransform: cache.TransformStripManagedFields()})
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}
	cl, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}
	// Register the informer before Start.
	if _, err := c.GetInformer(context.Background(), &v1alpha1.MalwareReport{}); err != nil {
		return nil, fmt.Errorf("informer for MalwareReports: %w", err)
	}
	return &KubeReports{cache: c, client: cl}, nil
}

// Start runs the cache until ctx is canceled.
func (k *KubeReports) Start(ctx context.Context) error {
	go func() {
		if k.cache.WaitForCacheSync(ctx) {
			k.synced.Store(true)
		}
	}()
	return k.cache.Start(ctx)
}

func (k *KubeReports) List(ctx context.Context) ([]v1alpha1.MalwareReport, error) {
	if !k.synced.Load() {
		return nil, errNotSynced
	}
	var list v1alpha1.MalwareReportList
	if err := k.cache.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list MalwareReports: %w", err)
	}
	return list.Items, nil
}

func (k *KubeReports) Get(ctx context.Context, namespace, name string) (*v1alpha1.MalwareReport, error) {
	if !k.synced.Load() {
		return nil, errNotSynced
	}
	var rep v1alpha1.MalwareReport
	if err := k.cache.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &rep); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("MalwareReport %s/%s: %w", namespace, name, store.ErrNotFound)
		}
		return nil, fmt.Errorf("get MalwareReport %s/%s: %w", namespace, name, err)
	}
	return &rep, nil
}

func (k *KubeReports) RequestRescan(ctx context.Context, namespace, name string) error {
	rep := &v1alpha1.MalwareReport{}
	rep.Namespace, rep.Name = namespace, name
	patch := fmt.Sprintf(`{"metadata":{"annotations":{%q:%q}}}`, v1alpha1.AnnotationRescan, time.Now().UTC().Format(time.RFC3339))
	if err := k.client.Patch(ctx, rep, client.RawPatch(types.MergePatchType, []byte(patch))); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("MalwareReport %s/%s: %w", namespace, name, store.ErrNotFound)
		}
		return fmt.Errorf("annotate MalwareReport %s/%s: %w", namespace, name, err)
	}
	return nil
}

// Status values of cluster reports in the UI, matching the run statuses
// where they mean the same.
const statusIncomplete = "incomplete"

// clusterStatus maps a report status to the UI status.
func clusterStatus(s string) string {
	switch s {
	case v1alpha1.StatusClean:
		return store.StatusClean
	case v1alpha1.StatusInfected:
		return store.StatusInfected
	case v1alpha1.StatusIncomplete:
		return statusIncomplete
	}
	return store.StatusError
}

// clusterStatuses in the order of urgency.
var clusterStatuses = []string{store.StatusInfected, store.StatusError, statusIncomplete, store.StatusClean}

// clusterCounts counts reports by UI status.
type clusterCounts struct {
	Total, Infected, Error, Incomplete, Clean int
}

func countReports(reps []v1alpha1.MalwareReport) clusterCounts {
	var c clusterCounts
	for _, r := range reps {
		c.Total++
		switch clusterStatus(r.Report.Summary.Status) {
		case store.StatusInfected:
			c.Infected++
		case store.StatusError:
			c.Error++
		case statusIncomplete:
			c.Incomplete++
		default:
			c.Clean++
		}
	}
	return c
}

// clusterFilter selects reports for the cluster page.
type clusterFilter struct {
	Status    string
	Namespace string
	Query     string
}

func (f clusterFilter) match(r *v1alpha1.MalwareReport) bool {
	if f.Status != "" && clusterStatus(r.Report.Summary.Status) != f.Status {
		return false
	}
	if f.Namespace != "" && r.Namespace != f.Namespace {
		return false
	}
	if q := strings.ToLower(f.Query); q != "" {
		d := r.Report
		hay := strings.ToLower(strings.Join([]string{r.Namespace, d.Workload.Name, d.Workload.Container, d.Image.Repository, d.Image.Reference, d.Image.Digest}, " "))
		if !strings.Contains(hay, q) {
			return false
		}
	}
	return true
}

// sortReports orders by urgency, then namespace, workload and container.
func sortReports(reps []v1alpha1.MalwareReport) {
	rank := map[string]int{}
	for i, s := range clusterStatuses {
		rank[s] = i
	}
	slices.SortFunc(reps, func(a, b v1alpha1.MalwareReport) int {
		return cmp.Or(
			cmp.Compare(rank[clusterStatus(a.Report.Summary.Status)], rank[clusterStatus(b.Report.Summary.Status)]),
			cmp.Compare(a.Namespace, b.Namespace),
			cmp.Compare(a.Report.Workload.Name, b.Report.Workload.Name),
			cmp.Compare(a.Report.Workload.Container, b.Report.Workload.Container),
		)
	})
}

func namespaces(reps []v1alpha1.MalwareReport) []string {
	var ns []string
	for _, r := range reps {
		ns = append(ns, r.Namespace)
	}
	slices.Sort(ns)
	return slices.Compact(ns)
}

func rescanPending(r *v1alpha1.MalwareReport) bool {
	_, ok := r.Annotations[v1alpha1.AnnotationRescan]
	return ok
}

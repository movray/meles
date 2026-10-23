// Package operator scans the images of all pods in the cluster and writes
// the results as MalwareReports, one per workload and container. Every image
// digest is scanned once; further workloads with the same image get a copy
// of the result.
package operator

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

// ImageScanner scans one image reference; *scan.Scanner implements it.
type ImageScanner interface {
	Scan(ctx context.Context, ref string, platforms source.PlatformFilter, progress func(scan.Progress)) (*scan.Report, error)
}

// PlatformsNodes selects the architectures of the cluster's nodes.
const PlatformsNodes = "nodes"

// Reconciler writes the MalwareReports of a pod's containers.
type Reconciler struct {
	Client  client.Client
	Scanner ImageScanner
	// Version of meles, recorded in the reports.
	Version string
	// Platforms is PlatformsNodes, "all" or a list such as "linux/amd64".
	Platforms string
	// Workers is the number of pods reconciled (and images scanned) in
	// parallel.
	Workers int
	// ScanTimeout bounds a single image scan.
	ScanTimeout time.Duration
	// RetryAfter is the wait before an image whose scan failed is retried.
	RetryAfter time.Duration
	Logger     *slog.Logger

	scans singleflight.Group
	// results remembers recent scan results by digest and platform filter:
	// the cache of the client may not yet show a report just written.
	mu      sync.Mutex
	results map[string]result
	order   []string
}

// maxResults bounds the results kept in memory; reports keep them anyway.
const maxResults = 1000

func (r *Reconciler) remembered(key string) (result, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res, ok := r.results[key]
	return res, ok
}

func (r *Reconciler) remember(key string, res result) {
	if res.summary.Status == v1alpha1.StatusError {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.results == nil {
		r.results = map[string]result{}
	}
	if _, ok := r.results[key]; !ok {
		r.order = append(r.order, key)
	}
	r.results[key] = res
	for len(r.order) > maxResults {
		delete(r.results, r.order[0])
		r.order = r.order[1:]
	}
}

// SetupWithManager registers the reconciler. Pods are reconciled when they
// are created and whenever the images their containers run change.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("malwarereport").
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				return !slices.Equal(imageIDs(e.ObjectOld.(*corev1.Pod)), imageIDs(e.ObjectNew.(*corev1.Pod)))
			},
			DeleteFunc: func(event.DeleteEvent) bool { return false },
		})).
		WithOptions(controller.Options{MaxConcurrentReconciles: max(r.Workers, 1)}).
		Complete(r)
}

func imageIDs(p *corev1.Pod) []string {
	var ids []string
	for _, s := range append(slices.Clone(p.Status.InitContainerStatuses), p.Status.ContainerStatuses...) {
		ids = append(ids, s.Name+"="+s.ImageID)
	}
	return ids
}

// Reconcile writes or updates the reports of all containers of a pod.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pod corev1.Pod
	if err := r.Client.Get(ctx, req.NamespacedName, &pod); err != nil {
		// A deleted pod's reports belong to its workload and are garbage
		// collected with it.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	owner, err := resolveWorkload(ctx, r.Client, &pod)
	if err != nil {
		return ctrl.Result{}, err
	}

	var requeue time.Duration
	statuses := []struct {
		list []corev1.ContainerStatus
		init bool
	}{{pod.Status.InitContainerStatuses, true}, {pod.Status.ContainerStatuses, false}}
	for _, group := range statuses {
		for _, cs := range group.list {
			if cs.ImageID == "" {
				continue // not pulled yet; the next status update brings it
			}
			wait, err := r.reconcileContainer(ctx, &pod, owner, cs, group.init)
			if err != nil {
				return ctrl.Result{}, fmt.Errorf("container %s: %w", cs.Name, err)
			}
			if wait > 0 && (requeue == 0 || wait < requeue) {
				requeue = wait
			}
		}
	}
	return ctrl.Result{RequeueAfter: requeue}, nil
}

// reconcileContainer makes sure the report of one container describes the
// image it runs. It returns when to look again, for failed scans.
func (r *Reconciler) reconcileContainer(ctx context.Context, pod *corev1.Pod, owner metav1.OwnerReference, cs corev1.ContainerStatus, init bool) (time.Duration, error) {
	img, pullable := parseImageID(cs.ImageID, cs.Image)
	name := reportName(owner.Kind, owner.Name, cs.Name)

	var existing v1alpha1.MalwareReport
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: name}, &existing)
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return 0, fmt.Errorf("get report %s: %w", name, err)
	case existing.Report.Image.Digest == img.digest:
		if existing.Report.Summary.Status != v1alpha1.StatusError {
			return 0, nil // up to date
		}
		if wait := time.Until(existing.Report.ScannedAt.Add(r.RetryAfter)); wait > 0 {
			return wait, nil
		}
	}

	var res result
	switch {
	case !pullable:
		res = resultFromError(fmt.Errorf("image %q has no registry reference (imported into the node?); it cannot be pulled and scanned", cs.ImageID), r.Version)
	default:
		res, err = r.resultFor(ctx, img)
		if err != nil {
			return 0, err
		}
	}

	rep := &v1alpha1.MalwareReport{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: name}}
	_, err = ctrl.CreateOrUpdate(ctx, r.Client, rep, func() error {
		if rep.Labels == nil {
			rep.Labels = map[string]string{}
		}
		rep.Labels["app.kubernetes.io/managed-by"] = "meles-operator"
		rep.Labels[v1alpha1.LabelWorkloadKind] = labelValue(owner.Kind)
		rep.Labels[v1alpha1.LabelWorkloadName] = labelValue(owner.Name)
		rep.Labels[v1alpha1.LabelContainer] = labelValue(cs.Name)
		rep.Labels[v1alpha1.LabelDigest] = digestLabel(img.digest)
		rep.OwnerReferences = []metav1.OwnerReference{owner}
		rep.Report.Workload = v1alpha1.Workload{Kind: owner.Kind, Name: owner.Name, Container: cs.Name, InitContainer: init}
		rep.Report.Image = v1alpha1.Image{Repository: img.repository, Reference: img.reference, Digest: img.digest}
		res.apply(&rep.Report)
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("write report %s: %w", name, err)
	}
	r.log().Info("report written", "namespace", pod.Namespace, "report", name, "image", img.ref, "status", res.summary.Status, "findings", res.summary.Findings)
	if res.summary.Status == v1alpha1.StatusError {
		return r.RetryAfter, nil
	}
	return 0, nil
}

// resultFor returns the scan result of an image: from another report of the
// same digest and platforms if there is one, otherwise from a new scan.
// Concurrent requests for the same image share one scan.
func (r *Reconciler) resultFor(ctx context.Context, img image) (result, error) {
	platforms, err := r.platforms(ctx)
	if err != nil {
		return result{}, err
	}
	key := img.digest + "|" + platforms
	v, err, _ := r.scans.Do(key, func() (any, error) {
		if res, ok := r.remembered(key); ok {
			return res, nil
		}
		if res, ok, err := r.reuse(ctx, img.digest, platforms); err != nil || ok {
			if ok {
				r.remember(key, res)
			}
			return res, err
		}
		sctx, cancel := context.WithTimeout(ctx, r.ScanTimeout)
		defer cancel()
		filter, err := source.ParsePlatforms(platforms)
		if err != nil {
			return result{}, err
		}
		start := time.Now()
		rep, err := r.Scanner.Scan(sctx, img.ref, filter, nil)
		if err != nil {
			r.log().Warn("scan failed", "image", img.ref, "err", err)
			return resultFromError(err, r.Version), nil
		}
		r.log().Info("image scanned", "image", img.ref, "platforms", platforms, "files", rep.Files(), "findings", len(rep.Findings()), "duration", time.Since(start).Round(time.Millisecond))
		res := resultFromReport(rep, platforms, r.Version)
		r.remember(key, res)
		return res, nil
	})
	if err != nil {
		return result{}, err
	}
	return v.(result), nil
}

// reuse looks for a report of another workload with the same image, scanned
// for the same platforms without error.
func (r *Reconciler) reuse(ctx context.Context, digest, platforms string) (result, bool, error) {
	var list v1alpha1.MalwareReportList
	if err := r.Client.List(ctx, &list, client.MatchingLabels{v1alpha1.LabelDigest: digestLabel(digest)}); err != nil {
		return result{}, false, fmt.Errorf("list reports: %w", err)
	}
	for _, rep := range list.Items {
		d := rep.Report
		if d.Image.Digest == digest && d.Summary.Status != v1alpha1.StatusError && d.PlatformFilter == platforms {
			return resultFromData(d), true, nil
		}
	}
	return result{}, false, nil
}

// platforms returns the platform filter as a sorted, comma-separated list
// (or "all"), for the cache key and the scan.
func (r *Reconciler) platforms(ctx context.Context) (string, error) {
	if r.Platforms != PlatformsNodes {
		f, err := source.ParsePlatforms(r.Platforms)
		if err != nil {
			return "", err
		}
		return f.String(), nil
	}
	var nodes corev1.NodeList
	if err := r.Client.List(ctx, &nodes); err != nil {
		return "", fmt.Errorf("list nodes: %w", err)
	}
	seen := map[string]bool{}
	for _, n := range nodes.Items {
		if os, arch := n.Status.NodeInfo.OperatingSystem, n.Status.NodeInfo.Architecture; os != "" && arch != "" {
			seen[os+"/"+arch] = true
		}
	}
	if len(seen) == 0 {
		return "", fmt.Errorf("no node reports its platform")
	}
	list := make([]string, 0, len(seen))
	for p := range seen {
		list = append(list, p)
	}
	sort.Strings(list)
	return strings.Join(list, ","), nil
}

func (r *Reconciler) log() *slog.Logger {
	if r.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return r.Logger
}

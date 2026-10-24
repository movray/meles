// Package operator scans the images of all pods in the cluster and writes
// the results as MalwareReports, one per workload and container. Every image
// digest is scanned once; further workloads with the same image get a copy
// of the result. Results are rescanned when the signature database changed
// (at most once per RescanInterval), after RetryAfter if the scan failed and
// after RetryIncompleteAfter if files were skipped, or right away if the
// report is annotated with meles.io/rescan. A new result is copied into all
// reports of the digest.
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
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

// ImageScanner scans one image reference; *scan.Scanner implements it.
type ImageScanner interface {
	Scan(ctx context.Context, ref string, platforms source.PlatformFilter, progress func(scan.Progress)) (*scan.Report, error)
}

// EngineVersioner reports the current engine and signature version;
// engine.Engine implements it.
type EngineVersioner interface {
	Version(ctx context.Context) (engine.Version, error)
}

// versionTTL is how long the engine version is cached. clamd reloads its
// database at most every few minutes.
const versionTTL = 5 * time.Minute

// PlatformsNodes selects the architectures of the cluster's nodes.
const PlatformsNodes = "nodes"

// Reconciler writes the MalwareReports of a pod's containers.
type Reconciler struct {
	Client  client.Client
	Scanner ImageScanner
	// Engine is asked for the signature version, to find outdated reports.
	Engine EngineVersioner
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
	// RetryIncompleteAfter is the wait before an image with skipped files is
	// rescanned. Usually clamd's limits are the cause, so a retry only helps
	// once they were raised, and it scans the large files again.
	RetryIncompleteAfter time.Duration
	// RescanInterval is the minimum age of a result before it is rescanned
	// because the signature database changed. 0 disables rescans.
	RescanInterval time.Duration
	Logger         *slog.Logger

	scans singleflight.Group
	// results remembers recent scan results by digest and platform filter:
	// the cache of the client may not yet show a report just written.
	mu      sync.Mutex
	results map[string]result
	order   []string

	verMu sync.Mutex
	ver   engine.Version
	verAt time.Time
	// versionTTL overrides the constant in tests.
	versionTTL time.Duration
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
// are created, whenever the images their containers run change, and when a
// report of their workload is deleted or annotated with meles.io/rescan.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("malwarereport").
		For(&corev1.Pod{}, builder.WithPredicates(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				return !slices.Equal(imageIDs(e.ObjectOld.(*corev1.Pod)), imageIDs(e.ObjectNew.(*corev1.Pod)))
			},
			DeleteFunc: func(event.DeleteEvent) bool { return false },
		})).
		Watches(&v1alpha1.MalwareReport{}, handler.EnqueueRequestsFromMapFunc(r.podsOfReport), builder.WithPredicates(predicate.Funcs{
			CreateFunc:  func(e event.CreateEvent) bool { return rescanRequested(e.Object) },
			UpdateFunc:  func(e event.UpdateEvent) bool { return rescanRequested(e.ObjectNew) },
			GenericFunc: func(event.GenericEvent) bool { return false },
		})).
		// Changed rules apply to the reports right away; status updates of
		// the ignore objects do not change their generation.
		Watches(&v1alpha1.MalwareIgnore{}, handler.EnqueueRequestsFromMapFunc(r.podsOfIgnore), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&v1alpha1.ClusterMalwareIgnore{}, handler.EnqueueRequestsFromMapFunc(r.podsOfIgnore), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		WithOptions(controller.Options{MaxConcurrentReconciles: max(r.Workers, 1)}).
		Complete(r)
}

func rescanRequested(obj client.Object) bool {
	_, ok := obj.GetAnnotations()[v1alpha1.AnnotationRescan]
	return ok
}

// podsOfReport maps a deleted report, or one annotated for a rescan, to the
// pods of its workload, so that the report is written again.
func (r *Reconciler) podsOfReport(ctx context.Context, obj client.Object) []reconcile.Request {
	owners := obj.GetOwnerReferences()
	if len(owners) == 0 {
		return nil
	}
	var pods corev1.PodList
	if err := r.Client.List(ctx, &pods, client.InNamespace(obj.GetNamespace())); err != nil {
		r.log().Warn("list pods of deleted report", "namespace", obj.GetNamespace(), "report", obj.GetName(), "err", err)
		return nil
	}
	var reqs []reconcile.Request
	for i := range pods.Items {
		pod := &pods.Items[i]
		if owner, err := resolveWorkload(ctx, r.Client, pod); err == nil && owner.UID == owners[0].UID {
			reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(pod)})
		}
	}
	return reqs
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
	if pod.DeletionTimestamp != nil {
		// Its workload may be gone already; a report written now would be
		// garbage collected again, and its deletion would bring us back.
		return ctrl.Result{}, nil
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
// image it runs and is not outdated. It returns when to look again.
func (r *Reconciler) reconcileContainer(ctx context.Context, pod *corev1.Pod, owner metav1.OwnerReference, cs corev1.ContainerStatus, init bool) (time.Duration, error) {
	img, pullable := parseImageID(cs.ImageID, cs.Image)
	name := reportName(owner.Kind, owner.Name, cs.Name)
	parent := parentOf(pod, owner)

	key := client.ObjectKey{Namespace: pod.Namespace, Name: name}
	now := time.Now()
	rules, err := r.rulesFor(ctx, pod.Namespace, now)
	if err != nil {
		return 0, err
	}
	// Reports are evaluated again when the next rule expires.
	expiry := time.Duration(0)
	if next := rules.NextExpiry(now); !next.IsZero() {
		expiry = time.Until(next) + time.Second
	}
	var existing v1alpha1.MalwareReport
	err = r.Client.Get(ctx, key, &existing)
	force := err == nil && rescanRequested(&existing)
	switch {
	case apierrors.IsNotFound(err):
	case err != nil:
		return 0, fmt.Errorf("get report %s: %w", name, err)
	case existing.Report.Image.Digest == img.digest && !force:
		cur := resultFromData(existing.Report).withIgnore(rules, img, now)
		stale, wait, err := r.stale(ctx, cur)
		if err != nil {
			return 0, err
		}
		if !stale {
			wait = minWait(wait, expiry)
			// Write only if the rules or the workload fields (reports
			// written before Parent existed) changed the report.
			want := existing.Report.DeepCopy()
			cur.apply(want)
			want.Workload.Parent = parent
			if equality.Semantic.DeepEqual(*want, existing.Report) {
				return wait, nil
			}
			return wait, r.writeReport(ctx, pod, owner, cs, init, img, parent, name, cur)
		}
	}

	var res result
	switch {
	case !pullable:
		res = resultFromError(fmt.Errorf("image %q has no registry reference (imported into the node?); it cannot be pulled and scanned", cs.ImageID), r.Version)
	default:
		res, err = r.resultFor(ctx, img, force, key)
		if err != nil {
			return 0, err
		}
	}

	res = res.withIgnore(rules, img, now)
	if err := r.writeReport(ctx, pod, owner, cs, init, img, parent, name, res); err != nil {
		return 0, err
	}
	r.log().Info("report written", "namespace", pod.Namespace, "report", name, "image", img.ref, "status", res.summary.Status, "findings", res.summary.Findings, "ignored", res.summary.Ignored)
	stale, wait, err := r.stale(ctx, res)
	if stale {
		// Due again already (retry shorter than scan and write).
		return time.Second, err
	}
	return minWait(wait, expiry), err
}

// minWait returns the shorter of two waits, where 0 means none.
func minWait(a, b time.Duration) time.Duration {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}

// writeReport creates or updates the report of a container with res.
func (r *Reconciler) writeReport(ctx context.Context, pod *corev1.Pod, owner metav1.OwnerReference, cs corev1.ContainerStatus, init bool, img image, parent, name string, res result) error {
	rep := &v1alpha1.MalwareReport{ObjectMeta: metav1.ObjectMeta{Namespace: pod.Namespace, Name: name}}
	_, err := ctrl.CreateOrUpdate(ctx, r.Client, rep, func() error {
		if rep.Labels == nil {
			rep.Labels = map[string]string{}
		}
		delete(rep.Annotations, v1alpha1.AnnotationRescan)
		rep.Labels["app.kubernetes.io/managed-by"] = "meles-operator"
		rep.Labels[v1alpha1.LabelWorkloadKind] = labelValue(owner.Kind)
		rep.Labels[v1alpha1.LabelWorkloadName] = labelValue(owner.Name)
		rep.Labels[v1alpha1.LabelContainer] = labelValue(cs.Name)
		rep.Labels[v1alpha1.LabelDigest] = digestLabel(img.digest)
		rep.OwnerReferences = []metav1.OwnerReference{owner}
		rep.Report.Workload = v1alpha1.Workload{Kind: owner.Kind, Name: owner.Name, Parent: parent, Container: cs.Name, InitContainer: init}
		rep.Report.Image = v1alpha1.Image{Repository: img.repository, Reference: img.reference, Digest: img.digest}
		res.apply(&rep.Report)
		return nil
	})
	if err != nil {
		return fmt.Errorf("write report %s: %w", name, err)
	}
	return nil
}

// stale reports whether res needs a new scan: a failed scan after
// RetryAfter, an incomplete one after RetryIncompleteAfter, any other after
// RescanInterval if the engine or its signatures changed since. If res is current, wait is when to look again
// (0: not before the next pod event).
func (r *Reconciler) stale(ctx context.Context, res result) (stale bool, wait time.Duration, err error) {
	retry := time.Duration(0)
	switch res.summary.Status {
	case v1alpha1.StatusError:
		retry = r.RetryAfter
	case v1alpha1.StatusIncomplete:
		retry = r.RetryIncompleteAfter
	}
	if retry > 0 {
		if wait := time.Until(res.scannedAt.Add(retry)); wait > 0 {
			return false, wait, nil
		}
		return true, 0, nil
	}
	if r.RescanInterval <= 0 {
		return false, 0, nil
	}
	if wait := time.Until(res.scannedAt.Add(r.RescanInterval)); wait > 0 {
		return false, wait, nil
	}
	v, err := r.engineVersion(ctx)
	if err != nil {
		return false, 0, err
	}
	if v.Engine == res.scanner.Engine && v.Signatures == res.scanner.Signatures {
		return false, r.RescanInterval, nil
	}
	return true, 0, nil
}

// engineVersion returns the engine version, cached for versionTTL.
func (r *Reconciler) engineVersion(ctx context.Context) (engine.Version, error) {
	ttl := r.versionTTL
	if ttl == 0 {
		ttl = versionTTL
	}
	r.verMu.Lock()
	defer r.verMu.Unlock()
	if time.Since(r.verAt) < ttl {
		return r.ver, nil
	}
	v, err := r.Engine.Version(ctx)
	if err != nil {
		return engine.Version{}, fmt.Errorf("engine version: %w", err)
	}
	r.ver, r.verAt = v, time.Now()
	return v, nil
}

// resultFor returns the scan result of an image: from another current report
// of the same digest and platforms if there is one, otherwise (or if force)
// from a new scan, which is then copied into the other reports of the digest
// except self. Concurrent requests for the same image share one scan.
func (r *Reconciler) resultFor(ctx context.Context, img image, force bool, self client.ObjectKey) (result, error) {
	platforms, err := r.platforms(ctx)
	if err != nil {
		return result{}, err
	}
	key := img.digest + "|" + platforms
	flight := key
	if force {
		// Must not join a request that returns a cached result.
		flight += "|force"
	}
	v, err, _ := r.scans.Do(flight, func() (any, error) {
		if res, ok := r.remembered(key); ok && !force {
			stale, _, err := r.stale(ctx, res)
			if err != nil {
				return result{}, err
			}
			if !stale {
				return res, nil
			}
		}
		if !force {
			if res, ok, err := r.reuse(ctx, img.digest, platforms); err != nil || ok {
				if ok {
					r.remember(key, res)
				}
				return res, err
			}
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
		r.propagate(ctx, img.digest, res, self)
		return res, nil
	})
	if err != nil {
		return result{}, err
	}
	return v.(result), nil
}

// reuse looks for a current report of another workload with the same image,
// scanned for the same platforms without error.
func (r *Reconciler) reuse(ctx context.Context, digest, platforms string) (result, bool, error) {
	var list v1alpha1.MalwareReportList
	if err := r.Client.List(ctx, &list, client.MatchingLabels{v1alpha1.LabelDigest: digestLabel(digest)}); err != nil {
		return result{}, false, fmt.Errorf("list reports: %w", err)
	}
	for _, rep := range list.Items {
		d := rep.Report
		if d.Image.Digest != digest || d.Summary.Status == v1alpha1.StatusError || d.PlatformFilter != platforms {
			continue
		}
		res := resultFromData(d)
		stale, _, err := r.stale(ctx, res)
		if err != nil {
			return result{}, false, err
		}
		if !stale {
			return res, true, nil
		}
	}
	return result{}, false, nil
}

// propagate copies a new scan result into the other reports of the digest
// (except self, which the caller writes), so that they do not keep an older
// result until they are due themselves. Failures are only logged: those
// reports are rescanned or copied again later.
func (r *Reconciler) propagate(ctx context.Context, digest string, res result, self client.ObjectKey) {
	var list v1alpha1.MalwareReportList
	if err := r.Client.List(ctx, &list, client.MatchingLabels{v1alpha1.LabelDigest: digestLabel(digest)}); err != nil {
		r.log().Warn("list reports to update", "digest", digest, "err", err)
		return
	}
	for i := range list.Items {
		rep := &list.Items[i]
		d := rep.Report
		// Error reports have no platform filter; they take any result.
		if client.ObjectKeyFromObject(rep) == self || d.Image.Digest != digest || (d.PlatformFilter != "" && d.PlatformFilter != res.filter) {
			continue
		}
		now := time.Now()
		rules, err := r.rulesFor(ctx, rep.Namespace, now)
		if err != nil {
			r.log().Warn("ignore rules for report", "namespace", rep.Namespace, "report", rep.Name, "err", err)
			continue
		}
		cur := res.withIgnore(rules, image{repository: d.Image.Repository, digest: digest}, now)
		cur.apply(&rep.Report)
		delete(rep.Annotations, v1alpha1.AnnotationRescan)
		if err := r.Client.Update(ctx, rep); err != nil {
			r.log().Warn("update report with new result", "namespace", rep.Namespace, "report", rep.Name, "err", err)
			continue
		}
		r.log().Info("report updated", "namespace", rep.Namespace, "report", rep.Name, "status", cur.summary.Status, "findings", cur.summary.Findings, "ignored", cur.summary.Ignored)
	}
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

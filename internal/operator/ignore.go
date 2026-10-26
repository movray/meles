package operator

import (
	"context"
	"fmt"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/ignore"
)

// rulesFor returns the valid ignore rules for reports in namespace: those
// of all ClusterMalwareIgnores and of the MalwareIgnores in the namespace.
// Invalid rules are left out; the status of their object says why.
func (r *Reconciler) rulesFor(ctx context.Context, namespace string, now time.Time) (*ignore.Rules, error) {
	var cluster v1alpha1.ClusterMalwareIgnoreList
	if err := r.Client.List(ctx, &cluster); err != nil {
		return nil, fmt.Errorf("list ClusterMalwareIgnores: %w", err)
	}
	var local v1alpha1.MalwareIgnoreList
	if err := r.Client.List(ctx, &local, client.InNamespace(namespace)); err != nil {
		return nil, fmt.Errorf("list MalwareIgnores: %w", err)
	}
	var sets []*ignore.Rules
	for _, o := range cluster.Items {
		rs, _ := ignore.New(ignore.FromSpec(o.Spec, o.Name), o.Name, now)
		sets = append(sets, rs)
	}
	for _, o := range local.Items {
		src := o.Namespace + "/" + o.Name
		rs, _ := ignore.New(ignore.FromSpec(o.Spec, src), src, now)
		sets = append(sets, rs)
	}
	return ignore.Merge(sets...), nil
}

// podsOfIgnore maps a changed MalwareIgnore to the pods of its namespace,
// a ClusterMalwareIgnore to all pods: their reports are evaluated again,
// without a rescan.
func (r *Reconciler) podsOfIgnore(ctx context.Context, obj client.Object) []reconcile.Request {
	var pods corev1.PodList
	var opts []client.ListOption
	if ns := obj.GetNamespace(); ns != "" {
		opts = append(opts, client.InNamespace(ns))
	}
	if err := r.Client.List(ctx, &pods, opts...); err != nil {
		r.log().Warn("list pods for changed ignore rules", "ignore", obj.GetName(), "err", err)
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(pods.Items))
	for i := range pods.Items {
		reqs = append(reqs, reconcile.Request{NamespacedName: client.ObjectKeyFromObject(&pods.Items[i])})
	}
	return reqs
}

// lowPriority enqueues the requests of fn below all other events, as
// controller-runtime does for the initial list: a changed
// ClusterMalwareIgnore enqueues every pod of the cluster, and new pods,
// pods held by the scan gate and finished scans must not wait behind them.
// The queue keeps the highest priority of an item, so a pod event still
// lifts a pod that waits here.
type lowPriority handler.MapFunc

var _ handler.EventHandler = lowPriority(nil)

func (fn lowPriority) enqueue(ctx context.Context, obj client.Object, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	reqs := fn(ctx, obj)
	if pq, ok := q.(priorityqueue.PriorityQueue[reconcile.Request]); ok {
		pq.AddWithOpts(priorityqueue.AddOpts{Priority: new(handler.LowPriority)}, reqs...)
		return
	}
	for _, req := range reqs {
		q.Add(req)
	}
}

func (fn lowPriority) Create(ctx context.Context, e event.CreateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	fn.enqueue(ctx, e.Object, q)
}

func (fn lowPriority) Update(ctx context.Context, e event.UpdateEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	fn.enqueue(ctx, e.ObjectNew, q)
}

func (fn lowPriority) Delete(ctx context.Context, e event.DeleteEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	fn.enqueue(ctx, e.Object, q)
}

func (fn lowPriority) Generic(ctx context.Context, e event.GenericEvent, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	fn.enqueue(ctx, e.Object, q)
}

// IgnoreStatusReconciler validates the rules of MalwareIgnores and
// ClusterMalwareIgnores and writes the result to their status, so that the
// owner of a rule sees why it is not in effect.
type IgnoreStatusReconciler struct {
	Client client.Client
	// Cluster selects ClusterMalwareIgnores instead of MalwareIgnores.
	Cluster bool
}

// SetupWithManager registers the reconciler.
func (r *IgnoreStatusReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr)
	if r.Cluster {
		return b.Named("clustermalwareignore").For(&v1alpha1.ClusterMalwareIgnore{}).Complete(r)
	}
	return b.Named("malwareignore").For(&v1alpha1.MalwareIgnore{}).Complete(r)
}

// Reconcile writes the status of one ignore object. It runs again when a
// rule expires.
func (r *IgnoreStatusReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var obj client.Object
	var spec *v1alpha1.IgnoreSpec
	var status *v1alpha1.IgnoreStatus
	source := req.Name
	if r.Cluster {
		o := &v1alpha1.ClusterMalwareIgnore{}
		obj, spec, status = o, &o.Spec, &o.Status
	} else {
		o := &v1alpha1.MalwareIgnore{}
		obj, spec, status = o, &o.Spec, &o.Status
		source = req.Namespace + "/" + req.Name
	}
	if err := r.Client.Get(ctx, req.NamespacedName, obj); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	now := time.Now()
	rules, errs := ignore.New(ignore.FromSpec(*spec, source), source, now)
	want := v1alpha1.IgnoreStatus{Rules: rules.Len()}
	for _, err := range errs {
		want.Problems = append(want.Problems, err.Error())
	}
	for _, rule := range ignore.FromSpec(*spec, source) {
		if t, err := time.Parse("2006-01-02", rule.Expires); err == nil && now.After(t.Add(24*time.Hour)) {
			want.Problems = append(want.Problems, fmt.Sprintf("rule %s: expired on %s, no longer in effect", rule.Name, rule.Expires))
			want.Rules--
		}
	}
	slices.Sort(want.Problems)
	want.Problems = slices.Compact(want.Problems)
	var res ctrl.Result
	if next := rules.NextExpiry(now); !next.IsZero() {
		res.RequeueAfter = time.Until(next) + time.Second
	}
	if equality.Semantic.DeepEqual(*status, want) {
		return res, nil
	}
	*status = want
	if err := r.Client.Status().Update(ctx, obj); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status of %s: %w", source, err)
	}
	return res, nil
}

package operator

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/priorityqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/movray/meles/api/v1alpha1"
)

func podRequest(name string) reconcile.Request {
	return reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "shop", Name: name}}
}

func TestLowPriority(t *testing.T) {
	all := []reconcile.Request{podRequest("a"), podRequest("b"), podRequest("c")}
	h := lowPriority(func(context.Context, client.Object) []reconcile.Request { return all })
	rule := &v1alpha1.ClusterMalwareIgnore{ObjectMeta: metav1.ObjectMeta{Name: "rule"}}

	q := priorityqueue.New[reconcile.Request]("test")
	defer q.ShutDown()
	h.Update(t.Context(), event.UpdateEvent{ObjectOld: rule, ObjectNew: rule}, q)
	// A new pod, and an event for a pod that waits for the rules.
	q.Add(podRequest("new"))
	q.Add(podRequest("b"))

	var first []string
	for range 2 {
		req, prio, _ := q.GetWithPriority()
		if prio != 0 {
			t.Fatalf("%s came with priority %d before the pod events", req.Name, prio)
		}
		first = append(first, req.Name)
		q.Done(req)
	}
	slices.Sort(first)
	if !slices.Equal(first, []string{"b", "new"}) {
		t.Errorf("first = %v, want the pod events b and new", first)
	}
	for _, want := range []string{"a", "c"} {
		req, prio, _ := q.GetWithPriority()
		if req.Name != want || prio != handler.LowPriority {
			t.Errorf("got %s with priority %d, want %s with %d", req.Name, prio, want, handler.LowPriority)
		}
		q.Done(req)
	}
	if n := q.Len(); n != 0 {
		t.Errorf("%d requests left", n)
	}

	// Without a priority queue the requests are added as usual.
	plain := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer plain.ShutDown()
	h.Delete(t.Context(), event.DeleteEvent{Object: &corev1.Pod{}}, plain)
	if n := plain.Len(); n != len(all) {
		t.Errorf("plain queue has %d requests, want %d", n, len(all))
	}
}

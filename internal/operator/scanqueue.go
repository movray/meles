package operator

import (
	"context"
	"errors"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

// maxQueued bounds the scans waiting for a worker.
const maxQueued = 4096

var errQueueFull = errors.New("scan queue full")

// scanQueue runs image scans outside the reconcile loop. A reconcile that
// needs a new result requests a scan and returns; a large image then holds
// one scan worker, not the reconcilers, so that new pods, deleted reports,
// rescan requests and changed rules are handled meanwhile. Requests for the
// same image share one scan; once it is done, the result is written to the
// image's reports and the waiting pods are reconciled again.
type scanQueue struct {
	mu      sync.Mutex
	pending map[string]*scanJob // queued or running, by result key
	jobs    chan *scanJob
}

type scanJob struct {
	key, platforms string
	img            image
	waiters        map[types.NamespacedName]struct{}
}

func newScanQueue() *scanQueue {
	return &scanQueue{pending: map[string]*scanJob{}, jobs: make(chan *scanJob, maxQueued)}
}

// request queues a scan of img, unless one is queued or running, and
// records pod to be reconciled when it is done.
func (q *scanQueue) request(key, platforms string, img image, pod types.NamespacedName) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j, ok := q.pending[key]; ok {
		j.waiters[pod] = struct{}{}
		return nil
	}
	j := &scanJob{key: key, platforms: platforms, img: img, waiters: map[types.NamespacedName]struct{}{pod: {}}}
	select {
	case q.jobs <- j:
	default:
		return errQueueFull
	}
	q.pending[key] = j
	return nil
}

// waiters returns the pods waiting for a job so far.
func (q *scanQueue) waiters(key string) []types.NamespacedName {
	q.mu.Lock()
	defer q.mu.Unlock()
	j := q.pending[key]
	if j == nil {
		return nil
	}
	out := make([]types.NamespacedName, 0, len(j.waiters))
	for p := range j.waiters {
		out = append(out, p)
	}
	return out
}

// done removes a finished job and returns the pods waiting for it.
func (q *scanQueue) done(key string) []types.NamespacedName {
	out := q.waiters(key)
	q.mu.Lock()
	defer q.mu.Unlock()
	delete(q.pending, key)
	return out
}

// runScans runs workers scan workers until ctx is canceled.
func (r *Reconciler) runScans(ctx context.Context, workers int) error {
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-r.queue.jobs:
					r.runScan(ctx, j)
				}
			}
		})
	}
	wg.Wait()
	return nil
}

// runScan scans one image, remembers the result, writes it to the image's
// reports and reconciles the waiting pods. A failed scan is remembered too:
// the waiting pods write it as Error, and it is retried after RetryAfter.
func (r *Reconciler) runScan(ctx context.Context, j *scanJob) {
	res := r.scan(ctx, j.img, j.platforms, r.queue.waiters(j.key))
	r.remember(j.key, res)
	if res.summary.Status != v1alpha1.StatusError {
		r.propagate(ctx, j.img.digest, res)
	}
	for _, p := range r.queue.done(j.key) {
		select {
		case r.events <- event.GenericEvent{Object: &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.Name}}}:
		case <-ctx.Done():
			return
		}
	}
}

// scan scans img with the pull secrets of pods.
func (r *Reconciler) scan(ctx context.Context, img image, platforms string, pods []types.NamespacedName) result {
	sctx, cancel := context.WithTimeout(ctx, r.ScanTimeout)
	defer cancel()
	filter, err := source.ParsePlatforms(platforms)
	if err != nil {
		return resultFromError(err, r.Version)
	}
	auth, err := r.pullKeychain(ctx, pods)
	if err != nil {
		r.log().Warn("scan failed", "image", img.ref, "err", err)
		return resultFromError(err, r.Version)
	}
	start := time.Now()
	rep, err := r.Scanner.Scan(sctx, img.ref, filter, nil, scan.WithKeychain(auth.keychain))
	if err != nil {
		r.log().Warn("scan failed", "image", img.ref, "err", err)
		return resultFromError(errors.New(r.authHint(err, auth)), r.Version)
	}
	r.log().Info("image scanned", "image", img.ref, "platforms", platforms, "files", rep.Files(), "findings", len(rep.Findings()), "duration", time.Since(start).Round(time.Millisecond))
	return resultFromReport(rep, platforms, r.Version)
}

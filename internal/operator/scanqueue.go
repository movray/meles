package operator

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/event"

	"github.com/movray/meles/api/v1alpha1"
	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/source"
)

// maxQueued bounds the scans waiting for a worker.
const maxQueued = 4096

// engineRetryWaits are the waits before a scan that failed in the engine is
// tried again. Together with the connection retries of the clamd client they
// cover almost 4 minutes, enough for clamd to load its database after a new
// install or while it is replaced by an upgrade.
var engineRetryWaits = []time.Duration{15 * time.Second, 30 * time.Second, time.Minute}

var errQueueFull = errors.New("scan queue full")

// priority orders the scan queue: pods held by the scan gate first, then
// images without a result, then rescans (new signatures, retries).
type priority int

const (
	prioGated priority = iota
	prioNew
	prioRescan
	numPrios
)

// scanQueue runs image scans outside the reconcile loop. A reconcile that
// needs a new result requests a scan and returns; a large image then holds
// one scan worker, not the reconcilers, so that new pods, deleted reports,
// rescan requests and changed rules are handled meanwhile. Requests for the
// same image share one scan; once it is done, the result is written to the
// image's reports and the waiting pods are reconciled again.
type scanQueue struct {
	mu      sync.Mutex
	pending map[string]*scanJob // queued or running, by result key
	queued  [numPrios][]*scanJob
	n       int
	// ready wakes a worker after a request.
	ready chan struct{}
}

type scanJob struct {
	key, platforms string
	img            image
	prio           priority
	running        bool
	// queuedAt is when the scan was requested, started when it began.
	queuedAt, started time.Time
	waiters           map[types.NamespacedName]struct{}
}

func newScanQueue() *scanQueue {
	return &scanQueue{pending: map[string]*scanJob{}, ready: make(chan struct{}, 1)}
}

// request queues a scan of img, unless one is queued or running, and
// records pod to be reconciled when it is done. A queued scan moves up if
// requested with a higher priority.
func (q *scanQueue) request(key, platforms string, img image, prio priority, pod types.NamespacedName) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if j, ok := q.pending[key]; ok {
		j.waiters[pod] = struct{}{}
		if !j.running && prio < j.prio {
			q.queued[j.prio] = slices.DeleteFunc(q.queued[j.prio], func(o *scanJob) bool { return o == j })
			j.prio = prio
			q.queued[prio] = append(q.queued[prio], j)
			q.updateMetrics()
		}
		return nil
	}
	if q.n >= maxQueued {
		return errQueueFull
	}
	j := &scanJob{key: key, platforms: platforms, img: img, prio: prio, queuedAt: time.Now(), waiters: map[types.NamespacedName]struct{}{pod: {}}}
	q.pending[key] = j
	q.queued[prio] = append(q.queued[prio], j)
	q.n++
	q.updateMetrics()
	q.wake()
	return nil
}

func (q *scanQueue) wake() {
	select {
	case q.ready <- struct{}{}:
	default:
	}
}

// next returns the first job of the highest priority, or nil.
func (q *scanQueue) next() *scanJob {
	q.mu.Lock()
	defer q.mu.Unlock()
	for p := range q.queued {
		if len(q.queued[p]) == 0 {
			continue
		}
		j := q.queued[p][0]
		q.queued[p] = q.queued[p][1:]
		q.n--
		j.running, j.started = true, time.Now()
		q.updateMetrics()
		if q.n > 0 {
			q.wake() // for the next idle worker
		}
		return j
	}
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
	q.updateMetrics()
	return out
}

// runScans runs workers scan workers until ctx is canceled.
func (r *Reconciler) runScans(ctx context.Context, workers int) error {
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Go(func() {
			for {
				if j := r.queue.next(); j != nil {
					r.runScan(ctx, j)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-r.queue.ready:
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
	r.recordScan(j, res)
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
	rep, err := r.scanRetrying(ctx, img, filter, auth.keychain)
	if err != nil {
		r.log().Warn("scan failed", "image", img.ref, "err", err)
		if scan.IsEngineError(err) {
			return resultFromError(err, r.Version)
		}
		return resultFromError(errors.New(r.authHint(err, auth)), r.Version)
	}
	r.log().Info("image scanned", "image", img.ref, "platforms", platforms, "files", rep.Files(), "findings", len(rep.Findings()), "duration", time.Since(start).Round(time.Millisecond))
	return resultFromReport(rep, platforms, r.Version)
}

// scanRetrying scans img and tries again if the engine failed, so that a
// clamd that is just starting or being replaced does not end in a report
// with Error. Each attempt may take ScanTimeout. Once the retries were used
// up, the engine counts as down until it answers again: without this, every
// image of a long outage would wait for all retries, and pods held by the
// scan gate would wait for those in front of them.
func (r *Reconciler) scanRetrying(ctx context.Context, img image, filter source.PlatformFilter, keychain authn.Keychain) (*scan.Report, error) {
	waits := r.engineWaits
	if waits == nil {
		waits = engineRetryWaits
	}
	for {
		sctx, cancel := context.WithTimeout(ctx, r.ScanTimeout)
		rep, err := r.Scanner.Scan(sctx, img.ref, filter, nil, scan.WithKeychain(keychain))
		expired := sctx.Err() != nil
		cancel()
		if !scan.IsEngineError(err) {
			r.engineDown.Store(false)
			return rep, err
		}
		if expired {
			return nil, err
		}
		if len(waits) == 0 || r.engineDown.Load() {
			r.engineDown.Store(true)
			return nil, err
		}
		r.log().Info("engine failed, retrying the scan", "image", img.ref, "wait", waits[0], "err", err)
		select {
		case <-time.After(waits[0]):
		case <-ctx.Done():
			return nil, err
		}
		waits = waits[1:]
	}
}

package operator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/metrics"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/opstatus"
)

// maxRecent is the number of finished scans kept for the status.
const maxRecent = 20

var prioNames = [numPrios]string{"gated", "new", "rescan"}

func (p priority) String() string {
	if p >= 0 && p < numPrios {
		return prioNames[p]
	}
	return "unknown"
}

// Metrics in the controller-runtime registry, served at /metrics.
var (
	metricQueued = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "meles_operator_scan_queue", Help: "Image scans waiting for a worker, by priority (gated, new, rescan).",
	}, []string{"priority"})
	metricRunning = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meles_operator_scans_running", Help: "Image scans running.",
	})
	metricScans = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meles_operator_scans_total", Help: "Finished image scans by status (Clean, Infected, Incomplete, Error).",
	}, []string{"status"})
	metricDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "meles_operator_scan_duration_seconds", Help: "Duration of image scans.",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 600, 1200, 1800},
	})
	metricHeld = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meles_operator_gate_held_pods", Help: "Pods the scan gate holds.",
	})
	metricReleased = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "meles_operator_gate_released_total", Help: "Pods the scan gate released, by scan (complete, or unscanned after an engine failure or in audit mode).",
	}, []string{"scan"})
	metricLeader = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meles_operator_leader", Help: "1 if this replica is the leader, which scans.",
	})
)

func init() {
	metrics.Registry.MustRegister(metricQueued, metricRunning, metricScans, metricDuration, metricHeld, metricReleased, metricLeader)
}

// SetLeader records that this replica became the leader.
func SetLeader() { metricLeader.Set(1) }

var reportsDesc = prometheus.NewDesc("meles_operator_reports",
	"MalwareReports by namespace and status (Clean, Infected, Incomplete, Error); only the leader reports them.",
	[]string{"namespace", "status"}, nil)

// reportCollector counts the MalwareReports in the cache at each scrape.
type reportCollector struct {
	reader   client.Reader
	isLeader func() bool
}

func (c reportCollector) Describe(ch chan<- *prometheus.Desc) { ch <- reportsDesc }

func (c reportCollector) Collect(ch chan<- prometheus.Metric) {
	// Every replica caches the reports; one series per report set is enough.
	if c.isLeader != nil && !c.isLeader() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var list v1alpha1.MalwareReportList
	if err := c.reader.List(ctx, &list); err != nil {
		ch <- prometheus.NewInvalidMetric(reportsDesc, err)
		return
	}
	type key struct{ ns, status string }
	counts := map[key]int{}
	for _, rep := range list.Items {
		counts[key{rep.Namespace, rep.Report.Summary.Status}]++
	}
	for k, n := range counts {
		ch <- prometheus.MustNewConstMetric(reportsDesc, prometheus.GaugeValue, float64(n), k.ns, k.status)
	}
}

// RegisterReportMetrics exports meles_operator_reports, counted from the
// reports reader (the manager's cache) lists.
func RegisterReportMetrics(reader client.Reader, isLeader func() bool) error {
	err := metrics.Registry.Register(reportCollector{reader, isLeader})
	var are prometheus.AlreadyRegisteredError
	if errors.As(err, &are) {
		return nil
	}
	return err
}

// stats is what the status reports beyond the queue.
type stats struct {
	started  time.Time
	recent   []opstatus.Scan
	totals   map[string]int
	held     map[types.NamespacedName]opstatus.Held
	released opstatus.Counter
}

func (r *Reconciler) recordScan(j *scanJob, res result) {
	now := time.Now()
	d := now.Sub(j.started)
	metricScans.WithLabelValues(res.summary.Status).Inc()
	metricDuration.Observe(d.Seconds())
	s := opstatus.Scan{
		Image: j.img.ref, Priority: j.prio.String(), Started: j.started, Finished: &now, Duration: d,
		Status: res.summary.Status, Error: res.err, ErrorSource: res.errSource,
		Findings: res.summary.Findings, Skipped: res.summary.Skipped,
	}
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	r.stats.recent = append([]opstatus.Scan{s}, r.stats.recent...)
	r.stats.recent = r.stats.recent[:min(len(r.stats.recent), maxRecent)]
	if r.stats.totals == nil {
		r.stats.totals = map[string]int{}
	}
	r.stats.totals[res.summary.Status]++
}

// recordHeld remembers a pod the gate holds, or forgets it (reasons nil).
func (r *Reconciler) recordHeld(pod types.NamespacedName, mode string, reasons []string) {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if r.stats.held == nil {
		r.stats.held = map[types.NamespacedName]opstatus.Held{}
	}
	if reasons == nil {
		delete(r.stats.held, pod)
	} else {
		h, ok := r.stats.held[pod]
		if !ok {
			h = opstatus.Held{Namespace: pod.Namespace, Pod: pod.Name, Since: time.Now()}
		}
		h.Mode, h.Reasons = mode, reasons
		r.stats.held[pod] = h
	}
	metricHeld.Set(float64(len(r.stats.held)))
}

func (r *Reconciler) recordReleased(unscanned bool) {
	label := "complete"
	if unscanned {
		label = "unscanned"
	}
	metricReleased.WithLabelValues(label).Inc()
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if unscanned {
		r.stats.released.Unscanned++
	} else {
		r.stats.released.Scanned++
	}
}

// Status returns the operator's status. Only the leader has a queue.
func (r *Reconciler) Status() opstatus.Status {
	pod, _ := os.Hostname()
	st := opstatus.Status{
		Pod: pod, Version: r.Version, Workers: r.Workers,
		Leader: r.IsLeader == nil || r.IsLeader(),
		Queued: map[string]int{}, Totals: map[string]int{},
		Gate: opstatus.Gate{Enabled: r.Gate, FailOpen: r.GateFailOpen},
	}
	r.verMu.Lock()
	if !r.verAt.IsZero() {
		st.Engine = r.ver.Raw
	}
	r.verMu.Unlock()
	if r.queue != nil {
		r.queue.snapshot(&st)
	}
	r.statsMu.Lock()
	st.StartedAt = r.stats.started
	st.Recent = slices.Clone(r.stats.recent)
	for k, v := range r.stats.totals {
		st.Totals[k] = v
	}
	for _, h := range r.stats.held {
		st.Gate.Held = append(st.Gate.Held, h)
	}
	st.Gate.Released = r.stats.released
	r.statsMu.Unlock()
	slices.SortFunc(st.Gate.Held, func(a, b opstatus.Held) int { return a.Since.Compare(b.Since) })
	return st
}

// StatusHandler serves Status as JSON.
func (r *Reconciler) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(r.Status())
	})
}

// snapshot adds the queue to st.
func (q *scanQueue) snapshot(st *opstatus.Status) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for p, jobs := range q.queued {
		st.Queued[priority(p).String()] = len(jobs)
		for _, j := range jobs {
			if st.OldestQueued == nil || j.queuedAt.Before(*st.OldestQueued) {
				t := j.queuedAt
				st.OldestQueued = &t
			}
		}
	}
	for _, j := range q.pending {
		if j.running {
			st.Running = append(st.Running, opstatus.Scan{Image: j.img.ref, Priority: j.prio.String(), Pods: len(j.waiters), Started: j.started})
		}
	}
	slices.SortFunc(st.Running, func(a, b opstatus.Scan) int { return a.Started.Compare(b.Started) })
}

// updateMetrics sets the queue gauges; q.mu must be held.
func (q *scanQueue) updateMetrics() {
	running := 0
	for _, j := range q.pending {
		if j.running {
			running++
		}
	}
	for p, jobs := range q.queued {
		metricQueued.WithLabelValues(priority(p).String()).Set(float64(len(jobs)))
	}
	metricRunning.Set(float64(running))
}

// statusReason shortens a reason of the gate for the status.
func statusReason(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return strings.TrimSpace(s)
}

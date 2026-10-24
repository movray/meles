package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/engine/fake"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/runner"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/schedule"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/store"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

type env struct {
	t   *testing.T
	s   *Server
	srv *httptest.Server
	reg *testimage.Registry
	st  *store.Store
}

// newEnv starts a server; configure, if given, adjusts its Config.
func newEnv(t *testing.T, configure ...func(*Config)) *env {
	t.Helper()
	reg, err := testimage.Serve(testimage.Cases())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	st, err := store.Open(filepath.Join(t.TempDir(), "meles.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	log := slog.New(slog.DiscardHandler)
	eng := &fake.Engine{}
	cache := scan.NewCache(100)
	sc := &scan.Scanner{Engine: eng, Limits: extract.Limits{MaxFileSize: 1 << 20}, Concurrency: 2, Cache: cache, Source: source.Options{Insecure: true}}
	ctx, cancel := context.WithCancel(context.Background())
	run := runner.New(st, sc, 1, time.Minute, log)
	sched := schedule.New(st, run, time.UTC, log)
	cfg := Config{Store: st, Runner: run, Scheduler: sched, Engine: eng, Cache: cache, Location: time.UTC, Logger: log, Version: "test"}
	for _, c := range configure {
		c(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	run.Start(ctx)
	s.checkEngine(ctx)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); cancel(); run.Wait() })
	return &env{t: t, s: s, srv: srv, reg: reg, st: st}
}

func (e *env) do(method, path, contentType, body string, header ...string) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (e *env) waitDone(id int64) *store.Run {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, err := e.st.GetRun(context.Background(), id)
		if err != nil {
			e.t.Fatal(err)
		}
		if r.Done() {
			return r
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("run %d did not finish", id)
	return nil
}

func TestScanLifecycle(t *testing.T) {
	e := newEnv(t)

	body := fmt.Sprintf(`{"name":"whiteout","imageRef":%q,"platforms":"all","schedule":"0 3 * * *"}`, e.reg.Ref("eicar-whiteout"))
	resp, out := e.do("POST", "/api/scans", "application/json", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create scan: %d %s", resp.StatusCode, out)
	}
	var sc store.Scan
	json.Unmarshal([]byte(out), &sc)
	if !sc.Enabled {
		t.Error("new scan not enabled by default")
	}

	resp, out = e.do("POST", fmt.Sprintf("/api/scans/%d/run", sc.ID), "", "")
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("run scan: %d %s", resp.StatusCode, out)
	}
	var run store.Run
	json.Unmarshal([]byte(out), &run)
	done := e.waitDone(run.ID)
	if done.Status != store.StatusInfected || done.Findings != 1 {
		t.Fatalf("run = %+v", done)
	}

	pages := map[string]string{
		"/":                                    "Infected images",
		"/scans":                               "whiteout",
		fmt.Sprintf("/scans/%d", sc.ID):        "daily at 03:00",
		fmt.Sprintf("/scans/%d?edit=1", sc.ID): "Save changes",
		"/scans/new":                           "Create scan",
		"/runs":                                "eicar-whiteout",
		"/runs?status=infected":                "eicar-whiteout",
		fmt.Sprintf("/runs/%d", run.ID):        "whiteout in layer 4",
		"/reports":                             "Eicar-Test-Signature",
		"/reports?days=7":                      "Runs per day",
	}
	for path, want := range pages {
		resp, out := e.do("GET", path, "", "")
		if resp.StatusCode != http.StatusOK || !strings.Contains(out, want) {
			t.Errorf("GET %s: %d, want %q in body", path, resp.StatusCode, want)
		}
	}

	resp, out = e.do("GET", "/reports/findings.csv", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, "/tmp/payload/eicar.com,Eicar-Test-Signature,deleted") {
		t.Errorf("CSV: %d %s", resp.StatusCode, out)
	}
	resp, out = e.do("GET", fmt.Sprintf("/runs/%d/report.json", run.ID), "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, `"hiddenHow": "whiteout"`) {
		t.Errorf("report JSON: %d %s", resp.StatusCode, out)
	}
	resp, _ = e.do("GET", "/runs/9999", "", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing run: %d", resp.StatusCode)
	}
}

func TestForms(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"image_ref": {e.reg.Ref("clean")}, "platforms": {"all"}, "schedule": {"@every 6h"}, "enabled": {"1"}, "run_now": {"1"}}
	resp, out := e.do("POST", "/scans", "application/x-www-form-urlencoded", form.Encode())
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/runs/") {
		t.Fatalf("create via form: %d %s", resp.StatusCode, out)
	}
	var id int64
	fmt.Sscanf(resp.Header.Get("Location"), "/runs/%d", &id)
	if r := e.waitDone(id); r.Status != store.StatusClean {
		t.Errorf("clean image: %+v", r)
	}

	bad := url.Values{"image_ref": {"UPPER CASE::bad"}, "schedule": {"every tuesday"}}
	resp, out = e.do("POST", "/scans", "application/x-www-form-urlencoded", bad.Encode())
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "Not a valid image reference") || !strings.Contains(out, "Not a valid schedule") {
		t.Errorf("invalid form: %d", resp.StatusCode)
	}

	adhoc := url.Values{"image_ref": {e.reg.Ref("eicar-opaque")}, "platforms": {"linux/amd64"}}
	resp, _ = e.do("POST", "/runs", "application/x-www-form-urlencoded", adhoc.Encode())
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("ad-hoc run: %d", resp.StatusCode)
	}
	fmt.Sscanf(resp.Header.Get("Location"), "/runs/%d", &id)
	if r := e.waitDone(id); r.Status != store.StatusInfected || r.ScanID != nil {
		t.Errorf("ad-hoc run: %+v", r)
	}

	// Cross-site form posts are rejected.
	resp, _ = e.do("POST", "/runs", "application/x-www-form-urlencoded", adhoc.Encode(), "Sec-Fetch-Site", "cross-site")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site POST: %d, want 403", resp.StatusCode)
	}
}

func TestUnreachableImageIsError(t *testing.T) {
	e := newEnv(t)
	resp, out := e.do("POST", "/api/runs", "application/json", fmt.Sprintf(`{"imageRef":%q}`, e.reg.Ref("does-not-exist")))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create run: %d %s", resp.StatusCode, out)
	}
	var run store.Run
	json.Unmarshal([]byte(out), &run)
	if r := e.waitDone(run.ID); r.Status != store.StatusError || r.Error == "" {
		t.Errorf("run of missing image = %+v, want error", r)
	}
}

// fakeReports holds MalwareReports in memory.
type fakeReports struct {
	mu      sync.Mutex
	reports []v1alpha1.MalwareReport
}

func (f *fakeReports) List(context.Context) ([]v1alpha1.MalwareReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reports), nil
}

func (f *fakeReports) Get(_ context.Context, ns, name string) (*v1alpha1.MalwareReport, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.reports {
		if r.Namespace == ns && r.Name == name {
			return &r, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeReports) RequestRescan(_ context.Context, ns, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, r := range f.reports {
		if r.Namespace == ns && r.Name == name {
			f.reports[i].Annotations = map[string]string{v1alpha1.AnnotationRescan: "now"}
			return nil
		}
	}
	return store.ErrNotFound
}

func malwareReport(ns, workload, status string, findings ...v1alpha1.Finding) v1alpha1.MalwareReport {
	return v1alpha1.MalwareReport{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "replicaset-" + workload + "-app"},
		Report: v1alpha1.ReportData{
			Workload:  v1alpha1.Workload{Kind: "ReplicaSet", Name: workload, Container: "app"},
			Image:     v1alpha1.Image{Repository: "docker.io/acme/" + workload, Reference: "acme/" + workload + ":1", Digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
			Summary:   v1alpha1.Summary{Status: status, Findings: len(findings), Files: 10},
			Findings:  findings,
			ScannedAt: metav1.Now(),
		},
	}
}

func TestClusterReports(t *testing.T) {
	reports := &fakeReports{reports: []v1alpha1.MalwareReport{
		malwareReport("shop", "web", v1alpha1.StatusClean),
		malwareReport("tools", "backup", v1alpha1.StatusIncomplete),
		malwareReport("shop", "miner", v1alpha1.StatusInfected, v1alpha1.Finding{Platform: "linux/amd64", Layer: 2, Path: "/usr/bin/xmrig", Signature: "Unix.Coinminer.Xmrig", Status: "present"}),
	}}
	e := newEnv(t, func(c *Config) { c.Cluster, c.ClusterRescan = reports, true })

	resp, out := e.do("GET", "/cluster", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /cluster: %d", resp.StatusCode)
	}
	miner, backup, web := strings.Index(out, "shop / miner"), strings.Index(out, "tools / backup"), strings.Index(out, "shop / web")
	if miner < 0 || backup < miner || web < backup {
		t.Errorf("not sorted by urgency: miner %d, backup %d, web %d", miner, backup, web)
	}
	filtered := map[string][]string{
		"/cluster?status=incomplete": {"tools / backup"},
		"/cluster?namespace=shop":    {"shop / miner", "shop / web"},
		"/cluster?q=acme/web":        {"shop / web"},
	}
	for path, want := range filtered {
		_, out := e.do("GET", path, "", "")
		for _, w := range []string{"shop / miner", "tools / backup", "shop / web"} {
			if strings.Contains(out, w) != slices.Contains(want, w) {
				t.Errorf("GET %s: %q shown = %v", path, w, !slices.Contains(want, w))
			}
		}
	}
	if _, out := e.do("GET", "/", "", ""); !strings.Contains(out, "Cluster workloads") || !strings.Contains(out, `href="/cluster"`) {
		t.Error("dashboard without cluster tile or navigation")
	}

	resp, out = e.do("GET", "/cluster/shop/replicaset-miner-app", "", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, "/usr/bin/xmrig") || !strings.Contains(out, "Unix.Coinminer.Xmrig") || !strings.Contains(out, ">Rescan<") {
		t.Errorf("report page: %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/cluster/shop/missing", "", ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing report: %d", resp.StatusCode)
	}

	// Rescan sets the annotation; cross-site posts are rejected.
	if resp, _ := e.do("POST", "/cluster/shop/replicaset-miner-app/rescan", "", "", "Sec-Fetch-Site", "cross-site"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site rescan: %d, want 403", resp.StatusCode)
	}
	resp, _ = e.do("POST", "/cluster/shop/replicaset-miner-app/rescan", "", "")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/cluster/shop/replicaset-miner-app" {
		t.Errorf("rescan: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, out := e.do("GET", "/cluster/shop/replicaset-miner-app", "", ""); !strings.Contains(out, "Rescan requested") {
		t.Error("pending rescan not shown")
	}

	resp, out = e.do("GET", "/api/cluster/reports", "", "")
	var list []v1alpha1.MalwareReport
	if err := json.Unmarshal([]byte(out), &list); resp.StatusCode != http.StatusOK || err != nil || len(list) != 3 || list[0].Report.Workload.Name != "miner" {
		t.Errorf("API: %d %v %d reports", resp.StatusCode, err, len(list))
	}
}

func TestClusterHistory(t *testing.T) {
	reports := &fakeReports{}
	e := newEnv(t, func(c *Config) { c.Cluster = reports })
	old := malwareReport("shop", "web-5d8f7c", v1alpha1.StatusClean)
	old.Report.Workload.Parent = "web"
	old.Report.ScannedAt = metav1.NewTime(time.Now().Add(-48 * time.Hour).Truncate(time.Second))
	e.s.recordReport(&old, false)
	e.s.recordReport(&old, false) // seen again after a restart

	// A rollout: the new ReplicaSet runs an infected image, the old one's
	// report is deleted while the server is down.
	cur := malwareReport("shop", "web-7c9b4d", v1alpha1.StatusInfected, v1alpha1.Finding{Path: "/usr/bin/xmrig", Signature: "Unix.Coinminer.Xmrig", Status: "present"})
	cur.Report.Workload.Parent = "web"
	cur.Report.ScannedAt = metav1.NewTime(time.Now().Add(-time.Hour).Truncate(time.Second))
	e.s.recordReport(&cur, false)
	cur.Report.ScannedAt = metav1.NewTime(time.Now().Add(-10 * time.Minute).Truncate(time.Second)) // rescan, still infected
	e.s.recordReport(&cur, false)
	reports.reports = []v1alpha1.MalwareReport{cur}
	if err := e.s.recordMissedDeletions(context.Background()); err != nil {
		t.Fatal(err)
	}

	hist, err := e.st.ClusterHistory(context.Background(), "", "shop", "Deployment/web/app", 10)
	if err != nil || len(hist) != 4 || hist[0].Report != old.Name || !hist[0].Deleted || hist[1].Status != v1alpha1.StatusInfected {
		t.Fatalf("history = %+v, %v", hist, err)
	}
	_, out := e.do("GET", "/cluster/shop/"+cur.Name, "", "")
	if !strings.Contains(out, "History") || !strings.Contains(out, "report deleted") || !strings.Contains(out, "web-5d8f7c") {
		t.Error("report page without the history of the Deployment")
	}
	if _, out := e.do("GET", "/cluster", "", ""); !strings.Contains(out, "shop / web") || !strings.Contains(out, "1 h ago") || !strings.Contains(out, "10 min ago") {
		t.Error("cluster page without Deployment name or status since")
	}
	if _, out := e.do("GET", "/cluster?days=7", "", ""); !strings.Contains(out, "Workloads per day") || !strings.Contains(out, "0 clean · 1 infected · 0 errors · 0 incomplete") {
		t.Error("cluster page without the trend of today")
	}
	resp, out := e.do("GET", "/api/cluster/reports/shop/"+cur.Name+"/history", "", "")
	var events []store.ClusterEvent
	if err := json.Unmarshal([]byte(out), &events); resp.StatusCode != http.StatusOK || err != nil || len(events) != 4 {
		t.Errorf("history API: %d %v %d events", resp.StatusCode, err, len(events))
	}
}

func TestClusterReportsDisabled(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/cluster", "/api/cluster/reports"} {
		if resp, _ := e.do("GET", path, "", ""); resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s without cluster reports: %d", path, resp.StatusCode)
		}
	}
	if _, out := e.do("GET", "/", "", ""); strings.Contains(out, `href="/cluster"`) {
		t.Error("navigation shows Cluster although disabled")
	}
}

func TestHumanSchedule(t *testing.T) {
	tests := map[string]string{
		"":                                "manual only",
		"@daily":                          "daily at 00:00",
		"@every 6h":                       "every 6h",
		"30 2 * * *":                      "daily at 02:30",
		"0 3 * * 1-5":                     "Mon–Fri at 03:00",
		"0 4 * * 0":                       "Sun at 04:00",
		"15 * * * *":                      "hourly at minute 15",
		"CRON_TZ=Europe/Berlin 0 3 * * *": "daily at 03:00 (Europe/Berlin)",
		"*/5 * * * *":                     "*/5 * * * *",
	}
	for in, want := range tests {
		if got := humanSchedule(in); got != want {
			t.Errorf("humanSchedule(%q) = %q, want %q", in, got, want)
		}
	}
}

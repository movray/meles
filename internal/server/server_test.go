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
	"strings"
	"testing"
	"time"

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
	srv *httptest.Server
	reg *testimage.Registry
	st  *store.Store
}

func newEnv(t *testing.T) *env {
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
	s, err := New(Config{Store: st, Runner: run, Scheduler: sched, Engine: eng, Cache: cache, Location: time.UTC, Logger: log, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	run.Start(ctx)
	s.checkEngine(ctx)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); cancel(); run.Wait() })
	return &env{t: t, srv: srv, reg: reg, st: st}
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

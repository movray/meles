package server

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/opstatus"
	"git.itknecht.de/sugras/meles/internal/schedule"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/store"
	"git.itknecht.de/sugras/meles/internal/yararules"
)

// scanInput is the editable part of a scan, from a form or JSON.
type scanInput struct {
	Name      string `json:"name"`
	ImageRef  string `json:"imageRef"`
	Platforms string `json:"platforms"`
	Schedule  string `json:"schedule"`
	Enabled   *bool  `json:"enabled"`
}

// validate normalises the input and returns errors by field.
func (in *scanInput) validate() map[string]string {
	in.Name = strings.TrimSpace(in.Name)
	in.ImageRef = strings.TrimSpace(in.ImageRef)
	in.Platforms = strings.TrimSpace(in.Platforms)
	in.Schedule = strings.TrimSpace(in.Schedule)
	if in.Platforms == "" {
		in.Platforms = "all"
	}
	if in.Name == "" {
		in.Name = in.ImageRef
	}

	errs := map[string]string{}
	if in.ImageRef == "" {
		errs["ImageRef"] = "Enter an image reference, e.g. alpine:3.20 or registry.example.com/app@sha256:…"
	} else if _, err := name.ParseReference(in.ImageRef); err != nil {
		errs["ImageRef"] = "Not a valid image reference: " + err.Error()
	}
	if len(in.Name) > 100 {
		errs["Name"] = "Use at most 100 characters."
	}
	if _, err := source.ParsePlatforms(in.Platforms); err != nil {
		errs["Platforms"] = "Use all, host or a list like linux/amd64,linux/arm64."
	}
	if err := schedule.Validate(in.Schedule); err != nil {
		errs["Schedule"] = "Not a valid schedule. Examples: @daily, @every 6h, 0 3 * * * or CRON_TZ=Europe/Berlin 0 3 * * 1-5."
	}
	return errs
}

func (in scanInput) apply(sc *store.Scan) {
	sc.Name, sc.ImageRef, sc.Platforms, sc.Schedule = in.Name, in.ImageRef, in.Platforms, in.Schedule
	sc.Enabled = in.Enabled == nil || *in.Enabled
}

func formInput(r *http.Request) scanInput {
	enabled := r.PostFormValue("enabled") != ""
	return scanInput{
		Name:      r.PostFormValue("name"),
		ImageRef:  r.PostFormValue("image_ref"),
		Platforms: r.PostFormValue("platforms"),
		Schedule:  r.PostFormValue("schedule"),
		Enabled:   &enabled,
	}
}

func validateRun(ref, platforms string) error {
	if _, err := name.ParseReference(ref); err != nil {
		return fmt.Errorf("not a valid image reference %q: %w", ref, err)
	}
	if _, err := source.ParsePlatforms(platforms); err != nil {
		return err
	}
	return nil
}

// --- dashboard ---

type upcoming struct {
	Scan store.Scan
	Next time.Time
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	stats, err := s.store.Stats(ctx, time.Now().Add(-24*time.Hour))
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	recent, err := s.store.ListRuns(ctx, store.RunFilter{Limit: 10})
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	images, err := s.store.ImageStatus(ctx)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	var attention []store.Run
	for _, im := range images {
		if im.Status != store.StatusClean {
			attention = append(attention, im)
		}
	}
	scans, err := s.store.ListScans(ctx)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	var next []upcoming
	for _, sc := range scans {
		if t := s.scheduler.NextRun(sc.ID); !t.IsZero() {
			next = append(next, upcoming{sc, t})
		}
	}
	sort.Slice(next, func(i, j int) bool { return next[i].Next.Before(next[j].Next) })
	if len(next) > 5 {
		next = next[:5]
	}

	refresh := 0
	for _, run := range recent {
		if !run.Done() {
			refresh = 5
		}
	}
	var cluster *clusterCounts
	if s.cluster != nil {
		// The dashboard works without the cluster's reports.
		if reps, err := s.cluster.List(ctx); err == nil {
			c := countReports(reps)
			cluster = &c
		}
	}
	s.render(w, http.StatusOK, "dashboard", page{Title: "Dashboard", Nav: "dashboard", Refresh: refresh, Data: map[string]any{
		"Stats":     stats,
		"Recent":    recent,
		"Attention": attention,
		"Upcoming":  next,
		"Cluster":   cluster,
	}})
}

// --- scans ---

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans(r.Context())
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.render(w, http.StatusOK, "scans", page{Title: "Scans", Nav: "scans", Data: map[string]any{"Scans": scans}})
}

func (s *Server) handleScanNew(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	enabled := true
	in := scanInput{Platforms: q.Get("platforms"), Enabled: &enabled, ImageRef: q.Get("image_ref")}
	if in.Platforms == "" {
		in.Platforms = "all"
	}
	s.renderScanForm(w, http.StatusOK, nil, in, nil)
}

func (s *Server) renderScanForm(w http.ResponseWriter, status int, sc *store.Scan, in scanInput, errs map[string]string) {
	title := "New scan"
	if sc != nil {
		title = "Edit " + sc.Name
	}
	s.render(w, status, "scan_form", page{Title: title, Nav: "scans", Data: map[string]any{
		"Scan":    sc,
		"Input":   in,
		"Enabled": in.Enabled == nil || *in.Enabled,
		"Errors":  errs,
	}})
}

func (s *Server) handleScanCreate(w http.ResponseWriter, r *http.Request) {
	in := formInput(r)
	if errs := in.validate(); len(errs) > 0 {
		s.renderScanForm(w, http.StatusBadRequest, nil, in, errs)
		return
	}
	sc := &store.Scan{}
	in.apply(sc)
	if err := s.store.CreateScan(r.Context(), sc); err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.syncSchedule(r)
	if r.PostFormValue("run_now") != "" {
		run, err := s.runner.Enqueue(r.Context(), sc, sc.ImageRef, sc.Platforms, store.TriggerManual)
		if err != nil {
			s.renderError(w, errStatus(err), err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/runs/%d", run.ID), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/scans/%d", sc.ID), http.StatusSeeOther)
}

func (s *Server) syncSchedule(r *http.Request) {
	if err := s.scheduler.Sync(r.Context()); err != nil {
		s.log.Error("sync schedules", "err", err)
	}
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	sc, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	runs, err := s.store.ListRuns(r.Context(), store.RunFilter{ScanID: id, Limit: 50})
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	if r.URL.Query().Get("edit") != "" {
		enabled := sc.Enabled
		s.renderScanForm(w, http.StatusOK, sc, scanInput{Name: sc.Name, ImageRef: sc.ImageRef, Platforms: sc.Platforms, Schedule: sc.Schedule, Enabled: &enabled}, nil)
		return
	}
	refresh := 0
	for _, run := range runs {
		if !run.Done() {
			refresh = 5
		}
	}
	s.render(w, http.StatusOK, "scan", page{Title: sc.Name, Nav: "scans", Refresh: refresh, Data: map[string]any{
		"Scan": sc,
		"Runs": runs,
		"Next": s.scheduler.NextRun(sc.ID),
	}})
}

func (s *Server) handleScanUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	sc, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	in := formInput(r)
	if errs := in.validate(); len(errs) > 0 {
		s.renderScanForm(w, http.StatusBadRequest, sc, in, errs)
		return
	}
	in.apply(sc)
	if err := s.store.UpdateScan(r.Context(), sc); err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.syncSchedule(r)
	http.Redirect(w, r, fmt.Sprintf("/scans/%d", sc.ID), http.StatusSeeOther)
}

func (s *Server) handleScanDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	if err := s.store.DeleteScan(r.Context(), id); err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.syncSchedule(r)
	http.Redirect(w, r, "/scans", http.StatusSeeOther)
}

func (s *Server) handleScanRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	sc, err := s.store.GetScan(r.Context(), id)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	run, err := s.runner.Enqueue(r.Context(), sc, sc.ImageRef, sc.Platforms, store.TriggerManual)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", run.ID), http.StatusSeeOther)
}

// --- runs ---

const runsPerPage = 50

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.RunFilter{Status: q.Get("status"), ImageRef: q.Get("image"), Limit: runsPerPage}
	if id, err := strconv.ParseInt(q.Get("scan"), 10, 64); err == nil {
		f.ScanID = id
	}
	pg, _ := strconv.Atoi(q.Get("page"))
	pg = max(pg, 1)
	f.Offset = (pg - 1) * runsPerPage

	runs, err := s.store.ListRuns(r.Context(), f)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	total, err := s.store.CountRuns(r.Context(), f)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	refresh := 0
	for _, run := range runs {
		if !run.Done() {
			refresh = 5
		}
	}
	s.render(w, http.StatusOK, "runs", page{Title: "Runs", Nav: "runs", Refresh: refresh, Data: map[string]any{
		"Runs":     runs,
		"Filter":   f,
		"Statuses": []string{store.StatusInfected, store.StatusError, store.StatusClean, store.StatusRunning, store.StatusQueued},
		"Page":     pg,
		"Total":    total,
		"HasPrev":  pg > 1,
		"HasNext":  pg*runsPerPage < total,
	}})
}

func (s *Server) handleRunCreate(w http.ResponseWriter, r *http.Request) {
	ref := strings.TrimSpace(r.PostFormValue("image_ref"))
	platforms := strings.TrimSpace(r.PostFormValue("platforms"))
	if platforms == "" {
		platforms = "all"
	}
	if err := validateRun(ref, platforms); err != nil {
		s.renderError(w, http.StatusBadRequest, err)
		return
	}
	run, err := s.runner.Enqueue(r.Context(), nil, ref, platforms, store.TriggerManual)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/runs/%d", run.ID), http.StatusSeeOther)
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	run, err := s.store.GetRun(r.Context(), id)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	rep, err := s.store.GetReport(r.Context(), id)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	refresh := 0
	if !run.Done() {
		refresh = 3
	}
	s.render(w, http.StatusOK, "run", page{Title: fmt.Sprintf("Run #%d", run.ID), Nav: "runs", Refresh: refresh, Data: map[string]any{
		"Run":    run,
		"Report": rep,
	}})
}

func (s *Server) handleRunReport(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		writeJSONError(w, http.StatusNotFound, store.ErrNotFound)
		return
	}
	rep, err := s.store.GetReport(r.Context(), id)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	if rep == nil {
		writeJSONError(w, http.StatusNotFound, errors.New("run has no report (not finished or failed)"))
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="meles-run-%d.json"`, id))
	writeJSON(w, http.StatusOK, rep)
}

// --- reports ---

func reportDays(r *http.Request) int {
	switch d, _ := strconv.Atoi(r.URL.Query().Get("days")); d {
	case 7, 30, 90:
		return d
	}
	return 30
}

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	days := reportDays(r)
	since := time.Now().AddDate(0, 0, -days)
	daily, err := s.store.Daily(ctx, days, s.loc)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	stats, err := s.store.Stats(ctx, since)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	sigs, err := s.store.TopSignatures(ctx, since, 10)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	images, err := s.store.ImageStatus(ctx)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.render(w, http.StatusOK, "reports", page{Title: "Reports", Nav: "reports", Data: map[string]any{
		"Days":       days,
		"DayOptions": []int{7, 30, 90},
		"Daily":      daily,
		"Stats":      stats,
		"Signatures": sigs,
		"Images":     images,
	}})
}

func (s *Server) handleFindingsCSV(w http.ResponseWriter, r *http.Request) {
	days := reportDays(r)
	rows, err := s.store.Findings(r.Context(), time.Now().AddDate(0, 0, -days))
	if err != nil {
		http.Error(w, err.Error(), errStatus(err))
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="meles-findings-%dd.csv"`, days))
	cw := csv.NewWriter(w)
	cw.Write([]string{"run_id", "finished_at", "image_ref", "digest", "platform", "layer", "path", "signature", "status", "rule_author", "rule_license"})
	for _, f := range rows {
		rule, _ := yararules.Lookup(f.Signature)
		cw.Write([]string{
			strconv.FormatInt(f.RunID, 10), f.FinishedAt.UTC().Format(time.RFC3339), f.ImageRef, f.Digest,
			f.Platform, strconv.Itoa(f.Layer), f.Path, f.Signature, f.Status, rule.Author, rule.License,
		})
	}
	cw.Flush()
}

// --- cluster (MalwareReports of the operator) ---

var errNoCluster = fmt.Errorf("the reports of the meles operator are not enabled (meles server --cluster-reports): %w", store.ErrNotFound)

func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		s.renderError(w, http.StatusNotFound, errNoCluster)
		return
	}
	reps, err := s.cluster.List(r.Context())
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	q := r.URL.Query()
	f := clusterFilter{Status: q.Get("status"), Namespace: q.Get("namespace"), Query: strings.TrimSpace(q.Get("q"))}
	var shown []v1alpha1.MalwareReport
	for i := range reps {
		if f.match(&reps[i]) {
			shown = append(shown, reps[i])
		}
	}
	sortReports(shown)
	// Since when each report's status holds, from the history.
	since := map[string]time.Time{}
	if bySince, err := s.store.ClusterStatusSince(r.Context(), s.clusterName); err != nil {
		s.log.Warn("cluster status since", "err", err)
	} else {
		for _, rep := range shown {
			if t, ok := bySince[store.ClusterKey{Namespace: rep.Namespace, Group: historyGroup(rep.Report.Workload)}]; ok {
				since[rep.Namespace+"/"+rep.Name] = t
			}
		}
	}
	days := reportDays(r)
	daily, err := s.store.ClusterDaily(r.Context(), s.clusterName, days, s.loc)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	var op *opstatus.Status
	var opErr error
	if s.operator != nil {
		if op, opErr = s.operator.Fetch(r.Context()); opErr != nil {
			s.log.Warn("operator status", "err", opErr)
		}
	}
	s.render(w, http.StatusOK, "cluster", page{Title: "Cluster", Nav: "cluster", Data: map[string]any{
		"Operator":    op,
		"OperatorOn":  s.operator != nil,
		"OperatorErr": opErr,
		"Days":        days,
		"DayOptions":  []int{7, 30, 90},
		"Daily":       daily,
		"Reports":     shown,
		"Since":       since,
		"Counts":      countReports(reps),
		"Filter":      f,
		"Statuses":    clusterStatuses,
		"Namespaces":  namespaces(reps),
	}})
}

func (s *Server) handleClusterReport(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		s.renderError(w, http.StatusNotFound, errNoCluster)
		return
	}
	rep, err := s.cluster.Get(r.Context(), r.PathValue("namespace"), r.PathValue("name"))
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	hist, err := s.store.ClusterHistory(r.Context(), s.clusterName, rep.Namespace, historyGroup(rep.Report.Workload), historyLimit)
	if err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	refresh := 0
	if rescanPending(rep) {
		refresh = 10
	}
	s.render(w, http.StatusOK, "cluster_report", page{Title: rep.Report.Workload.Name, Nav: "cluster", Refresh: refresh, Data: map[string]any{
		"Report":  rep,
		"Rescan":  s.rescan,
		"History": hist,
	}})
}

func (s *Server) handleClusterRescan(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil || !s.rescan {
		s.renderError(w, http.StatusNotFound, errNoCluster)
		return
	}
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if err := s.cluster.RequestRescan(r.Context(), ns, name); err != nil {
		s.renderError(w, errStatus(err), err)
		return
	}
	s.log.Info("rescan requested", "namespace", ns, "report", name)
	http.Redirect(w, r, "/cluster/"+url.PathEscape(ns)+"/"+url.PathEscape(name), http.StatusSeeOther)
}

// historyLimit bounds the events shown and returned per workload.
const historyLimit = 100

func (s *Server) apiClusterHistory(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeJSONError(w, http.StatusNotFound, errNoCluster)
		return
	}
	rep, err := s.cluster.Get(r.Context(), r.PathValue("namespace"), r.PathValue("name"))
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	hist, err := s.store.ClusterHistory(r.Context(), s.clusterName, rep.Namespace, historyGroup(rep.Report.Workload), historyLimit)
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, hist)
}

func (s *Server) apiClusterReports(w http.ResponseWriter, r *http.Request) {
	if s.cluster == nil {
		writeJSONError(w, http.StatusNotFound, errNoCluster)
		return
	}
	reps, err := s.cluster.List(r.Context())
	if err != nil {
		writeJSONError(w, errStatus(err), err)
		return
	}
	sortReports(reps)
	writeJSON(w, http.StatusOK, reps)
}

// apiOperator returns the operator's status as JSON.
func (s *Server) apiOperator(w http.ResponseWriter, r *http.Request) {
	if s.operator == nil {
		writeJSONError(w, http.StatusNotFound, errors.New("the operator status is not configured (meles server --operator-status)"))
		return
	}
	st, err := s.operator.Fetch(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

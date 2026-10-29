// Package server is the meles web UI and JSON API: configured scans with
// schedules, scan runs with their results, reports, and the MalwareReports
// of the meles operator.
package server

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/movray/meles/internal/engine"
	"github.com/movray/meles/internal/opstatus"
	"github.com/movray/meles/internal/runner"
	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/schedule"
	"github.com/movray/meles/internal/store"
)

//go:embed web
var webFS embed.FS

// Server serves the UI and API.
type Server struct {
	store     *store.Store
	runner    *runner.Runner
	scheduler *schedule.Scheduler
	engine    engine.Engine
	cache     *scan.Cache
	loc       *time.Location
	log       *slog.Logger
	version   string
	pages     map[string]*pageTemplate
	cluster   ClusterReports
	rescan    bool
	ignores   ClusterIgnores
	// clusterName tags the history of the cluster's reports.
	clusterName string
	operator    OperatorStatus

	mu           sync.Mutex
	engineStatus EngineStatus
}

// EngineStatus is the last result of the engine health check.
type EngineStatus struct {
	OK        bool
	Version   engine.Version
	Error     string
	CheckedAt time.Time
}

// Config configures a Server.
type Config struct {
	Store     *store.Store
	Runner    *runner.Runner
	Scheduler *schedule.Scheduler
	Engine    engine.Engine
	Cache     *scan.Cache
	Location  *time.Location
	Logger    *slog.Logger
	Version   string
	// Cluster, if set, shows the operator's MalwareReports.
	Cluster ClusterReports
	// ClusterRescan allows requesting a rescan from the UI.
	ClusterRescan bool
	// Ignores, if set, allows creating ignore rules from the UI.
	Ignores ClusterIgnores
	// ClusterName tags the history of the cluster's reports, for several
	// clusters later; empty for one.
	ClusterName string
	// Operator, if set, shows what the operator does on the Cluster page.
	Operator OperatorStatus
}

// OperatorStatus fetches the status of the meles operator;
// *opstatus.Client implements it.
type OperatorStatus interface {
	Fetch(ctx context.Context) (*opstatus.Status, error)
}

// New returns a server.
func New(c Config) (*Server, error) {
	s := &Server{
		store:       c.Store,
		runner:      c.Runner,
		scheduler:   c.Scheduler,
		engine:      c.Engine,
		cache:       c.Cache,
		loc:         c.Location,
		log:         c.Logger,
		version:     c.Version,
		cluster:     c.Cluster,
		rescan:      c.ClusterRescan,
		ignores:     c.Ignores,
		clusterName: c.ClusterName,
		operator:    c.Operator,
	}
	if s.loc == nil {
		s.loc = time.Local
	}
	pages, err := s.parseTemplates()
	if err != nil {
		return nil, err
	}
	s.pages = pages
	return s, nil
}

// WatchEngine checks the engine every interval until ctx is canceled.
func (s *Server) WatchEngine(ctx context.Context, interval time.Duration) {
	s.checkEngine(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.checkEngine(ctx)
		}
	}
}

func (s *Server) checkEngine(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	v, err := s.engine.Version(ctx)
	st := EngineStatus{OK: err == nil, Version: v, CheckedAt: time.Now()}
	if err != nil {
		st.Error = err.Error()
	}
	s.mu.Lock()
	prev := s.engineStatus
	s.engineStatus = st
	s.mu.Unlock()
	if prev.OK != st.OK || prev.CheckedAt.IsZero() {
		if st.OK {
			s.log.Info("engine available", "version", v.Raw)
		} else {
			s.log.Warn("engine unavailable", "err", err)
		}
	}
}

// Engine returns the last engine health check.
func (s *Server) Engine() EngineStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.engineStatus
}

// Handler returns the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(webFS, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /{$}", s.handleDashboard)
	mux.HandleFunc("GET /scans", s.handleScans)
	mux.HandleFunc("GET /scans/new", s.handleScanNew)
	mux.HandleFunc("POST /scans", s.handleScanCreate)
	mux.HandleFunc("GET /scans/{id}", s.handleScan)
	mux.HandleFunc("POST /scans/{id}", s.handleScanUpdate)
	mux.HandleFunc("POST /scans/{id}/delete", s.handleScanDelete)
	mux.HandleFunc("POST /scans/{id}/run", s.handleScanRun)
	mux.HandleFunc("GET /runs", s.handleRuns)
	mux.HandleFunc("POST /runs", s.handleRunCreate)
	mux.HandleFunc("GET /runs/{id}", s.handleRun)
	mux.HandleFunc("GET /runs/{id}/report.json", s.handleRunReport)
	mux.HandleFunc("GET /reports", s.handleReports)
	mux.HandleFunc("GET /reports/findings.csv", s.handleFindingsCSV)
	mux.HandleFunc("GET /cluster", s.handleCluster)
	mux.HandleFunc("GET /cluster/{namespace}/{name}", s.handleClusterReport)
	mux.HandleFunc("POST /cluster/{namespace}/{name}/rescan", s.handleClusterRescan)
	mux.HandleFunc("GET /ignores", s.handleIgnores)
	mux.HandleFunc("GET /ignores/new", s.handleIgnoreNew)
	mux.HandleFunc("POST /ignores", s.handleIgnoreCreate)
	mux.HandleFunc("POST /ignores/delete", s.handleIgnoreDelete)

	mux.HandleFunc("GET /api/scans", s.apiListScans)
	mux.HandleFunc("POST /api/scans", s.apiCreateScan)
	mux.HandleFunc("GET /api/scans/{id}", s.apiGetScan)
	mux.HandleFunc("PUT /api/scans/{id}", s.apiUpdateScan)
	mux.HandleFunc("DELETE /api/scans/{id}", s.apiDeleteScan)
	mux.HandleFunc("POST /api/scans/{id}/run", s.apiRunScan)
	mux.HandleFunc("GET /api/runs", s.apiListRuns)
	mux.HandleFunc("POST /api/runs", s.apiCreateRun)
	mux.HandleFunc("GET /api/runs/{id}", s.apiGetRun)
	mux.HandleFunc("GET /api/runs/{id}/report", s.handleRunReport)
	mux.HandleFunc("GET /api/cluster/reports", s.apiClusterReports)
	mux.HandleFunc("GET /api/cluster/reports/{namespace}/{name}/history", s.apiClusterHistory)
	mux.HandleFunc("GET /api/cluster/operator", s.apiOperator)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ping(r.Context()); err != nil {
			http.Error(w, "database: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if st := s.Engine(); !st.OK {
			http.Error(w, "engine: "+st.Error, http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok\n"))
	})

	// Reject cross-site form posts and API writes (CSRF).
	return securityHeaders(http.NewCrossOriginProtection().Handler(mux))
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "same-origin")
		h.ServeHTTP(w, r)
	})
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// errStatus maps store errors to HTTP status codes.
func errStatus(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, runner.ErrQueueFull), errors.Is(err, errNotSynced):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

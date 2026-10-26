package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // time zones in minimal container images

	"github.com/spf13/cobra"
	ctrl "sigs.k8s.io/controller-runtime"

	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/opstatus"
	"git.itknecht.de/sugras/meles/internal/runner"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/schedule"
	"git.itknecht.de/sugras/meles/internal/server"
	"git.itknecht.de/sugras/meles/internal/store"
)

func newServerCmd() *cobra.Command {
	var (
		sf          scanFlags
		listen      string
		dbPath      string
		workers     int
		runTimeout  time.Duration
		timezone    string
		cacheSize   int
		cachePaths  int
		cluster     bool
		rescan      bool
		clusterIgn  bool
		ignoreF     string
		clusterName string
		historyDays int
		opStatus    string
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the web UI with scheduled scans and reports",
		Long: `server runs the meles web UI and JSON API. Scans can be configured with a
cron schedule; every run is stored with its full report in a SQLite database.

With --cluster-reports it also shows the MalwareReports of the meles operator,
read from the Kubernetes API (KUBECONFIG or, in a pod, its service account),
and records every change in the database as their history. --operator-status
names the operator's headless metrics service (e.g.
http://meles-operator-metrics.meles:8080); the Cluster page then shows what the
operator does: its queue, running scans and the pods its scan gate holds.

The UI has no login of its own: expose it only inside the cluster or behind an
authenticating proxy (e.g. oauth2-proxy).

--cluster-ignore adds an "Ignore" button to findings and skipped files: it
creates a MalwareIgnore in the report's namespace or a ClusterMalwareIgnore,
recording the user from the X-Forwarded-Email header of oauth2-proxy. The
server's own runs then also apply the ClusterMalwareIgnores. A run keeps the
verdict of its time; a new rule applies from the next run on.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			loc, err := time.LoadLocation(timezone)
			if err != nil {
				return fmt.Errorf("--timezone: %w", err)
			}
			st, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer st.Close()

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			log := slog.Default()

			if n, err := st.FailUnfinished(ctx); err != nil {
				return err
			} else if n > 0 {
				log.Warn("marked runs interrupted by the last shutdown as failed", "runs", n)
			}

			cache := scan.NewCache(cacheSize)
			cache.MaxPaths = cachePaths
			sc, err := sf.scanner(cache)
			if err != nil {
				return err
			}
			if ignoreF != "" {
				// Fail at start on an invalid file; every run reads it again.
				if _, err := ignore.Load(ignoreF, time.Now()); err != nil {
					return fmt.Errorf("--ignorefile: %w", err)
				}
			}
			if clusterIgn && !cluster {
				return errors.New("--cluster-ignore needs --cluster-reports")
			}
			run := runner.New(st, sc, workers, runTimeout, log)
			sched := schedule.New(st, run, loc, log)
			if err := sched.Sync(ctx); err != nil {
				return err
			}
			var reports *server.KubeReports
			if cluster {
				cfg, err := ctrl.GetConfig()
				if err != nil {
					return fmt.Errorf("--cluster-reports: kubernetes config: %w", err)
				}
				if reports, err = server.NewKubeReports(cfg, clusterIgn); err != nil {
					return fmt.Errorf("--cluster-reports: %w", err)
				}
			}
			if ignoreF != "" || clusterIgn {
				run.SetIgnore(func(ctx context.Context) (*ignore.Rules, error) {
					var sets []*ignore.Rules
					var errs []error
					if ignoreF != "" {
						rs, err := ignore.Load(ignoreF, time.Now())
						sets, errs = append(sets, rs), append(errs, err)
					}
					if clusterIgn {
						rs, err := reports.Ignores().ClusterRules(ctx)
						sets, errs = append(sets, rs), append(errs, err)
					}
					return ignore.Merge(sets...), errors.Join(errs...)
				})
			}
			cfg := server.Config{
				Store: st, Runner: run, Scheduler: sched, Engine: sc.Engine, Cache: cache,
				Location: loc, Logger: log, Version: version,
			}
			if reports != nil {
				cfg.Cluster, cfg.ClusterRescan, cfg.ClusterName = reports, rescan, clusterName
				if clusterIgn {
					cfg.Ignores = reports.Ignores()
				}
				if opStatus != "" {
					cfg.Operator = &opstatus.Client{URL: opStatus}
				}
			}
			srv, err := server.New(cfg)
			if err != nil {
				return err
			}

			run.Start(ctx)
			sched.Start()
			go srv.WatchEngine(ctx, 30*time.Second)
			if reports != nil {
				go func() {
					if err := srv.RunClusterHistory(ctx, reports, time.Duration(historyDays)*24*time.Hour); err != nil {
						log.Error("cluster history stopped", "err", err)
					}
				}()
				go func() {
					if err := reports.Start(ctx); err != nil {
						log.Error("cluster reports stopped", "err", err)
					}
				}()
			}

			hs := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
			errc := make(chan error, 1)
			go func() {
				log.Info("listening", "addr", listen, "db", dbPath, "clamd", sf.clamd, "workers", workers, "timezone", loc.String())
				errc <- hs.ListenAndServe()
			}()

			select {
			case err := <-errc:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case <-ctx.Done():
				log.Info("shutting down")
			}
			shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			hs.Shutdown(shutdown)
			sched.Stop()
			run.Wait()
			return nil
		},
	}
	sf.register(cmd.Flags())
	cmd.Flags().StringVar(&listen, "listen", ":8080", "HTTP listen address")
	cmd.Flags().StringVar(&dbPath, "db", "meles.db", "SQLite database file")
	cmd.Flags().IntVar(&workers, "workers", 1, "images scanned in parallel (each uses --concurrency clamd sessions)")
	cmd.Flags().DurationVar(&runTimeout, "run-timeout", time.Hour, "maximum duration of a single run")
	cmd.Flags().StringVar(&timezone, "timezone", "Local", "time zone for display and schedules without CRON_TZ, e.g. Europe/Berlin")
	cmd.Flags().IntVar(&cacheSize, "cache-layers", 2000, "layer results kept in memory")
	cmd.Flags().BoolVar(&cluster, "cluster-reports", false, "show the MalwareReports of the meles operator (needs get/list/watch on malwarereports.meles.io)")
	cmd.Flags().StringVar(&clusterName, "cluster-name", "", "with --cluster-reports: name of the cluster in the history (for several clusters later)")
	cmd.Flags().IntVar(&historyDays, "history-days", 365, "with --cluster-reports: keep the history of the reports this many days (the last event of each report is kept)")
	cmd.Flags().StringVar(&opStatus, "operator-status", "", "with --cluster-reports: URL of the operator's headless metrics service, e.g. http://meles-operator-metrics.meles:8080; shows its queue and held pods")
	cmd.Flags().BoolVar(&rescan, "cluster-rescan", true, "with --cluster-reports: allow requesting a rescan from the UI (needs patch on malwarereports.meles.io)")
	cmd.Flags().BoolVar(&clusterIgn, "cluster-ignore", false, "with --cluster-reports: create and delete ignore rules (MalwareIgnore, ClusterMalwareIgnore) from the UI, and apply the ClusterMalwareIgnores to the server's own runs (needs get/list/watch/create/delete on both)")
	cmd.Flags().StringVar(&ignoreF, "ignorefile", "", "YAML file with ignore rules for the server's own runs, read at every run (format of meles image --ignorefile)")
	cmd.Flags().IntVar(&cachePaths, "cache-paths", scan.DefaultMaxPaths, "file paths kept in the layer cache over all layers (about 100-150 bytes each)")
	return cmd
}

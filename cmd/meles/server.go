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

	"git.itknecht.de/sugras/meles/internal/runner"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/schedule"
	"git.itknecht.de/sugras/meles/internal/server"
	"git.itknecht.de/sugras/meles/internal/store"
)

func newServerCmd() *cobra.Command {
	var (
		sf         scanFlags
		listen     string
		dbPath     string
		workers    int
		runTimeout time.Duration
		timezone   string
		cacheSize  int
		cachePaths int
	)
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Run the web UI with scheduled scans and reports",
		Long: `server runs the meles web UI and JSON API. Scans can be configured with a
cron schedule; every run is stored with its full report in a SQLite database.

The UI has no login of its own: expose it only inside the cluster or behind an
authenticating proxy (e.g. oauth2-proxy).`,
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
			run := runner.New(st, sc, workers, runTimeout, log)
			sched := schedule.New(st, run, loc, log)
			if err := sched.Sync(ctx); err != nil {
				return err
			}
			srv, err := server.New(server.Config{
				Store: st, Runner: run, Scheduler: sched, Engine: sc.Engine, Cache: cache,
				Location: loc, Logger: log, Version: version,
			})
			if err != nil {
				return err
			}

			run.Start(ctx)
			sched.Start()
			go srv.WatchEngine(ctx, 30*time.Second)

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
	cmd.Flags().IntVar(&cachePaths, "cache-paths", scan.DefaultMaxPaths, "file paths kept in the layer cache over all layers (about 100-150 bytes each)")
	return cmd
}

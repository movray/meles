package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/movray/meles/internal/mirror"
)

func newMirrorCmd() *cobra.Command {
	var listen, dbDir, rulesDir string
	cmd := &cobra.Command{
		Use:   "mirror",
		Short: "Serve the ClamAV database mirror and YARA rules to freshclam",
		Long: `mirror serves a private ClamAV database mirror over HTTP, for freshclam's
PrivateMirror and DatabaseCustomURL: the files in --db-dir (kept up to date
by cvdupdate) under /, the YARA rules in --rules-dir under /rules/, and
/healthz. It does not download anything itself.

Only regular files directly in the two directories are served; no listings,
no subdirectories, no names starting with a dot.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			log := slog.Default()
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			hs := &http.Server{
				Addr:              listen,
				Handler:           mirror.Handler(dbDir, rulesDir, log),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       2 * time.Minute,
			}
			errc := make(chan error, 1)
			go func() {
				log.Info("mirror listening", "addr", listen, "dbDir", dbDir, "rulesDir", rulesDir)
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
			return hs.Shutdown(shutdown)
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&listen, "listen", ":8080", "HTTP listen address")
	fs.StringVar(&dbDir, "db-dir", "/mirror/db", "directory with the ClamAV databases, served under /")
	fs.StringVar(&rulesDir, "rules-dir", "", "directory with YARA rules, served under /rules/ (empty: none)")
	return cmd
}

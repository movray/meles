package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"git.itknecht.de/sugras/meles/internal/harbor"
	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
)

func newHarborAdapterCmd() *cobra.Command {
	var (
		sf          scanFlags
		listen      string
		tokenFile   string
		tlsCert     string
		tlsKey      string
		workers     int
		scanTimeout time.Duration
		keep        time.Duration
		ignoreF     string
		skippedSev  string
		upstreamURL string
		upstreamTok string
		harborNS    string
		cacheSize   int
		cachePaths  int
	)
	cmd := &cobra.Command{
		Use:   "harbor-adapter",
		Short: "Scan the images pushed to Harbor (pluggable scanner adapter)",
		Long: `harbor-adapter implements Harbor's pluggable scanner API, so that Harbor scans
every pushed image with meles. Register it in Harbor under Interrogation
Services with the authorization "Bearer" and the token from --token-file.

Harbor knows vulnerability and SBOM reports only: findings become entries of
severity Critical (signature as ID, file path as package), files that were not
scanned entries of --skipped-severity. Harbor's "prevent vulnerable images
from running" with severity Critical then blocks infected images.

A Harbor project uses one scanner. With --upstream-url the adapter chains
another adapter, e.g. Trivy's: every scan goes to both, the report contains
the CVEs and the malware findings, and SBOM requests are passed through.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !harbor.ValidSeverity(skippedSev) {
				return fmt.Errorf("--skipped-severity %q: use Unknown, Negligible, Low, Medium, High or Critical", skippedSev)
			}
			if (tlsCert == "") != (tlsKey == "") {
				return errors.New("--tls-cert and --tls-key go together")
			}
			token, err := readToken(tokenFile)
			if err != nil {
				return fmt.Errorf("--token-file: %w", err)
			}
			log := slog.Default()
			if token == "" {
				log.Warn("no --token-file: anyone who reaches the adapter can make it pull and scan images")
			}
			var rules *ignore.Rules
			if ignoreF != "" {
				if rules, err = ignore.Load(ignoreF, time.Now()); err != nil {
					return fmt.Errorf("--ignorefile: %w", err)
				}
			}
			var upstream *harbor.Upstream
			if upstreamURL != "" {
				upstream = &harbor.Upstream{URL: upstreamURL, Client: &http.Client{Timeout: time.Minute}}
				tok, err := readToken(upstreamTok)
				if err != nil {
					return fmt.Errorf("--upstream-token-file: %w", err)
				}
				if tok != "" {
					upstream.Authorization = "Bearer " + tok
				}
			}
			c := scan.NewCache(cacheSize)
			c.MaxPaths = cachePaths
			sc, err := sf.scanner(c)
			if err != nil {
				return err
			}
			sc.Logger = log
			a := harbor.New(harbor.Config{
				Scanner: sc, Version: version, Token: token, Rules: rules, SkippedSeverity: skippedSev,
				Upstream: upstream, Workers: workers, ScanTimeout: scanTimeout, KeepReports: keep, HarborNamespace: harborNS, Logger: log,
			})

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			go a.Run(ctx)
			hs := &http.Server{Addr: listen, Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
			errc := make(chan error, 1)
			go func() {
				log.Info("harbor adapter listening", "addr", listen, "tls", tlsCert != "", "clamd", sf.clamd, "upstream", upstreamURL, "workers", workers, "ignoreRules", rules.Len())
				if tlsCert != "" {
					errc <- hs.ListenAndServeTLS(tlsCert, tlsKey)
				} else {
					errc <- hs.ListenAndServe()
				}
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
	sf.register(cmd.Flags())
	fs := cmd.Flags()
	fs.StringVar(&listen, "listen", ":8080", "HTTP listen address")
	fs.StringVar(&tokenFile, "token-file", "", "file with the bearer token Harbor sends (scanner registration: Authorization Bearer)")
	fs.StringVar(&tlsCert, "tls-cert", "", "TLS certificate (PEM); empty: plain HTTP")
	fs.StringVar(&tlsKey, "tls-key", "", "TLS private key (PEM)")
	fs.IntVar(&workers, "workers", 2, "images scanned in parallel; each scan uses --concurrency clamd sessions")
	fs.DurationVar(&scanTimeout, "scan-timeout", 30*time.Minute, "maximum duration of a scan, including the upstream's")
	fs.DurationVar(&keep, "keep-reports", 24*time.Hour, "how long reports are kept for Harbor to fetch")
	fs.StringVar(&ignoreF, "ignorefile", "", "YAML file with ignore rules; ignored entries are left out of the reports")
	fs.StringVar(&skippedSev, "skipped-severity", "Critical", "Harbor severity of files that were not scanned")
	fs.StringVar(&upstreamURL, "upstream-url", "", "scanner adapter to chain, e.g. Trivy's: http://harbor-trivy:8080")
	fs.StringVar(&upstreamTok, "upstream-token-file", "", "file with a bearer token for the upstream adapter, if it wants one")
	fs.StringVar(&harborNS, "harbor-namespace", "", "namespace of Harbor: completes the short service name Harbor sends as its registry address (http://harbor-core:80 becomes harbor-core.<namespace>) when the adapter runs elsewhere")
	fs.IntVar(&cacheSize, "cache-layers", 2000, "layer results kept in memory; Harbor's images share many base layers")
	fs.IntVar(&cachePaths, "cache-paths", scan.DefaultMaxPaths, "file paths kept in the layer cache over all layers (about 100-150 bytes each)")
	return cmd
}

// readToken returns the trimmed content of path, or "" for no path.
func readToken(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

package main

import (
	"fmt"
	"log/slog"
	"net"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"git.itknecht.de/sugras/meles/internal/clamdproxy"
)

func newClamdProxyCmd() *cobra.Command {
	p := &clamdproxy.Proxy{}
	var listen string
	cmd := &cobra.Command{
		Use:   "clamd-proxy",
		Short: "Put TLS and token authentication in front of clamd",
		Long: `clamd-proxy runs next to clamd (e.g. as a sidecar) and adds what clamd lacks:
TLS, token authentication and a command filter. Only PING, VERSION, IDSESSION,
INSTREAM and END are forwarded; SHUTDOWN, SCAN <path> and all other commands
close the connection. Let clamd listen only on 127.0.0.1 or a Unix socket.

Clients connect with --clamd tls://host:port and MELES_CLAMD_TOKEN.

With --rules-dir, VERSION replies carry a hash of the YARA rules clamd loads
(ClamAV 1.4.6/28164+rules.<hash>/...).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if p.CertFile == "" || p.KeyFile == "" || p.TokenFile == "" {
				return fmt.Errorf("--tls-cert, --tls-key and --token-file are required")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			ln, err := net.Listen("tcp", listen)
			if err != nil {
				return fmt.Errorf("listen: %w", err)
			}
			p.Logger = slog.Default()
			p.Logger.Info("listening", "addr", listen, "upstream", p.Upstream)
			return p.Serve(ctx, ln)
		},
	}
	fs := cmd.Flags()
	fs.StringVar(&listen, "listen", ":3311", "TLS listen address")
	fs.StringVar(&p.Upstream, "upstream", "tcp://127.0.0.1:3310", "clamd address: tcp://127.0.0.1:3310 or unix:///path")
	fs.StringVar(&p.CertFile, "tls-cert", "", "TLS certificate (PEM), reloaded when it changes")
	fs.StringVar(&p.KeyFile, "tls-key", "", "TLS private key (PEM)")
	fs.StringVar(&p.TokenFile, "token-file", "", "file with accepted tokens, one per line, reloaded when it changes")
	fs.DurationVar(&p.AuthTimeout, "auth-timeout", 10*time.Second, "time for TLS handshake and authentication")
	fs.IntVar(&p.MaxConns, "max-connections", 100, "concurrent client connections (0 = no limit)")
	fs.StringVar(&p.RulesDir, "rules-dir", "", "clamd's database directory: VERSION replies get a hash of the YARA rules in it, so that changed rules trigger rescans")
	return cmd
}

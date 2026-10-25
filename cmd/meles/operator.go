package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/operator"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

func newOperatorCmd() *cobra.Command {
	var (
		sf           scanFlags
		platforms    string
		workers      int
		scanTimeout  time.Duration
		retryAfter   time.Duration
		retryIncompl time.Duration
		rescan       time.Duration
		prune        time.Duration
		pullRole     string
		operatorSA   string
		healthListen string
		metricsAddr  string
		leaderElect  bool
		leaderNS     string
		cacheSize    int
		cachePaths   int
		gate         bool
		gateFailOpen bool
		webhookPort  int
		webhookCerts string
	)
	cmd := &cobra.Command{
		Use:   "operator",
		Short: "Scan the images of all pods in the cluster and write MalwareReports",
		Long: `operator watches the pods of the cluster and scans the image every container
runs, by digest. The result is written as a MalwareReport (meles.io/v1alpha1)
in the pod's namespace, one per workload and container, owned by the workload.
Every digest is scanned once; other workloads with the same image get a copy.
Reports are rescanned when the signature database changed, at most once per
--rescan-interval, after --retry-after if the scan failed and after
--retry-incomplete-after if files were skipped. Every --prune-interval, reports
of ReplicaSets, StatefulSets and DaemonSets without pods (e.g. old ReplicaSets
of a Deployment) are deleted.

MalwareIgnores (per namespace) and ClusterMalwareIgnores hold ignore rules;
matching entries stay in the report, marked, but no longer count for its
status. Changed rules apply without a rescan.

Images are pulled with the imagePullSecrets of the pods that run them and of
their service accounts, where the operator may read them (a RoleBinding to the
pull-secret-reader ClusterRole per namespace, or cluster-wide), then with the
Docker config (DOCKER_CONFIG).

With --gate, the operator serves the mutating webhook of the scan gate
(/gate/enforce, /gate/audit) and releases the pods it holds: once their images
are Clean (enforce) or not Infected (audit), pinned to the scanned digests.
--gate-fail-open releases them also when the scan failed in clamd.

It uses the kubeconfig from KUBECONFIG or, in a pod, its service account.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if platforms != operator.PlatformsNodes {
				if _, err := source.ParsePlatforms(platforms); err != nil {
					return fmt.Errorf("--platform: %w", err)
				}
			}
			c := scan.NewCache(cacheSize)
			c.MaxPaths = cachePaths
			sc, err := sf.scanner(c)
			if err != nil {
				return err
			}
			log := slog.Default()
			ctrl.SetLogger(logr.FromSlogHandler(log.Handler()))

			cfg, err := ctrl.GetConfig()
			if err != nil {
				return fmt.Errorf("kubernetes config: %w", err)
			}
			scheme := runtime.NewScheme()
			if err := clientgoscheme.AddToScheme(scheme); err != nil {
				return err
			}
			if err := v1alpha1.AddToScheme(scheme); err != nil {
				return err
			}
			// The reconciler is created after the manager; the handler is
			// needed before.
			var r *operator.Reconciler
			status := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.StatusHandler().ServeHTTP(w, req) })
			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme:                  scheme,
				Metrics:                 metricsserver.Options{BindAddress: metricsAddr, ExtraHandlers: map[string]http.Handler{"/status": status}},
				HealthProbeBindAddress:  healthListen,
				LeaderElection:          leaderElect,
				LeaderElectionID:        "meles-operator.meles.io",
				LeaderElectionNamespace: leaderNS,
				// The cache holds every pod of the cluster.
				Cache:         cache.Options{DefaultTransform: cache.TransformStripManagedFields()},
				WebhookServer: webhook.NewServer(webhook.Options{Port: webhookPort, CertDir: webhookCerts}),
			})
			if err != nil {
				return fmt.Errorf("create manager: %w", err)
			}
			r = &operator.Reconciler{
				Client: mgr.GetClient(), Scanner: sc, Engine: sc.Engine, Version: version,
				Platforms: platforms, Workers: workers,
				APIReader: mgr.GetAPIReader(), PullSecretRole: pullRole, ServiceAccount: operatorSA,
				ScanTimeout: scanTimeout, RetryAfter: retryAfter, RetryIncompleteAfter: retryIncompl, RescanInterval: rescan, Logger: log,
				Gate: gate, GateFailOpen: gateFailOpen, Insecure: sf.insecure,
				IsLeader: func() bool {
					select {
					case <-mgr.Elected():
						return true
					default:
						return false
					}
				},
			}
			go func() {
				<-mgr.Elected()
				operator.SetLeader()
			}()
			if gate {
				r.Recorder = mgr.GetEventRecorder("meles-operator")
				operator.RegisterGateWebhooks(mgr)
				if err := mgr.AddReadyzCheck("webhook", mgr.GetWebhookServer().StartedChecker()); err != nil {
					return err
				}
			}
			if err := r.SetupWithManager(mgr); err != nil {
				return fmt.Errorf("set up controller: %w", err)
			}
			for _, cluster := range []bool{false, true} {
				if err := (&operator.IgnoreStatusReconciler{Client: mgr.GetClient(), Cluster: cluster}).SetupWithManager(mgr); err != nil {
					return fmt.Errorf("set up ignore controller: %w", err)
				}
			}
			if prune > 0 {
				// Runs only on the leader, once the caches are filled.
				err := mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
					if !mgr.GetCache().WaitForCacheSync(ctx) {
						return nil
					}
					return r.RunPrune(ctx, prune)
				}))
				if err != nil {
					return err
				}
			}
			if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
				return err
			}
			if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
				return err
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			log.Info("operator starting", "clamd", sf.clamd, "platforms", platforms, "workers", workers, "rescan-interval", rescan, "gate", gate, "version", version)
			return mgr.Start(ctx)
		},
	}
	sf.register(cmd.Flags())
	cmd.Flags().StringVar(&platforms, "platform", operator.PlatformsNodes, "platforms to scan: nodes (architectures of the cluster's nodes), all, or a list such as linux/amd64,linux/arm64")
	cmd.Flags().IntVar(&workers, "workers", 2, "images scanned in parallel, apart from reconciling pods; each scan uses --concurrency clamd sessions")
	cmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 30*time.Minute, "maximum duration of a single image scan")
	cmd.Flags().DurationVar(&retryAfter, "retry-after", time.Hour, "wait before retrying an image whose scan failed")
	cmd.Flags().DurationVar(&retryIncompl, "retry-incomplete-after", 12*time.Hour, "wait before rescanning an image with skipped files (usually clamd limits, see clamd.maxScanSize/maxScanTime in the chart)")
	cmd.Flags().StringVar(&pullRole, "pull-secret-role", "", "ClusterRole that grants reading pull secrets, named in the error of a refused pull")
	cmd.Flags().StringVar(&operatorSA, "service-account", "", "service account of the operator as namespace:name, named in the error of a refused pull")
	cmd.Flags().DurationVar(&prune, "prune-interval", 30*time.Minute, "delete reports of ReplicaSets, StatefulSets and DaemonSets without pods this often; 0 disables")
	cmd.Flags().DurationVar(&rescan, "rescan-interval", 24*time.Hour, "rescan images when the signature database changed, at most this often per image; 0 disables")
	cmd.Flags().StringVar(&healthListen, "health-listen", ":8081", "listen address of /healthz and /readyz")
	cmd.Flags().StringVar(&metricsAddr, "metrics-listen", ":8080", "listen address of /metrics (Prometheus) and /status (JSON, read by meles server); 0 disables")
	cmd.Flags().BoolVar(&leaderElect, "leader-elect", true, "use leader election, so that only one replica scans")
	cmd.Flags().StringVar(&leaderNS, "leader-election-namespace", "", "namespace of the leader election lease; default: the pod's namespace")
	cmd.Flags().IntVar(&cacheSize, "cache-layers", 2000, "layer results kept in memory")
	cmd.Flags().BoolVar(&gate, "gate", false, "scan gate: serve the webhook that holds new pods and release them once their images are scanned")
	cmd.Flags().BoolVar(&gateFailOpen, "gate-fail-open", true, "release held pods also when the scan failed in clamd (an outage of meles), with a warning event")
	cmd.Flags().IntVar(&webhookPort, "webhook-port", 9443, "port of the scan gate's webhook (HTTPS)")
	cmd.Flags().StringVar(&webhookCerts, "webhook-cert-dir", "/tls", "directory with tls.crt and tls.key of the webhook")
	cmd.Flags().IntVar(&cachePaths, "cache-paths", scan.DefaultMaxPaths, "file paths kept in the layer cache over all layers (about 100-150 bytes each)")
	return cmd
}

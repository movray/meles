package harbor

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

// ImageScanner scans one image; *scan.Scanner implements it.
type ImageScanner interface {
	Scan(ctx context.Context, ref string, platforms source.PlatformFilter, progress func(scan.Progress), opts ...scan.Option) (*scan.Report, error)
}

// Config configures an Adapter.
type Config struct {
	Scanner ImageScanner
	// Version of meles, reported as the scanner version.
	Version string
	// Token, if set, is the bearer token Harbor must send (scanner
	// registration: Authorization "Bearer").
	Token string
	// Rules are ignore rules; ignored entries are left out of the report.
	Rules *ignore.Rules
	// SkippedSeverity is the severity of files that were not scanned
	// (default Critical: an unscanned file must not pass a gate).
	SkippedSeverity string
	// Upstream, if set, is chained: e.g. Trivy's adapter for CVEs.
	Upstream *Upstream
	// Workers is the number of images scanned in parallel.
	Workers int
	// ScanTimeout bounds a scan, including the upstream's.
	ScanTimeout time.Duration
	// KeepReports is how long reports are kept for Harbor to fetch.
	KeepReports time.Duration
	// HarborNamespace completes the short service names Harbor sends as its
	// registry address ("http://harbor-core:80" with use_internal_addr), so
	// that the adapter can run in another namespace.
	HarborNamespace string
	Logger          *slog.Logger
}

// Adapter serves the scanner adapter API.
type Adapter struct {
	cfg   Config
	queue chan *job

	mu   sync.Mutex
	jobs map[string]*job
}

type job struct {
	id         string
	req        ScanRequest
	raw        []byte // the request as received, for the upstream
	created    time.Time
	upstreamID string

	// Set once the scan is done.
	done   bool
	report *VulnerabilityReport
	err    error
}

// maxQueued bounds the scans waiting for a worker.
const maxQueued = 1024

// New returns an adapter; Run starts its scan workers.
func New(cfg Config) *Adapter {
	if cfg.SkippedSeverity == "" {
		cfg.SkippedSeverity = "Critical"
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = 30 * time.Minute
	}
	if cfg.KeepReports <= 0 {
		cfg.KeepReports = 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Adapter{cfg: cfg, queue: make(chan *job, maxQueued), jobs: map[string]*job{}}
}

// Run scans queued requests with cfg.Workers workers until ctx is canceled,
// and drops old reports.
func (a *Adapter) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range max(a.cfg.Workers, 1) {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-a.queue:
					a.run(ctx, j)
				}
			}
		})
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
			a.expire(time.Now())
		}
	}
}

func (a *Adapter) expire(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, j := range a.jobs {
		if j.done && now.Sub(j.created) > a.cfg.KeepReports {
			delete(a.jobs, id)
		}
	}
}

// Handler returns the HTTP handler: the API under /api/v1 (with the bearer
// token, if configured) and unauthenticated probes.
func (a *Adapter) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/metadata", a.auth(a.handleMetadata))
	mux.HandleFunc("POST /api/v1/scan", a.auth(a.handleScan))
	mux.HandleFunc("GET /api/v1/scan/{id}/report", a.auth(a.handleReport))
	mux.HandleFunc("GET /probe/healthy", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /probe/ready", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

func (a *Adapter) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.Token != "" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(a.cfg.Token)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="meles"`)
				writeError(w, http.StatusUnauthorized, errors.New("missing or wrong bearer token"))
				return
			}
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, contentType string, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	var e errorResponse
	e.Error.Message = err.Error()
	writeJSON(w, status, mimeError, e)
}

func (a *Adapter) handleMetadata(w http.ResponseWriter, r *http.Request) {
	m := Metadata{
		Scanner: Scanner{Name: "meles", Vendor: "meles", Version: a.cfg.Version},
		Capabilities: []Capability{{
			Type:              "vulnerability",
			ConsumesMimeTypes: []string{mimeOCIManifest, mimeDockerManifest},
			ProducesMimeTypes: []string{mimeVulnReport, mimeVulnReportV10},
		}},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type": "malware",
		},
	}
	if u := a.cfg.Upstream; u != nil {
		up, err := u.Metadata(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		m.Scanner.Name = "meles + " + up.Scanner.Name
		// Offer what the upstream offers apart from vulnerabilities, e.g.
		// SBOMs, which are passed through.
		for _, c := range up.Capabilities {
			if c.Type != "" && c.Type != "vulnerability" {
				m.Capabilities = append(m.Capabilities, c)
			}
		}
		for k, v := range up.Properties {
			m.Properties["upstream/"+k] = v
		}
		m.Properties["harbor.scanner-adapter/scanner-type"] = "malware, " + up.Scanner.Name
	}
	writeJSON(w, http.StatusOK, mimeMetadata, m)
}

func (a *Adapter) handleScan(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var req ScanRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid scan request: %w", err))
		return
	}
	if _, _, err := imageRef(req, a.cfg.HarborNamespace); err != nil {
		writeError(w, http.StatusUnprocessableEntity, err)
		return
	}
	j := &job{id: newID(), req: req, raw: raw, created: time.Now()}
	if u := a.cfg.Upstream; u != nil {
		// Asked right away, so that a pass-through report (an SBOM) is
		// available as soon as the upstream has it.
		if j.upstreamID, err = u.Scan(r.Context(), raw); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
	}
	a.mu.Lock()
	select {
	case a.queue <- j:
		a.jobs[j.id] = j
	default:
		a.mu.Unlock()
		writeError(w, http.StatusServiceUnavailable, errors.New("scan queue full"))
		return
	}
	a.mu.Unlock()
	a.cfg.Logger.Info("scan requested", "id", j.id, "repository", req.Artifact.Repository, "digest", req.Artifact.Digest)
	writeJSON(w, http.StatusAccepted, mimeScanResponse, ScanResponse{ID: j.id})
}

func (a *Adapter) handleReport(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	j, ok := a.jobs[r.PathValue("id")]
	var done bool
	var report *VulnerabilityReport
	var jobErr error
	if ok {
		done, report, jobErr = j.done, j.report, j.err
	}
	a.mu.Unlock()
	if !ok {
		// Harbor asks for a new scan (e.g. after a restart of the adapter).
		http.NotFound(w, r)
		return
	}

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "sbom") {
		a.passThrough(w, r, j, accept)
		return
	}
	if accept != "" && !strings.Contains(accept, "vulnerability.report") && !strings.Contains(accept, "vuln.report.harbor") && !strings.Contains(accept, "*/*") {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("unsupported report type %q", accept))
		return
	}
	switch {
	case !done:
		w.Header().Set("Refresh-After", "15")
		w.Header().Set("Retry-After", "15")
		w.WriteHeader(http.StatusFound)
	case jobErr != nil:
		writeError(w, http.StatusInternalServerError, jobErr)
	default:
		writeJSON(w, http.StatusOK, mimeVulnReport, report)
	}
}

// passThrough returns the upstream's report of another type, e.g. an SBOM.
func (a *Adapter) passThrough(w http.ResponseWriter, r *http.Request, j *job, accept string) {
	if a.cfg.Upstream == nil || j.upstreamID == "" {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("unsupported report type %q", accept))
		return
	}
	resp, err := a.cfg.Upstream.Report(r.Context(), j.upstreamID, accept, r.URL.Query())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	defer resp.Body.Close()
	for _, k := range []string{"Content-Type", "Refresh-After", "Retry-After"} {
		if v := resp.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// run scans one request, and waits for the upstream's report if chained.
func (a *Adapter) run(ctx context.Context, j *job) {
	ctx, cancel := context.WithTimeout(ctx, a.cfg.ScanTimeout)
	defer cancel()
	report, err := a.scan(ctx, j)
	if err == nil && a.cfg.Upstream != nil {
		var up *VulnerabilityReport
		if up, err = a.cfg.Upstream.WaitVulnerabilities(ctx, j.upstreamID); err == nil {
			report = merge(up, report)
		}
	}
	if err != nil {
		a.cfg.Logger.Warn("scan failed", "id", j.id, "repository", j.req.Artifact.Repository, "digest", j.req.Artifact.Digest, "err", err)
	} else {
		a.cfg.Logger.Info("scan done", "id", j.id, "repository", j.req.Artifact.Repository, "severity", report.Severity, "entries", len(report.Vulnerabilities))
	}
	a.mu.Lock()
	j.done, j.report, j.err = true, report, err
	a.mu.Unlock()
}

func (a *Adapter) scan(ctx context.Context, j *job) (*VulnerabilityReport, error) {
	ref, insecure, err := imageRef(j.req, a.cfg.HarborNamespace)
	if err != nil {
		return nil, err
	}
	auth, err := authenticator(j.req.Registry.Authorization)
	if err != nil {
		return nil, err
	}
	opts := []scan.Option{scan.WithKeychain(staticKeychain{auth})}
	if insecure {
		opts = append(opts, scan.WithInsecure())
	}
	rep, err := a.cfg.Scanner.Scan(ctx, ref, source.PlatformFilter{}, nil, opts...)
	if err != nil {
		return nil, err
	}
	rep.ApplyIgnore(a.cfg.Rules, time.Now())
	return a.toReport(j.req.Artifact, rep), nil
}

// toReport turns findings that count into Critical entries and files that
// were not scanned into entries of SkippedSeverity.
func (a *Adapter) toReport(art Artifact, rep *scan.Report) *VulnerabilityReport {
	out := &VulnerabilityReport{
		GeneratedAt:     rep.FinishedAt,
		Artifact:        art,
		Scanner:         Scanner{Name: "meles", Vendor: "meles", Version: a.cfg.Version},
		Vulnerabilities: []Vulnerability{},
	}
	engine := strings.TrimSpace(rep.Engine.Engine + " signatures " + rep.Engine.Signatures)
	for _, f := range rep.ActiveFindings() {
		where := fmt.Sprintf("layer %d", f.Layer)
		desc := fmt.Sprintf("Malware: %s detected %s in %s (%s).", engine, f.Signature, f.Path, where)
		if f.Status != scan.StatusPresent {
			desc += fmt.Sprintf(" The file was %s in layer %d but is still shipped with the image and can be restored from layer %d.", f.Status, f.HiddenByLayer, f.Layer)
		}
		attrs := map[string]any{"kind": "malware", "platform": f.Platform, "layer": f.Layer, "diffID": f.DiffID,
			"status": f.Status, "sha256": f.SHA256, "createdBy": f.CreatedBy}
		var links []string
		if f.Rule != nil {
			// The Detection Rule License requires the rule author with every match.
			desc += fmt.Sprintf(" YARA rule %s by %s (%s).", f.Rule.Name, f.Rule.Author, f.Rule.License)
			attrs["rule"] = f.Rule
			links = []string{f.Rule.URL}
		}
		out.Vulnerabilities = append(out.Vulnerabilities, Vulnerability{
			ID: f.Signature, Package: f.Path, Version: where, Severity: "Critical", Description: desc, Links: links,
			VendorAttributes: map[string]any{"meles": attrs},
		})
	}
	for _, s := range rep.ActiveSkipped() {
		out.Vulnerabilities = append(out.Vulnerabilities, Vulnerability{
			ID: s.Signature, Package: s.Path, Version: fmt.Sprintf("layer %d", s.Layer), Severity: a.cfg.SkippedSeverity,
			Description: fmt.Sprintf("Not scanned for malware: %s (%d bytes). The image is not fully checked; ignore known harmless cases with a meles ignore rule.", s.Reason, s.Size),
			VendorAttributes: map[string]any{
				"meles": map[string]any{"kind": "skipped", "platform": s.Platform, "layer": s.Layer, "sha256": s.SHA256, "reason": s.Reason},
			},
		})
	}
	out.Severity = maxSeverity(out.Vulnerabilities)
	return out
}

// merge adds meles' entries to the upstream's report.
func merge(up, mel *VulnerabilityReport) *VulnerabilityReport {
	out := *up
	out.Vulnerabilities = append(slices.Clone(up.Vulnerabilities), mel.Vulnerabilities...)
	out.Scanner = Scanner{Name: "meles + " + up.Scanner.Name, Vendor: "meles, " + up.Scanner.Vendor, Version: mel.Scanner.Version + ", " + up.Scanner.Version}
	if severityRank(up.Severity) > severityRank(mel.Severity) {
		out.Severity = up.Severity
	} else {
		out.Severity = mel.Severity
	}
	return &out
}

func maxSeverity(vs []Vulnerability) string {
	best := "Unknown"
	for _, v := range vs {
		if severityRank(v.Severity) > severityRank(best) {
			best = v.Severity
		}
	}
	return best
}

// imageRef returns the image reference of a scan request by digest, and
// whether the registry is plain HTTP. A host without a dot (a service name
// in Harbor's namespace) gets namespace appended, if set.
func imageRef(req ScanRequest, namespace string) (string, bool, error) {
	u, err := url.Parse(req.Registry.URL)
	if err != nil || u.Host == "" {
		return "", false, fmt.Errorf("registry url %q: want e.g. https://harbor.example.com", req.Registry.URL)
	}
	if req.Artifact.Repository == "" || !strings.HasPrefix(req.Artifact.Digest, "sha256:") {
		return "", false, errors.New("artifact needs repository and a sha256 digest")
	}
	host := u.Host
	if namespace != "" && !strings.Contains(u.Hostname(), ".") && u.Hostname() != "localhost" {
		host = u.Hostname() + "." + namespace
		if p := u.Port(); p != "" {
			host += ":" + p
		}
	}
	ref := host + "/" + req.Artifact.Repository + "@" + req.Artifact.Digest
	if _, err := name.NewDigest(ref, name.Insecure); err != nil {
		return "", false, fmt.Errorf("artifact %s: %w", ref, err)
	}
	return ref, u.Scheme == "http", nil
}

// authenticator turns the Authorization header Harbor passes for its
// registry into credentials.
func authenticator(header string) (authn.Authenticator, error) {
	scheme, value, _ := strings.Cut(strings.TrimSpace(header), " ")
	switch strings.ToLower(scheme) {
	case "":
		return authn.Anonymous, nil
	case "basic":
		return authn.FromConfig(authn.AuthConfig{Auth: value}), nil
	case "bearer":
		return authn.FromConfig(authn.AuthConfig{RegistryToken: value}), nil
	}
	return nil, fmt.Errorf("registry authorization: unsupported scheme %q", scheme)
}

// staticKeychain answers every registry with the credentials of the scan
// request: it is only used to pull that one artifact.
type staticKeychain struct{ auth authn.Authenticator }

func (k staticKeychain) Resolve(authn.Resource) (authn.Authenticator, error) { return k.auth, nil }

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

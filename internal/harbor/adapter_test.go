package harbor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"git.itknecht.de/sugras/meles/internal/engine/fake"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

const token = "harbor-t0ken"

// env is Harbor's view: a registry that wants a robot account, and the
// adapter.
type env struct {
	t       *testing.T
	srv     *httptest.Server
	reg     *testimage.Registry
	digests map[string]string
	engine  *fake.Engine
}

func newEnv(t *testing.T, configure func(*Config)) *env {
	t.Helper()
	reg, err := testimage.Serve(testimage.Cases())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	e := &env{t: t, reg: reg, digests: map[string]string{}, engine: &fake.Engine{}}
	for _, c := range []string{"clean", "eicar-whiteout"} {
		ref, err := name.ParseReference(reg.Ref(c), name.Insecure)
		if err != nil {
			t.Fatal(err)
		}
		desc, err := remote.Head(ref)
		if err != nil {
			t.Fatal(err)
		}
		e.digests[c] = desc.Digest.String()
	}
	reg.RequireAuth("robot$scanner", "pw")

	cfg := Config{
		Scanner: &scan.Scanner{Engine: e.engine, Limits: extract.Limits{MaxFileSize: 1 << 20}, Concurrency: 2},
		Version: "test", Token: token, Workers: 2, ScanTimeout: time.Minute,
	}
	if configure != nil {
		configure(&cfg)
	}
	a := New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(func() { e.srv.Close(); cancel(); <-done })
	return e
}

func (e *env) do(method, path, accept, body string, auth bool) (*http.Response, string) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", mimeScanRequest)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// scanRequest is what Harbor sends for an image of the test registry.
func (e *env) scanRequest(image, user, password string) string {
	b, _ := json.Marshal(ScanRequest{
		Registry: Registry{URL: "http://" + e.reg.Host, Authorization: "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))},
		Artifact: Artifact{Repository: "selftest/" + image, Digest: e.digests[image], Tag: "latest", MimeType: mimeOCIManifest},
	})
	return string(b)
}

// scan submits a request and polls the report like Harbor.
func (e *env) scan(body string) (int, string) {
	e.t.Helper()
	resp, out := e.do("POST", "/api/v1/scan", "", body, true)
	if resp.StatusCode != http.StatusAccepted {
		e.t.Fatalf("scan: %d %s", resp.StatusCode, out)
	}
	var sr ScanResponse
	json.Unmarshal([]byte(out), &sr)
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, out := e.do("GET", "/api/v1/scan/"+sr.ID+"/report", mimeVulnReport, "", true)
		if resp.StatusCode != http.StatusFound {
			return resp.StatusCode, out
		}
		if resp.Header.Get("Refresh-After") == "" {
			e.t.Error("302 without Refresh-After")
		}
		if time.Now().After(deadline) {
			e.t.Fatal("report not ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func report(t *testing.T, out string) VulnerabilityReport {
	t.Helper()
	var r VulnerabilityReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("report %s: %v", out, err)
	}
	return r
}

func TestAdapter(t *testing.T) {
	e := newEnv(t, nil)

	if resp, _ := e.do("GET", "/api/v1/metadata", "", "", false); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("metadata without token: %d", resp.StatusCode)
	}
	resp, out := e.do("GET", "/api/v1/metadata", mimeMetadata, "", true)
	var m Metadata
	json.Unmarshal([]byte(out), &m)
	if resp.StatusCode != http.StatusOK || m.Scanner.Name != "meles" || len(m.Capabilities) != 1 || m.Capabilities[0].ProducesMimeTypes[0] != mimeVulnReport {
		t.Errorf("metadata: %d %s", resp.StatusCode, out)
	}

	// The deleted EICAR file is still shipped: Critical, and said so.
	status, out := e.scan(e.scanRequest("eicar-whiteout", "robot$scanner", "pw"))
	r := report(t, out)
	if status != http.StatusOK || r.Severity != "Critical" || len(r.Vulnerabilities) != 1 {
		t.Fatalf("infected: %d %s", status, out)
	}
	v := r.Vulnerabilities[0]
	if v.ID != "Eicar-Test-Signature" || v.Package != "/tmp/payload/eicar.com" || !strings.Contains(v.Description, "still shipped") || r.Artifact.Digest != e.digests["eicar-whiteout"] {
		t.Errorf("entry = %+v", v)
	}

	status, out = e.scan(e.scanRequest("clean", "robot$scanner", "pw"))
	if r := report(t, out); status != http.StatusOK || len(r.Vulnerabilities) != 0 || r.Severity != "Unknown" || !strings.Contains(out, `"vulnerabilities":[]`) {
		t.Errorf("clean: %d %s", status, out)
	}

	// Wrong robot credentials: an error, never a clean report.
	if status, out := e.scan(e.scanRequest("clean", "robot$scanner", "wrong")); status != http.StatusInternalServerError || !strings.Contains(out, "UNAUTHORIZED") {
		t.Errorf("wrong credentials: %d %s", status, out)
	}

	if resp, out := e.do("POST", "/api/v1/scan", "", `{"registry":{"url":"http://x"},"artifact":{"repository":"a"}}`, true); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("request without digest: %d %s", resp.StatusCode, out)
	}
	if resp, _ := e.do("GET", "/api/v1/scan/unknown/report", mimeVulnReport, "", true); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown request: %d", resp.StatusCode)
	}
	if resp, _ := e.do("GET", "/api/v1/scan/x/report", mimeSBOMReport, "", true); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown SBOM request: %d", resp.StatusCode)
	}
}

// Files that were not scanned count like a finding by default; an ignore
// rule takes them out.
func TestAdapterSkippedAndIgnored(t *testing.T) {
	rules, errs := ignore.New([]ignore.Rule{{Path: "/etc/hello.txt", Reason: "test", Expires: time.Now().AddDate(0, 1, 0).Format("2006-01-02")}}, "test", time.Now())
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, tt := range []struct {
		name  string
		rules *ignore.Rules
		want  int
	}{{"skipped", nil, 1}, {"ignored", rules, 0}} {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, func(c *Config) { c.Rules = tt.rules })
			e.engine.MaxSize = 1 // every file is refused
			_, out := e.scan(e.scanRequest("clean", "robot$scanner", "pw"))
			r := report(t, out)
			var skipped []Vulnerability
			for _, v := range r.Vulnerabilities {
				if v.Package == "/etc/hello.txt" {
					skipped = append(skipped, v)
				}
			}
			if len(skipped) != tt.want || (tt.want > 0 && (skipped[0].Severity != "Critical" || skipped[0].ID != extract.SigEngineTooBig)) {
				t.Errorf("entries for /etc/hello.txt: %+v", skipped)
			}
		})
	}
}

// With an upstream (Trivy) the project keeps its CVEs: one merged report,
// SBOMs passed through, the upstream's capabilities offered.
func TestAdapterChainsUpstream(t *testing.T) {
	var got atomic.Pointer[string]
	var polls atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer trivy" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/metadata":
			json.NewEncoder(w).Encode(Metadata{Scanner: Scanner{Name: "Trivy", Vendor: "Aqua Security", Version: "0.60"}, Capabilities: []Capability{
				{Type: "vulnerability", ConsumesMimeTypes: []string{mimeOCIManifest}, ProducesMimeTypes: []string{mimeVulnReport}},
				{Type: "sbom", ConsumesMimeTypes: []string{mimeOCIManifest}, ProducesMimeTypes: []string{mimeSBOMReport}},
			}})
		case r.URL.Path == "/api/v1/scan":
			b, _ := io.ReadAll(r.Body)
			s := string(b)
			got.Store(&s)
			w.WriteHeader(http.StatusAccepted)
			json.NewEncoder(w).Encode(ScanResponse{ID: "up-1"})
		case r.URL.Path == "/api/v1/scan/up-1/report" && strings.Contains(r.Header.Get("Accept"), "sbom"):
			w.Write([]byte(`{"media_type":"` + r.URL.Query().Get("sbom_media_type") + `","sbom":{"packages":[]}}`))
		case r.URL.Path == "/api/v1/scan/up-1/report":
			if polls.Add(1) == 1 {
				w.Header().Set("Refresh-After", "1")
				w.WriteHeader(http.StatusFound)
				return
			}
			json.NewEncoder(w).Encode(VulnerabilityReport{Scanner: Scanner{Name: "Trivy", Vendor: "Aqua Security", Version: "0.60"}, Severity: "High",
				Vulnerabilities: []Vulnerability{{ID: "CVE-2026-0001", Package: "openssl", Version: "3.0.1", FixVersion: "3.0.2", Severity: "High"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer up.Close()
	e := newEnv(t, func(c *Config) { c.Upstream = &Upstream{URL: up.URL, Authorization: "Bearer trivy"} })

	_, out := e.do("GET", "/api/v1/metadata", mimeMetadata, "", true)
	if !strings.Contains(out, `"meles + Trivy"`) || !strings.Contains(out, `"sbom"`) {
		t.Errorf("metadata: %s", out)
	}

	body := e.scanRequest("eicar-whiteout", "robot$scanner", "pw")
	status, out := e.scan(body)
	r := report(t, out)
	if status != http.StatusOK || r.Severity != "Critical" || len(r.Vulnerabilities) != 2 || r.Vulnerabilities[0].ID != "CVE-2026-0001" || r.Vulnerabilities[1].ID != "Eicar-Test-Signature" {
		t.Errorf("merged report: %d %s", status, out)
	}
	if p := got.Load(); p == nil || *p != body {
		t.Errorf("upstream got %v, want Harbor's request unchanged", p)
	}

	// The SBOM of the same request comes from the upstream as is.
	var sr ScanResponse
	_, out = e.do("POST", "/api/v1/scan", "", body, true)
	json.Unmarshal([]byte(out), &sr)
	resp, out := e.do("GET", "/api/v1/scan/"+sr.ID+"/report?sbom_media_type=application%2Fspdx%2Bjson", mimeSBOMReport, "", true)
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, "application/spdx+json") {
		t.Errorf("SBOM: %d %s", resp.StatusCode, out)
	}
}

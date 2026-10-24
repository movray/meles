package harbor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Upstream is another scanner adapter, e.g. Trivy's, that the adapter
// chains: scan requests go to both, and the reports are merged.
type Upstream struct {
	// URL of the adapter, e.g. http://harbor-trivy:8080.
	URL string
	// Authorization is sent as the Authorization header, e.g. "Bearer …".
	Authorization string
	Client        *http.Client
}

func (u *Upstream) do(ctx context.Context, method, path, contentType, accept string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(u.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if u.Authorization != "" {
		req.Header.Set("Authorization", u.Authorization)
	}
	c := u.Client
	if c == nil {
		c = http.DefaultClient
	}
	// Redirects mean "not ready" in this API, never follow them.
	nc := *c
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return nc.Do(req)
}

// Metadata returns the upstream adapter's metadata.
func (u *Upstream) Metadata(ctx context.Context) (Metadata, error) {
	resp, err := u.do(ctx, http.MethodGet, "/api/v1/metadata", "", mimeMetadata, nil)
	if err != nil {
		return Metadata{}, fmt.Errorf("upstream metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Metadata{}, fmt.Errorf("upstream metadata: %s", resp.Status)
	}
	var m Metadata
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return Metadata{}, fmt.Errorf("upstream metadata: %w", err)
	}
	return m, nil
}

// Scan forwards Harbor's scan request unchanged and returns the upstream's
// scan request ID.
func (u *Upstream) Scan(ctx context.Context, body []byte) (string, error) {
	resp, err := u.do(ctx, http.MethodPost, "/api/v1/scan", mimeScanRequest, "", body)
	if err != nil {
		return "", fmt.Errorf("upstream scan: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("upstream scan: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var r ScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || r.ID == "" {
		return "", fmt.Errorf("upstream scan: no request ID (%v)", err)
	}
	return r.ID, nil
}

// Report fetches a report as is, for passing it through (e.g. an SBOM).
func (u *Upstream) Report(ctx context.Context, id, accept string, query url.Values) (*http.Response, error) {
	path := "/api/v1/scan/" + url.PathEscape(id) + "/report"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return u.do(ctx, http.MethodGet, path, "", accept, nil)
}

// WaitVulnerabilities polls the upstream's vulnerability report until it is
// ready or ctx ends.
func (u *Upstream) WaitVulnerabilities(ctx context.Context, id string) (*VulnerabilityReport, error) {
	for {
		resp, err := u.Report(ctx, id, mimeVulnReport, nil)
		if err != nil {
			return nil, fmt.Errorf("upstream report: %w", err)
		}
		switch resp.StatusCode {
		case http.StatusOK:
			var r VulnerabilityReport
			err := json.NewDecoder(resp.Body).Decode(&r)
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("upstream report: %w", err)
			}
			return &r, nil
		case http.StatusFound:
			resp.Body.Close()
			wait := retryAfter(resp.Header)
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("upstream report: %w", ctx.Err())
			case <-time.After(wait):
			}
		default:
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			return nil, fmt.Errorf("upstream report: %s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
	}
}

// retryAfter reads the wait from Refresh-After (spec) or Retry-After
// (seen in adapters), in seconds; default 5s, at most a minute.
func retryAfter(h http.Header) time.Duration {
	for _, k := range []string{"Refresh-After", "Retry-After"} {
		if n, err := strconv.Atoi(h.Get(k)); err == nil && n > 0 {
			return min(time.Duration(n)*time.Second, time.Minute)
		}
	}
	return 5 * time.Second
}

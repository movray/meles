package operator

import (
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
)

// maxListed bounds the findings and skipped files stored in a report. etcd
// limits objects to about 1.5 MB; the summary keeps the totals.
const maxListed = 100

// result is what a scan of one image digest produced, shared by all reports
// of that digest: the raw result, before ignore rules. withIgnore applies
// the rules of a report's namespace.
type result struct {
	scanner   v1alpha1.Scanner
	filter    string
	platforms []string
	summary   v1alpha1.Summary
	findings  []v1alpha1.Finding
	skipped   []v1alpha1.Skipped
	err       string
	scannedAt time.Time
}

func resultFromReport(rep *scan.Report, filter, version string) result {
	r := result{
		scanner:   v1alpha1.Scanner{Version: version, Engine: rep.Engine.Engine, Signatures: rep.Engine.Signatures},
		filter:    filter,
		scannedAt: rep.FinishedAt,
	}
	for _, p := range rep.Platforms {
		r.platforms = append(r.platforms, p.Platform)
	}
	findings, skipped := rep.Findings(), rep.Skipped()
	for _, f := range findings[:min(len(findings), maxListed)] {
		r.findings = append(r.findings, v1alpha1.Finding{
			Platform: f.Platform, Layer: f.Layer, DiffID: f.DiffID, Path: f.Path,
			Signature: f.Signature, Status: f.Status, HiddenByLayer: f.HiddenByLayer, CreatedBy: f.CreatedBy, SHA256: f.SHA256,
		})
	}
	for _, s := range skipped[:min(len(skipped), maxListed)] {
		r.skipped = append(r.skipped, v1alpha1.Skipped{
			Platform: s.Platform, Layer: s.Layer, Path: s.Path, Size: s.Size, Reason: s.Reason, Signature: s.Signature, SHA256: s.SHA256,
		})
	}
	r.summary = v1alpha1.Summary{Findings: len(findings), Skipped: len(skipped), Files: rep.Files()}
	r.summary.Status = rawStatus(r.err, r.summary.Findings, r.summary.Skipped)
	return r
}

func rawStatus(err string, findings, skipped int) string {
	switch {
	case err != "":
		return v1alpha1.StatusError
	case findings > 0:
		return v1alpha1.StatusInfected
	case skipped > 0:
		return v1alpha1.StatusIncomplete
	}
	return v1alpha1.StatusClean
}

func resultFromError(err error, version string) result {
	return result{
		scanner:   v1alpha1.Scanner{Version: version},
		summary:   v1alpha1.Summary{Status: v1alpha1.StatusError},
		err:       err.Error(),
		scannedAt: time.Now(),
	}
}

// resultFromData restores the raw result of an existing report, so that
// another workload with the same image does not need a scan of its own and
// changed ignore rules apply without a rescan.
func resultFromData(d v1alpha1.ReportData) result {
	r := result{
		scanner: d.Scanner, filter: d.PlatformFilter, platforms: d.Platforms, summary: d.Summary,
		err: d.Error, scannedAt: d.ScannedAt.Time,
	}
	for _, f := range d.Findings {
		f.Ignored = nil
		r.findings = append(r.findings, f)
	}
	for _, s := range d.Skipped {
		s.Ignored = nil
		r.skipped = append(r.skipped, s)
	}
	s := &r.summary
	s.Findings += s.IgnoredFindings
	s.Skipped += s.IgnoredSkipped
	s.Ignored, s.IgnoredFindings, s.IgnoredSkipped = 0, 0, 0
	if s.Status != v1alpha1.StatusError {
		s.Status = rawStatus(r.err, s.Findings, s.Skipped)
	}
	return r
}

// withIgnore returns the result with the entries rules ignore at now
// marked, and the summary counting only the others. Entries beyond the
// listed ones cannot be matched and always count. An error is never
// ignored.
func (r result) withIgnore(rules *ignore.Rules, img image, now time.Time) result {
	if rules.Len() == 0 || r.summary.Status == v1alpha1.StatusError {
		return r
	}
	ii := ignore.Image{Repository: img.repository, Digests: []string{img.digest}}
	out := r
	out.findings = make([]v1alpha1.Finding, len(r.findings))
	out.skipped = make([]v1alpha1.Skipped, len(r.skipped))
	s := &out.summary
	for i, f := range r.findings {
		f.Ignored = match(rules.Find(ii, ignore.Entry{Path: f.Path, Signature: f.Signature, SHA256: f.SHA256}, now))
		if f.Ignored != nil && !f.Ignored.Expired {
			s.Findings--
			s.IgnoredFindings++
		}
		out.findings[i] = f
	}
	for i, sk := range r.skipped {
		sk.Ignored = match(rules.Find(ii, ignore.Entry{Path: sk.Path, Signature: sk.Signature, SHA256: sk.SHA256}, now))
		if sk.Ignored != nil && !sk.Ignored.Expired {
			s.Skipped--
			s.IgnoredSkipped++
		}
		out.skipped[i] = sk
	}
	s.Ignored = s.IgnoredFindings + s.IgnoredSkipped
	s.Status = rawStatus(out.err, s.Findings, s.Skipped)
	return out
}

func match(m *ignore.Match) *v1alpha1.IgnoreMatch {
	if m == nil {
		return nil
	}
	return &v1alpha1.IgnoreMatch{Rule: m.Rule, Reason: m.Reason, Expires: m.Expires, Expired: m.Expired}
}

func (r result) apply(d *v1alpha1.ReportData) {
	d.Scanner, d.PlatformFilter, d.Platforms, d.Summary = r.scanner, r.filter, r.platforms, r.summary
	d.Findings, d.Skipped, d.Error = r.findings, r.skipped, r.err
	d.ScannedAt = metav1.NewTime(r.scannedAt)
}

// image is a container image as the kubelet reports it.
type image struct {
	// ref is the pullable reference by digest, e.g.
	// "docker.io/library/nginx@sha256:3f1a…".
	ref        string
	repository string
	digest     string
	// reference is the image from the pod spec, e.g. "nginx:1.29".
	reference string
}

// parseImageID interprets ContainerStatus.ImageID: "repo@sha256:…" with
// containerd, "docker-pullable://repo@sha256:…" with Docker. A bare
// "sha256:…" (an image imported into the node, not pulled from a registry)
// has no repository and cannot be scanned.
func parseImageID(imageID, specImage string) (image, bool) {
	id := strings.TrimPrefix(imageID, "docker-pullable://")
	repo, digest, ok := strings.Cut(id, "@")
	if !ok || repo == "" || !strings.HasPrefix(digest, "sha256:") {
		return image{reference: specImage, digest: strings.TrimPrefix(id, "@")}, false
	}
	return image{ref: id, repository: repo, digest: digest, reference: specImage}, true
}

// digestLabel is the value of LabelDigest: the first 40 hex characters.
func digestLabel(digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	return hex[:min(len(hex), 40)]
}

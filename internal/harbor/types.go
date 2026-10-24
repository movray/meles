// Package harbor implements Harbor's pluggable scanner adapter API (spec
// v1.2, https://github.com/goharbor/pluggable-scanner-spec), so that Harbor
// scans every pushed image with meles. Harbor knows vulnerability and SBOM
// reports only: malware findings become vulnerabilities of severity
// Critical, so that Harbor's "prevent vulnerable images from running"
// blocks infected images at the registry. Optionally the adapter chains an
// upstream adapter such as Trivy's: a project keeps its CVE scan and gets
// the malware findings in the same report.
package harbor

import "time"

// MIME types of the scanner adapter API.
const (
	mimeMetadata     = "application/vnd.scanner.adapter.metadata+json; version=1.1"
	mimeScanRequest  = "application/vnd.scanner.adapter.scan.request+json; version=1.1"
	mimeScanResponse = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	mimeError        = "application/vnd.scanner.adapter.error+json; version=1.0"
	// Vulnerability reports in Harbor's format, current and older name.
	mimeVulnReport     = "application/vnd.security.vulnerability.report; version=1.1"
	mimeVulnReportV10  = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeSBOMReport     = "application/vnd.security.sbom.report+json; version=1.0"
	mimeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mimeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

// Severities, lowest first.
var severities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical"}

// ValidSeverity reports whether s is one of Harbor's severities.
func ValidSeverity(s string) bool {
	return severityRank(s) >= 0
}

func severityRank(s string) int {
	for i, v := range severities {
		if v == s {
			return i
		}
	}
	return -1
}

// Scanner identifies a scanner.
type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

// Capability is what a scanner consumes and produces.
type Capability struct {
	Type                 string         `json:"type,omitempty"`
	ConsumesMimeTypes    []string       `json:"consumes_mime_types"`
	ProducesMimeTypes    []string       `json:"produces_mime_types"`
	AdditionalAttributes map[string]any `json:"additional_attributes,omitempty"`
}

// Metadata is the answer to GET /api/v1/metadata.
type Metadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// Registry is where Harbor stores the artifact, with credentials for it.
type Registry struct {
	URL string `json:"url"`
	// Authorization is the value of an HTTP Authorization header for the
	// registry, e.g. "Basic …" of a robot account.
	Authorization string `json:"authorization"`
}

// Artifact is the image to scan.
type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	Tag        string `json:"tag,omitempty"`
	MimeType   string `json:"mime_type,omitempty"`
}

// ScanRequest is the body of POST /api/v1/scan.
type ScanRequest struct {
	Registry            Registry         `json:"registry"`
	Artifact            Artifact         `json:"artifact"`
	EnabledCapabilities []map[string]any `json:"enabled_capabilities,omitempty"`
}

// ScanResponse is the answer to POST /api/v1/scan.
type ScanResponse struct {
	ID string `json:"id"`
}

// VulnerabilityReport is Harbor's vulnerability report.
type VulnerabilityReport struct {
	GeneratedAt     time.Time       `json:"generated_at"`
	Artifact        Artifact        `json:"artifact"`
	Scanner         Scanner         `json:"scanner"`
	Severity        string          `json:"severity"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability is one entry of a report: a CVE from an upstream scanner,
// or a malware finding or skipped file of meles.
type Vulnerability struct {
	ID               string         `json:"id"`
	Package          string         `json:"package"`
	Version          string         `json:"version"`
	FixVersion       string         `json:"fix_version,omitempty"`
	Severity         string         `json:"severity"`
	Description      string         `json:"description,omitempty"`
	Links            []string       `json:"links,omitempty"`
	PreferredCVSS    map[string]any `json:"preferred_cvss,omitempty"`
	CWEIDs           []string       `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]any `json:"vendor_attributes,omitempty"`
}

type errorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

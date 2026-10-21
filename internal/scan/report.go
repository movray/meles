package scan

import (
	"time"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/extract"
)

// Finding statuses.
const (
	// StatusPresent: the file is visible in the final image filesystem.
	StatusPresent = "present"
	// StatusDeleted: a later layer deleted the file (whiteout or opaque
	// directory), but it is still shipped with the image.
	StatusDeleted = "deleted"
	// StatusOverwritten: a later layer replaced the file or a parent
	// directory.
	StatusOverwritten = "overwritten"
)

// Report is the result of scanning one image reference.
type Report struct {
	Ref    string         `json:"ref"`
	Digest string         `json:"digest"`
	Engine engine.Version `json:"engine"`
	// Platform is the platform filter that was applied ("all", "host", ...).
	Platform   string           `json:"platformFilter"`
	StartedAt  time.Time        `json:"startedAt"`
	FinishedAt time.Time        `json:"finishedAt"`
	Platforms  []PlatformReport `json:"platforms"`
	// Complete is false if any file was skipped. A report without findings
	// then does not mean the image is clean.
	Complete bool `json:"complete"`
}

// PlatformReport is the result for one platform of an image.
type PlatformReport struct {
	Platform string        `json:"platform"`
	Digest   string        `json:"digest"`
	Files    int           `json:"files"`
	Layers   []LayerReport `json:"layers"`
	Findings []Finding     `json:"findings"`
	Skipped  []SkippedFile `json:"skipped"`
}

// LayerReport describes one layer of a platform image.
type LayerReport struct {
	Index     int    `json:"index"`
	DiffID    string `json:"diffID"`
	Digest    string `json:"digest"`
	CreatedBy string `json:"createdBy,omitempty"`
	Files     int    `json:"files"`
	Bytes     int64  `json:"bytes"`
	Cached    bool   `json:"cached"`
}

// Finding is a file the engine flagged.
type Finding struct {
	Platform  string `json:"platform"`
	Layer     int    `json:"layer"`
	DiffID    string `json:"diffID"`
	Path      string `json:"path"`
	Signature string `json:"signature"`
	Status    string `json:"status"`
	// HiddenByLayer is the layer that deleted or replaced the file.
	HiddenByLayer int `json:"hiddenByLayer,omitempty"`
	// HiddenHow is "whiteout", "opaque" or "overwritten".
	HiddenHow string `json:"hiddenHow,omitempty"`
	CreatedBy string `json:"createdBy,omitempty"`
}

// SkippedFile is a file that was not scanned.
type SkippedFile struct {
	Platform string `json:"platform"`
	Layer    int    `json:"layer"`
	extract.Skipped
}

// Findings returns the findings of all platforms.
func (r *Report) Findings() []Finding {
	var out []Finding
	for _, p := range r.Platforms {
		out = append(out, p.Findings...)
	}
	return out
}

// Skipped returns the skipped files of all platforms.
func (r *Report) Skipped() []SkippedFile {
	var out []SkippedFile
	for _, p := range r.Platforms {
		out = append(out, p.Skipped...)
	}
	return out
}

// Files returns the number of scanned files over all platforms, counting
// shared layers once per platform.
func (r *Report) Files() int {
	n := 0
	for _, p := range r.Platforms {
		n += p.Files
	}
	return n
}

// Infected reports whether any platform has a finding.
func (r *Report) Infected() bool {
	return len(r.Findings()) > 0
}

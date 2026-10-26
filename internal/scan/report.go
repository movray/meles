package scan

import (
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"git.itknecht.de/sugras/meles/internal/engine"
	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/yararules"
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
	// Complete is false if any file was skipped (and not ignored). A report
	// without findings then does not mean the image is clean.
	Complete bool `json:"complete"`
	// IgnoreRules is the number of ignore rules the report was checked
	// against.
	IgnoreRules int `json:"ignoreRules,omitempty"`
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
	// SHA256 of the file content, hex.
	SHA256 string `json:"sha256,omitempty"`
	Status string `json:"status"`
	// HiddenByLayer is the layer that deleted or replaced the file.
	HiddenByLayer int `json:"hiddenByLayer,omitempty"`
	// HiddenHow is "whiteout", "opaque" or "overwritten".
	HiddenHow string `json:"hiddenHow,omitempty"`
	CreatedBy string `json:"createdBy,omitempty"`
	// Rule describes the YARA rule behind the signature if it is one of the
	// default rules. Its author must appear wherever the finding is shown
	// (Detection Rule License).
	Rule *yararules.Info `json:"rule,omitempty"`
	// Ignored is set if an ignore rule matched: the finding does not count
	// (unless the rule expired).
	Ignored *ignore.Match `json:"ignored,omitempty"`
}

// SkippedFile is a file that was not scanned.
type SkippedFile struct {
	Platform string `json:"platform"`
	Layer    int    `json:"layer"`
	extract.Skipped
	// Ignored is set if an ignore rule matched.
	Ignored *ignore.Match `json:"ignored,omitempty"`
}

// counts reports whether an entry counts for the verdict.
func counts(m *ignore.Match) bool { return m == nil || m.Expired }

// ApplyIgnore marks the findings and skipped files that rules ignore at now
// and sets Complete accordingly. Ignored entries stay in the report.
func (r *Report) ApplyIgnore(rules *ignore.Rules, now time.Time) {
	r.IgnoreRules = rules.Len()
	img := ignore.Image{}
	if ref, err := name.ParseReference(r.Ref); err == nil {
		img.Repository = ref.Context().Name()
	}
	for _, p := range r.Platforms {
		img.Digests = append(img.Digests, p.Digest)
	}
	if r.Digest != "" {
		img.Digests = append(img.Digests, r.Digest)
	}
	for pi := range r.Platforms {
		p := &r.Platforms[pi]
		for i := range p.Findings {
			f := &p.Findings[i]
			f.Ignored = rules.Find(img, ignore.Entry{Path: f.Path, Signature: f.Signature, SHA256: f.SHA256}, now)
		}
		for i := range p.Skipped {
			s := &p.Skipped[i]
			s.Ignored = rules.Find(img, ignore.Entry{Path: s.Path, Signature: s.Signature, SHA256: s.SHA256}, now)
		}
	}
	r.Complete = len(r.ActiveSkipped()) == 0
}

// ActiveFindings returns the findings that count: not ignored.
func (r *Report) ActiveFindings() []Finding {
	var out []Finding
	for _, f := range r.Findings() {
		if counts(f.Ignored) {
			out = append(out, f)
		}
	}
	return out
}

// ActiveSkipped returns the skipped files that count: not ignored.
func (r *Report) ActiveSkipped() []SkippedFile {
	var out []SkippedFile
	for _, s := range r.Skipped() {
		if counts(s.Ignored) {
			out = append(out, s)
		}
	}
	return out
}

// Findings returns the findings of all platforms, including ignored ones.
func (r *Report) Findings() []Finding {
	var out []Finding
	for _, p := range r.Platforms {
		out = append(out, p.Findings...)
	}
	return out
}

// Skipped returns the skipped files of all platforms, including ignored
// ones.
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

// Infected reports whether any platform has a finding that is not ignored.
func (r *Report) Infected() bool {
	return len(r.ActiveFindings()) > 0
}

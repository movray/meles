package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/movray/meles/internal/ignore"
	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/yararules"
)

// InformationURI is the project page named in SARIF output.
const InformationURI = "https://github.com/movray/meles"

// security-severity values, read by GitHub code scanning: 9.0 and above is
// critical, 4.0 to 6.9 medium.
const (
	severityFinding = "10.0"
	severitySkipped = "5.0"
)

// SARIF 2.1.0 (https://docs.oasis-open.org/sarif/sarif/v2.1.0/), only the
// parts meles fills.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name,omitempty"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      *sarifText     `json:"fullDescription,omitempty"`
	HelpURI              string         `json:"helpUri,omitempty"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           map[string]any `json:"properties,omitempty"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	// GitHub code scanning wants a region; a file in an image has no lines
	// meles could point to, so the alert is on line 1.
	Region sarifRegion `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

// SARIF writes the reports as one SARIF 2.1.0 run. Findings are errors,
// skipped files warnings (the scan is incomplete); entries an ignore rule
// takes out of the verdict are suppressed, not left out. Failed scans make
// the invocation unsuccessful, so that an empty result list never reads as
// clean.
func SARIF(w io.Writer, reps []*scan.Report, inv Invocation) error {
	b := &sarifBuilder{ruleIdx: map[string]int{}}
	for _, r := range reps {
		b.add(r)
	}
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name: "meles", Version: inv.Version, InformationURI: InformationURI, Rules: b.rules,
		}},
		Invocations: []sarifInvocation{{ExecutionSuccessful: len(inv.Failed) == 0}},
		Results:     b.results,
	}
	if run.Tool.Driver.Rules == nil {
		run.Tool.Driver.Rules = []sarifRule{}
	}
	if run.Results == nil {
		run.Results = []sarifResult{}
	}
	for _, f := range inv.Failed {
		run.Invocations[0].ToolExecutionNotifications = append(run.Invocations[0].ToolExecutionNotifications,
			sarifNotification{Level: "error", Message: sarifText{Text: fmt.Sprintf("scan of %s failed: %s", f.Ref, f.Err)}})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{run},
	})
}

type sarifBuilder struct {
	rules   []sarifRule
	ruleIdx map[string]int
	results []sarifResult
}

func (b *sarifBuilder) add(r *scan.Report) {
	repo := Repository(r.Ref)
	for _, f := range r.Findings() {
		idx := b.rule(f.Signature, f.Rule, false)
		msg := fmt.Sprintf("%s detected %s in %s (%s, layer %d).", engineName(r), f.Signature, f.Path, f.Platform, f.Layer)
		if f.Status != scan.StatusPresent {
			msg += fmt.Sprintf(" The file was %s in layer %d but is still shipped with the image.", f.Status, f.HiddenByLayer)
		}
		if f.Rule != nil {
			// The Detection Rule License requires the rule author with every match.
			msg += fmt.Sprintf(" YARA rule %s by %s (%s).", f.Rule.Name, f.Rule.Author, f.Rule.License)
		}
		props := map[string]any{
			"image": r.Ref, "digest": r.Digest, "platform": f.Platform, "layer": f.Layer, "diffID": f.DiffID,
			"status": f.Status, "sha256": f.SHA256,
		}
		if r.Input != "" {
			props["input"] = r.Input
		}
		if f.CreatedBy != "" {
			props["createdBy"] = f.CreatedBy
		}
		if f.HiddenByLayer > 0 {
			props["hiddenByLayer"] = f.HiddenByLayer
		}
		b.results = append(b.results, b.result(idx, "error", msg, r, repo, f.Platform, f.Path, f.Ignored, props))
	}
	for _, s := range r.Skipped() {
		idx := b.rule(s.Signature, nil, true)
		msg := fmt.Sprintf("%s (%s, layer %d) was not scanned: %s. The scan is incomplete.", s.Path, s.Platform, s.Layer, s.Reason)
		props := map[string]any{
			"image": r.Ref, "digest": r.Digest, "platform": s.Platform, "layer": s.Layer, "size": s.Size,
		}
		if s.SHA256 != "" {
			props["sha256"] = s.SHA256
		}
		b.results = append(b.results, b.result(idx, "warning", msg, r, repo, s.Platform, s.Path, s.Ignored, props))
	}
}

// rule returns the index of the rule for a signature, adding it first.
func (b *sarifBuilder) rule(sig string, info *yararules.Info, skipped bool) int {
	id := sig
	if skipped {
		// A limit signature can also be a finding's (clamd reports
		// Heuristics.Limits.Exceeded.* for both): keep the two apart.
		id = "skipped/" + sig
	}
	if i, ok := b.ruleIdx[id]; ok {
		return i
	}
	rule := sarifRule{
		ID:                   id,
		ShortDescription:     sarifText{Text: "Malware signature " + sig},
		DefaultConfiguration: sarifConfig{Level: "error"},
		Properties:           map[string]any{"tags": []string{"security", "malware"}, "security-severity": severityFinding},
	}
	switch {
	case skipped:
		rule.ShortDescription.Text = "File not scanned (" + sig + ")"
		rule.FullDescription = &sarifText{Text: "meles or the scan engine skipped the file, e.g. because of a size limit. Any limit can be dodged by making a file larger, so an unscanned file is not clean."}
		rule.DefaultConfiguration.Level = "warning"
		rule.Properties = map[string]any{"tags": []string{"security", "incomplete-scan"}, "security-severity": severitySkipped}
	case info != nil:
		rule.Name = info.Name
		rule.ShortDescription.Text = fmt.Sprintf("YARA rule %s by %s", info.Name, info.Author)
		rule.HelpURI = info.URL
		rule.Properties["author"] = info.Author
		rule.Properties["license"] = info.License
	}
	b.rules = append(b.rules, rule)
	b.ruleIdx[id] = len(b.rules) - 1
	return len(b.rules) - 1
}

func (b *sarifBuilder) result(idx int, level, msg string, r *scan.Report, repo, platform, path string, m *ignore.Match, props map[string]any) sarifResult {
	res := sarifResult{
		RuleID:    b.rules[idx].ID,
		RuleIndex: idx,
		Level:     level,
		Message:   sarifText{Text: msg},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: fileURI(path)}, Region: sarifRegion{StartLine: 1}},
			LogicalLocations: []sarifLogical{{Name: r.Ref, FullyQualifiedName: r.Ref + "@" + platform, Kind: "module"}},
		}},
		// Without the digest: the alert stays the same alert in the next
		// version of the image.
		PartialFingerprints: map[string]string{"meles/v1": fingerprint(repo, platform, path, b.rules[idx].ID)},
		Properties:          props,
	}
	if m != nil && !m.Expired {
		res.Suppressions = []sarifSuppression{{
			Kind: "external", Status: "accepted",
			Justification: fmt.Sprintf("%s (ignore rule %s, expires %s)", m.Reason, m.Rule, m.Expires),
		}}
	}
	return res
}

func engineName(r *scan.Report) string {
	if r.Engine.Engine == "" {
		return "The engine"
	}
	return r.Engine.Engine
}

// fileURI turns a path in the image into a relative URI reference, as
// code scanning expects one relative to the repository.
func fileURI(path string) string {
	return (&url.URL{Path: strings.TrimLeft(path, "/")}).EscapedPath()
}

// Repository returns the repository of a reference, e.g.
// "index.docker.io/library/alpine" for "alpine:3.20".
func Repository(ref string) string {
	if r, err := name.ParseReference(ref); err == nil {
		return r.Context().Name()
	}
	return ref
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

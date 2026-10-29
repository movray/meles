package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/movray/meles/internal/engine"
	"github.com/movray/meles/internal/extract"
	"github.com/movray/meles/internal/ignore"
	"github.com/movray/meles/internal/scan"
	"github.com/movray/meles/internal/yararules"
)

func sarifOf(t *testing.T, reps []*scan.Report, inv Invocation) sarifLog {
	t.Helper()
	var buf bytes.Buffer
	if err := Write(&buf, "sarif", reps, inv); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version %q, %d runs", log.Version, len(log.Runs))
	}
	return log
}

func TestSARIF(t *testing.T) {
	yara := "YARA.SIGNATURE_BASE_XMRIG_Monero_Miner.UNOFFICIAL"
	info, ok := yararules.Lookup(yara)
	if !ok {
		t.Fatal("rule not in the index")
	}
	rep := func(digest string) *scan.Report {
		return &scan.Report{
			Ref: "example.com/app:1", Digest: digest, Engine: engine.Version{Engine: "ClamAV 1.4.6", Signatures: "28165"},
			Platforms: []scan.PlatformReport{{
				Platform: "linux/amd64",
				Findings: []scan.Finding{
					{Platform: "linux/amd64", Layer: 2, Path: "/opt/eicar.com", Signature: "Eicar-Test-Signature", Status: scan.StatusPresent},
					{Platform: "linux/amd64", Layer: 3, Path: "/tmp/a b/eicar.com", Signature: "Eicar-Test-Signature", Status: scan.StatusDeleted, HiddenByLayer: 4},
					{Platform: "linux/amd64", Layer: 2, Path: "/usr/bin/xmrig", Signature: yara, Status: scan.StatusPresent, Rule: &info,
						Ignored: &ignore.Match{Rule: "known#0", Reason: "miner detector test data", Expires: "2027-01-31"}},
				},
				Skipped: []scan.SkippedFile{{Platform: "linux/amd64", Layer: 1, Skipped: extract.Skipped{
					Path: "/big.bin", Size: 1 << 30, Reason: "larger than --max-file-size", Signature: extract.SigMaxFileSize}}},
			}},
		}
	}
	log := sarifOf(t, []*scan.Report{rep("sha256:aaa")}, Invocation{Version: "1.2.3"})
	run := log.Runs[0]
	if d := run.Tool.Driver; d.Name != "meles" || d.Version != "1.2.3" || d.InformationURI == "" {
		t.Errorf("driver = %+v", d)
	}
	if !run.Invocations[0].ExecutionSuccessful {
		t.Error("invocation not successful")
	}

	// One rule per signature; skipped files under their own id.
	ids := map[string]sarifRule{}
	for _, r := range run.Tool.Driver.Rules {
		if _, dup := ids[r.ID]; dup {
			t.Errorf("rule %s twice", r.ID)
		}
		ids[r.ID] = r
	}
	if len(ids) != 3 {
		t.Errorf("rules = %v", ids)
	}
	if r := ids[yara]; r.HelpURI != info.URL || r.Properties["author"] != info.Author || !strings.Contains(r.ShortDescription.Text, info.Author) {
		t.Errorf("YARA rule = %+v", r)
	}
	if r := ids["skipped/"+extract.SigMaxFileSize]; r.DefaultConfiguration.Level != "warning" {
		t.Errorf("skipped rule = %+v", r)
	}

	if len(run.Results) != 4 {
		t.Fatalf("%d results", len(run.Results))
	}
	byPath := map[string]sarifResult{}
	for _, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %s: ruleIndex %d points to %s", res.RuleID, res.RuleIndex, run.Tool.Driver.Rules[res.RuleIndex].ID)
		}
		loc := res.Locations[0]
		if loc.PhysicalLocation.Region.StartLine != 1 || loc.LogicalLocations[0].FullyQualifiedName != "example.com/app:1@linux/amd64" {
			t.Errorf("location = %+v", loc)
		}
		byPath[loc.PhysicalLocation.ArtifactLocation.URI] = res
	}
	if res, ok := byPath["tmp/a%20b/eicar.com"]; !ok || res.Level != "error" || !strings.Contains(res.Message.Text, "deleted in layer 4") {
		t.Errorf("deleted finding = %+v (URIs %v)", res, byPath)
	}
	miner := byPath["usr/bin/xmrig"]
	if !strings.Contains(miner.Message.Text, info.Author) || !strings.Contains(miner.Message.Text, info.License) {
		t.Errorf("YARA finding without author and license: %q", miner.Message.Text)
	}
	if len(miner.Suppressions) != 1 || !strings.Contains(miner.Suppressions[0].Justification, "miner detector test data") {
		t.Errorf("ignored finding not suppressed: %+v", miner.Suppressions)
	}
	if res := byPath["big.bin"]; res.Level != "warning" || !strings.Contains(res.Message.Text, "incomplete") {
		t.Errorf("skipped file = %+v", res)
	}

	// The same file in the next version of the image is the same alert.
	next := sarifOf(t, []*scan.Report{rep("sha256:bbb")}, Invocation{}).Runs[0]
	for i, res := range next.Results {
		if res.PartialFingerprints["meles/v1"] != run.Results[i].PartialFingerprints["meles/v1"] {
			t.Errorf("fingerprint of %s changed with the digest", res.RuleID)
		}
	}
}

// A failed scan must not look like a clean one.
func TestSARIFFailedScan(t *testing.T) {
	log := sarifOf(t, nil, Invocation{Failed: []Failure{{Ref: "example.com/app:1", Err: "pull: unauthorized"}}})
	run := log.Runs[0]
	if run.Invocations[0].ExecutionSuccessful || len(run.Invocations[0].ToolExecutionNotifications) != 1 {
		t.Errorf("invocation = %+v", run.Invocations[0])
	}
	if run.Results == nil || run.Tool.Driver.Rules == nil {
		t.Error("results and rules must be empty lists, not null")
	}
}

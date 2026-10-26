package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/yararules"
)

// Names from the image must not forge lines or escape sequences.
func TestTableEscapesImageStrings(t *testing.T) {
	evil := "/opt/x\n\nNo malware found.\n\x1b[2K"
	rep := &scan.Report{
		Ref: "example.com/app:1",
		Platforms: []scan.PlatformReport{{
			Platform: "linux/amd64",
			Findings: []scan.Finding{{Platform: "linux/amd64", Layer: 1, Path: evil, Signature: "Eicar-Test-Signature", Status: scan.StatusPresent, CreatedBy: "RUN x\x1b[2K"}},
			Skipped:  []scan.SkippedFile{{Platform: "linux/amd64", Layer: 1, Skipped: extract.Skipped{Path: evil, Size: 1, Reason: "too large"}}},
		}},
	}
	var buf bytes.Buffer
	if err := Table(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.ContainsRune(out, '\x1b') {
		t.Errorf("output contains an escape sequence:\n%q", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "No malware found.") {
			t.Errorf("forged line %q in output:\n%s", line, out)
		}
	}
}

func TestTableIncomplete(t *testing.T) {
	rep := &scan.Report{
		Ref: "example.com/app:1",
		Platforms: []scan.PlatformReport{{
			Platform: "linux/amd64",
			Skipped:  []scan.SkippedFile{{Platform: "linux/amd64", Layer: 1, Skipped: extract.Skipped{Path: "/big", Size: 1 << 30, Reason: "too large"}}},
		}},
	}
	var buf bytes.Buffer
	if err := Table(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\nNo malware found.\n") || !strings.Contains(buf.String(), "INCOMPLETE") {
		t.Errorf("incomplete scan not marked:\n%s", buf.String())
	}
}

// The PHP case: the only skipped file is ignored, the report is clean, and
// the ignored entry is still listed with its rule; an expired rule is
// pointed out.
func TestTableIgnored(t *testing.T) {
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	rules, errs := ignore.New([]ignore.Rule{
		{Name: "php-quine", Path: "/usr/src/php.tar.xz", Signature: "Heuristics.Limits.Exceeded.MaxRecursion", Reason: "bug81726.gz unpacks to itself", Expires: "2027-06-30"},
		{Name: "old-tool", Path: "/opt/tool", Reason: "was reviewed", Expires: "2026-09-30"},
	}, "test", now)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	php := func() *scan.Report {
		return &scan.Report{
			Ref: "docker.io/library/nextcloud:33",
			Platforms: []scan.PlatformReport{{
				Platform: "linux/amd64",
				Skipped: []scan.SkippedFile{{Platform: "linux/amd64", Layer: 8, Skipped: extract.Skipped{
					Path: "/usr/src/php.tar.xz", Size: 13731260, Reason: "engine limit exceeded (Heuristics.Limits.Exceeded.MaxRecursion)",
					Signature: "Heuristics.Limits.Exceeded.MaxRecursion",
				}}},
			}},
		}
	}

	rep := php()
	rep.ApplyIgnore(rules, now)
	var buf bytes.Buffer
	if err := Table(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !rep.Complete || rep.Infected() || !strings.Contains(out, "\nNo malware found.\n") || !strings.Contains(out, "Ignored by rules, not counted (1)") || !strings.Contains(out, "php-quine") {
		t.Errorf("complete = %v, output:\n%s", rep.Complete, out)
	}

	rep = php()
	rep.Platforms[0].Findings = []scan.Finding{{Platform: "linux/amd64", Layer: 2, Path: "/opt/tool", Signature: "Unix.Tool.X", Status: scan.StatusPresent}}
	rep.ApplyIgnore(rules, now)
	buf.Reset()
	Table(&buf, rep)
	if !rep.Infected() || !strings.Contains(buf.String(), "old-tool for /opt/tool expired on 2026-09-30") {
		t.Errorf("expired rule: infected = %v, output:\n%s", rep.Infected(), buf.String())
	}
}

// The Detection Rule License requires the rule author with every match.
func TestTableRuleAuthors(t *testing.T) {
	sig := "YARA.SIGNATURE_BASE_XMRIG_Monero_Miner.UNOFFICIAL"
	info, ok := yararules.Lookup(sig)
	if !ok {
		t.Fatal("rule not in the index")
	}
	f := scan.Finding{Platform: "linux/amd64", Layer: 1, Path: "/usr/bin/xmrig", Signature: sig, Status: scan.StatusPresent, Rule: &info}
	rep := &scan.Report{
		Ref:       "example.com/app:1",
		Complete:  true,
		Platforms: []scan.PlatformReport{{Platform: "linux/amd64", Findings: []scan.Finding{f, f}}},
	}
	var buf bytes.Buffer
	if err := Table(&buf, rep); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Count(out, "Florian Roth (Nextron Systems)") != 1 || !strings.Contains(out, "DRL-1.1") {
		t.Errorf("rule author missing or repeated:\n%s", out)
	}
}

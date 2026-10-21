package report

import (
	"bytes"
	"strings"
	"testing"

	"git.itknecht.de/sugras/meles/internal/extract"
	"git.itknecht.de/sugras/meles/internal/scan"
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

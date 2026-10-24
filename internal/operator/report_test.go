package operator

import (
	"errors"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"

	"git.itknecht.de/sugras/meles/api/v1alpha1"
	"git.itknecht.de/sugras/meles/internal/ignore"
)

func TestWithIgnore(t *testing.T) {
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	rules, errs := ignore.New([]ignore.Rule{
		{Path: "/usr/src/php.tar.xz", Signature: "Heuristics.Limits.Exceeded.MaxRecursion", Reason: "PHP test quine", Expires: "2027-06-30"},
		{Signature: "Unix.Tool.*", Image: "docker.io/acme/*", Reason: "our tool", Expires: "2027-01-31"},
	}, "test", now)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	img := image{repository: "docker.io/acme/app", digest: "sha256:1"}
	raw := result{
		summary: v1alpha1.Summary{Status: v1alpha1.StatusInfected, Findings: 102, Skipped: 1, Files: 10},
		findings: []v1alpha1.Finding{
			{Path: "/opt/tool", Signature: "Unix.Tool.Scanner"},
			{Path: "/opt/evil", Signature: "Unix.Trojan.X"},
		},
		skipped: []v1alpha1.Skipped{{Path: "/usr/src/php.tar.xz", Signature: "Heuristics.Limits.Exceeded.MaxRecursion"}},
	}

	got := raw.withIgnore(rules, img, now)
	// 100 findings beyond the listed ones cannot be matched and count.
	if s := got.summary; s.Status != v1alpha1.StatusInfected || s.Findings != 101 || s.Skipped != 0 || s.IgnoredFindings != 1 || s.IgnoredSkipped != 1 || s.Ignored != 2 {
		t.Errorf("summary = %+v", s)
	}
	if got.findings[0].Ignored == nil || got.findings[1].Ignored != nil || raw.findings[0].Ignored != nil {
		t.Errorf("marks: %+v, raw changed: %+v", got.findings, raw.findings[0])
	}

	// Stored and read back, the raw result is restored for other rules.
	var d v1alpha1.ReportData
	got.apply(&d)
	if back := resultFromData(d); !equality.Semantic.DeepEqual(back.summary, raw.summary) || back.findings[0].Ignored != nil || back.skipped[0].Ignored != nil {
		t.Errorf("restored %+v, want %+v", back.summary, raw.summary)
	}

	// Only the PHP rule applies elsewhere: a clean image with the quine.
	php := result{summary: v1alpha1.Summary{Status: v1alpha1.StatusIncomplete, Skipped: 1}, skipped: raw.skipped}
	if s := php.withIgnore(rules, image{repository: "docker.io/library/nextcloud"}, now).summary; s.Status != v1alpha1.StatusClean {
		t.Errorf("nextcloud summary = %+v", s)
	}

	// An error is never ignored.
	failed := resultFromError(errors.New("pull failed"), "test")
	if s := failed.withIgnore(rules, img, now).summary; s.Status != v1alpha1.StatusError {
		t.Errorf("error became %s", s.Status)
	}
}

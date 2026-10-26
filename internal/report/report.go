// Package report writes scan reports in the CLI output formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"

	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/scan"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json", "sarif"}

// Invocation describes the run of meles, for formats that record it.
type Invocation struct {
	// Version of meles.
	Version string
	// Failed lists the scans that ended with an error.
	Failed []Failure
}

// Failure is a scan that ended with an error.
type Failure struct {
	Ref string
	Err string
}

// Write writes reports in the given format.
func Write(w io.Writer, format string, reps []*scan.Report, inv Invocation) error {
	switch format {
	case "table":
		for _, r := range reps {
			if err := Table(w, r); err != nil {
				return err
			}
		}
		return nil
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if len(reps) == 1 {
			return enc.Encode(reps[0])
		}
		return enc.Encode(reps)
	case "sarif":
		return SARIF(w, reps, inv)
	default:
		return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats, ", "))
	}
}

// Table writes a human-readable report.
func Table(w io.Writer, r *scan.Report) error {
	if r.Input != "" && r.Input != r.Ref {
		fmt.Fprintf(w, "\n%s (%s) from %s\n", safe(r.Ref), safe(short(r.Digest)), safe(r.Input))
	} else {
		fmt.Fprintf(w, "\n%s (%s)\n", safe(r.Ref), safe(short(r.Digest)))
	}
	fmt.Fprintf(w, "engine: %s, signatures %s, scanned in %s\n\n", safe(r.Engine.Engine), safe(r.Engine.Signatures), r.FinishedAt.Sub(r.StartedAt).Round(1e6))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PLATFORM\tLAYERS\tFILES\tFINDINGS\tSKIPPED")
	for _, p := range r.Platforms {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", safe(p.Platform), len(p.Layers), p.Files, len(p.Findings), len(p.Skipped))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fs := r.ActiveFindings()
	switch {
	case len(fs) == 0 && r.Complete:
		fmt.Fprintln(w, "\nNo malware found.")
	case len(fs) == 0:
		fmt.Fprintf(w, "\nNo malware found in the scanned files. Scan INCOMPLETE: %d files were not scanned (see below).\n", len(r.ActiveSkipped()))
	default:
		fmt.Fprintf(w, "\nFindings (%d):\n", len(fs))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PLATFORM\tLAYER\tPATH\tSIGNATURE\tSTATUS\tCREATED BY")
		for _, f := range fs {
			fmt.Fprintf(tw, "%s\t%d (%s)\t%s\t%s\t%s\t%s\n", safe(f.Platform), f.Layer, short(f.DiffID), safe(f.Path), safe(f.Signature), Status(f), safe(truncate(f.CreatedBy, 60)))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if sk := r.ActiveSkipped(); len(sk) > 0 {
		fmt.Fprintf(w, "\nSkipped, not scanned (%d):\n", len(sk))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PLATFORM\tLAYER\tPATH\tSIZE\tREASON")
		for _, s := range sk {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%s\n", safe(s.Platform), s.Layer, safe(s.Path), s.Size, safe(s.Reason))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if err := ignored(w, r); err != nil {
		return err
	}
	return ruleAuthors(w, r)
}

// ruleAuthors names the authors of the YARA rules behind the findings, as
// the Detection Rule License requires for messages about matches.
func ruleAuthors(w io.Writer, r *scan.Report) error {
	seen := map[string]bool{}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, f := range r.Findings() {
		if f.Rule == nil || seen[f.Rule.Name] {
			continue
		}
		if len(seen) == 0 {
			fmt.Fprintln(w, "\nYARA rules:")
			fmt.Fprintln(tw, "RULE\tAUTHOR\tLICENSE\tSOURCE")
		}
		seen[f.Rule.Name] = true
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", safe(f.Rule.Name), safe(f.Rule.Author), safe(f.Rule.License), safe(f.Rule.URL))
	}
	return tw.Flush()
}

// ignored lists the entries ignore rules took out of the verdict, and the
// rules that matched but expired.
func ignored(w io.Writer, r *scan.Report) error {
	type row struct {
		kind, platform, path, what string
		m                          *ignore.Match
	}
	var rows []row
	for _, f := range r.Findings() {
		if f.Ignored != nil {
			rows = append(rows, row{"finding", f.Platform, f.Path, f.Signature, f.Ignored})
		}
	}
	for _, s := range r.Skipped() {
		if s.Ignored != nil {
			rows = append(rows, row{"skipped", s.Platform, s.Path, s.Signature, s.Ignored})
		}
	}
	var active, expired []row
	for _, rw := range rows {
		if rw.m.Expired {
			expired = append(expired, rw)
		} else {
			active = append(active, rw)
		}
	}
	if len(active) > 0 {
		fmt.Fprintf(w, "\nIgnored by rules, not counted (%d):\n", len(active))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "KIND\tPLATFORM\tPATH\tSIGNATURE\tRULE\tEXPIRES\tREASON")
		for _, rw := range active {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", rw.kind, safe(rw.platform), safe(rw.path), safe(rw.what), safe(rw.m.Rule), rw.m.Expires, safe(truncate(rw.m.Reason, 60)))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	for _, rw := range expired {
		fmt.Fprintf(w, "\nNote: ignore rule %s for %s expired on %s; the %s counts again.\n", safe(rw.m.Rule), safe(rw.path), rw.m.Expires, rw.kind)
	}
	return nil
}

// Status describes a finding's status, e.g. "deleted in layer 4 (whiteout)".
func Status(f scan.Finding) string {
	if f.Status == scan.StatusPresent {
		return "present"
	}
	return fmt.Sprintf("%s in layer %d (%s)", f.Status, f.HiddenByLayer, f.HiddenHow)
}

// safe quotes s if it contains control or other non-printable characters.
// File names, platforms and history come from the image and must not be
// able to forge lines or terminal escape sequences in CI logs.
func safe(s string) string {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

func short(digest string) string {
	_, hex, ok := strings.Cut(digest, ":")
	if !ok || len(hex) < 12 {
		return digest
	}
	return hex[:12]
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Package report writes scan reports in the CLI output formats.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"git.itknecht.de/sugras/meles/internal/scan"
)

// Formats lists the supported output formats.
var Formats = []string{"table", "json"}

// Write writes reports in the given format.
func Write(w io.Writer, format string, reps []*scan.Report) error {
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
	default:
		return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(Formats, ", "))
	}
}

// Table writes a human-readable report.
func Table(w io.Writer, r *scan.Report) error {
	fmt.Fprintf(w, "\n%s (%s)\n", r.Ref, short(r.Digest))
	fmt.Fprintf(w, "engine: %s, signatures %s, scanned in %s\n\n", r.Engine.Engine, r.Engine.Signatures, r.FinishedAt.Sub(r.StartedAt).Round(1e6))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PLATFORM\tLAYERS\tFILES\tFINDINGS\tSKIPPED")
	for _, p := range r.Platforms {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\n", p.Platform, len(p.Layers), p.Files, len(p.Findings), len(p.Skipped))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	fs := r.Findings()
	if len(fs) == 0 {
		fmt.Fprintln(w, "\nNo malware found.")
	} else {
		fmt.Fprintf(w, "\nFindings (%d):\n", len(fs))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PLATFORM\tLAYER\tPATH\tSIGNATURE\tSTATUS\tCREATED BY")
		for _, f := range fs {
			fmt.Fprintf(tw, "%s\t%d (%s)\t%s\t%s\t%s\t%s\n", f.Platform, f.Layer, short(f.DiffID), f.Path, f.Signature, Status(f), truncate(f.CreatedBy, 60))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if sk := r.Skipped(); len(sk) > 0 {
		fmt.Fprintf(w, "\nSkipped, not scanned (%d):\n", len(sk))
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "PLATFORM\tLAYER\tPATH\tSIZE\tREASON")
		for _, s := range sk {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%s\n", s.Platform, s.Layer, s.Path, s.Size, s.Reason)
		}
		return tw.Flush()
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

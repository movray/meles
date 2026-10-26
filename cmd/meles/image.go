package main

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"git.itknecht.de/sugras/meles/internal/ignore"
	"git.itknecht.de/sugras/meles/internal/report"
	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
)

func newImageCmd() *cobra.Command {
	var (
		sf        scanFlags
		format    string
		exitCode  int
		skipped   int
		platforms string
		ignoreF   string
		input     string
	)
	cmd := &cobra.Command{
		Use:   "image <ref>... | --input <path> [name]",
		Short: "Scan container images from a registry or a local archive",
		Long: `image scans container images layer by layer: from a registry, without a
Docker daemon, or with --input from a local OCI image layout or docker save
archive, so that CI can scan an image before pushing it.

--input takes a directory with an OCI image layout, or a tar of one (docker
save since Docker 25, docker buildx build --output type=oci,dest=app.tar,
podman save --format oci-archive, skopeo copy ... oci-archive:app.tar), or a
docker save archive of older Docker versions (also podman save). Tars may be
gzip or zstd compressed; a compressed tar is unpacked into one temporary file
(TMPDIR) first. If the input holds several images, name the one to scan.`,
		Example: `  meles image alpine:3.20
  meles image --platform host --format json ghcr.io/org/app:1.2
  meles image --format sarif ghcr.io/org/app:1.2 > meles.sarif
  MELES_CLAMD=tcp://clamd:3310 meles image registry.example.com/app@sha256:...
  meles image --ignorefile meles-ignore.yaml nextcloud:33
  docker save app:1.4 -o app.tar && meles image --input app.tar
  meles image --input oci-layout/ registry.example.com/app:1.4`,
		Args: func(cmd *cobra.Command, args []string) error {
			if input != "" {
				return cobra.MaximumNArgs(1)(cmd, args)
			}
			return cobra.MinimumNArgs(1)(cmd, args)
		},
		RunE: func(cmd *cobra.Command, refs []string) error {
			if exitCode == exitError || exitCode < 0 || exitCode > 255 {
				return fmt.Errorf("--exit-code %d: must be 0..255 and not %d, which is reserved for errors", exitCode, exitError)
			}
			if skipped < 0 || skipped > 255 {
				return fmt.Errorf("--skipped-exit-code %d: must be 0..255", skipped)
			}
			if !slices.Contains(report.Formats, format) {
				return fmt.Errorf("--format %q: supported are %s", format, strings.Join(report.Formats, ", "))
			}
			pf, err := source.ParsePlatforms(platforms)
			if err != nil {
				return fmt.Errorf("--platform: %w", err)
			}
			var rules *ignore.Rules
			if ignoreF != "" {
				if rules, err = ignore.Load(ignoreF, time.Now()); err != nil {
					return fmt.Errorf("--ignorefile: %w", err)
				}
			}
			s, err := sf.scanner(scan.NewCache(1000))
			if err != nil {
				return err
			}

			var opts []scan.Option
			if input != "" {
				opts = append(opts, scan.WithInput(input))
				if len(refs) == 0 {
					refs = []string{""}
				}
			}
			var reps []*scan.Report
			inv := report.Invocation{Version: version}
			for _, ref := range refs {
				rep, err := s.Scan(cmd.Context(), ref, pf, nil, opts...)
				if err != nil {
					what := ref
					if input != "" {
						what = strings.TrimSpace(input + " " + ref)
					}
					slog.Error("scan failed", "ref", what, "err", err)
					inv.Failed = append(inv.Failed, report.Failure{Ref: what, Err: err.Error()})
					continue
				}
				rep.ApplyIgnore(rules, time.Now())
				reps = append(reps, rep)
			}
			if err := report.Write(cmd.OutOrStdout(), format, reps, inv); err != nil {
				return err
			}

			// Errors win over findings: a failed scan must never pass.
			switch {
			case len(inv.Failed) > 0:
				return exitCodeError{exitError}
			case anyInfected(reps) && exitCode != exitClean:
				return exitCodeError{exitCode}
			case anyIncomplete(reps) && skipped != exitClean:
				return exitCodeError{skipped}
			}
			return nil
		},
	}
	sf.register(cmd.Flags())
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json, sarif (e.g. for GitHub code scanning)")
	cmd.Flags().IntVar(&exitCode, "exit-code", exitFound, "exit code when malware is found (0 = report only; 2 is reserved for errors)")
	cmd.Flags().IntVar(&skipped, "skipped-exit-code", exitFound, "exit code when files were not scanned (e.g. above --max-file-size): 1 = treat as finding, 2 = treat as error, 0 = report only")
	cmd.Flags().StringVar(&ignoreF, "ignorefile", "", "YAML file with ignore rules (path, signature, image, sha256; each with reason and expires): matching findings and skipped files are listed but do not count")
	cmd.Flags().StringVar(&input, "input", "", "read the image from a local OCI image layout (directory or tar) or docker save archive instead of a registry; the argument then names the image in it, if it holds several")
	cmd.Flags().StringVar(&platforms, "platform", "all", "platforms of multi-arch images: all, host or a list like linux/amd64,linux/arm64")
	return cmd
}

func anyIncomplete(reps []*scan.Report) bool {
	for _, r := range reps {
		if !r.Complete {
			return true
		}
	}
	return false
}

func anyInfected(reps []*scan.Report) bool {
	for _, r := range reps {
		if r.Infected() {
			return true
		}
	}
	return false
}

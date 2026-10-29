package main

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"

	"git.itknecht.de/sugras/meles/internal/scan"
	"git.itknecht.de/sugras/meles/internal/source"
	"git.itknecht.de/sugras/meles/internal/testimage"
)

func newSelftestCmd() *cobra.Command {
	var sf scanFlags
	var yara bool
	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Check the whole scan chain with generated EICAR test images",
		Long: `selftest builds test images with EICAR files at runtime, serves them from an
in-memory registry and scans them with the configured clamd. It checks that
files deleted by a whiteout in a later layer are still found. No EICAR image
has to be stored in a real registry.

With --yara it also checks that clamd has loaded the default YARA rules
(charts/meles/rules) with a harmless XMRig configuration file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cases := testimage.Cases()
			if yara {
				cases = append(cases, testimage.YaraCases()...)
			}
			reg, err := testimage.Serve(cases)
			if err != nil {
				return err
			}
			defer reg.Close()

			sf.insecure = true
			s, err := sf.scanner(nil)
			if err != nil {
				return err
			}
			v, err := s.Engine.Version(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "engine: %s\n", v.Raw)

			ok := true
			for _, c := range cases {
				rep, err := s.Scan(cmd.Context(), reg.Ref(c.Name), source.PlatformFilter{}, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", c.Name, err)
				}
				got := selftestFindings(rep)
				if slices.Equal(got, c.Want) {
					fmt.Fprintf(out, "PASS  %-17s %v\n", c.Name, got)
				} else {
					fmt.Fprintf(out, "FAIL  %-17s got %v, want %v\n", c.Name, got, c.Want)
					ok = false
				}
			}
			if !ok {
				return fmt.Errorf("selftest failed")
			}
			if !yara {
				fmt.Fprintln(out, "YARA rules not checked (--yara)")
			}
			fmt.Fprintln(out, "selftest passed")
			return nil
		},
	}
	sf.register(cmd.Flags())
	cmd.Flags().BoolVar(&yara, "yara", false, "also check that clamd has loaded the default YARA rules")
	return cmd
}

func selftestFindings(r *scan.Report) []string {
	var out []string
	for _, f := range r.Findings() {
		out = append(out, f.Path+" "+f.Status)
	}
	return out
}

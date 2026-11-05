package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/movray/meles/internal/selftest"
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
			s, err := sf.scanner(nil)
			if err != nil {
				return err
			}
			res, err := selftest.Run(cmd.Context(), s, yara)
			out := cmd.OutOrStdout()
			if res.Engine != "" {
				fmt.Fprintf(out, "engine: %s\n", res.Engine)
			}
			for _, c := range res.Checks {
				if c.Pass() {
					fmt.Fprintf(out, "PASS  %-17s %v\n", c.Name, c.Got)
				} else {
					fmt.Fprintf(out, "FAIL  %-17s got %v, want %v\n", c.Name, c.Got, c.Want)
				}
			}
			if err != nil {
				return err
			}
			if len(res.Failed()) > 0 {
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

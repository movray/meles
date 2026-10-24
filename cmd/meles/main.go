// Command meles is a malware scanner for container images.
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes. An error must never exit with exitClean.
const (
	exitClean = 0
	exitFound = 1
	exitError = 2
)

// exitCodeError ends the program with a specific exit code and no message.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

func main() {
	err := newRootCmd().Execute()
	var ec exitCodeError
	switch {
	case err == nil:
		os.Exit(exitClean)
	case errors.As(err, &ec):
		os.Exit(ec.code)
	default:
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(exitError)
	}
}

func newRootCmd() *cobra.Command {
	var logLevel string
	root := &cobra.Command{
		Use:           "meles",
		Short:         "Malware scanner for container images",
		Long:          "meles scans container images layer by layer for malware, without a Docker daemon.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := applyEnv(cmd.Flags()); err != nil {
				return err
			}
			var lvl slog.Level
			if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
				return fmt.Errorf("--log-level: %w", err)
			}
			slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})))
			return nil
		},
	}
	root.PersistentFlags().StringVar(&logLevel, "log-level", "info", "log level: debug, info, warn, error")
	root.AddCommand(newImageCmd(), newSelftestCmd(), newServerCmd(), newOperatorCmd(), newClamdProxyCmd(), newHarborAdapterCmd(), newVersionCmd())
	return root
}

// applyEnv sets every flag that was not given on the command line from the
// environment variable MELES_<FLAG>, e.g. --max-file-size from
// MELES_MAX_FILE_SIZE. Precedence: flag, environment, default.
func applyEnv(fs *pflag.FlagSet) error {
	var err error
	fs.VisitAll(func(f *pflag.Flag) {
		if err != nil || f.Changed {
			return
		}
		key := "MELES_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(key); ok {
			if serr := fs.Set(f.Name, v); serr != nil {
				err = fmt.Errorf("%s: %w", key, serr)
			}
		}
	})
	return err
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintln(cmd.OutOrStdout(), "meles", version)
		},
	}
}

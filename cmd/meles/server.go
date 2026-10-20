package main

import "github.com/spf13/cobra"

func newServerCmd() *cobra.Command {
	return &cobra.Command{Use: "server", Short: "Run the web UI and scheduler", Hidden: true}
}

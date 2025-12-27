package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// These variables are set via ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version, git commit, and build date of amp-port-sync.`,
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("amp-port-sync %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

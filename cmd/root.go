package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var verbose bool

var rootCmd = &cobra.Command{
	Use:   "amp-port-sync",
	Short: "Sync AMP game server ports to Mikrotik routers",
	Long: `amp-port-sync polls the AMP API for running game server instances
and synchronizes port forwarding rules on a chain of Mikrotik routers.

It creates NAT and filter rules to forward traffic from the internet
through your router chain to the AMP VM.

Configuration is done via environment variables and CLI flags.
See 'amp-port-sync sync --help' for available options.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose logging")
}

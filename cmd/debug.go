package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jtdoepke/amp-mikrotik-port-forwarder/config"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/amp"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Debug commands for testing",
	Long:  `Debug commands for testing connections and inspecting data.`,
}

var debugAmpCmd = &cobra.Command{
	Use:   "amp",
	Short: "Test AMP API connection and dump instances",
	Long: `Connect to the AMP API and dump all instances as JSON.
This is useful for testing the connection and capturing data for mocks.

Configuration can be provided via CLI flags or environment variables.`,
	RunE: runDebugAmp,
}

var (
	debugAmpURL          string
	debugAmpUsername     string
	debugAmpPassword     string
	debugAmpPasswordFile string
)

func init() {
	rootCmd.AddCommand(debugCmd)
	debugCmd.AddCommand(debugAmpCmd)

	debugAmpCmd.Flags().StringVar(&debugAmpURL, "url", "", "AMP API URL (env: AMP_SYNC_AMP_URL)")
	debugAmpCmd.Flags().StringVar(&debugAmpUsername, "username", "", "AMP username (env: AMP_SYNC_AMP_USERNAME)")
	debugAmpCmd.Flags().StringVar(&debugAmpPassword, "password", "", "AMP password (env: AMP_SYNC_AMP_PASSWORD)")
	debugAmpCmd.Flags().StringVar(&debugAmpPasswordFile, "password-file", "", "Path to AMP password file (env: AMP_SYNC_AMP_PASSWORD_FILE)")
}

func runDebugAmp(cmd *cobra.Command, args []string) error {
	// Load and validate AMP config from env vars + flags
	ampCfg, err := config.LoadAMPConfig(debugAmpURL, debugAmpUsername, debugAmpPassword, debugAmpPasswordFile)
	if err != nil {
		return err
	}

	resolvedPassword, err := config.ResolvePassword(ampCfg.Password, ampCfg.PasswordFile)
	if err != nil {
		return fmt.Errorf("failed to resolve password: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Connecting to AMP at %s...\n", ampCfg.URL)

	client, err := amp.NewClient(ampCfg.URL, ampCfg.Username, resolvedPassword)
	if err != nil {
		return fmt.Errorf("failed to create AMP client: %w", err)
	}
	defer func() { _ = client.Close() }()

	fmt.Fprintf(os.Stderr, "Fetching instances...\n")

	instances, err := client.GetInstances()
	if err != nil {
		return fmt.Errorf("failed to get instances: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Found %d instances\n\n", len(instances))

	// Output as JSON for easy capture
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(instances); err != nil {
		return fmt.Errorf("failed to encode instances: %w", err)
	}

	return nil
}

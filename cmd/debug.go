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

var debugAmpNetworkCmd = &cobra.Command{
	Use:   "amp-network",
	Short: "Test AMP API and dump detailed network port info",
	Long: `Connect to the AMP API and dump detailed network port information for each instance.
This uses the GetInstanceNetworkInfo API which provides more detail than GetInstances,
including protocol type (TCP/UDP/Both) and firewall target status.

Only instances in Idle (0) or Running (20) state will have network info fetched.

Configuration can be provided via CLI flags or environment variables.`,
	RunE: runDebugAmpNetwork,
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
	debugCmd.AddCommand(debugAmpNetworkCmd)

	debugAmpCmd.Flags().StringVar(&debugAmpURL, "url", "", "AMP API URL (env: AMP_SYNC_AMP_URL)")
	debugAmpCmd.Flags().StringVar(&debugAmpUsername, "username", "", "AMP username (env: AMP_SYNC_AMP_USERNAME)")
	debugAmpCmd.Flags().StringVar(&debugAmpPassword, "password", "", "AMP password (env: AMP_SYNC_AMP_PASSWORD)")
	debugAmpCmd.Flags().StringVar(&debugAmpPasswordFile, "password-file", "", "Path to AMP password file (env: AMP_SYNC_AMP_PASSWORD_FILE)")

	debugAmpNetworkCmd.Flags().StringVar(&debugAmpURL, "url", "", "AMP API URL (env: AMP_SYNC_AMP_URL)")
	debugAmpNetworkCmd.Flags().StringVar(&debugAmpUsername, "username", "", "AMP username (env: AMP_SYNC_AMP_USERNAME)")
	debugAmpNetworkCmd.Flags().StringVar(&debugAmpPassword, "password", "", "AMP password (env: AMP_SYNC_AMP_PASSWORD)")
	debugAmpNetworkCmd.Flags().StringVar(&debugAmpPasswordFile, "password-file", "", "Path to AMP password file (env: AMP_SYNC_AMP_PASSWORD_FILE)")
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

// instanceNetworkResult holds an instance's info and its network port details.
type instanceNetworkResult struct {
	InstanceID   string              `json:"InstanceID"`
	InstanceName string              `json:"InstanceName"`
	FriendlyName string              `json:"FriendlyName"`
	Module       string              `json:"Module"`
	State        amp.State           `json:"State"`
	NetworkPorts []amp.NetworkPortInfo `json:"NetworkPorts"`
	Error        string              `json:"Error,omitempty"`
}

func runDebugAmpNetwork(cmd *cobra.Command, args []string) error {
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

	fmt.Fprintf(os.Stderr, "Found %d instances\n", len(instances))

	// Fetch network info for each ADS, Idle, or Running instance
	const stateADS = amp.State(-1)
	const stateIdle = amp.State(0)
	const stateRunning = amp.State(20)

	var results []instanceNetworkResult
	for _, inst := range instances {
		result := instanceNetworkResult{
			InstanceID:   inst.InstanceID,
			InstanceName: inst.InstanceName,
			FriendlyName: inst.FriendlyName,
			Module:       inst.Module,
			State:        inst.State,
		}

		// Only fetch network info for ADS, Idle, or Running instances
		if inst.State != stateADS && inst.State != stateIdle && inst.State != stateRunning {
			fmt.Fprintf(os.Stderr, "  Skipping %s (state %d)\n", inst.InstanceName, inst.State)
			result.Error = fmt.Sprintf("skipped: state %d is not ADS (-1), Idle (0), or Running (20)", inst.State)
			results = append(results, result)
			continue
		}

		fmt.Fprintf(os.Stderr, "  Fetching network info for %s...\n", inst.InstanceName)
		networkInfo, err := client.GetInstanceNetworkInfo(inst.InstanceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    Error: %v\n", err)
			result.Error = err.Error()
		} else {
			result.NetworkPorts = networkInfo
			fmt.Fprintf(os.Stderr, "    Found %d ports\n", len(networkInfo))
		}
		results = append(results, result)
	}

	fmt.Fprintf(os.Stderr, "\n")

	// Output as JSON for easy capture
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("failed to encode results: %w", err)
	}

	return nil
}

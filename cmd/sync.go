package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jtdoepke/amp-mikrotik-port-forwarder/config"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/amp"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/mikrotik"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/sync"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Synchronize port forwarding rules",
	Long: `Synchronize port forwarding rules from AMP to Mikrotik routers.

This command polls the AMP API for running game server instances and
updates firewall rules on the configured Mikrotik routers to forward
the appropriate ports.

Configuration can be provided via CLI flags or environment variables.
Environment variables use the AMP_SYNC_ prefix.

Examples:
  # Using environment variables
  export AMP_SYNC_AMP_URL=http://localhost:8080/
  export AMP_SYNC_AMP_USERNAME=admin
  export AMP_SYNC_AMP_PASSWORD_FILE=/run/secrets/amp-password
  export AMP_SYNC_TARGET_IP=192.168.100.10
  export AMP_SYNC_ROUTER_0_NAME=wan-router
  export AMP_SYNC_ROUTER_0_ADDRESS=192.168.1.1
  # ... more router config
  amp-port-sync sync

  # Using CLI flags
  amp-port-sync sync \
    --amp-url http://localhost:8080/ \
    --amp-username admin \
    --amp-password-file /run/secrets/amp-password \
    --target-ip 192.168.100.10 \
    --router name=wan,address=192.168.1.1,username=admin,password-file=/secrets/pw,wan-interface=WAN,wan-hostname=example.com,lan-subnet=192.168.0.0/16`,
	RunE: runSync,
}

var (
	// Sync behavior flags
	syncDryRun   bool
	syncOnce     bool
	syncInterval time.Duration

	// AMP config flags
	ampURL          string
	ampUsername     string
	ampPassword     string
	ampPasswordFile string

	// General config flags
	targetIP  string
	protocols []string

	// Router config flags (can be repeated)
	routerFlags []string
)

func init() {
	rootCmd.AddCommand(syncCmd)

	// Sync behavior
	syncCmd.Flags().BoolVar(&syncDryRun, "dry-run", false, "Show what would change without making changes")
	syncCmd.Flags().BoolVar(&syncOnce, "once", false, "Run once and exit (instead of continuous polling)")
	syncCmd.Flags().DurationVar(&syncInterval, "interval", time.Minute, "Polling interval (default: 1m)")

	// AMP config
	syncCmd.Flags().StringVar(&ampURL, "amp-url", "", "AMP API URL (env: AMP_SYNC_AMP_URL)")
	syncCmd.Flags().StringVar(&ampUsername, "amp-username", "", "AMP username (env: AMP_SYNC_AMP_USERNAME)")
	syncCmd.Flags().StringVar(&ampPassword, "amp-password", "", "AMP password (env: AMP_SYNC_AMP_PASSWORD)")
	syncCmd.Flags().StringVar(&ampPasswordFile, "amp-password-file", "", "Path to AMP password file (env: AMP_SYNC_AMP_PASSWORD_FILE)")

	// General config
	syncCmd.Flags().StringVar(&targetIP, "target-ip", "", "Target IP for port forwarding (env: AMP_SYNC_TARGET_IP)")
	syncCmd.Flags().StringSliceVar(&protocols, "protocols", nil, "Protocols to forward (default: tcp,udp) (env: AMP_SYNC_PROTOCOLS)")

	// Router config (repeated flag)
	syncCmd.Flags().StringArrayVar(&routerFlags, "router", nil,
		`Router config in key=value format (can be repeated).
Keys: name, address, username, password, password-file, use-tls, tls-insecure, tls-ca-file, wan-interface, wan-hostname, lan-subnet, forward-to
TLS: use-tls=true enables TLS (port 8729), tls-insecure defaults to true, set tls-insecure=false with tls-ca-file for verification
Example: --router name=wan,address=192.168.1.1:8729,username=admin,password-file=/secrets/pw,use-tls=true,wan-interface=WAN,wan-hostname=example.com,lan-subnet=192.168.0.0/16`)
}

func runSync(cmd *cobra.Command, args []string) error {
	// Parse router flags
	var routers []config.RouterConfig
	for _, rf := range routerFlags {
		router, err := config.ParseRouterFlag(rf)
		if err != nil {
			return fmt.Errorf("invalid --router flag: %w", err)
		}
		routers = append(routers, router)
	}

	// Load and validate AMP config from env vars + flags
	ampCfg, err := config.LoadAMPConfig(ampURL, ampUsername, ampPassword, ampPasswordFile)
	if err != nil {
		return err
	}

	// Set other flag-based env vars so Load() will use them
	if targetIP != "" {
		_ = os.Setenv("AMP_SYNC_TARGET_IP", targetIP)
	}
	if len(protocols) > 0 {
		_ = os.Setenv("AMP_SYNC_PROTOCOLS", strings.Join(protocols, ","))
	}

	// Set AMP config env vars so Load() will use them
	_ = os.Setenv("AMP_SYNC_AMP_URL", ampCfg.URL)
	_ = os.Setenv("AMP_SYNC_AMP_USERNAME", ampCfg.Username)
	_ = os.Setenv("AMP_SYNC_AMP_PASSWORD", ampCfg.Password)
	_ = os.Setenv("AMP_SYNC_AMP_PASSWORD_FILE", ampCfg.PasswordFile)

	// Load full configuration (including routers, target IP, etc.)
	cfg, err := config.Load(routers)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Set up logging
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Resolve AMP password
	ampPwd, err := config.ResolvePassword(cfg.AMP.Password, cfg.AMP.PasswordFile)
	if err != nil {
		return fmt.Errorf("failed to resolve AMP password: %w", err)
	}

	// Create AMP client
	ampClient, err := amp.NewClient(cfg.AMP.URL, cfg.AMP.Username, ampPwd)
	if err != nil {
		return fmt.Errorf("failed to create AMP client: %w", err)
	}
	defer func() { _ = ampClient.Close() }()

	// Create router client factory
	clientFactory := func(routerCfg config.RouterConfig) (mikrotik.RouterClient, error) {
		password, err := config.ResolvePassword(routerCfg.Password, routerCfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve router password: %w", err)
		}
		tlsConfig, err := config.BuildTLSConfig(routerCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build TLS config: %w", err)
		}
		return mikrotik.NewClient(routerCfg.Address, routerCfg.Username, password, tlsConfig)
	}

	// Create reconciler
	reconciler, err := sync.NewReconciler(cfg, ampClient, clientFactory, syncDryRun, logger)
	if err != nil {
		return fmt.Errorf("failed to create reconciler: %w", err)
	}

	if syncOnce {
		// Run once and exit
		logger.Info("Running single sync")
		if err := reconciler.Reconcile(); err != nil {
			return fmt.Errorf("sync failed: %w", err)
		}
		logger.Info("Sync completed successfully")
		return nil
	}

	// Run continuously
	logger.Info("Starting continuous sync", "interval", syncInterval, "dry_run", syncDryRun)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	// Run immediately on start
	runReconcile(reconciler, logger)

	for {
		select {
		case <-ticker.C:
			runReconcile(reconciler, logger)
		case sig := <-sigChan:
			logger.Info("Received signal, shutting down", "signal", sig)
			return nil
		}
	}
}

func runReconcile(reconciler *sync.Reconciler, logger *slog.Logger) {
	if err := reconciler.Reconcile(); err != nil {
		logger.Error("Sync failed", "error", err)
		return
	}
	logger.Info("Sync completed successfully")
}

package sync

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/jtdoepke/amp-mikrotik-port-forwarder/config"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/amp"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/mikrotik"
	mockamp "github.com/jtdoepke/amp-mikrotik-port-forwarder/mocks/amp"
	mockmikrotik "github.com/jtdoepke/amp-mikrotik-port-forwarder/mocks/mikrotik"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func testConfig() *config.Config {
	return &config.Config{
		TargetIP:  "10.0.50.100",
		Protocols: []string{"tcp", "udp"},
		Routers: []config.RouterConfig{
			{
				Name:         "wan-router",
				Address:      "10.0.1.1:8728",
				Username:     "admin",
				PasswordFile: "/tmp/password",
				WANInterface: "WAN",
				WANHostname:  "localhost", // Use localhost for tests
				LANSubnet:    "10.0.1.0/24",
				ForwardTo:    "10.0.2.1",
			},
		},
	}
}

func TestNewReconcilerValidation(t *testing.T) {
	cfg := testConfig()
	ampClient := mockamp.NewMockClient(t)
	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return nil, nil
	}
	logger := testLogger()

	tests := []struct {
		name          string
		cfg           *config.Config
		ampClient     amp.Client
		clientFactory RouterClientFactory
		logger        *slog.Logger
		wantErr       string
	}{
		{"nil config", nil, ampClient, clientFactory, logger, "config is required"},
		{"nil ampClient", cfg, nil, clientFactory, logger, "ampClient is required"},
		{"nil clientFactory", cfg, ampClient, nil, logger, "clientFactory is required"},
		{"nil logger", cfg, ampClient, clientFactory, nil, "logger is required"},
		{"valid", cfg, ampClient, clientFactory, logger, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewReconciler(tt.cfg, tt.ampClient, tt.clientFactory, false, tt.logger)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCollectPorts(t *testing.T) {
	instances := []amp.Instance{
		{
			InstanceName: "GameServer1",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
				{Port: 25565, Protocol: "udp", Name: "Game", Type: amp.PortTypeGame},
				{Port: 2222, Protocol: "tcp", Name: "SFTP Server", Type: amp.PortTypeSFTP},
				{Port: 8080, Protocol: "tcp", Name: "Main", Type: amp.PortTypeManagement},
			},
		},
		{
			InstanceName: "GameServer2",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 7777, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
		{
			InstanceName: "StoppedServer",
			Module:       "GenericModule",
			State:        amp.StateStopped,
			Ports: []amp.Port{
				{Port: 9999, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
		{
			InstanceName: "ADS",
			Module:       "ADS",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 8081, Protocol: "tcp", Name: "Main", Type: amp.PortTypeManagement},
			},
		},
	}

	ports := CollectPorts(instances)

	// Should include game ports and SFTP from running game servers
	// Should exclude: stopped servers, management instances, management ports
	assert.Equal(t, []int{2222, 7777, 25565}, ports["tcp"])
	assert.Equal(t, []int{25565}, ports["udp"])
}

func TestFormatPortList(t *testing.T) {
	tests := []struct {
		name     string
		ports    []int
		expected string
	}{
		{"empty", nil, ""},
		{"single", []int{25565}, "25565"},
		{"multiple", []int{80, 443, 8080}, "80,443,8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, FormatPortList(tt.ports))
		})
	}
}

func TestReconcileFirstRouter(t *testing.T) {
	cfg := testConfig()
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	// Return test instances
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{
		{
			InstanceName: "TestServer",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
				{Port: 25565, Protocol: "udp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
	}, nil)

	// Expect rule lookups and creates for TCP
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()

	// Expect rule lookups and creates for UDP
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:udp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:udp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:udp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()

	routerClient.EXPECT().Close().Return(nil)

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileUpdateExistingRule(t *testing.T) {
	cfg := testConfig()
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	// Return test instances with new port
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{
		{
			InstanceName: "TestServer",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
				{Port: 25566, Protocol: "tcp", Name: "Game2", Type: amp.PortTypeGame},
			},
		},
	}, nil)

	// Existing rule has different port list - should update
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").
		Return(&mikrotik.Rule{ID: "*1", DstPort: "25565"}, nil)
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*1", mock.Anything).Return(nil)

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").
		Return(&mikrotik.Rule{ID: "*2", DstPort: "25565"}, nil)
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*2", mock.Anything).Return(nil)

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").
		Return(&mikrotik.Rule{ID: "*3", DstPort: "25565"}, nil)
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*3", mock.Anything).Return(nil)

	// UDP has no ports, skip
	routerClient.EXPECT().Close().Return(nil)

	// Only TCP protocol for this test
	cfg.Protocols = []string{"tcp"}

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileDryRun(t *testing.T) {
	cfg := testConfig()
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	ampClient.EXPECT().GetInstances().Return([]amp.Instance{
		{
			InstanceName: "TestServer",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
	}, nil)

	// In dry run, we only look up rules, never create/update
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound)
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound)
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").Return(nil, mikrotik.ErrRuleNotFound)
	routerClient.EXPECT().Close().Return(nil)

	cfg.Protocols = []string{"tcp"}

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, true, testLogger()) // dryRun=true
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileSubsequentRouter(t *testing.T) {
	cfg := &config.Config{
		TargetIP:  "10.0.50.100",
		Protocols: []string{"tcp"},
		Routers: []config.RouterConfig{
			{
				Name:         "wan-router",
				Address:      "10.0.1.1:8728",
				Username:     "admin",
				PasswordFile: "/tmp/password",
				WANInterface: "WAN",
				WANHostname:  "localhost",
				LANSubnet:    "10.0.1.0/24",
				ForwardTo:    "10.0.2.1",
			},
			{
				Name:         "internal-router",
				Address:      "10.0.2.1:8728",
				Username:     "admin",
				PasswordFile: "/tmp/password",
				ForwardTo:    "10.0.50.100",
			},
		},
	}

	ampClient := mockamp.NewMockClient(t)
	wanRouter := mockmikrotik.NewMockRouterClient(t)
	internalRouter := mockmikrotik.NewMockRouterClient(t)

	// Return test instances
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{
		{
			InstanceName: "TestServer",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
	}, nil)

	// First router (index 0) - WAN-facing rules
	wanRouter.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	wanRouter.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()
	wanRouter.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	wanRouter.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()
	wanRouter.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	wanRouter.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()
	wanRouter.EXPECT().Close().Return(nil)

	// Second router (index 1) - internal router rules
	internalRouter.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:dstnat:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	internalRouter.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.Anything).Return(nil).Once()
	internalRouter.EXPECT().FindRuleByComment(mikrotik.RuleTypeFilter, "forward", "amp-sync:forward:tcp").Return(nil, mikrotik.ErrRuleNotFound).Once()
	internalRouter.EXPECT().CreateRule(mikrotik.RuleTypeFilter, mock.Anything).Return(nil).Once()
	internalRouter.EXPECT().Close().Return(nil)

	routerIndex := 0
	clientFactory := func(routerCfg config.RouterConfig) (mikrotik.RouterClient, error) {
		defer func() { routerIndex++ }()
		if routerIndex == 0 {
			return wanRouter, nil
		}
		return internalRouter, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileDisablesRulesWhenNoPorts(t *testing.T) {
	cfg := testConfig()
	cfg.Protocols = []string{"tcp"}
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	// Return no instances (no ports to forward)
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{}, nil)

	// Expect rules to be found and updated to disabled (not deleted)
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").
		Return(&mikrotik.Rule{ID: "*1", DstPort: "25565"}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*1", mock.Anything).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").
		Return(&mikrotik.Rule{ID: "*2", DstPort: "25565"}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*2", mock.Anything).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").
		Return(&mikrotik.Rule{ID: "*3", DstPort: "25565"}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*3", mock.Anything).Return(nil).Once()

	routerClient.EXPECT().Close().Return(nil)

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileCreatesDisabledRulesWhenNoPorts(t *testing.T) {
	cfg := testConfig()
	cfg.Protocols = []string{"tcp"}
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	// Return no instances (no ports to forward)
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{}, nil)

	// Rules don't exist - should create them as disabled
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").
		Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.MatchedBy(func(r mikrotik.Rule) bool {
		return r.Disabled && r.DstPort == ""
	})).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").
		Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.MatchedBy(func(r mikrotik.Rule) bool {
		return r.Disabled && r.DstPort == ""
	})).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").
		Return(nil, mikrotik.ErrRuleNotFound).Once()
	routerClient.EXPECT().CreateRule(mikrotik.RuleTypeNAT, mock.MatchedBy(func(r mikrotik.Rule) bool {
		return r.Disabled && r.DstPort == ""
	})).Return(nil).Once()

	routerClient.EXPECT().Close().Return(nil)

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileReEnablesRulesWhenPortsReturn(t *testing.T) {
	cfg := testConfig()
	cfg.Protocols = []string{"tcp"}
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	// Return instances with ports (game server started back up)
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{
		{
			InstanceName: "TestServer",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
	}, nil)

	// Existing rules are disabled with empty ports - should re-enable with new ports
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").
		Return(&mikrotik.Rule{ID: "*1", DstPort: "", Disabled: true, Props: map[string]string{}}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*1", mock.MatchedBy(func(r mikrotik.Rule) bool {
		return !r.Disabled && r.DstPort == "25565"
	})).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").
		Return(&mikrotik.Rule{ID: "*2", DstPort: "", Disabled: true, Props: map[string]string{}}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*2", mock.MatchedBy(func(r mikrotik.Rule) bool {
		return !r.Disabled && r.DstPort == "25565"
	})).Return(nil).Once()

	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").
		Return(&mikrotik.Rule{ID: "*3", DstPort: "", Disabled: true, Props: map[string]string{}}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*3", mock.MatchedBy(func(r mikrotik.Rule) bool {
		return !r.Disabled && r.DstPort == "25565"
	})).Return(nil).Once()

	routerClient.EXPECT().Close().Return(nil)

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

func TestReconcileUpdatesWhenWANIPChanges(t *testing.T) {
	cfg := testConfig()
	cfg.Protocols = []string{"tcp"}
	ampClient := mockamp.NewMockClient(t)
	routerClient := mockmikrotik.NewMockRouterClient(t)

	// Return test instances with same ports as before
	ampClient.EXPECT().GetInstances().Return([]amp.Instance{
		{
			InstanceName: "TestServer",
			Module:       "GenericModule",
			State:        amp.StateRunning,
			Ports: []amp.Port{
				{Port: 25565, Protocol: "tcp", Name: "Game", Type: amp.PortTypeGame},
			},
		},
	}, nil)

	// WAN dstnat - same ports and all props match - rule should not update
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:wan-dstnat:tcp").
		Return(&mikrotik.Rule{
			ID:      "*1",
			DstPort: "25565",
			Props: map[string]string{
				mikrotik.PropInInterface: "WAN",
				mikrotik.PropToAddresses: "10.0.2.1",
			},
		}, nil).Once()
	// No update expected - ports same, all props match

	// Hairpin dstnat - same ports but different WAN IP - should trigger update
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "dstnat", "amp-sync:hairpin-dstnat:tcp").
		Return(&mikrotik.Rule{
			ID:      "*2",
			DstPort: "25565",
			Props: map[string]string{
				mikrotik.PropDstAddress:  "1.2.3.4",   // Old WAN IP
				mikrotik.PropToAddresses: "10.0.2.1", // Same forward-to
			},
		}, nil).Once()
	routerClient.EXPECT().UpdateRule(mikrotik.RuleTypeNAT, "*2", mock.MatchedBy(func(r mikrotik.Rule) bool {
		// New WAN IP should be 127.0.0.1 (from resolving "localhost" in testConfig)
		return r.DstPort == "25565" && r.Props[mikrotik.PropDstAddress] == "127.0.0.1"
	})).Return(nil).Once()

	// Hairpin masq - same ports and all props match - rule should not update
	routerClient.EXPECT().FindRuleByComment(mikrotik.RuleTypeNAT, "srcnat", "amp-sync:hairpin-masq:tcp").
		Return(&mikrotik.Rule{
			ID:      "*3",
			DstPort: "25565",
			Props: map[string]string{
				mikrotik.PropSrcAddress: "10.0.1.0/24", // LANSubnet
				mikrotik.PropDstAddress: "10.0.2.1",    // forwardTo
			},
		}, nil).Once()
	// No update expected - ports same, all props match

	routerClient.EXPECT().Close().Return(nil)

	clientFactory := func(cfg config.RouterConfig) (mikrotik.RouterClient, error) {
		return routerClient, nil
	}

	r, err := NewReconciler(cfg, ampClient, clientFactory, false, testLogger())
	require.NoError(t, err)

	err = r.Reconcile()
	require.NoError(t, err)
}

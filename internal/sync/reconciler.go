package sync

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/jtdoepke/amp-mikrotik-port-forwarder/config"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/amp"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/mikrotik"
)

// Comment patterns for firewall rules.
const (
	CommentWANDstNat     = "amp-sync:wan-dstnat:%s"     // First router: WAN dstnat
	CommentHairpinDstNat = "amp-sync:hairpin-dstnat:%s" // First router: hairpin dstnat
	CommentHairpinMasq   = "amp-sync:hairpin-masq:%s"   // First router: hairpin masquerade
	CommentDstNat        = "amp-sync:dstnat:%s"         // Subsequent routers: dstnat
	CommentForward       = "amp-sync:forward:%s"        // Subsequent routers: forward filter
)

// RouterClientFactory creates a RouterClient for a given router config.
type RouterClientFactory func(cfg config.RouterConfig) (mikrotik.RouterClient, error)

// Reconciler synchronizes AMP port forwarding rules to Mikrotik routers.
type Reconciler struct {
	cfg           *config.Config
	ampClient     amp.Client
	clientFactory RouterClientFactory
	dryRun        bool
	logger        *slog.Logger
}

// NewReconciler creates a new reconciler.
// Returns an error if required parameters are nil.
func NewReconciler(
	cfg *config.Config,
	ampClient amp.Client,
	clientFactory RouterClientFactory,
	dryRun bool,
	logger *slog.Logger,
) (*Reconciler, error) {
	if cfg == nil {
		return nil, errors.New("config is required")
	}
	if ampClient == nil {
		return nil, errors.New("ampClient is required")
	}
	if clientFactory == nil {
		return nil, errors.New("clientFactory is required")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}

	return &Reconciler{
		cfg:           cfg,
		ampClient:     ampClient,
		clientFactory: clientFactory,
		dryRun:        dryRun,
		logger:        logger,
	}, nil
}

// Reconcile performs a single reconciliation cycle.
func (r *Reconciler) Reconcile() error {
	// Fetch instances from AMP
	instances, err := r.ampClient.GetInstances()
	if err != nil {
		return fmt.Errorf("failed to get AMP instances: %w", err)
	}

	// Collect ports from running game servers
	ports := CollectPorts(instances)
	r.logger.Info("Collected ports from AMP",
		"total_instances", len(instances),
		"game_servers", CountGameServers(instances),
		"tcp_ports", len(ports["tcp"]),
		"udp_ports", len(ports["udp"]),
	)

	// Reconcile each router
	for i, routerCfg := range r.cfg.Routers {
		if err := r.reconcileRouter(i, routerCfg, ports); err != nil {
			return fmt.Errorf("failed to reconcile router %s: %w", routerCfg.Name, err)
		}
	}

	return nil
}

// reconcileRouter reconciles rules for a single router.
func (r *Reconciler) reconcileRouter(index int, routerCfg config.RouterConfig, ports map[string][]int) error {
	r.logger.Info("Reconciling router", "router", routerCfg.Name, "index", index)

	client, err := r.clientFactory(routerCfg)
	if err != nil {
		return fmt.Errorf("failed to connect to router: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			r.logger.Warn("Failed to close router connection", "router", routerCfg.Name, "error", err)
		}
	}()

	forwardTo := r.cfg.GetForwardTo(index)

	for _, proto := range r.cfg.Protocols {
		portList := FormatPortList(ports[proto])
		// Disable rule when no ports (keeps rule in place for positioning)
		disabled := portList == ""

		if index == 0 {
			// First router: WAN dstnat, hairpin dstnat, hairpin masquerade
			if err := r.reconcileFirstRouter(client, routerCfg, proto, portList, forwardTo, disabled); err != nil {
				return err
			}
		} else {
			// Subsequent routers: dstnat, forward filter
			if err := r.reconcileSubsequentRouter(client, routerCfg, proto, portList, forwardTo, index, disabled); err != nil {
				return err
			}
		}
	}

	return nil
}

// reconcileFirstRouter handles rules for the first (WAN-facing) router.
func (r *Reconciler) reconcileFirstRouter(
	client mikrotik.RouterClient,
	cfg config.RouterConfig,
	proto, portList, forwardTo string,
	disabled bool,
) error {
	// Resolve WAN IP for hairpin NAT - either from hostname or auto-detect
	var wanIP string
	var err error
	if cfg.WANHostname != "" {
		wanIP, err = ResolveHostname(cfg.WANHostname)
		if err != nil {
			return fmt.Errorf("failed to resolve WAN hostname %s: %w", cfg.WANHostname, err)
		}
	} else {
		wanIP, err = DetectPublicIP()
		if err != nil {
			return fmt.Errorf("failed to detect public IP: %w", err)
		}
		r.logger.Info("Auto-detected public IP", "ip", wanIP)
	}

	return r.reconcileRules(client, cfg, proto, portList, forwardTo, wanIP, disabled, firstRouterRules)
}

// reconcileSubsequentRouter handles rules for subsequent routers.
func (r *Reconciler) reconcileSubsequentRouter(
	client mikrotik.RouterClient,
	cfg config.RouterConfig,
	proto, portList, forwardTo string,
	index int,
	disabled bool,
) error {
	listenIP := r.cfg.GetListenIP(index)
	return r.reconcileRules(client, cfg, proto, portList, forwardTo, listenIP, disabled, subsequentRouterRules)
}

// reconcileRules applies a set of rule specifications.
func (r *Reconciler) reconcileRules(
	client mikrotik.RouterClient,
	cfg config.RouterConfig,
	proto, portList, forwardTo, wanIP string,
	disabled bool,
	specs []ruleSpec,
) error {
	for _, spec := range specs {
		comment := fmt.Sprintf(spec.commentPattern, proto)
		rule := mikrotik.Rule{
			Comment:  comment,
			Chain:    spec.chain,
			Action:   spec.action,
			Protocol: proto,
			DstPort:  portList,
			Disabled: disabled,
			Props:    spec.buildProps(&cfg, forwardTo, wanIP),
		}
		if err := r.ensureRule(client, spec.ruleType, rule, cfg.Name); err != nil {
			return err
		}
	}
	return nil
}

// ensureRule ensures a rule exists with the correct port list.
func (r *Reconciler) ensureRule(
	client mikrotik.RouterClient,
	ruleType mikrotik.RuleType,
	rule mikrotik.Rule,
	routerName string,
) error {
	// Check if rule exists by querying the router directly
	existing, err := client.FindRuleByComment(ruleType, rule.Chain, rule.Comment)
	if err != nil && !errors.Is(err, mikrotik.ErrRuleNotFound) {
		return fmt.Errorf("failed to find rule %s: %w", rule.Comment, err)
	}

	if errors.Is(err, mikrotik.ErrRuleNotFound) {
		// Create new rule
		r.logger.Info("Creating rule",
			"router", routerName,
			"comment", rule.Comment,
			"ports", rule.DstPort,
			"dry_run", r.dryRun,
		)
		if !r.dryRun {
			if err := client.CreateRule(ruleType, rule); err != nil {
				return fmt.Errorf("failed to create rule %s: %w", rule.Comment, err)
			}
		}
	} else if existing.DstPort != rule.DstPort {
		// Update existing rule
		r.logger.Info("Updating rule",
			"router", routerName,
			"comment", rule.Comment,
			"old_ports", existing.DstPort,
			"new_ports", rule.DstPort,
			"dry_run", r.dryRun,
		)
		if !r.dryRun {
			if err := client.UpdateRule(ruleType, existing.ID, rule); err != nil {
				return fmt.Errorf("failed to update rule %s: %w", rule.Comment, err)
			}
		}
	} else {
		r.logger.Debug("Rule up to date",
			"router", routerName,
			"comment", rule.Comment,
			"ports", rule.DstPort,
		)
	}

	return nil
}

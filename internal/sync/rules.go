package sync

import (
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/config"
	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/mikrotik"
)

// ruleSpec defines a firewall rule template.
type ruleSpec struct {
	commentPattern string
	ruleType       mikrotik.RuleType
	chain          string
	action         string
	buildProps     func(cfg *config.RouterConfig, forwardTo, wanIP string) map[string]string
}

// firstRouterRules defines the rules for the first (WAN-facing) router.
var firstRouterRules = []ruleSpec{
	{
		commentPattern: CommentWANDstNat,
		ruleType:       mikrotik.RuleTypeNAT,
		chain:          "dstnat",
		action:         "dst-nat",
		buildProps: func(cfg *config.RouterConfig, forwardTo, _ string) map[string]string {
			props := map[string]string{
				mikrotik.PropToAddresses: forwardTo,
			}
			if cfg.WANInterfaceList != "" {
				props[mikrotik.PropInInterfaceList] = cfg.WANInterfaceList
			} else {
				props[mikrotik.PropInInterface] = cfg.WANInterface
			}
			return props
		},
	},
	{
		commentPattern: CommentHairpinDstNat,
		ruleType:       mikrotik.RuleTypeNAT,
		chain:          "dstnat",
		action:         "dst-nat",
		buildProps: func(cfg *config.RouterConfig, forwardTo, wanIP string) map[string]string {
			return map[string]string{
				mikrotik.PropDstAddress:  wanIP,
				mikrotik.PropToAddresses: forwardTo,
			}
		},
	},
	{
		commentPattern: CommentHairpinMasq,
		ruleType:       mikrotik.RuleTypeNAT,
		chain:          "srcnat",
		action:         "masquerade",
		buildProps: func(cfg *config.RouterConfig, forwardTo, _ string) map[string]string {
			return map[string]string{
				mikrotik.PropSrcAddress: cfg.LANSubnet,
				mikrotik.PropDstAddress: forwardTo,
			}
		},
	},
}

// subsequentRouterRules defines the rules for subsequent routers in the chain.
var subsequentRouterRules = []ruleSpec{
	{
		commentPattern: CommentDstNat,
		ruleType:       mikrotik.RuleTypeNAT,
		chain:          "dstnat",
		action:         "dst-nat",
		buildProps: func(cfg *config.RouterConfig, forwardTo, listenIP string) map[string]string {
			return map[string]string{
				mikrotik.PropDstAddress:  listenIP,
				mikrotik.PropToAddresses: forwardTo,
			}
		},
	},
	{
		commentPattern: CommentForward,
		ruleType:       mikrotik.RuleTypeFilter,
		chain:          "forward",
		action:         "accept",
		buildProps: func(cfg *config.RouterConfig, forwardTo, _ string) map[string]string {
			return map[string]string{
				mikrotik.PropDstAddress: forwardTo,
			}
		},
	},
}

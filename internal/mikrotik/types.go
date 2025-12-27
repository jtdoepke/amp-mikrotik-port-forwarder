package mikrotik

// Property key constants for firewall rules.
const (
	PropInInterface     = "in-interface"
	PropInInterfaceList = "in-interface-list"
	PropOutInterface    = "out-interface"
	PropSrcAddress      = "src-address"
	PropDstAddress      = "dst-address"
	PropToAddresses     = "to-addresses"
	PropToPorts         = "to-ports"
)

// Rule represents a firewall rule on a Mikrotik router.
type Rule struct {
	ID       string            // RouterOS internal ID (.id)
	Comment  string            // Rule comment used for identification
	Chain    string            // Firewall chain (dstnat, srcnat, forward, etc.)
	Action   string            // Action (dst-nat, masquerade, accept, etc.)
	Protocol string            // Protocol (tcp, udp)
	DstPort  string            // Destination port(s), comma-separated
	Disabled bool              // Whether the rule is disabled
	Props    map[string]string // Additional properties
}

// NewRule creates a new Rule with initialized Props map.
func NewRule(chain, action, protocol, dstPort, comment string) *Rule {
	return &Rule{
		Chain:    chain,
		Action:   action,
		Protocol: protocol,
		DstPort:  dstPort,
		Comment:  comment,
		Props:    make(map[string]string),
	}
}

// WithInInterfaceList sets the in-interface-list property.
func (r *Rule) WithInInterfaceList(iface string) *Rule {
	r.Props[PropInInterfaceList] = iface
	return r
}

// WithSrcAddress sets the src-address property.
func (r *Rule) WithSrcAddress(addr string) *Rule {
	r.Props[PropSrcAddress] = addr
	return r
}

// WithDstAddress sets the dst-address property.
func (r *Rule) WithDstAddress(addr string) *Rule {
	r.Props[PropDstAddress] = addr
	return r
}

// WithToAddresses sets the to-addresses property.
func (r *Rule) WithToAddresses(addr string) *Rule {
	r.Props[PropToAddresses] = addr
	return r
}

// RuleType indicates which firewall table a rule belongs to.
type RuleType string

const (
	RuleTypeNAT    RuleType = "nat"    // /ip/firewall/nat
	RuleTypeFilter RuleType = "filter" // /ip/firewall/filter
)

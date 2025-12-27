package mikrotik

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRule(t *testing.T) {
	rule := NewRule("dstnat", "dst-nat", "tcp", "25565", "test-comment")

	assert.Equal(t, "dstnat", rule.Chain)
	assert.Equal(t, "dst-nat", rule.Action)
	assert.Equal(t, "tcp", rule.Protocol)
	assert.Equal(t, "25565", rule.DstPort)
	assert.Equal(t, "test-comment", rule.Comment)
	assert.NotNil(t, rule.Props)
	assert.Empty(t, rule.Props)
}

func TestRuleBuilderMethods(t *testing.T) {
	rule := NewRule("dstnat", "dst-nat", "tcp", "25565", "test").
		WithInInterfaceList("WAN").
		WithSrcAddress("192.168.1.0/24").
		WithDstAddress("10.0.0.1").
		WithToAddresses("10.0.0.100")

	assert.Equal(t, "WAN", rule.Props[PropInInterfaceList])
	assert.Equal(t, "192.168.1.0/24", rule.Props[PropSrcAddress])
	assert.Equal(t, "10.0.0.1", rule.Props[PropDstAddress])
	assert.Equal(t, "10.0.0.100", rule.Props[PropToAddresses])
}

func TestRuleTypeConstants(t *testing.T) {
	assert.Equal(t, RuleType("nat"), RuleTypeNAT)
	assert.Equal(t, RuleType("filter"), RuleTypeFilter)
}

func TestPropertyConstants(t *testing.T) {
	// Verify property constants match RouterOS API names
	assert.Equal(t, "in-interface-list", PropInInterfaceList)
	assert.Equal(t, "out-interface", PropOutInterface)
	assert.Equal(t, "src-address", PropSrcAddress)
	assert.Equal(t, "dst-address", PropDstAddress)
	assert.Equal(t, "to-addresses", PropToAddresses)
	assert.Equal(t, "to-ports", PropToPorts)
}

package mikrotik

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleTypePath(t *testing.T) {
	tests := []struct {
		ruleType RuleType
		expected string
	}{
		{RuleTypeNAT, "/ip/firewall/nat"},
		{RuleTypeFilter, "/ip/firewall/filter"},
		{RuleType("unknown"), "/ip/firewall/nat"}, // default case
	}

	for _, tt := range tests {
		t.Run(string(tt.ruleType), func(t *testing.T) {
			assert.Equal(t, tt.expected, ruleTypePath(tt.ruleType))
		})
	}
}

func TestErrRuleNotFound(t *testing.T) {
	// Verify the sentinel error works with errors.Is
	err := ErrRuleNotFound
	assert.True(t, errors.Is(err, ErrRuleNotFound))

	// Verify wrapped error works
	wrappedErr := errors.New("some context: " + err.Error())
	assert.False(t, errors.Is(wrappedErr, ErrRuleNotFound))
}

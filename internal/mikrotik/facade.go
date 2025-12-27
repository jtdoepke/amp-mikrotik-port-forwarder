package mikrotik

import "errors"

// ErrRuleNotFound is returned when a rule cannot be found by comment.
var ErrRuleNotFound = errors.New("rule not found")

// RouterClient provides an interface for interacting with a Mikrotik router's firewall.
type RouterClient interface {
	// FindRuleByComment finds a rule by its comment in the specified table and chain.
	// Returns ErrRuleNotFound if no matching rule exists.
	FindRuleByComment(ruleType RuleType, chain, comment string) (*Rule, error)

	// CreateRule creates a new firewall rule.
	CreateRule(ruleType RuleType, rule Rule) error

	// UpdateRule updates an existing firewall rule by ID.
	UpdateRule(ruleType RuleType, id string, rule Rule) error

	// DeleteRule deletes a firewall rule by ID.
	DeleteRule(ruleType RuleType, id string) error

	// Close closes the connection to the router.
	Close() error
}

package mikrotik

import (
	"crypto/tls"
	"fmt"
	"maps"
	"time"

	"github.com/go-routeros/routeros/v3"
)

// routerosClient implements RouterClient using the go-routeros library.
type routerosClient struct {
	client *routeros.Client
}

// NewClient creates a new Mikrotik router client.
// If tlsConfig is not nil, uses TLS connection (typically port 8729).
// If tlsConfig is nil, uses plain-text connection (typically port 8728).
func NewClient(address, username, password string, tlsConfig *tls.Config) (RouterClient, error) {
	var client *routeros.Client
	var err error

	if tlsConfig != nil {
		client, err = routeros.DialTLSTimeout(address, username, password, tlsConfig, 10*time.Second)
	} else {
		client, err = routeros.DialTimeout(address, username, password, 10*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to router: %w", err)
	}

	return &routerosClient{client: client}, nil
}

// ruleTypePath returns the RouterOS API path for the given rule type.
func ruleTypePath(rt RuleType) string {
	switch rt {
	case RuleTypeNAT:
		return "/ip/firewall/nat"
	case RuleTypeFilter:
		return "/ip/firewall/filter"
	default:
		return "/ip/firewall/nat"
	}
}

// FindRuleByComment finds a rule by its comment.
func (c *routerosClient) FindRuleByComment(ruleType RuleType, chain, comment string) (*Rule, error) {
	path := ruleTypePath(ruleType)

	reply, err := c.client.Run(
		path+"/print",
		fmt.Sprintf("?chain=%s", chain),
		fmt.Sprintf("?comment=%s", comment),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query rules: %w", err)
	}

	if len(reply.Re) == 0 {
		return nil, ErrRuleNotFound
	}

	// Return the first matching rule
	sentence := reply.Re[0]
	rule := &Rule{
		ID:      sentence.Map[".id"],
		Comment: sentence.Map["comment"],
		Chain:   sentence.Map["chain"],
		Action:  sentence.Map["action"],
		DstPort: sentence.Map["dst-port"],
		Props:   make(map[string]string),
	}

	// Copy all properties
	maps.Copy(rule.Props, sentence.Map)

	return rule, nil
}

// CreateRule creates a new firewall rule.
func (c *routerosClient) CreateRule(ruleType RuleType, rule Rule) error {
	path := ruleTypePath(ruleType)

	args := []string{path + "/add"}

	// Add required fields
	if rule.Chain != "" {
		args = append(args, fmt.Sprintf("=chain=%s", rule.Chain))
	}
	if rule.Action != "" {
		args = append(args, fmt.Sprintf("=action=%s", rule.Action))
	}
	if rule.Protocol != "" {
		args = append(args, fmt.Sprintf("=protocol=%s", rule.Protocol))
	}
	if rule.DstPort != "" {
		args = append(args, fmt.Sprintf("=dst-port=%s", rule.DstPort))
	}
	if rule.Comment != "" {
		args = append(args, fmt.Sprintf("=comment=%s", rule.Comment))
	}
	if rule.Disabled {
		args = append(args, "=disabled=yes")
	}

	// Add additional properties
	for k, v := range rule.Props {
		// Skip fields we already handled
		switch k {
		case "chain", "action", "protocol", "dst-port", "comment", ".id":
			continue
		}
		args = append(args, fmt.Sprintf("=%s=%s", k, v))
	}

	_, err := c.client.Run(args...)
	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	return nil
}

// UpdateRule updates an existing firewall rule.
func (c *routerosClient) UpdateRule(ruleType RuleType, id string, rule Rule) error {
	path := ruleTypePath(ruleType)

	args := []string{
		path + "/set",
		fmt.Sprintf("=.id=%s", id),
	}

	// Add fields to update
	if rule.DstPort != "" {
		args = append(args, fmt.Sprintf("=dst-port=%s", rule.DstPort))
	}

	// Set disabled state
	if rule.Disabled {
		args = append(args, "=disabled=yes")
	} else {
		args = append(args, "=disabled=no")
	}

	// Add additional properties
	for k, v := range rule.Props {
		// Skip fields we don't update
		switch k {
		case ".id", "chain", "comment":
			continue
		}
		args = append(args, fmt.Sprintf("=%s=%s", k, v))
	}

	_, err := c.client.Run(args...)
	if err != nil {
		return fmt.Errorf("failed to update rule: %w", err)
	}

	return nil
}

// DeleteRule deletes a firewall rule.
func (c *routerosClient) DeleteRule(ruleType RuleType, id string) error {
	path := ruleTypePath(ruleType)

	_, err := c.client.Run(
		path+"/remove",
		fmt.Sprintf("=.id=%s", id),
	)
	if err != nil {
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	return nil
}

// Close closes the connection to the router.
func (c *routerosClient) Close() error {
	return c.client.Close()
}

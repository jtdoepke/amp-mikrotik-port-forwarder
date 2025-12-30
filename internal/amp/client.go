package amp

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ampClient implements the Client interface.
type ampClient struct {
	api *apiClient
}

// NewClient creates a new AMP client.
// baseURL should be the AMP API URL (e.g., "http://127.0.0.1:8080/")
// username and password are the AMP credentials.
func NewClient(baseURL, username, password string) (Client, error) {
	api := newAPIClient(baseURL, username, password)

	// Perform initial login to validate credentials
	if err := api.login(); err != nil {
		return nil, fmt.Errorf("failed to create AMP client: %w", err)
	}

	return &ampClient{api: api}, nil
}

// GetInstances returns all game server instances from AMP.
func (c *ampClient) GetInstances() ([]Instance, error) {
	targets, err := c.api.getInstances()
	if err != nil {
		return nil, fmt.Errorf("failed to get instances: %w", err)
	}

	var instances []Instance
	for _, target := range targets {
		for _, inst := range target.AvailableInstances {
			instance := Instance{
				InstanceID:   inst.InstanceID,
				InstanceName: inst.InstanceName,
				FriendlyName: inst.FriendlyName,
				Module:       inst.Module,
				State:        State(inst.AppState),
				Ports:        extractPorts(inst),
			}
			instances = append(instances, instance)
		}
	}

	return instances, nil
}

// GetInstanceNetworkInfo returns detailed network port information for an instance.
func (c *ampClient) GetInstanceNetworkInfo(instanceName string) ([]NetworkPortInfo, error) {
	return c.api.getInstanceNetworkInfo(instanceName)
}

// Close releases any resources held by the client.
func (c *ampClient) Close() error {
	// Sessions expire automatically, no cleanup needed
	return nil
}

// extractPorts extracts port information from an AMP instance.
// It parses ApplicationEndpoints to find port numbers.
func extractPorts(inst apiInstance) []Port {
	var ports []Port
	seen := make(map[string]bool)

	for _, endpoint := range inst.ApplicationEndpoints {
		// Endpoint format is typically "host:port" or just a URL
		port, protocol := parseEndpoint(endpoint.Endpoint)
		if port > 0 {
			key := fmt.Sprintf("%d/%s", port, protocol)
			if !seen[key] {
				seen[key] = true
				ports = append(ports, Port{
					Port:     port,
					Protocol: protocol,
					Name:     endpoint.DisplayName,
					Type:     portTypeFromName(endpoint.DisplayName),
				})
			}
		}
	}

	// Also check the main Port field if set
	if inst.Port > 0 {
		key := fmt.Sprintf("%d/tcp", inst.Port)
		if !seen[key] {
			ports = append(ports, Port{
				Port:     inst.Port,
				Protocol: "tcp",
				Name:     "Main",
				Type:     PortTypeManagement,
			})
		}
	}

	return ports
}

// portTypeFromName determines the port type based on its display name.
func portTypeFromName(name string) PortType {
	switch name {
	case "Main":
		return PortTypeManagement
	case "SFTP Server":
		return PortTypeSFTP
	default:
		return PortTypeGame
	}
}

// parseEndpoint extracts port and protocol from an endpoint string.
// Returns port number and protocol ("tcp" or "udp").
func parseEndpoint(endpoint string) (int, string) {
	// Handle various formats:
	// - "192.168.1.1:25565"
	// - ":25565"
	// - "25565/udp"
	// - "example.com:25565"

	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return 0, ""
	}

	// Check for protocol suffix
	protocol := "tcp"
	if strings.HasSuffix(endpoint, "/udp") {
		protocol = "udp"
		endpoint = strings.TrimSuffix(endpoint, "/udp")
	} else if strings.HasSuffix(endpoint, "/tcp") {
		endpoint = strings.TrimSuffix(endpoint, "/tcp")
	}

	// Try to extract port from host:port format
	_, portStr, err := net.SplitHostPort(endpoint)
	if err == nil {
		port, err := strconv.Atoi(portStr)
		if err == nil && port > 0 && port <= 65535 {
			return port, protocol
		}
	}

	// Try parsing as just a port number
	port, err := strconv.Atoi(endpoint)
	if err == nil && port > 0 && port <= 65535 {
		return port, protocol
	}

	return 0, ""
}

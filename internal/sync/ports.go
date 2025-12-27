package sync

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jtdoepke/amp-mikrotik-port-forwarder/internal/amp"
)

// CollectPorts collects all forwardable ports from instances, grouped by protocol.
// Only ports from running game servers are included. Management ports are excluded.
func CollectPorts(instances []amp.Instance) map[string][]int {
	ports := make(map[string][]int)
	seen := make(map[string]bool)

	for _, inst := range instances {
		if !inst.IsGameServer() {
			continue
		}

		for _, port := range inst.Ports {
			// Only forward game and SFTP ports, not management
			if port.Type == amp.PortTypeManagement {
				continue
			}

			key := fmt.Sprintf("%s:%d", port.Protocol, port.Port)
			if seen[key] {
				continue
			}
			seen[key] = true

			ports[port.Protocol] = append(ports[port.Protocol], port.Port)
		}
	}

	// Sort ports for consistent rule generation
	for proto := range ports {
		slices.Sort(ports[proto])
	}

	return ports
}

// FormatPortList formats a slice of ports as a comma-separated string.
func FormatPortList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = strconv.Itoa(p)
	}
	return strings.Join(strs, ",")
}

// ResolveHostname resolves a hostname to an IPv4 address.
// If the hostname resolves to multiple addresses, IPv4 is preferred.
func ResolveHostname(hostname string) (string, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return "", err
	}

	// Prefer IPv4
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	if len(ips) > 0 {
		return ips[0].String(), nil
	}

	return "", fmt.Errorf("no IP addresses found for %s", hostname)
}

// DetectPublicIP queries an external service to determine the public IP.
func DetectPublicIP() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://icanhazip.com")
	if err != nil {
		return "", fmt.Errorf("failed to detect public IP: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Best effort close

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP returned: %s", ip)
	}
	return ip, nil
}

// CountGameServers counts how many instances are running game servers.
func CountGameServers(instances []amp.Instance) int {
	count := 0
	for _, inst := range instances {
		if inst.IsGameServer() {
			count++
		}
	}
	return count
}

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

// Instance states for filtering.
const (
	StateADS     = amp.State(-1) // ADS control panel is always "running"
	StateIdle    = amp.State(0)
	StateRunning = amp.State(20)
)

// CollectPorts collects all forwardable ports from instances using the GetInstanceNetworkInfo API.
// Ports are collected from instances in ADS (-1), Idle (0), or Running (20) state.
// Only ports where IsFirewallTarget and Verified are true are included.
// Protocol=2 (Both) results in the port being added to both TCP and UDP lists.
func CollectPorts(client amp.Client, instances []amp.Instance) (map[string][]int, error) {
	ports := make(map[string][]int)
	seen := make(map[string]bool)

	for _, inst := range instances {
		// Only fetch network info for ADS, Idle, or Running instances
		if inst.State != StateADS && inst.State != StateIdle && inst.State != StateRunning {
			continue
		}

		// Get detailed network info for this instance
		networkInfo, err := client.GetInstanceNetworkInfo(inst.InstanceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get network info for %s: %w", inst.InstanceName, err)
		}

		for _, port := range networkInfo {
			// Only forward ports marked as firewall targets and verified
			if !port.IsFirewallTarget || !port.Verified {
				continue
			}

			// Handle protocol: 0=TCP, 1=UDP, 2=Both
			switch port.Protocol {
			case amp.ProtocolTCP:
				key := fmt.Sprintf("tcp:%d", port.PortNumber)
				if !seen[key] {
					seen[key] = true
					ports["tcp"] = append(ports["tcp"], port.PortNumber)
				}
			case amp.ProtocolUDP:
				key := fmt.Sprintf("udp:%d", port.PortNumber)
				if !seen[key] {
					seen[key] = true
					ports["udp"] = append(ports["udp"], port.PortNumber)
				}
			case amp.ProtocolBoth:
				// Add to both TCP and UDP
				tcpKey := fmt.Sprintf("tcp:%d", port.PortNumber)
				if !seen[tcpKey] {
					seen[tcpKey] = true
					ports["tcp"] = append(ports["tcp"], port.PortNumber)
				}
				udpKey := fmt.Sprintf("udp:%d", port.PortNumber)
				if !seen[udpKey] {
					seen[udpKey] = true
					ports["udp"] = append(ports["udp"], port.PortNumber)
				}
			}
		}
	}

	// Sort ports for consistent rule generation
	for proto := range ports {
		slices.Sort(ports[proto])
	}

	return ports, nil
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

// CountActiveInstances counts how many instances are active (ADS, Idle, or Running).
func CountActiveInstances(instances []amp.Instance) int {
	count := 0
	for _, inst := range instances {
		if inst.State == StateADS || inst.State == StateIdle || inst.State == StateRunning {
			count++
		}
	}
	return count
}

package config

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

const envPrefix = "AMP_SYNC"

// Load builds configuration from environment variables and the provided options.
// Routers can be passed directly or will be loaded from indexed env vars.
func Load(routers []RouterConfig) (*Config, error) {
	cfg := Defaults()

	// Load AMP config from env vars
	if v := getEnv("AMP_URL"); v != "" {
		cfg.AMP.URL = v
	}
	if v := getEnv("AMP_USERNAME"); v != "" {
		cfg.AMP.Username = v
	}
	if v := getEnv("AMP_PASSWORD"); v != "" {
		cfg.AMP.Password = v
	}
	if v := getEnv("AMP_PASSWORD_FILE"); v != "" {
		cfg.AMP.PasswordFile = v
	}

	// Load target IP
	if v := getEnv("TARGET_IP"); v != "" {
		cfg.TargetIP = v
	}

	// Load protocols
	if v := getEnv("PROTOCOLS"); v != "" {
		cfg.Protocols = strings.Split(v, ",")
		for i := range cfg.Protocols {
			cfg.Protocols[i] = strings.TrimSpace(cfg.Protocols[i])
		}
	}

	// Use provided routers or load from env vars
	if len(routers) > 0 {
		cfg.Routers = routers
	} else {
		cfg.Routers = loadRoutersFromEnv()
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// loadRoutersFromEnv loads router configs from indexed environment variables.
// Variables follow the pattern: AMP_SYNC_ROUTER_0_NAME, AMP_SYNC_ROUTER_0_ADDRESS, etc.
func loadRoutersFromEnv() []RouterConfig {
	var routers []RouterConfig

	for i := 0; ; i++ {
		prefix := fmt.Sprintf("ROUTER_%d", i)

		// Check if this router exists by looking for required fields
		name := getEnv(prefix + "_NAME")
		address := getEnv(prefix + "_ADDRESS")

		// Stop when we hit a gap
		if name == "" && address == "" {
			break
		}

		router := RouterConfig{
			Name:         name,
			Address:      address,
			Username:     getEnv(prefix + "_USERNAME"),
			Password:     getEnv(prefix + "_PASSWORD"),
			PasswordFile: getEnv(prefix + "_PASSWORD_FILE"),
			UseTLS:       getEnv(prefix+"_USE_TLS") == "true",
			TLSInsecure:  getEnv(prefix+"_TLS_INSECURE") != "false", // Defaults to true
			TLSCAFile:        getEnv(prefix + "_TLS_CA_FILE"),
			WANInterface:     getEnv(prefix + "_WAN_INTERFACE"),
			WANInterfaceList: getEnv(prefix + "_WAN_INTERFACE_LIST"),
			WANHostname:      getEnv(prefix + "_WAN_HOSTNAME"),
			LANSubnet:        getEnv(prefix + "_LAN_SUBNET"),
			ForwardTo:        getEnv(prefix + "_FORWARD_TO"),
		}

		routers = append(routers, router)
	}

	return routers
}

// ParseRouterFlag parses a router configuration from a flag value.
// Format: name=value,address=value,username=value,...
func ParseRouterFlag(value string) (RouterConfig, error) {
	router := RouterConfig{
		TLSInsecure: true, // Default to true
	}

	pairs := strings.Split(value, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) != 2 {
			return router, fmt.Errorf("invalid router config format: %s (expected key=value)", pair)
		}

		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])

		switch strings.ToLower(key) {
		case "name":
			router.Name = val
		case "address":
			router.Address = val
		case "username":
			router.Username = val
		case "password":
			router.Password = val
		case "password-file":
			router.PasswordFile = val
		case "use-tls":
			router.UseTLS = val == "true"
		case "tls-insecure":
			router.TLSInsecure = val != "false" // Defaults to true
		case "tls-ca-file":
			router.TLSCAFile = val
		case "wan-interface":
			router.WANInterface = val
		case "wan-interface-list":
			router.WANInterfaceList = val
		case "wan-hostname":
			router.WANHostname = val
		case "lan-subnet":
			router.LANSubnet = val
		case "forward-to":
			router.ForwardTo = val
		default:
			return router, fmt.Errorf("unknown router config key: %s", key)
		}
	}

	return router, nil
}

// Validate checks that the configuration has all required fields.
func (c *Config) Validate() error {
	// Validate AMP config
	if c.AMP.Password == "" && c.AMP.PasswordFile == "" {
		return fmt.Errorf("either amp.password or amp.password_file is required")
	}
	if c.AMP.Username == "" {
		return fmt.Errorf("amp.username is required")
	}

	if c.TargetIP == "" {
		return fmt.Errorf("target_ip is required")
	}

	if len(c.Routers) == 0 {
		return fmt.Errorf("at least one router is required")
	}

	for i, r := range c.Routers {
		if r.Address == "" {
			return fmt.Errorf("router[%d].address is required", i)
		}
		if r.Username == "" {
			return fmt.Errorf("router[%d].username is required", i)
		}
		if r.Password == "" && r.PasswordFile == "" {
			return fmt.Errorf("router[%d]: either password or password_file is required", i)
		}

		// First router needs WAN config (WANHostname is optional - auto-detected if empty)
		if i == 0 {
			if r.WANInterface == "" && r.WANInterfaceList == "" {
				return fmt.Errorf("router[%d]: either wan_interface or wan_interface_list is required for first router", i)
			}
			if r.LANSubnet == "" {
				return fmt.Errorf("router[%d].lan_subnet is required for first router", i)
			}
		}

		// All routers except the last need forward_to
		if i < len(c.Routers)-1 && r.ForwardTo == "" {
			return fmt.Errorf("router[%d].forward_to is required (not the last router)", i)
		}
	}

	return nil
}

// ResolvePassword returns the password, reading from file if necessary.
// Priority: PasswordFile (if set) > Password
func ResolvePassword(password, passwordFile string) (string, error) {
	if passwordFile != "" {
		return ReadPasswordFile(passwordFile)
	}
	if password != "" {
		return password, nil
	}
	return "", fmt.Errorf("no password provided")
}

// ReadPasswordFile reads a password from a file, trimming whitespace.
func ReadPasswordFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read password file %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// GetForwardTo returns the forward_to address for a router,
// defaulting to target_ip for the last router.
func (c *Config) GetForwardTo(routerIndex int) string {
	r := c.Routers[routerIndex]
	if r.ForwardTo != "" {
		return r.ForwardTo
	}
	return c.TargetIP
}

// getEnv gets an environment variable with the AMP_SYNC_ prefix.
func getEnv(key string) string {
	return os.Getenv(envPrefix + "_" + key)
}

// BuildTLSConfig creates a TLS configuration from router settings.
// Returns nil if TLS is not enabled.
func BuildTLSConfig(r RouterConfig) (*tls.Config, error) {
	if !r.UseTLS {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: r.TLSInsecure, //nolint:gosec // User-configurable, defaults to true for ease of use
		MinVersion:         tls.VersionTLS12,
	}

	// If CA file provided, load it for verification
	if r.TLSCAFile != "" {
		caCert, err := os.ReadFile(r.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = pool
	}

	return tlsConfig, nil
}

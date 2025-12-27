package config

// Config represents the application configuration.
type Config struct {
	AMP       AMPConfig      `mapstructure:"amp"`
	TargetIP  string         `mapstructure:"target_ip"`
	Protocols []string       `mapstructure:"protocols"`
	Routers   []RouterConfig `mapstructure:"routers"`
}

// AMPConfig contains AMP API connection settings.
type AMPConfig struct {
	URL          string `mapstructure:"url"`
	Username     string `mapstructure:"username"`
	Password     string `mapstructure:"password"`
	PasswordFile string `mapstructure:"password_file"`
}

// RouterConfig contains settings for a single router in the chain.
type RouterConfig struct {
	Name         string `mapstructure:"name"`
	Address      string `mapstructure:"address"`
	Username     string `mapstructure:"username"`
	Password     string `mapstructure:"password"`
	PasswordFile string `mapstructure:"password_file"`

	// TLS configuration
	UseTLS      bool   `mapstructure:"use_tls"`
	TLSInsecure bool   `mapstructure:"tls_insecure"` // Skip cert verification (default: true)
	TLSCAFile   string `mapstructure:"tls_ca_file"`  // CA certificate path

	// First router only (index 0):
	WANInterface     string `mapstructure:"wan_interface"`      // Single interface name
	WANInterfaceList string `mapstructure:"wan_interface_list"` // Interface list name
	WANHostname      string `mapstructure:"wan_hostname"`
	LANSubnet        string `mapstructure:"lan_subnet"`

	// All routers except last:
	ForwardTo string `mapstructure:"forward_to"`
}

// IsFirstRouter returns true if this router is the first in the chain (WAN-facing).
func (r *RouterConfig) IsFirstRouter(index int) bool {
	return index == 0
}

// Defaults returns a Config with default values.
func Defaults() Config {
	return Config{
		AMP: AMPConfig{
			URL: "http://127.0.0.1:8080/",
		},
		Protocols: []string{"tcp", "udp"},
	}
}

// GetListenIP returns the listen IP for a router (previous router's ForwardTo).
// Returns empty string for the first router.
func (c *Config) GetListenIP(routerIndex int) string {
	if routerIndex == 0 {
		return ""
	}
	return c.Routers[routerIndex-1].ForwardTo
}

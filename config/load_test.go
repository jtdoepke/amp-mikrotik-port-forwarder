package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearEnv clears all AMP_SYNC_ environment variables for test isolation.
func clearEnv(t *testing.T) {
	t.Helper()
	envVars := []string{
		"AMP_SYNC_AMP_URL",
		"AMP_SYNC_AMP_USERNAME",
		"AMP_SYNC_AMP_PASSWORD",
		"AMP_SYNC_AMP_PASSWORD_FILE",
		"AMP_SYNC_TARGET_IP",
		"AMP_SYNC_PROTOCOLS",
	}
	// Clear router env vars (up to 10 routers)
	for i := 0; i < 10; i++ {
		envVars = append(envVars,
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_NAME",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_ADDRESS",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_USERNAME",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_PASSWORD",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_PASSWORD_FILE",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_USE_TLS",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_TLS_INSECURE",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_TLS_CA_FILE",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_WAN_INTERFACE",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_WAN_INTERFACE_LIST",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_WAN_HOSTNAME",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_LAN_SUBNET",
			"AMP_SYNC_ROUTER_"+string(rune('0'+i))+"_FORWARD_TO",
		)
	}
	for _, env := range envVars {
		_ = os.Unsetenv(env)
	}
}

// validFirstRouter returns a RouterConfig valid for the first router position.
func validFirstRouter() RouterConfig {
	return RouterConfig{
		Name:         "wan-router",
		Address:      "192.168.1.1:8728",
		Username:     "admin",
		Password:     "secret",
		TLSInsecure:  true, // Default
		WANInterface: "ether1",
		WANHostname:  "example.com",
		LANSubnet:    "192.168.0.0/16",
	}
}

// validSecondRouter returns a RouterConfig valid for subsequent router positions.
func validSecondRouter() RouterConfig {
	return RouterConfig{
		Name:        "internal-router",
		Address:     "192.168.2.1:8728",
		Username:    "admin",
		Password:    "secret",
		TLSInsecure: true, // Default
	}
}

// validConfig returns a Config that passes all validation.
func validConfig() Config {
	return Config{
		AMP: AMPConfig{
			URL:      "http://127.0.0.1:8080/",
			Username: "ampuser",
			Password: "amppass",
		},
		TargetIP:  "10.0.50.100",
		Protocols: []string{"tcp", "udp"},
		Routers:   []RouterConfig{validFirstRouter()},
	}
}

// TestParseRouterFlag tests the ParseRouterFlag function.
func TestParseRouterFlag(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      RouterConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "valid full config",
			input: "name=wan,address=192.168.1.1:8728,username=admin,password=secret,wan-interface=ether1,wan-hostname=example.com,lan-subnet=192.168.0.0/16,forward-to=192.168.2.1",
			want: RouterConfig{
				Name:         "wan",
				Address:      "192.168.1.1:8728",
				Username:     "admin",
				Password:     "secret",
				TLSInsecure:  true, // Default
				WANInterface: "ether1",
				WANHostname:  "example.com",
				LANSubnet:    "192.168.0.0/16",
				ForwardTo:    "192.168.2.1",
			},
		},
		{
			name:  "minimal config",
			input: "address=192.168.1.1,username=admin,password=secret",
			want: RouterConfig{
				Address:     "192.168.1.1",
				Username:    "admin",
				Password:    "secret",
				TLSInsecure: true, // Default
			},
		},
		{
			name:  "password-file instead of password",
			input: "address=192.168.1.1,username=admin,password-file=/run/secrets/pw",
			want: RouterConfig{
				Address:      "192.168.1.1",
				Username:     "admin",
				PasswordFile: "/run/secrets/pw",
				TLSInsecure:  true, // Default
			},
		},
		{
			name:      "unknown key",
			input:     "address=192.168.1.1,badkey=value",
			wantErr:   true,
			errSubstr: "unknown router config key: badkey",
		},
		{
			name:      "missing value (no equals)",
			input:     "address=192.168.1.1,username",
			wantErr:   true,
			errSubstr: "invalid router config format",
		},
		{
			name:  "whitespace handling",
			input: " name = wan , address = 192.168.1.1 ",
			want: RouterConfig{
				Name:        "wan",
				Address:     "192.168.1.1",
				TLSInsecure: true, // Default
			},
		},
		{
			name:  "case insensitivity",
			input: "NAME=wan,ADDRESS=192.168.1.1,Username=admin,PASSWORD=secret",
			want: RouterConfig{
				Name:        "wan",
				Address:     "192.168.1.1",
				Username:    "admin",
				Password:    "secret",
				TLSInsecure: true, // Default
			},
		},
		{
			name:  "empty value",
			input: "name=,address=192.168.1.1",
			want: RouterConfig{
				Name:        "",
				Address:     "192.168.1.1",
				TLSInsecure: true, // Default
			},
		},
		{
			name:  "value with equals sign",
			input: "address=192.168.1.1,password=abc=123=xyz",
			want: RouterConfig{
				Address:     "192.168.1.1",
				Password:    "abc=123=xyz",
				TLSInsecure: true, // Default
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRouterFlag(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestLoadRoutersFromEnv tests loading routers from indexed environment variables.
func TestLoadRoutersFromEnv(t *testing.T) {
	tests := []struct {
		name   string
		envs   map[string]string
		want   []RouterConfig
	}{
		{
			name: "single router",
			envs: map[string]string{
				"AMP_SYNC_ROUTER_0_NAME":          "wan",
				"AMP_SYNC_ROUTER_0_ADDRESS":       "192.168.1.1:8728",
				"AMP_SYNC_ROUTER_0_USERNAME":      "admin",
				"AMP_SYNC_ROUTER_0_PASSWORD":      "secret",
				"AMP_SYNC_ROUTER_0_WAN_INTERFACE": "ether1",
				"AMP_SYNC_ROUTER_0_WAN_HOSTNAME":  "example.com",
				"AMP_SYNC_ROUTER_0_LAN_SUBNET":    "192.168.0.0/16",
			},
			want: []RouterConfig{
				{
					Name:         "wan",
					Address:      "192.168.1.1:8728",
					Username:     "admin",
					Password:     "secret",
					TLSInsecure:  true, // Default
					WANInterface: "ether1",
					WANHostname:  "example.com",
					LANSubnet:    "192.168.0.0/16",
				},
			},
		},
		{
			name: "multiple routers",
			envs: map[string]string{
				"AMP_SYNC_ROUTER_0_NAME":    "wan",
				"AMP_SYNC_ROUTER_0_ADDRESS": "192.168.1.1:8728",
				"AMP_SYNC_ROUTER_1_NAME":    "internal",
				"AMP_SYNC_ROUTER_1_ADDRESS": "192.168.2.1:8728",
				"AMP_SYNC_ROUTER_2_NAME":    "core",
				"AMP_SYNC_ROUTER_2_ADDRESS": "192.168.3.1:8728",
			},
			want: []RouterConfig{
				{Name: "wan", Address: "192.168.1.1:8728", TLSInsecure: true},
				{Name: "internal", Address: "192.168.2.1:8728", TLSInsecure: true},
				{Name: "core", Address: "192.168.3.1:8728", TLSInsecure: true},
			},
		},
		{
			name: "gap detection - stops at first missing",
			envs: map[string]string{
				"AMP_SYNC_ROUTER_0_NAME":    "first",
				"AMP_SYNC_ROUTER_0_ADDRESS": "192.168.1.1:8728",
				// ROUTER_1 is missing
				"AMP_SYNC_ROUTER_2_NAME":    "third",
				"AMP_SYNC_ROUTER_2_ADDRESS": "192.168.3.1:8728",
			},
			want: []RouterConfig{
				{Name: "first", Address: "192.168.1.1:8728", TLSInsecure: true},
			},
		},
		{
			name: "all fields loaded",
			envs: map[string]string{
				"AMP_SYNC_ROUTER_0_NAME":          "full",
				"AMP_SYNC_ROUTER_0_ADDRESS":       "192.168.1.1:8728",
				"AMP_SYNC_ROUTER_0_USERNAME":      "admin",
				"AMP_SYNC_ROUTER_0_PASSWORD":      "secret",
				"AMP_SYNC_ROUTER_0_PASSWORD_FILE": "/run/secrets/pw",
				"AMP_SYNC_ROUTER_0_WAN_INTERFACE": "ether1",
				"AMP_SYNC_ROUTER_0_WAN_HOSTNAME":  "example.com",
				"AMP_SYNC_ROUTER_0_LAN_SUBNET":    "192.168.0.0/16",
				"AMP_SYNC_ROUTER_0_FORWARD_TO":    "192.168.2.1",
			},
			want: []RouterConfig{
				{
					Name:         "full",
					Address:      "192.168.1.1:8728",
					Username:     "admin",
					Password:     "secret",
					PasswordFile: "/run/secrets/pw",
					TLSInsecure:  true, // Default
					WANInterface: "ether1",
					WANHostname:  "example.com",
					LANSubnet:    "192.168.0.0/16",
					ForwardTo:    "192.168.2.1",
				},
			},
		},
		{
			name: "empty when no env vars",
			envs: map[string]string{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tt.envs {
				t.Setenv(k, v)
			}

			got := loadRoutersFromEnv()
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestLoad tests the main Load function.
func TestLoad(t *testing.T) {
	t.Run("defaults applied", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AMP_SYNC_AMP_USERNAME", "user")
		t.Setenv("AMP_SYNC_AMP_PASSWORD", "pass")
		t.Setenv("AMP_SYNC_TARGET_IP", "10.0.0.1")

		router := validFirstRouter()
		cfg, err := Load([]RouterConfig{router})
		require.NoError(t, err)

		assert.Equal(t, "http://127.0.0.1:8080/", cfg.AMP.URL)
		assert.Equal(t, []string{"tcp", "udp"}, cfg.Protocols)
	})

	t.Run("AMP config from env", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AMP_SYNC_AMP_URL", "http://custom:9090/")
		t.Setenv("AMP_SYNC_AMP_USERNAME", "customuser")
		t.Setenv("AMP_SYNC_AMP_PASSWORD", "custompass")
		t.Setenv("AMP_SYNC_TARGET_IP", "10.0.0.1")

		router := validFirstRouter()
		cfg, err := Load([]RouterConfig{router})
		require.NoError(t, err)

		assert.Equal(t, "http://custom:9090/", cfg.AMP.URL)
		assert.Equal(t, "customuser", cfg.AMP.Username)
		assert.Equal(t, "custompass", cfg.AMP.Password)
	})

	t.Run("target IP from env", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AMP_SYNC_AMP_USERNAME", "user")
		t.Setenv("AMP_SYNC_AMP_PASSWORD", "pass")
		t.Setenv("AMP_SYNC_TARGET_IP", "10.0.50.100")

		router := validFirstRouter()
		cfg, err := Load([]RouterConfig{router})
		require.NoError(t, err)

		assert.Equal(t, "10.0.50.100", cfg.TargetIP)
	})

	t.Run("protocols from env", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AMP_SYNC_AMP_USERNAME", "user")
		t.Setenv("AMP_SYNC_AMP_PASSWORD", "pass")
		t.Setenv("AMP_SYNC_TARGET_IP", "10.0.0.1")
		t.Setenv("AMP_SYNC_PROTOCOLS", "tcp, udp, icmp")

		router := validFirstRouter()
		cfg, err := Load([]RouterConfig{router})
		require.NoError(t, err)

		assert.Equal(t, []string{"tcp", "udp", "icmp"}, cfg.Protocols)
	})

	t.Run("provided routers used over env", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AMP_SYNC_AMP_USERNAME", "user")
		t.Setenv("AMP_SYNC_AMP_PASSWORD", "pass")
		t.Setenv("AMP_SYNC_TARGET_IP", "10.0.0.1")
		// Set env router that should be ignored
		t.Setenv("AMP_SYNC_ROUTER_0_NAME", "env-router")
		t.Setenv("AMP_SYNC_ROUTER_0_ADDRESS", "1.1.1.1:8728")

		providedRouter := validFirstRouter()
		providedRouter.Name = "provided-router"
		cfg, err := Load([]RouterConfig{providedRouter})
		require.NoError(t, err)

		require.Len(t, cfg.Routers, 1)
		assert.Equal(t, "provided-router", cfg.Routers[0].Name)
	})

	t.Run("env routers fallback", func(t *testing.T) {
		clearEnv(t)
		t.Setenv("AMP_SYNC_AMP_USERNAME", "user")
		t.Setenv("AMP_SYNC_AMP_PASSWORD", "pass")
		t.Setenv("AMP_SYNC_TARGET_IP", "10.0.0.1")
		t.Setenv("AMP_SYNC_ROUTER_0_NAME", "env-router")
		t.Setenv("AMP_SYNC_ROUTER_0_ADDRESS", "192.168.1.1:8728")
		t.Setenv("AMP_SYNC_ROUTER_0_USERNAME", "admin")
		t.Setenv("AMP_SYNC_ROUTER_0_PASSWORD", "secret")
		t.Setenv("AMP_SYNC_ROUTER_0_WAN_INTERFACE", "ether1")
		t.Setenv("AMP_SYNC_ROUTER_0_WAN_HOSTNAME", "example.com")
		t.Setenv("AMP_SYNC_ROUTER_0_LAN_SUBNET", "192.168.0.0/16")

		cfg, err := Load(nil) // No provided routers
		require.NoError(t, err)

		require.Len(t, cfg.Routers, 1)
		assert.Equal(t, "env-router", cfg.Routers[0].Name)
	})

	t.Run("validation called", func(t *testing.T) {
		clearEnv(t)
		// Missing required fields
		_, err := Load(nil)
		require.Error(t, err)
	})
}

// TestValidate tests the Config.Validate method.
func TestValidate(t *testing.T) {
	t.Run("valid single router", func(t *testing.T) {
		cfg := validConfig()
		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid router chain", func(t *testing.T) {
		cfg := validConfig()
		first := validFirstRouter()
		first.ForwardTo = "192.168.2.1"
		second := validSecondRouter()
		cfg.Routers = []RouterConfig{first, second}

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing AMP password", func(t *testing.T) {
		cfg := validConfig()
		cfg.AMP.Password = ""
		cfg.AMP.PasswordFile = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "amp.password")
	})

	t.Run("AMP password file is sufficient", func(t *testing.T) {
		cfg := validConfig()
		cfg.AMP.Password = ""
		cfg.AMP.PasswordFile = "/run/secrets/amp-pw"

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing AMP username", func(t *testing.T) {
		cfg := validConfig()
		cfg.AMP.Username = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "amp.username")
	})

	t.Run("missing target IP", func(t *testing.T) {
		cfg := validConfig()
		cfg.TargetIP = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "target_ip")
	})

	t.Run("no routers", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers = nil

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one router")
	})

	t.Run("missing router address", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].Address = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router[0].address")
	})

	t.Run("missing router username", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].Username = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router[0].username")
	})

	t.Run("missing router password", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].Password = ""
		cfg.Routers[0].PasswordFile = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router[0]")
		assert.Contains(t, err.Error(), "password")
	})

	t.Run("router password file is sufficient", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].Password = ""
		cfg.Routers[0].PasswordFile = "/run/secrets/router-pw"

		err := cfg.Validate()
		assert.NoError(t, err)
	})

	t.Run("first router missing wan_interface and wan_interface_list", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].WANInterface = ""
		cfg.Routers[0].WANInterfaceList = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "wan_interface or wan_interface_list")
	})

	t.Run("first router missing wan_hostname is OK (auto-detected)", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].WANHostname = ""

		err := cfg.Validate()
		require.NoError(t, err) // WANHostname is optional, auto-detected at runtime
	})

	t.Run("first router missing lan_subnet", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].LANSubnet = ""

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router[0].lan_subnet")
	})

	t.Run("non-last router missing forward_to", func(t *testing.T) {
		cfg := validConfig()
		first := validFirstRouter()
		first.ForwardTo = "" // Missing
		second := validSecondRouter()
		cfg.Routers = []RouterConfig{first, second}

		err := cfg.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "router[0].forward_to")
	})

	t.Run("last router without forward_to is ok", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].ForwardTo = "" // Last router, ok to be empty

		err := cfg.Validate()
		assert.NoError(t, err)
	})
}

// TestResolvePassword tests the ResolvePassword function.
func TestResolvePassword(t *testing.T) {
	t.Run("password file priority", func(t *testing.T) {
		tmpDir := t.TempDir()
		pwFile := filepath.Join(tmpDir, "password")
		err := os.WriteFile(pwFile, []byte("file-password\n"), 0600)
		require.NoError(t, err)

		pw, err := ResolvePassword("inline-password", pwFile)
		require.NoError(t, err)
		assert.Equal(t, "file-password", pw)
	})

	t.Run("inline password used", func(t *testing.T) {
		pw, err := ResolvePassword("inline-password", "")
		require.NoError(t, err)
		assert.Equal(t, "inline-password", pw)
	})

	t.Run("no password error", func(t *testing.T) {
		_, err := ResolvePassword("", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no password provided")
	})
}

// TestReadPasswordFile tests the ReadPasswordFile function.
func TestReadPasswordFile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tmpDir := t.TempDir()
		pwFile := filepath.Join(tmpDir, "password")
		err := os.WriteFile(pwFile, []byte("mysecret"), 0600)
		require.NoError(t, err)

		pw, err := ReadPasswordFile(pwFile)
		require.NoError(t, err)
		assert.Equal(t, "mysecret", pw)
	})

	t.Run("whitespace trimming", func(t *testing.T) {
		tmpDir := t.TempDir()
		pwFile := filepath.Join(tmpDir, "password")
		err := os.WriteFile(pwFile, []byte("  mysecret\n\n"), 0600)
		require.NoError(t, err)

		pw, err := ReadPasswordFile(pwFile)
		require.NoError(t, err)
		assert.Equal(t, "mysecret", pw)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ReadPasswordFile("/nonexistent/path/password")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read password file")
	})
}

// TestGetForwardTo tests the Config.GetForwardTo method.
func TestGetForwardTo(t *testing.T) {
	t.Run("router has forward_to", func(t *testing.T) {
		cfg := validConfig()
		cfg.Routers[0].ForwardTo = "192.168.2.1"

		got := cfg.GetForwardTo(0)
		assert.Equal(t, "192.168.2.1", got)
	})

	t.Run("fallback to target_ip", func(t *testing.T) {
		cfg := validConfig()
		cfg.TargetIP = "10.0.50.100"
		cfg.Routers[0].ForwardTo = ""

		got := cfg.GetForwardTo(0)
		assert.Equal(t, "10.0.50.100", got)
	})
}

// TestIsFirstRouter tests the RouterConfig.IsFirstRouter method.
func TestIsFirstRouter(t *testing.T) {
	r := RouterConfig{}

	assert.True(t, r.IsFirstRouter(0))
	assert.False(t, r.IsFirstRouter(1))
	assert.False(t, r.IsFirstRouter(99))
}

// TestDefaults tests the Defaults function.
func TestDefaults(t *testing.T) {
	cfg := Defaults()

	assert.Equal(t, "http://127.0.0.1:8080/", cfg.AMP.URL)
	assert.Equal(t, []string{"tcp", "udp"}, cfg.Protocols)
	assert.Empty(t, cfg.Routers)
	assert.Empty(t, cfg.TargetIP)
}

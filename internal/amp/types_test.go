package amp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadTestInstances(t *testing.T) {
	instances, err := LoadTestInstances("../../testdata/amp_instances.json")
	require.NoError(t, err)
	require.NotEmpty(t, instances)

	// Verify we have the expected number of instances
	assert.Len(t, instances, 13)

	// Find the running RimworldTogether instance
	var rimworld *Instance
	for i := range instances {
		if instances[i].InstanceName == "RimworldTogether-RimWorldServer01" {
			rimworld = &instances[i]
			break
		}
	}
	require.NotNil(t, rimworld, "RimworldTogether instance not found")

	// Verify it's running
	assert.Equal(t, StateRunning, rimworld.State)
	assert.True(t, rimworld.IsRunning())
	assert.False(t, rimworld.IsManagement())
	assert.True(t, rimworld.IsGameServer())

	// Verify port types are set correctly
	for _, port := range rimworld.Ports {
		switch port.Name {
		case "Application Address":
			assert.Equal(t, PortTypeGame, port.Type)
		case "SFTP Server":
			assert.Equal(t, PortTypeSFTP, port.Type)
		case "Main":
			assert.Equal(t, PortTypeManagement, port.Type)
		}
	}
}

func TestInstance_IsRunning(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		expected bool
	}{
		{"Stopped", StateStopped, false},
		{"PreStart", StatePreStart, false},
		{"Configuring", StateConfiguring, false},
		{"Starting", StateStarting, false},
		{"Running", StateRunning, true},
		{"Restarting", StateRestarting, false},
		{"Stopping", StateStopping, false},
		{"Sleeping", StateSleeping, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := Instance{State: tt.state}
			assert.Equal(t, tt.expected, inst.IsRunning())
		})
	}
}

func TestInstance_IsManagement(t *testing.T) {
	tests := []struct {
		name     string
		module   string
		expected bool
	}{
		{"ADS module", "ADS", true},
		{"GenericModule", "GenericModule", false},
		{"Minecraft", "Minecraft", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := Instance{Module: tt.module}
			assert.Equal(t, tt.expected, inst.IsManagement())
		})
	}
}

func TestInstance_IsGameServer(t *testing.T) {
	tests := []struct {
		name     string
		state    State
		module   string
		expected bool
	}{
		{"Running game server", StateRunning, "GenericModule", true},
		{"Running management", StateRunning, "ADS", false},
		{"Stopped game server", StateStopped, "GenericModule", false},
		{"Stopped management", StateStopped, "ADS", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inst := Instance{State: tt.state, Module: tt.module}
			assert.Equal(t, tt.expected, inst.IsGameServer())
		})
	}
}

func TestPortTypeFromName(t *testing.T) {
	tests := []struct {
		name     string
		portName string
		expected PortType
	}{
		{"Main port", "Main", PortTypeManagement},
		{"SFTP port", "SFTP Server", PortTypeSFTP},
		{"Application Address", "Application Address", PortTypeGame},
		{"Minecraft Server Address", "Minecraft Server Address", PortTypeGame},
		{"Unknown", "Something Else", PortTypeGame},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, portTypeFromName(tt.portName))
		})
	}
}

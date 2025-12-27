package amp

import "fmt"

// State represents the application state of an AMP instance.
type State int

const (
	StateStopped     State = 0
	StatePreStart    State = 5
	StateConfiguring State = 7
	StateStarting    State = 10
	StateRunning     State = 20
	StateRestarting  State = 30
	StateStopping    State = 40
	StateSleeping    State = 50
)

// String returns the string representation of a State.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "Stopped"
	case StatePreStart:
		return "PreStart"
	case StateConfiguring:
		return "Configuring"
	case StateStarting:
		return "Starting"
	case StateRunning:
		return "Running"
	case StateRestarting:
		return "Restarting"
	case StateStopping:
		return "Stopping"
	case StateSleeping:
		return "Sleeping"
	default:
		return fmt.Sprintf("State(%d)", s)
	}
}

// PortType categorizes the purpose of a port.
type PortType int

const (
	PortTypeGame       PortType = iota // Game server ports (Application Address, etc.)
	PortTypeSFTP                       // SFTP file transfer
	PortTypeManagement                 // AMP web management interface (Main)
)

// String returns the string representation of a PortType.
func (pt PortType) String() string {
	switch pt {
	case PortTypeGame:
		return "Game"
	case PortTypeSFTP:
		return "SFTP"
	case PortTypeManagement:
		return "Management"
	default:
		return fmt.Sprintf("PortType(%d)", pt)
	}
}

// Port represents a network port exposed by an AMP instance.
type Port struct {
	Port     int
	Protocol string // "tcp" or "udp"
	Name     string
	Type     PortType
}

// Instance represents a game server instance from AMP.
type Instance struct {
	InstanceID   string
	InstanceName string
	FriendlyName string
	Module       string
	State        State
	Ports        []Port
}

// IsRunning returns true if the instance is in the running state.
func (i *Instance) IsRunning() bool {
	return i.State == StateRunning
}

// IsManagement returns true if this is a management instance (ADS).
// Management instances should not have ports forwarded.
func (i *Instance) IsManagement() bool {
	return i.Module == "ADS"
}

// IsGameServer returns true if this is a running game server instance
// that should have its ports forwarded.
func (i *Instance) IsGameServer() bool {
	return i.IsRunning() && !i.IsManagement()
}

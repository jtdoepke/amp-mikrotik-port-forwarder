package amp

// Client defines the interface for interacting with the AMP API.
// This abstraction allows for easy mocking in tests.
type Client interface {
	// GetInstances returns all game server instances from AMP.
	GetInstances() ([]Instance, error)

	// Close releases any resources held by the client.
	Close() error
}

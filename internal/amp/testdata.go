package amp

import (
	"encoding/json"
	"os"
)

// LoadTestInstances loads instances from a JSON file for testing.
// The JSON file should contain an array of Instance objects.
func LoadTestInstances(path string) ([]Instance, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var instances []Instance
	if err := json.Unmarshal(data, &instances); err != nil {
		return nil, err
	}

	// Set port types based on name (JSON doesn't include Type field)
	for i := range instances {
		for j := range instances[i].Ports {
			instances[i].Ports[j].Type = portTypeFromName(instances[i].Ports[j].Name)
		}
	}

	return instances, nil
}

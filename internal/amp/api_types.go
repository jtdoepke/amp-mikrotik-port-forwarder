package amp

// loginResult represents the response from Core/Login.
type loginResult struct {
	Success      bool   `json:"success"`
	SessionID    string `json:"sessionID"`
	ResultReason string `json:"resultReason"`
}

// adsInstance represents an ADS target containing game instances.
type adsInstance struct {
	AvailableInstances []apiInstance `json:"AvailableInstances"`
}

// apiInstance represents a game server instance from the API.
type apiInstance struct {
	InstanceID           string         `json:"InstanceID"`
	InstanceName         string         `json:"InstanceName"`
	FriendlyName         string         `json:"FriendlyName"`
	Module               string         `json:"Module"`
	AppState             int            `json:"AppState"`
	Port                 int            `json:"Port"`
	ApplicationEndpoints []endpointInfo `json:"ApplicationEndpoints"`
}

// endpointInfo represents a network endpoint exposed by an instance.
type endpointInfo struct {
	DisplayName string `json:"DisplayName"`
	Endpoint    string `json:"Endpoint"`
}

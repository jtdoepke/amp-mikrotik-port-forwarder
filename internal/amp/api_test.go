package amp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIClient_Login(t *testing.T) {
	tests := []struct {
		name       string
		response   loginResult
		statusCode int
		wantErr    bool
	}{
		{
			name: "successful login",
			response: loginResult{
				Success:   true,
				SessionID: "test-session-123",
			},
			statusCode: http.StatusOK,
			wantErr:    false,
		},
		{
			name: "failed login - invalid credentials",
			response: loginResult{
				Success:      false,
				ResultReason: "Invalid username or password",
			},
			statusCode: http.StatusOK,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/API/Core/Login" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("unexpected method: %s", r.Method)
				}

				w.WriteHeader(tt.statusCode)
				if err := json.NewEncoder(w).Encode(tt.response); err != nil {
					t.Fatal(err)
				}
			}))
			defer server.Close()

			client := newAPIClient(server.URL, "testuser", "testpass")
			err := client.login()

			if (err != nil) != tt.wantErr {
				t.Errorf("login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && client.sessionID != tt.response.SessionID {
				t.Errorf("sessionID = %v, want %v", client.sessionID, tt.response.SessionID)
			}
		})
	}
}

func TestAPIClient_GetInstances(t *testing.T) {
	loginResponse := loginResult{
		Success:   true,
		SessionID: "test-session-123",
	}

	instancesResponse := []adsInstance{
		{
			AvailableInstances: []apiInstance{
				{
					InstanceID:   "test-instance-1",
					InstanceName: "TestServer01",
					FriendlyName: "Test Server 1",
					Module:       "GenericModule",
					AppState:     20, // StateRunning
					Port:         8080,
					ApplicationEndpoints: []endpointInfo{
						{DisplayName: "Application Address", Endpoint: "192.168.1.1:25565"},
						{DisplayName: "SFTP Server", Endpoint: ":2234"},
					},
				},
				{
					InstanceID:   "test-instance-2",
					InstanceName: "TestServer02",
					FriendlyName: "Test Server 2",
					Module:       "ADS",
					AppState:     20,
					Port:         8081,
					ApplicationEndpoints: []endpointInfo{
						{DisplayName: "Main", Endpoint: ":8081"},
					},
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/API/Core/Login":
			if err := json.NewEncoder(w).Encode(loginResponse); err != nil {
				t.Fatal(err)
			}
		case "/API/ADSModule/GetInstances":
			if err := json.NewEncoder(w).Encode(instancesResponse); err != nil {
				t.Fatal(err)
			}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newAPIClient(server.URL, "testuser", "testpass")
	instances, err := client.getInstances()
	if err != nil {
		t.Fatalf("getInstances() error = %v", err)
	}

	if len(instances) != 1 {
		t.Fatalf("expected 1 target, got %d", len(instances))
	}

	if len(instances[0].AvailableInstances) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(instances[0].AvailableInstances))
	}

	inst := instances[0].AvailableInstances[0]
	if inst.InstanceID != "test-instance-1" {
		t.Errorf("InstanceID = %v, want test-instance-1", inst.InstanceID)
	}
	if inst.InstanceName != "TestServer01" {
		t.Errorf("InstanceName = %v, want TestServer01", inst.InstanceName)
	}
	if len(inst.ApplicationEndpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(inst.ApplicationEndpoints))
	}
}

func TestAPIClient_SessionReuse(t *testing.T) {
	loginCount := 0
	loginResponse := loginResult{
		Success:   true,
		SessionID: "test-session-123",
	}

	instancesResponse := []adsInstance{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/API/Core/Login":
			loginCount++
			if err := json.NewEncoder(w).Encode(loginResponse); err != nil {
				t.Fatal(err)
			}
		case "/API/ADSModule/GetInstances":
			if err := json.NewEncoder(w).Encode(instancesResponse); err != nil {
				t.Fatal(err)
			}
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newAPIClient(server.URL, "testuser", "testpass")

	// First call should trigger login
	_, err := client.getInstances()
	if err != nil {
		t.Fatalf("first getInstances() error = %v", err)
	}

	// Second call should reuse session
	_, err = client.getInstances()
	if err != nil {
		t.Fatalf("second getInstances() error = %v", err)
	}

	if loginCount != 1 {
		t.Errorf("expected 1 login, got %d", loginCount)
	}
}

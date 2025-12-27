package amp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const defaultRelogInterval = 5 * time.Minute

// apiClient implements the AMP API HTTP client with session management.
type apiClient struct {
	baseURL       string
	username      string
	password      string
	httpClient    *http.Client
	sessionID     string
	lastAPICall   time.Time
	relogInterval time.Duration
	mu            sync.Mutex
}

// newAPIClient creates a new AMP API client.
func newAPIClient(baseURL, username, password string) *apiClient {
	baseURL = strings.TrimSuffix(baseURL, "/")
	return &apiClient{
		baseURL:       baseURL,
		username:      username,
		password:      password,
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		relogInterval: defaultRelogInterval,
	}
}

// login authenticates with the AMP API and stores the session ID.
func (c *apiClient) login() error {
	args := map[string]any{
		"username":   c.username,
		"password":   c.password,
		"token":      "",
		"rememberMe": false,
	}

	body, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("marshal login request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/API/Core/Login",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result loginResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode login response: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("login failed: %s", result.ResultReason)
	}

	c.sessionID = result.SessionID
	c.lastAPICall = time.Now()
	return nil
}

// apiCall makes an API call to the specified endpoint with automatic re-login.
func (c *apiClient) apiCall(endpoint string, args map[string]any) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-authenticate if session expired or not yet logged in
	if c.sessionID == "" || time.Since(c.lastAPICall) > c.relogInterval {
		if err := c.login(); err != nil {
			return nil, err
		}
	}

	// Add session ID to request
	if args == nil {
		args = make(map[string]any)
	}
	args["SESSIONID"] = c.sessionID

	body, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(
		c.baseURL+"/API/"+endpoint,
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("API request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	c.lastAPICall = time.Now()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return respBody, nil
}

// getInstances retrieves all game server instances from AMP.
func (c *apiClient) getInstances() ([]adsInstance, error) {
	body, err := c.apiCall("ADSModule/GetInstances", nil)
	if err != nil {
		return nil, err
	}

	var result []adsInstance
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode instances: %w", err)
	}

	return result, nil
}

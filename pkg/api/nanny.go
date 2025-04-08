package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type NannyClient struct {
	BaseURL string
	APIKey  string
}

func NewNannyClient(apiURL, apiKey string) (*NannyClient, error) {
	return &NannyClient{
		BaseURL: apiURL,
		APIKey:  apiKey,
	}, nil
}

func (c *NannyClient) DoRequest(endpoint string, method string, payload interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)

	var reqBody []byte
	var err error
	if payload != nil {
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.APIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	return resp, nil
}

func (c *NannyClient) GetStatus() (map[string]interface{}, error) {
	resp, err := c.DoRequest("/status", "GET", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode API status response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) GetUser(userID string) (map[string]interface{}, error) {
	resp, err := c.DoRequest(fmt.Sprintf("/api/user/%s", userID), "GET", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode user response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) RegisterAgent(metadata map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.DoRequest("/api/agent", "POST", metadata)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode agent registration response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) StartDiagnostic(payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.DoRequest("/api/diagnostic", "POST", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode diagnostic start response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) ContinueDiagnostic(id string, payload map[string]interface{}) (map[string]interface{}, error) {
	resp, err := c.DoRequest(fmt.Sprintf("/api/diagnostic/%s/continue", id), "POST", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode diagnostic continue response: %s", err)
	}

	return result, nil
}

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

type NannyClient struct {
	BaseURL string
	APIKey  string
}

func (c *NannyClient) Close() {
	// Currently, there are no resources to clean up.
	// This function can be updated in the future if needed.
}

func NewNannyClient() (*NannyClient, error) {
	apiKey := os.Getenv("NANNY_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("NANNY_API_KEY environment variable not set")
	}

	return &NannyClient{
		BaseURL: "http://localhost:8080",
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
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.APIKey))

	client := &http.Client{}
	return client.Do(req)
}

func (c *NannyClient) CheckStatus() (string, error) {
	resp, err := c.DoRequest("/status", "GET", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get status from server: %s", resp.Status)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result["status"], nil
}

func (c *NannyClient) GetGenerativeAIResponse(input string) ([]string, error) {
	payload := map[string]string{"input": input}
	resp, err := c.DoRequest("/generative-ai-response", "POST", payload)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response from server: %s", resp.Status)
	}

	var response []string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	return response, nil
}

func (c *NannyClient) FinalGenerativeAIResponse(input, output string) (string, error) {
	payload := map[string]string{
		"input":  input,
		"output": output,
	}
	resp, err := c.DoRequest("/final-generative-ai-response", "POST", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get response from server: %s", resp.Status)
	}

	var response string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", err
	}

	return response, nil
}

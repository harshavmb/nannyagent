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

func (c *NannyClient) Close() {
	// Currently, there are no resources to clean up.
	// This function can be updated in the future if needed.
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
		return "", fmt.Errorf("failed to decode API status response: %s", err)
	}

	return result["status"], nil
}

func (c *NannyClient) RegisterAgent(metadata map[string]string) (map[string]string, error) {
	resp, err := c.DoRequest("/api/agent-info", "POST", metadata)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to register agent: %s", resp.Status)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode agent registration response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) StartChat(chat map[string]interface{}) (map[string]string, error) {
	resp, err := c.DoRequest("/api/chat", "POST", chat)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to initiate chat: %s", resp.Status)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode chat initiation response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) AddPromptResponse(chatID string, promptResponse map[string]string) (map[string]string, error) {
	resp, err := c.DoRequest(fmt.Sprintf("/api/chat/%s", chatID), "PUT", promptResponse)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to add prompt response: %s", resp.Status)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode chat initiation response: %s", err)
	}

	return result, nil
}

func (c *NannyClient) GetChat(id string) (map[string]interface{}, error) {
	resp, err := c.DoRequest(fmt.Sprintf("/api/chat/%s", id), "GET", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("No chat record found for chat ID: %s\n", id)
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch chat history: %s", resp.Status)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode chat history: %s", err)
	}

	return result, nil
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

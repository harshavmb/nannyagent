package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const geminiAPIURL = "https://api.gemini.com/v1/flash"

type GeminiResponse struct {
	Commands []string `json:"commands"`
}

func SendRequest(input string) ([]string, error) {
	requestBody, err := json.Marshal(map[string]string{"input": input})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %v", err)
	}

	resp, err := http.Post(geminiAPIURL, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Gemini API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 response: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var geminiResponse GeminiResponse
	if err := json.Unmarshal(body, &geminiResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	return geminiResponse.Commands, nil
}

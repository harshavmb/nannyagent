package api

import (
	"testing"
)

func TestNewGeminiClient(t *testing.T) {
	client, err := NewGeminiClient()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer client.Close()

	if client == nil {
		t.Fatalf("Expected a valid client, got nil")
	}
}

func TestGetGenerativeAIResponse(t *testing.T) {
	client, err := NewGeminiClient()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	defer client.Close()

	input := "Test Input"
	response, err := client.GetGenerativeAIResponse(input)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if len(response) < 1 || response == nil {
		t.Fatalf("Expected a valid response, got empty string")
	}
}

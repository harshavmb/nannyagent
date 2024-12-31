package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// GeminiClient is a wrapper around the Generative AI client
type GeminiClient struct {
	client *genai.Client
}

// NewGeminiClient creates a new GeminiClient
func NewGeminiClient() (*GeminiClient, error) {
	genaiClient, err := genai.NewClient(context.Background(), option.WithAPIKey(os.Getenv("GEMINI_API_TOKEN")))
	if err != nil {
		return nil, fmt.Errorf("failed to create Generative AI client: %v", err)
	}

	return &GeminiClient{
		client: genaiClient,
	}, nil
}

// Close closes the GeminiClient
func (g *GeminiClient) Close() {
	g.client.Close()
}

// GetGenerativeAIResponse sends the input string to the Gemini API and returns the response
func (g *GeminiClient) GetGenerativeAIResponse(input string) ([]string, error) {
	ctx := context.Background()

	model := g.client.GenerativeModel("gemini-1.5-flash")
	model.ResponseMIMEType = "application/json"

	// Specify the schema.
	model.ResponseSchema = &genai.Schema{
		Type:  genai.TypeArray,
		Items: &genai.Schema{Type: genai.TypeString},
	}

	resp, err := model.GenerateContent(ctx, genai.Text(fmt.Sprintf("Run a list investigative Linux commands to diagnose %s on a server. If binaries are from sysstat, collect metrics for 5 seconds every 1 sec interval (only if required by the input prompt)", input)))
	if err != nil {
		return nil, fmt.Errorf("failed to create Generative AI client: %v", err)
	}

	var recipes []string

	for _, part := range resp.Candidates[0].Content.Parts {
		if txt, ok := part.(genai.Text); ok {
			if err := json.Unmarshal([]byte(txt), &recipes); err != nil {
				log.Fatal(err)
			}

		}
	}
	return recipes, nil
}

// FinalGenerativeAIResponse sends the input and output strings to the Gemini API and returns the feedback
func (g *GeminiClient) FinalGenerativeAIResponse(input, output string) (string, error) {

	ctx := context.Background()

	// Access your API key as an environment variable
	genaiClient, err := genai.NewClient(context.Background(), option.WithAPIKey(os.Getenv("GEMINI_API_TOKEN")))
	if err != nil {
		return "", fmt.Errorf("failed to create Generative AI client: %v", err)
	}
	defer genaiClient.Close()

	model := g.client.GenerativeModel("gemini-1.5-flash")
	model.ResponseMIMEType = "application/json"

	resp, err := model.GenerateContent(ctx, genai.Text(fmt.Sprintf("For given input commands %s. Output from the server %s.", input, output)))
	if err != nil {
		return "", fmt.Errorf("failed to create Generative AI client: %v", err)
	}

	var response string

	for _, part := range resp.Candidates[0].Content.Parts {
		if txt, ok := part.(genai.Text); ok {
			response += string(txt)
		}
	}
	return response, nil
}

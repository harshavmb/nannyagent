package realtime

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClient_Start(t *testing.T) {
	// Create a mock SSE server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/realtime" {
			if r.Method == "GET" {
				// Handshake
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")

				// Send clientId
				fmt.Fprintf(w, "data: {\"clientId\": \"test-client-id\"}\n\n")
				w.(http.Flusher).Flush()

				// Wait for subscription (simulated)
				time.Sleep(100 * time.Millisecond)

				// Send an event
				fmt.Fprintf(w, "data: {\"action\": \"create\", \"record\": {\"id\": \"inv-123\", \"user_prompt\": \"test prompt\"}}\n\n")
				w.(http.Flusher).Flush()

				// Keep connection open for a bit
				time.Sleep(1 * time.Second)
				return
			} else if r.Method == "POST" {
				// Subscription
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Channel to signal test completion
	done := make(chan struct{})

	// Handler to verify callback
	handler := func(id, prompt string) {
		if id != "inv-123" {
			t.Errorf("Expected investigation ID 'inv-123', got '%s'", id)
		}
		if prompt != "test prompt" {
			t.Errorf("Expected prompt 'test prompt', got '%s'", prompt)
		}
		close(done)
	}

	client := NewClient(server.URL, "test-token", handler)

	// Run Start in a goroutine
	go client.Start()

	// Wait for handler to be called or timeout
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for investigation handler")
	}
}

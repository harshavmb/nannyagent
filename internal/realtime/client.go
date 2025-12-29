package realtime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"nannyagent/internal/logging"
	"nannyagent/internal/types"
)

type RealtimeMessage struct {
	Action string                 `json:"action"`
	Record map[string]interface{} `json:"record"`
}

// InvestigationHandler is a callback function that processes an investigation request
type InvestigationHandler func(investigationID, prompt string)

// PatchHandler is a callback function that processes a patch operation request
type PatchHandler func(payload types.AgentPatchPayload)

// Client handles the Realtime (SSE) connection to NannyAPI
type Client struct {
	baseURL              string
	accessToken          string
	investigationHandler InvestigationHandler
	patchHandler         PatchHandler
}

// NewClient creates a new Realtime client
func NewClient(baseURL, accessToken string, investigationHandler InvestigationHandler, patchHandler PatchHandler) *Client {
	return &Client{
		baseURL:              baseURL,
		accessToken:          accessToken,
		investigationHandler: investigationHandler,
		patchHandler:         patchHandler,
	}
}

// Start begins the SSE connection loop. It blocks until the connection is permanently closed (which shouldn't happen).
func (c *Client) Start() {
	defer func() {
		if r := recover(); r != nil {
			logging.Error("SSE connection panicked: %v", r)
		}
	}()

	// Retry loop for SSE connection
	for {
		// IMPORTANT: SSE requires a client that doesn't buffer and doesn't timeout
		customClient := &http.Client{
			Transport: &http.Transport{
				DisableCompression: true, // Crucial for SSE
			},
			Timeout: 0, // No timeout for long-lived connections
		}

		logging.Debug("Connecting to SSE at %s/api/realtime...", c.baseURL)
		resp, err := customClient.Get(c.baseURL + "/api/realtime")
		if err != nil {
			logging.Warning("Connection error: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		reader := bufio.NewReader(resp.Body)

		// Read the first event to get the clientId
		var clientId string
		connectSuccess := false

		// Read loop for handshake
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				logging.Warning("Error reading from stream during handshake: %v", err)
				break
			}

			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				data := strings.TrimPrefix(line, "data:")
				var connectEvent struct {
					ClientId string `json:"clientId"`
				}
				if err := json.Unmarshal([]byte(data), &connectEvent); err == nil && connectEvent.ClientId != "" {
					clientId = connectEvent.ClientId
					connectSuccess = true
					break
				}
			}
		}

		if !connectSuccess {
			_ = resp.Body.Close()
			logging.Debug("Failed to get Client ID, retrying in 5s...")
			time.Sleep(5 * time.Second)
			continue
		}

		logging.Debug("Connected! Client ID: %s", clientId)

		// --- STEP 2: Authorize & Subscribe ---
		// This is where you tell PB: "I am this Agent, listen to 'investigations' and 'patch_operations'"
		subData, _ := json.Marshal(map[string]interface{}{
			"clientId":      clientId,
			"subscriptions": []string{"investigations", "patch_operations"},
		})

		req, _ := http.NewRequest("POST", c.baseURL+"/api/realtime", bytes.NewBuffer(subData))
		req.Header.Set("Authorization", "Bearer "+c.accessToken)
		req.Header.Set("Content-Type", "application/json")

		subResp, err := http.DefaultClient.Do(req)
		if err != nil || subResp.StatusCode != 204 {
			logging.Warning("Subscription failed: %v", err)
			_ = resp.Body.Close()
			time.Sleep(5 * time.Second)
			continue
		}
		logging.Debug("Subscribed to 'investigations' and 'patch_operations' successfully.")

		// --- STEP 3: Listen for Records ---
		logging.Debug("Waiting for events...")
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				logging.Debug("Connection lost: %v", err)
				break
			}

			line = strings.TrimSpace(line)

			// Debug: Log everything so we can see the 'event:' lines too
			if line != "" {
				logging.Debug("Received: %s", line)
			}

			// We only care about the data: line
			if strings.HasPrefix(line, "data:") {
				msgJSON := strings.TrimPrefix(line, "data:")

				// Ignore the initial connect message if it repeats
				if strings.Contains(msgJSON, "clientId") {
					continue
				}

				var msg RealtimeMessage
				if err := json.Unmarshal([]byte(msgJSON), &msg); err == nil {
					// Check if this is a patch operation
					if msg.Action == "create" {
						// Try to parse as patch operation first
						if operationID, ok := msg.Record["id"].(string); ok {
							if mode, okMode := msg.Record["mode"].(string); okMode {
								if scriptID, okScript := msg.Record["script_id"].(string); okScript {
									if scriptURL, okURL := msg.Record["script_url"].(string); okURL {
										// This is a patch operation
										payload := types.AgentPatchPayload{
											OperationID: operationID,
											Mode:        mode,
											ScriptURL:   scriptURL,
											ScriptID:    scriptID,
											Timestamp:   time.Now().Format(time.RFC3339),
										}

										// Optional script args
										if args, okArgs := msg.Record["script_args"].(string); okArgs {
											payload.ScriptArgs = args
										}

										// Optional LXC ID
										if lxcID, okLXC := msg.Record["lxc_id"].(string); okLXC {
											payload.LXCID = lxcID
										}

										// Optional VMID
										if vmid, okVMID := msg.Record["vmid"].(string); okVMID {
											payload.VMID = vmid
										} else if vmidFloat, okVMIDFloat := msg.Record["vmid"].(float64); okVMIDFloat {
											payload.VMID = fmt.Sprintf("%d", int(vmidFloat))
										}

										logging.Info("Received patch operation: %s (mode: %s)", operationID, mode)

										if c.patchHandler != nil {
											go c.patchHandler(payload)
										}
										continue
									}
								}
							}
						}
					}

					// Otherwise try to parse as investigation
					prompt := "N/A"
					if p, ok := msg.Record["user_prompt"]; ok {
						prompt = fmt.Sprintf("%v", p)
					}

					investigationID := ""
					if id, ok := msg.Record["id"]; ok {
						investigationID = fmt.Sprintf("%v", id)
					}

					// Trigger investigation if it's a create action and we have necessary data
					if msg.Action == "create" && prompt != "N/A" && investigationID != "" {
						logging.Info("Triggering investigation %s...", investigationID)

						// Call the handler
						if c.investigationHandler != nil {
							go c.investigationHandler(investigationID, prompt)
						}
					}
				} else {
					logging.Error("JSON Error: %v", err)
				}
			}
		}

		// Close body and wait before reconnecting
		_ = resp.Body.Close()
		logging.Debug("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}

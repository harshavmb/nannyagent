package types

import (
	"time"

	"nannyagentv2/internal/ebpf"

	"github.com/sashabaranov/go-openai"
)

// SystemMetrics represents comprehensive system performance metrics
type SystemMetrics struct {
	// System Information
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	PlatformFamily  string `json:"platform_family"`
	PlatformVersion string `json:"platform_version"`
	KernelVersion   string `json:"kernel_version"`
	KernelArch      string `json:"kernel_arch"`

	// CPU Metrics
	CPUUsage float64 `json:"cpu_usage"`
	CPUCores int     `json:"cpu_cores"`
	CPUModel string  `json:"cpu_model"`

	// Memory Metrics
	MemoryUsage     float64 `json:"memory_usage"`
	MemoryTotal     uint64  `json:"memory_total"`
	MemoryUsed      uint64  `json:"memory_used"`
	MemoryFree      uint64  `json:"memory_free"`
	MemoryAvailable uint64  `json:"memory_available"`
	SwapTotal       uint64  `json:"swap_total"`
	SwapUsed        uint64  `json:"swap_used"`
	SwapFree        uint64  `json:"swap_free"`

	// Disk Metrics
	DiskUsage float64 `json:"disk_usage"`
	DiskTotal uint64  `json:"disk_total"`
	DiskUsed  uint64  `json:"disk_used"`
	DiskFree  uint64  `json:"disk_free"`

	// Network Metrics
	NetworkInKbps   float64 `json:"network_in_kbps"`
	NetworkOutKbps  float64 `json:"network_out_kbps"`
	NetworkInBytes  uint64  `json:"network_in_bytes"`
	NetworkOutBytes uint64  `json:"network_out_bytes"`

	// System Load
	LoadAvg1  float64 `json:"load_avg_1"`
	LoadAvg5  float64 `json:"load_avg_5"`
	LoadAvg15 float64 `json:"load_avg_15"`

	// Process Information
	ProcessCount int `json:"process_count"`

	// Network Information
	IPAddress string `json:"ip_address"`
	Location  string `json:"location"`

	// Filesystem Information
	FilesystemInfo []FilesystemInfo `json:"filesystem_info"`
	BlockDevices   []BlockDevice    `json:"block_devices"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`
}

// FilesystemInfo represents filesystem information
type FilesystemInfo struct {
	Device       string  `json:"device"`
	Mountpoint   string  `json:"mountpoint"`
	Type         string  `json:"type"`
	Fstype       string  `json:"fstype"`
	Total        uint64  `json:"total"`
	Used         uint64  `json:"used"`
	Free         uint64  `json:"free"`
	Usage        float64 `json:"usage"`
	UsagePercent float64 `json:"usage_percent"`
}

// BlockDevice represents a block device
type BlockDevice struct {
	Name         string `json:"name"`
	Size         uint64 `json:"size"`
	Type         string `json:"type"`
	Model        string `json:"model,omitempty"`
	SerialNumber string `json:"serial_number"`
}

// NetworkStats represents network interface statistics
type NetworkStats struct {
	Interface   string `json:"interface"`
	BytesRecv   uint64 `json:"bytes_recv"`
	BytesSent   uint64 `json:"bytes_sent"`
	PacketsRecv uint64 `json:"packets_recv"`
	PacketsSent uint64 `json:"packets_sent"`
	ErrorsIn    uint64 `json:"errors_in"`
	ErrorsOut   uint64 `json:"errors_out"`
	DropsIn     uint64 `json:"drops_in"`
	DropsOut    uint64 `json:"drops_out"`
}

// AuthToken represents an authentication token
type AuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
	AgentID      string    `json:"agent_id"`
}

// DeviceAuthRequest represents the device authorization request
type DeviceAuthRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// DeviceAuthResponse represents the device authorization response
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// TokenRequest represents the token request for device flow
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	DeviceCode   string `json:"device_code,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
}

// TokenResponse represents the token response
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	AgentID          string `json:"agent_id,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// HeartbeatRequest represents the agent heartbeat request
type HeartbeatRequest struct {
	AgentID string        `json:"agent_id"`
	Status  string        `json:"status"`
	Metrics SystemMetrics `json:"metrics"`
}

// MetricsRequest represents the flattened metrics payload expected by agent-auth-api
type MetricsRequest struct {
	// Agent identification
	AgentID string `json:"agent_id"`

	// Basic metrics
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`

	// Network metrics
	NetworkInKbps  float64 `json:"network_in_kbps"`
	NetworkOutKbps float64 `json:"network_out_kbps"`

	// System information
	Hostname          string `json:"hostname"`
	IPAddress         string `json:"ip_address"`
	Location          string `json:"location"`
	AgentVersion      string `json:"agent_version"`
	KernelVersion     string `json:"kernel_version"`
	DeviceFingerprint string `json:"device_fingerprint"`

	// Structured data (JSON fields in database)
	LoadAverages   map[string]float64 `json:"load_averages"`
	OSInfo         map[string]string  `json:"os_info"`
	FilesystemInfo []FilesystemInfo   `json:"filesystem_info"`
	BlockDevices   []BlockDevice      `json:"block_devices"`
	NetworkStats   map[string]uint64  `json:"network_stats"`
}

// Agent types for TensorZero integration
type DiagnosticResponse struct {
	ResponseType string    `json:"response_type"`
	Reasoning    string    `json:"reasoning"`
	Commands     []Command `json:"commands"`
}

// ResolutionResponse represents a resolution response
type ResolutionResponse struct {
	ResponseType   string `json:"response_type"`
	RootCause      string `json:"root_cause"`
	ResolutionPlan string `json:"resolution_plan"`
	Confidence     string `json:"confidence"`
}

// Command represents a command to execute
type Command struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

// CommandResult represents the result of an executed command
type CommandResult struct {
	ID          string `json:"id"`
	Command     string `json:"command"`
	Description string `json:"description"`
	Output      string `json:"output"`
	ExitCode    int    `json:"exit_code"`
	Error       string `json:"error,omitempty"`
}

// EBPFRequest represents an eBPF trace request from external API
type EBPFRequest struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`              // "tracepoint", "kprobe", "kretprobe", "bpftrace"
	Target      string                 `json:"target"`            // tracepoint path, function name, or full bpftrace script
	Duration    int                    `json:"duration"`          // seconds
	Filters     map[string]interface{} `json:"filters,omitempty"` // Changed to interface{} for flexibility
	Description string                 `json:"description"`
}

// EBPFEnhancedDiagnosticResponse represents enhanced diagnostic response with eBPF
type EBPFEnhancedDiagnosticResponse struct {
	ResponseType string        `json:"response_type"`
	Reasoning    string        `json:"reasoning"`
	Commands     []string      `json:"commands"` // Changed to []string to match current prompt format
	EBPFPrograms []EBPFRequest `json:"ebpf_programs"`
	NextActions  []string      `json:"next_actions,omitempty"`
}

// TensorZeroRequest represents a request to TensorZero
type TensorZeroRequest struct {
	Model     string                   `json:"model"`
	Messages  []map[string]interface{} `json:"messages"`
	EpisodeID string                   `json:"tensorzero::episode_id,omitempty"`
}

// TensorZeroResponse represents a response from TensorZero
type TensorZeroResponse struct {
	Choices   []map[string]interface{} `json:"choices"`
	EpisodeID string                   `json:"episode_id"`
}

// SystemInfo represents system information (for compatibility)
type SystemInfo struct {
	Hostname      string              `json:"hostname"`
	Platform      string              `json:"platform"`
	PlatformInfo  map[string]string   `json:"platform_info"`
	KernelVersion string              `json:"kernel_version"`
	Uptime        string              `json:"uptime"`
	LoadAverage   []float64           `json:"load_average"`
	CPUInfo       map[string]string   `json:"cpu_info"`
	MemoryInfo    map[string]string   `json:"memory_info"`
	DiskInfo      []map[string]string `json:"disk_info"`
}

// AgentConfig represents agent configuration
type AgentConfig struct {
	TensorZeroAPIKey string `json:"tensorzero_api_key"`
	APIURL           string `json:"api_url"`
	Timeout          int    `json:"timeout"`
	Debug            bool   `json:"debug"`
	MaxRetries       int    `json:"max_retries"`
	BackoffFactor    int    `json:"backoff_factor"`
	EpisodeID        string `json:"episode_id,omitempty"`
}

// PendingInvestigation represents a pending investigation from the database
type PendingInvestigation struct {
	ID                string                 `json:"id"`
	InvestigationID   string                 `json:"investigation_id"`
	AgentID           string                 `json:"agent_id"`
	DiagnosticPayload map[string]interface{} `json:"diagnostic_payload"`
	EpisodeID         *string                `json:"episode_id"`
	Status            string                 `json:"status"`
	CreatedAt         time.Time              `json:"created_at"`
}

// PatchTask represents a patch management task
type PatchTask struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// PatchExecution represents a patch execution task from the database
type PatchExecution struct {
	ID            string    `json:"id"`
	AgentID       string    `json:"agent_id"`
	ScriptID      *string   `json:"script_id"`
	ExecutionType string    `json:"execution_type"` // Allowed values: "dry_run", "apply". If a reboot is required after applying, set ShouldReboot to true.
	Status        string    `json:"status"`         // pending, executing, completed, failed
	Command       string    `json:"command"`
	ShouldReboot  bool      `json:"should_reboot"`  // Indicates if a reboot should be performed after execution. Used in conjunction with ExecutionType="apply".
	CreatedAt     time.Time `json:"created_at"`
}

// DiagnosticAgent interface for agent functionality needed by other packages
type DiagnosticAgent interface {
	DiagnoseIssue(issue string) error
	// Exported method names to match what websocket client calls
	ConvertEBPFProgramsToTraceSpecs(ebpfRequests []EBPFRequest) []ebpf.TraceSpec
	ExecuteEBPFTraces(traceSpecs []ebpf.TraceSpec) []map[string]interface{}
	SendRequestWithEpisode(messages []openai.ChatCompletionMessage, episodeID string) (*openai.ChatCompletionResponse, error)
	SendRequest(messages []openai.ChatCompletionMessage) (*openai.ChatCompletionResponse, error)
	ExecuteCommand(cmd Command) CommandResult
}

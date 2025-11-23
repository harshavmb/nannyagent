package ebpf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TestTraceSpecs provides test trace specifications for unit testing the BCC-style tracing
// These are used to validate the tracing functionality without requiring remote API calls
var TestTraceSpecs = map[string]TraceSpec{
	// Basic system call tracing for testing
	"test_sys_open": {
		ProbeType: "p",
		Target:    "__x64_sys_openat",
		Format:    "opening file: %s",
		Arguments: []string{"arg2@user"}, // filename
		Duration:  5,                     // Short duration for testing
	},

	"test_sys_read": {
		ProbeType: "p",
		Target:    "__x64_sys_read",
		Format:    "read %d bytes from fd %d",
		Arguments: []string{"arg3", "arg1"}, // count, fd
		Filter:    "arg3 > 100",             // Only reads >100 bytes for testing
		Duration:  5,
	},

	"test_sys_write": {
		ProbeType: "p",
		Target:    "__x64_sys_write",
		Format:    "write %d bytes to fd %d",
		Arguments: []string{"arg3", "arg1"}, // count, fd
		Duration:  5,
	},

	"test_process_creation": {
		ProbeType: "p",
		Target:    "__x64_sys_execve",
		Format:    "exec: %s",
		Arguments: []string{"arg1@user"}, // filename
		Duration:  5,
	},

	// Test with different probe types
	"test_kretprobe": {
		ProbeType: "r",
		Target:    "__x64_sys_openat",
		Format:    "open returned: %d",
		Arguments: []string{"retval"},
		Duration:  5,
	},

	"test_with_filter": {
		ProbeType: "p",
		Target:    "__x64_sys_write",
		Format:    "stdout write: %d bytes",
		Arguments: []string{"arg3"},
		Filter:    "arg1 == 1", // Only stdout writes
		Duration:  5,
	},
}

// GetTestSpec returns a pre-defined test trace specification
func GetTestSpec(name string) (TraceSpec, bool) {
	spec, exists := TestTraceSpecs[name]
	return spec, exists
}

// ListTestSpecs returns all available test trace specifications
func ListTestSpecs() map[string]string {
	descriptions := map[string]string{
		"test_sys_open":         "Test file open operations",
		"test_sys_read":         "Test read operations (>100 bytes)",
		"test_sys_write":        "Test write operations",
		"test_process_creation": "Test process execution",
		"test_kretprobe":        "Test kretprobe on file open",
		"test_with_filter":      "Test filtered writes to stdout",
	}

	return descriptions
}

// TraceSpecBuilder helps build custom trace specifications
type TraceSpecBuilder struct {
	spec TraceSpec
}

// NewTraceSpecBuilder creates a new trace specification builder
func NewTraceSpecBuilder() *TraceSpecBuilder {
	return &TraceSpecBuilder{
		spec: TraceSpec{
			ProbeType: "p", // Default to kprobe
			Duration:  30,  // Default 30 seconds
		},
	}
}

// Kprobe sets up a kernel probe
func (b *TraceSpecBuilder) Kprobe(function string) *TraceSpecBuilder {
	b.spec.ProbeType = "p"
	b.spec.Target = function
	return b
}

// Kretprobe sets up a kernel return probe
func (b *TraceSpecBuilder) Kretprobe(function string) *TraceSpecBuilder {
	b.spec.ProbeType = "r"
	b.spec.Target = function
	return b
}

// Tracepoint sets up a tracepoint
func (b *TraceSpecBuilder) Tracepoint(category, name string) *TraceSpecBuilder {
	b.spec.ProbeType = "t"
	b.spec.Target = fmt.Sprintf("%s:%s", category, name)
	return b
}

// Uprobe sets up a userspace probe
func (b *TraceSpecBuilder) Uprobe(library, function string) *TraceSpecBuilder {
	b.spec.ProbeType = "u"
	b.spec.Library = library
	b.spec.Target = function
	return b
}

// Format sets the output format string
func (b *TraceSpecBuilder) Format(format string, args ...string) *TraceSpecBuilder {
	b.spec.Format = format
	b.spec.Arguments = args
	return b
}

// Filter adds a filter condition
func (b *TraceSpecBuilder) Filter(condition string) *TraceSpecBuilder {
	b.spec.Filter = condition
	return b
}

// Duration sets the trace duration in seconds
func (b *TraceSpecBuilder) Duration(seconds int) *TraceSpecBuilder {
	b.spec.Duration = seconds
	return b
}

// PID filters by process ID
func (b *TraceSpecBuilder) PID(pid int) *TraceSpecBuilder {
	b.spec.PID = pid
	return b
}

// UID filters by user ID
func (b *TraceSpecBuilder) UID(uid int) *TraceSpecBuilder {
	b.spec.UID = uid
	return b
}

// ProcessName filters by process name
func (b *TraceSpecBuilder) ProcessName(name string) *TraceSpecBuilder {
	b.spec.ProcessName = name
	return b
}

// Build returns the constructed trace specification
func (b *TraceSpecBuilder) Build() TraceSpec {
	return b.spec
}

// TraceSpecParser parses trace specifications from various formats
type TraceSpecParser struct{}

// NewTraceSpecParser creates a new parser
func NewTraceSpecParser() *TraceSpecParser {
	return &TraceSpecParser{}
}

// ParseFromBCCStyle parses BCC trace.py style specifications
// Examples:
//
//	"sys_open" -> trace sys_open syscall
//	"p::do_sys_open" -> kprobe on do_sys_open
//	"r::do_sys_open" -> kretprobe on do_sys_open
//	"t:syscalls:sys_enter_open" -> tracepoint
//	"sys_read (arg3 > 1024)" -> with filter
//	"sys_read \"read %d bytes\", arg3" -> with format
func (p *TraceSpecParser) ParseFromBCCStyle(spec string) (TraceSpec, error) {
	result := TraceSpec{
		ProbeType: "p",
		Duration:  30,
	}

	// Split by quotes to separate format string
	parts := strings.Split(spec, "\"")

	var probeSpec string
	if len(parts) >= 1 {
		probeSpec = strings.TrimSpace(parts[0])
	}

	var formatPart string
	if len(parts) >= 2 {
		formatPart = parts[1]
	}

	var argsPart string
	if len(parts) >= 3 {
		argsPart = strings.TrimSpace(parts[2])
		if strings.HasPrefix(argsPart, ",") {
			argsPart = strings.TrimSpace(argsPart[1:])
		}
	}

	// Parse probe specification
	if err := p.parseProbeSpec(probeSpec, &result); err != nil {
		return result, err
	}

	// Parse format string
	if formatPart != "" {
		result.Format = formatPart
	}

	// Parse arguments
	if argsPart != "" {
		result.Arguments = p.parseArguments(argsPart)
	}

	return result, nil
}

// parseProbeSpec parses the probe specification part
func (p *TraceSpecParser) parseProbeSpec(spec string, result *TraceSpec) error {
	// Handle filter conditions in parentheses
	if idx := strings.Index(spec, "("); idx != -1 {
		filterEnd := strings.LastIndex(spec, ")")
		if filterEnd > idx {
			result.Filter = strings.TrimSpace(spec[idx+1 : filterEnd])
			spec = strings.TrimSpace(spec[:idx])
		}
	}

	// Parse probe type and target
	if strings.Contains(spec, ":") {
		parts := strings.SplitN(spec, ":", 3)

		if len(parts) >= 1 && parts[0] != "" {
			switch parts[0] {
			case "p":
				result.ProbeType = "p"
			case "r":
				result.ProbeType = "r"
			case "t":
				result.ProbeType = "t"
			case "u":
				result.ProbeType = "u"
			default:
				return fmt.Errorf("unsupported probe type: %s", parts[0])
			}
		}

		if len(parts) >= 2 {
			result.Library = parts[1]
		}

		if len(parts) >= 3 {
			result.Target = parts[2]
		} else if len(parts) == 2 {
			result.Target = parts[1]
			result.Library = ""
		}
	} else {
		// Simple function name
		result.Target = spec

		// Auto-detect syscall format
		if strings.HasPrefix(spec, "sys_") && !strings.HasPrefix(spec, "__x64_sys_") {
			result.Target = "__x64_sys_" + spec[4:]
		}
	}

	return nil
}

// parseArguments parses the arguments part
func (p *TraceSpecParser) parseArguments(args string) []string {
	var result []string

	// Split by comma and clean up
	parts := strings.Split(args, ",")
	for _, part := range parts {
		arg := strings.TrimSpace(part)
		if arg != "" {
			result = append(result, arg)
		}
	}

	return result
}

// ParseFromJSON parses trace specification from JSON
func (p *TraceSpecParser) ParseFromJSON(jsonData []byte) (TraceSpec, error) {
	var spec TraceSpec
	err := json.Unmarshal(jsonData, &spec)
	return spec, err
}

// GetCommonSpec returns a pre-defined test trace specification (renamed for backward compatibility)
func GetCommonSpec(name string) (TraceSpec, bool) {
	// Map old names to new test names for compatibility
	testName := name
	if strings.HasPrefix(name, "trace_") {
		testName = strings.Replace(name, "trace_", "test_", 1)
	}

	spec, exists := TestTraceSpecs[testName]
	return spec, exists
}

// ListCommonSpecs returns all available test trace specifications (renamed for backward compatibility)
func ListCommonSpecs() map[string]string {
	return ListTestSpecs()
}

// ValidateTraceSpec validates a trace specification
func ValidateTraceSpec(spec TraceSpec) error {
	if spec.Target == "" {
		return fmt.Errorf("target function/syscall is required")
	}

	if spec.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}

	if spec.Duration > 600 { // 10 minutes max
		return fmt.Errorf("duration too long (max 600 seconds)")
	}

	switch spec.ProbeType {
	case "p", "r", "t", "u":
		// Valid probe types
	case "":
		// Default to kprobe
	default:
		return fmt.Errorf("unsupported probe type: %s", spec.ProbeType)
	}

	if spec.ProbeType == "u" && spec.Library == "" {
		return fmt.Errorf("library required for userspace probes")
	}

	if spec.ProbeType == "t" && !strings.Contains(spec.Target, ":") {
		return fmt.Errorf("tracepoint requires format 'category:name'")
	}

	return nil
}

// SuggestSyscallTargets suggests syscall targets based on the issue description
func SuggestSyscallTargets(issueDescription string) []string {
	description := strings.ToLower(issueDescription)
	var suggestions []string

	// File I/O issues
	if strings.Contains(description, "file") || strings.Contains(description, "disk") || strings.Contains(description, "io") {
		suggestions = append(suggestions, "trace_sys_open", "trace_sys_read", "trace_sys_write", "trace_sys_unlink")
	}

	// Network issues
	if strings.Contains(description, "network") || strings.Contains(description, "socket") || strings.Contains(description, "connection") {
		suggestions = append(suggestions, "trace_sys_connect", "trace_sys_socket", "trace_sys_bind", "trace_sys_accept")
	}

	// Process issues
	if strings.Contains(description, "process") || strings.Contains(description, "crash") || strings.Contains(description, "exec") {
		suggestions = append(suggestions, "trace_sys_execve", "trace_sys_clone", "trace_sys_exit", "trace_sys_kill")
	}

	// Memory issues
	if strings.Contains(description, "memory") || strings.Contains(description, "malloc") || strings.Contains(description, "leak") {
		suggestions = append(suggestions, "trace_sys_mmap", "trace_sys_brk")
	}

	// Performance issues - trace common syscalls
	if strings.Contains(description, "slow") || strings.Contains(description, "performance") || strings.Contains(description, "hang") {
		suggestions = append(suggestions, "trace_sys_read", "trace_sys_write", "trace_sys_connect", "trace_sys_mmap")
	}

	// If no specific suggestions, provide general monitoring
	if len(suggestions) == 0 {
		suggestions = append(suggestions, "trace_sys_execve", "trace_sys_open", "trace_sys_connect")
	}

	return suggestions
}

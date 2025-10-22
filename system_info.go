package main

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
)

// SystemInfo represents basic system information
type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Kernel       string `json:"kernel"`
	Architecture string `json:"architecture"`
	CPUCores     string `json:"cpu_cores"`
	Memory       string `json:"memory"`
	Uptime       string `json:"uptime"`
	PrivateIPs   string `json:"private_ips"`
	LoadAverage  string `json:"load_average"`
	DiskUsage    string `json:"disk_usage"`
}

// GatherSystemInfo collects basic system information
func GatherSystemInfo() *SystemInfo {
	info := &SystemInfo{}
	executor := NewCommandExecutor(5 * time.Second)

	// Basic system info
	if result := executor.Execute(Command{ID: "hostname", Command: "hostname"}); result.ExitCode == 0 {
		info.Hostname = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "os", Command: "lsb_release -d 2>/dev/null | cut -f2 || cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'"}); result.ExitCode == 0 {
		info.OS = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "kernel", Command: "uname -r"}); result.ExitCode == 0 {
		info.Kernel = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "arch", Command: "uname -m"}); result.ExitCode == 0 {
		info.Architecture = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "cores", Command: "nproc"}); result.ExitCode == 0 {
		info.CPUCores = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "memory", Command: "free -h | grep Mem | awk '{print $2}'"}); result.ExitCode == 0 {
		info.Memory = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "uptime", Command: "uptime -p"}); result.ExitCode == 0 {
		info.Uptime = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "load", Command: "uptime | awk -F'load average:' '{print $2}' | xargs"}); result.ExitCode == 0 {
		info.LoadAverage = strings.TrimSpace(result.Output)
	}

	if result := executor.Execute(Command{ID: "disk", Command: "df -h / | tail -1 | awk '{print \"Root: \" $3 \"/\" $2 \" (\" $5 \" used)\"}'"}); result.ExitCode == 0 {
		info.DiskUsage = strings.TrimSpace(result.Output)
	}

	// Get private IP addresses
	info.PrivateIPs = getPrivateIPs()

	return info
}

// getPrivateIPs returns private IP addresses
func getPrivateIPs() string {
	var privateIPs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return "Unable to determine"
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if isPrivateIP(ipnet.IP) {
					privateIPs = append(privateIPs, fmt.Sprintf("%s (%s)", ipnet.IP.String(), iface.Name))
				}
			}
		}
	}

	if len(privateIPs) == 0 {
		return "No private IPs found"
	}

	return strings.Join(privateIPs, ", ")
}

// isPrivateIP checks if an IP address is private
func isPrivateIP(ip net.IP) bool {
	// RFC 1918 private address ranges
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}

	for _, cidr := range private {
		_, subnet, _ := net.ParseCIDR(cidr)
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

// FormatSystemInfoForPrompt formats system information for inclusion in diagnostic prompts
func FormatSystemInfoForPrompt(info *SystemInfo) string {
	return fmt.Sprintf(`SYSTEM INFORMATION:
- Hostname: %s
- Operating System: %s
- Kernel Version: %s
- Architecture: %s
- CPU Cores: %s
- Total Memory: %s
- System Uptime: %s
- Current Load Average: %s
- Root Disk Usage: %s
- Private IP Addresses: %s
- Go Runtime: %s

ISSUE DESCRIPTION:`,
		info.Hostname,
		info.OS,
		info.Kernel,
		info.Architecture,
		info.CPUCores,
		info.Memory,
		info.Uptime,
		info.LoadAverage,
		info.DiskUsage,
		info.PrivateIPs,
		runtime.Version())
}

// FormatSystemInfoWithEBPFForPrompt formats system information including eBPF capabilities
func FormatSystemInfoWithEBPFForPrompt(info *SystemInfo, ebpfManager EBPFManagerInterface) string {
	baseInfo := FormatSystemInfoForPrompt(info)

	if ebpfManager == nil {
		return baseInfo + "\neBPF CAPABILITIES: Not available\n"
	}

	capabilities := ebpfManager.GetCapabilities()
	summary := ebpfManager.GetSummary()

	ebpfInfo := fmt.Sprintf(`
eBPF MONITORING CAPABILITIES:
- System Call Tracing: %v
- Network Activity Tracing: %v
- Process Monitoring: %v
- File System Monitoring: %v
- Performance Monitoring: %v
- Security Event Monitoring: %v

eBPF INTEGRATION GUIDE:
To request eBPF monitoring during diagnosis, include these fields in your JSON response:
{
  "response_type": "diagnostic",
  "reasoning": "explanation of why eBPF monitoring is needed",
  "commands": [regular diagnostic commands],
  "ebpf_capabilities": ["syscall_trace", "network_trace", "process_trace"],
  "ebpf_duration_seconds": 15,
  "ebpf_filters": {"pid": "process_id", "comm": "process_name", "path": "/specific/path"}
}

Available eBPF capabilities: %v
eBPF Status: %v

`,
		capabilities["tracepoint"],
		capabilities["kprobe"],
		capabilities["kernel_support"],
		capabilities["tracepoint"],
		capabilities["kernel_support"],
		capabilities["bpftrace_available"],
		capabilities,
		summary)

	return baseInfo + ebpfInfo
}

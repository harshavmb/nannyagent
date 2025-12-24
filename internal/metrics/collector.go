package metrics

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"

	"nannyagentv2/internal/logging"
	"nannyagentv2/internal/types"
)

// Collector handles system metrics collection
type Collector struct {
	agentVersion string
	apiBaseURL   string
	client       *http.Client
}

// NewCollector creates a new metrics collector
func NewCollector(agentVersion string, apiBaseURL string) *Collector {
	return &Collector{
		agentVersion: agentVersion,
		apiBaseURL:   apiBaseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GatherSystemMetrics collects comprehensive system metrics
func (c *Collector) GatherSystemMetrics() (*types.SystemMetrics, error) {
	metrics := &types.SystemMetrics{
		Timestamp: time.Now(),
		OSType:    runtime.GOOS,
	}

	// System Information
	if hostInfo, err := host.Info(); err == nil {
		metrics.Hostname = hostInfo.Hostname
		metrics.Platform = hostInfo.Platform
		metrics.PlatformFamily = hostInfo.PlatformFamily
		metrics.PlatformVersion = hostInfo.PlatformVersion
		metrics.KernelVersion = hostInfo.KernelVersion
		metrics.KernelArch = hostInfo.KernelArch
		if hostInfo.OS != "" {
			metrics.OSType = hostInfo.OS
		}
	}

	// CPU Metrics
	if percentages, err := cpu.Percent(time.Second, false); err == nil && len(percentages) > 0 {
		metrics.CPUUsage = math.Round(percentages[0]*100) / 100
	}

	if cpuInfo, err := cpu.Info(); err == nil && len(cpuInfo) > 0 {
		metrics.CPUCores = len(cpuInfo)
		metrics.CPUModel = cpuInfo[0].ModelName
	}

	// Memory Metrics
	if memInfo, err := mem.VirtualMemory(); err == nil {
		metrics.MemoryUsage = math.Round(float64(memInfo.Used)/(1024*1024)*100) / 100 // MB
		metrics.MemoryTotal = c.safeCastUint64Value(memInfo.Total)
		metrics.MemoryUsed = c.safeCastUint64Value(memInfo.Used)
		metrics.MemoryFree = c.safeCastUint64Value(memInfo.Free)
		metrics.MemoryAvailable = c.safeCastUint64Value(memInfo.Available)
	}

	if swapInfo, err := mem.SwapMemory(); err == nil {
		metrics.SwapTotal = c.safeCastUint64Value(swapInfo.Total)
		metrics.SwapUsed = c.safeCastUint64Value(swapInfo.Used)
		metrics.SwapFree = c.safeCastUint64Value(swapInfo.Free)
	}

	// Disk Metrics
	if diskInfo, err := disk.Usage("/"); err == nil {
		metrics.DiskUsage = math.Round(diskInfo.UsedPercent*100) / 100
		metrics.DiskTotal = c.safeCastUint64Value(diskInfo.Total)
		metrics.DiskUsed = c.safeCastUint64Value(diskInfo.Used)
		metrics.DiskFree = c.safeCastUint64Value(diskInfo.Free)
	}

	// Load Averages
	if loadAvg, err := LoadAvgParse(); err == nil {
		metrics.LoadAvg1 = loadAvg.LoadAverage1
		metrics.LoadAvg5 = loadAvg.LoadAverage5
		metrics.LoadAvg15 = loadAvg.LoadAverage10
	}

	// Process Count (simplified - using a constant for now)
	// Note: gopsutil doesn't have host.Processes(), would need process.Processes()
	metrics.ProcessCount = 0 // Placeholder

	// Network Metrics - convert cumulative bytes to Mbps (rounded to reasonable values)
	totalRxGB, totalTxGB, err := c.getNetworkStatsGbps()
	if err != nil {
		return nil, err
	}

	if totalRxGB > 0.0 && totalTxGB > 0.0 {
		metrics.NetworkInGb = math.Round(totalRxGB*100) / 100
		metrics.NetworkOutGb = math.Round(totalTxGB*100) / 100
	} else {
		metrics.NetworkInGb = 0.0
		metrics.NetworkOutGb = 0.0
	}

	// IP Address and Location
	metrics.IPAddress = c.getIPAddress()
	metrics.AllIPs = c.getAllIPs()
	metrics.Location = c.getLocation() // Placeholder

	// Filesystem Information
	metrics.FilesystemInfo = c.getFilesystemInfo()

	// Block Devices
	metrics.BlockDevices = c.getBlockDevices()

	return metrics, nil
}

// getNetworkStatsMbps returns network rates in Mbps (safe values that won't overflow)
// Since we don't track deltas over time, we return 0 to avoid massive cumulative values
func (c *Collector) getNetworkStatsGbps() (totalRxGB, totalTxGB float64, err error) {
	// Get aggregate stats for ALL interfaces
	stats, err := net.IOCounters(false) // false = sum of all interfaces
	if err != nil {
		return 0, 0, err
	}

	if len(stats) == 0 {
		return 0, 0, fmt.Errorf("no network interfaces found")
	}

	// Convert bytes to gigabytes (1 GB = 1024³ bytes)
	totalRxGB = float64(stats[0].BytesRecv) / (1024 * 1024 * 1024)
	totalTxGB = float64(stats[0].BytesSent) / (1024 * 1024 * 1024)

	return totalRxGB, totalTxGB, nil
}

// getIPAddress returns the primary IP address of the system
func (c *Collector) getIPAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}

	for _, iface := range interfaces {
		if len(iface.Addrs) > 0 && !strings.Contains(iface.Addrs[0].Addr, "127.0.0.1") {
			return strings.Split(iface.Addrs[0].Addr, "/")[0] // Remove CIDR if present
		}
	}

	return "unknown"
}

// getLocation returns basic location information (placeholder)
func (c *Collector) getLocation() string {
	return "unknown" // Would integrate with GeoIP service
}

// getFilesystemInfo returns information about mounted filesystems
// Only includes important persistent filesystems (whitelist approach)
func (c *Collector) getFilesystemInfo() []types.FilesystemInfo {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return []types.FilesystemInfo{}
	}

	// Whitelist of important filesystem types
	allowedFsTypes := map[string]bool{
		"ext2":  true,
		"ext3":  true,
		"ext4":  true,
		"xfs":   true,
		"btrfs": true,
		"zfs":   true,
		"ntfs":  true,
		"vfat":  true,
		"exfat": true,
	}

	var filesystems []types.FilesystemInfo
	for _, partition := range partitions {
		// Only include whitelisted filesystem types
		if !allowedFsTypes[partition.Fstype] {
			continue
		}

		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			continue
		}

		fs := types.FilesystemInfo{
			Mountpoint:   partition.Mountpoint,
			Fstype:       partition.Fstype,
			Total:        usage.Total,
			Used:         usage.Used,
			Free:         usage.Free,
			UsagePercent: math.Round(usage.UsedPercent*100) / 100,
		}
		filesystems = append(filesystems, fs)
	}

	return filesystems
}

// getBlockDevices returns information about block devices
// Includes physical and virtual block devices (whitelist approach)
func (c *Collector) getBlockDevices() []types.BlockDevice {
	partitions, err := disk.Partitions(true)
	if err != nil {
		return []types.BlockDevice{}
	}

	// Whitelist of important device prefixes (physical/virtual disks)
	allowedDevicePrefixes := []string{
		"/dev/sd",     // SCSI/SATA disks
		"/dev/hd",     // IDE disks
		"/dev/vd",     // Virtual disks (KVM/QEMU)
		"/dev/xvd",    // Xen virtual disks
		"/dev/nvme",   // NVMe disks
		"/dev/mmcblk", // SD/MMC cards
	}

	var devices []types.BlockDevice
	deviceMap := make(map[string]bool)

	for _, partition := range partitions {
		if !strings.HasPrefix(partition.Device, "/dev/") {
			continue
		}

		// Check if device matches any allowed prefix
		isAllowed := false
		for _, prefix := range allowedDevicePrefixes {
			if strings.HasPrefix(partition.Device, prefix) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			continue
		}

		deviceName := partition.Device
		if !deviceMap[deviceName] {
			deviceMap[deviceName] = true

			device := types.BlockDevice{
				Name:         deviceName,
				Model:        "unknown",
				Size:         0,
				SerialNumber: "unknown",
			}
			devices = append(devices, device)
		}
	}

	return devices
}

// getAllIPs returns all IP addresses of the system
func (c *Collector) getAllIPs() []string {
	var ips []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		for _, addr := range iface.Addrs {
			// Skip loopback
			if strings.Contains(addr.Addr, "127.0.0.1") || strings.Contains(addr.Addr, "::1") {
				continue
			}
			// Remove CIDR
			ip := strings.Split(addr.Addr, "/")[0]
			ips = append(ips, ip)
		}
	}
	return ips
}

// IngestMetrics sends system metrics to PocketBase /api/agent endpoint
// agentID is required for upsert operation - metrics will be updated for same agent
func (c *Collector) IngestMetrics(agentID string, authManager interface {
	AuthenticatedDo(method, url string, body []byte, headers map[string]string) (*http.Response, error)
}, systemMetrics *types.SystemMetrics) error {
	logging.Debug("Ingesting metrics for agent %s", agentID)

	// Convert SystemMetrics to PocketBaseSystemMetrics format
	pbMetrics := c.convertSystemMetrics(systemMetrics)

	// Create the ingest request payload with agent_id for upsert
	payload := types.IngestMetricsRequest{
		Action:        "ingest-metrics",
		SystemMetrics: pbMetrics,
		// Populate agent metadata updates
		OSInfo:         systemMetrics.Platform,
		OSVersion:      systemMetrics.PlatformVersion,
		OSType:         systemMetrics.OSType,
		PlatformFamily: systemMetrics.PlatformFamily, // Required for patch management
		Version:        c.agentVersion,
		PrimaryIP:      systemMetrics.IPAddress,
		KernelVersion:  systemMetrics.KernelVersion,
		Arch:           systemMetrics.KernelArch,
		AllIPs:         systemMetrics.AllIPs,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics payload: %w", err)
	}

	// Send request to PocketBase /api/agent endpoint with authorization
	url := fmt.Sprintf("%s/api/agent", c.apiBaseURL)

	resp, err := authManager.AuthenticatedDo("POST", url, jsonData, nil)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check for authorization errors
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("metrics ingestion failed: unauthorized - token may be expired")
	}

	// Check for other errors
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("metrics ingestion failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var metricsResp types.IngestMetricsResponse
	if err := json.Unmarshal(body, &metricsResp); err != nil {
		// If response doesn't parse as IngestMetricsResponse, check for generic error
		logging.Warning("Could not parse metrics response: %v", err)
		// Still consider it a success if status was OK
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			logging.Debug("Metrics ingested successfully (unparsed response)")
			return nil
		}
		// If status is not OK and response didn't parse, it's an error
		return fmt.Errorf("metrics ingestion failed with status %d: invalid response format", resp.StatusCode)
	}

	if !metricsResp.Success {
		logging.Warning("Metrics ingestion response: %s", metricsResp.Message)
		return fmt.Errorf("metrics ingestion failed: %s", metricsResp.Message)
	}

	logging.Debug("Metrics ingested successfully for agent %s", agentID)
	return nil
}

// convertSystemMetrics converts internal SystemMetrics to PocketBase format
func (c *Collector) convertSystemMetrics(systemMetrics *types.SystemMetrics) types.PocketBaseSystemMetrics {
	// Convert filesystems to PocketBase format
	filesystems := c.convertFilesystems(systemMetrics.FilesystemInfo)

	// Calculate memory percentage
	memoryPercent := 0.0
	if systemMetrics.MemoryTotal > 0 {
		memoryPercent = math.Round((float64(systemMetrics.MemoryUsed)/float64(systemMetrics.MemoryTotal))*10000) / 100
	}

	// Calculate disk usage percentage
	diskUsagePercent := 0.0
	if systemMetrics.DiskTotal > 0 {
		diskUsagePercent = math.Round((float64(systemMetrics.DiskUsed)/float64(systemMetrics.DiskTotal))*10000) / 100
	}

	// Convert memory from bytes to GB
	memoryUsedGB := float64(systemMetrics.MemoryUsed) / (1024 * 1024 * 1024)
	memoryTotalGB := float64(systemMetrics.MemoryTotal) / (1024 * 1024 * 1024)

	// Convert disk from bytes to GB
	diskUsedGB := float64(systemMetrics.DiskUsed) / (1024 * 1024 * 1024)
	diskTotalGB := float64(systemMetrics.DiskTotal) / (1024 * 1024 * 1024)

	return types.PocketBaseSystemMetrics{
		CPUPercent:       math.Round(systemMetrics.CPUUsage*100) / 100,
		CPUCores:         systemMetrics.CPUCores,
		MemoryUsedGB:     math.Round(memoryUsedGB*100) / 100,
		MemoryTotalGB:    math.Round(memoryTotalGB*100) / 100,
		MemoryPercent:    memoryPercent,
		DiskUsedGB:       math.Round(diskUsedGB*100) / 100,
		DiskTotalGB:      math.Round(diskTotalGB*100) / 100,
		DiskUsagePercent: diskUsagePercent,
		Filesystems:      filesystems,
		LoadAverage: types.LoadAverage{
			OneMin:     math.Round(systemMetrics.LoadAvg1*100) / 100,
			FiveMin:    math.Round(systemMetrics.LoadAvg5*100) / 100,
			FifteenMin: math.Round(systemMetrics.LoadAvg15*100) / 100,
		},
		NetworkStats: types.NetworkStats{
			InGB:  systemMetrics.NetworkInGb,
			OutGB: systemMetrics.NetworkOutGb,
		},
		KernelVersion: systemMetrics.KernelVersion,
	}
}

// convertFilesystems converts filesystem info to PocketBase format
func (c *Collector) convertFilesystems(filesystemInfo []types.FilesystemInfo) []types.FilesystemStats {
	if len(filesystemInfo) == 0 {
		return []types.FilesystemStats{}
	}

	filesystems := make([]types.FilesystemStats, 0, len(filesystemInfo))
	for _, fs := range filesystemInfo {
		// Convert bytes to GB
		usedGB := float64(fs.Used) / (1024 * 1024 * 1024)
		freeGB := float64(fs.Free) / (1024 * 1024 * 1024)
		totalGB := float64(fs.Total) / (1024 * 1024 * 1024)

		filesystems = append(filesystems, types.FilesystemStats{
			Device:       fs.Device,
			MountPath:    fs.Mountpoint,
			UsedGB:       math.Round(usedGB*100) / 100,
			FreeGB:       math.Round(freeGB*100) / 100,
			TotalGB:      math.Round(totalGB*100) / 100,
			UsagePercent: math.Round(fs.UsagePercent*100) / 100,
		})
	}

	return filesystems
}

// safeCastUint64 caps uint64 values to prevent database numeric overflow
// PostgreSQL numeric can handle very large numbers, but we cap at 2^53-1 for JSON safety
func (c *Collector) safeCastUint64(val uint64) uint64 {
	const maxSafeInt = 9007199254740991 // 2^53 - 1 (max safe integer in JSON/JavaScript)
	if val > maxSafeInt {
		return maxSafeInt
	}
	return val
}

// safeCastUint64Value is an alias for safeCastUint64 for consistency
func (c *Collector) safeCastUint64Value(val uint64) uint64 {
	return c.safeCastUint64(val)
}

// Computes load average
type Loadavg struct {
	LoadAverage1     float64
	LoadAverage5     float64
	LoadAverage10    float64
	RunningProcesses int
	TotalProcesses   int
	LastProcessId    int
}

func LoadAvgParse() (*Loadavg, error) {
	switch runtime.GOOS {
	case "linux":
		return parse_linux()
	default:
		return nil, errors.New("loadavg unimplemented on " + runtime.GOOS)
	}
}

func parse_linux() (*Loadavg, error) {
	self := new(Loadavg)

	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return self, err
	}

	_, err = fmt.Sscanf(string(raw), "%f %f %f %d/%d %d",
		&self.LoadAverage1, &self.LoadAverage5, &self.LoadAverage10,
		&self.RunningProcesses, &self.TotalProcesses,
		&self.LastProcessId)

	if err != nil {
		return self, err
	}

	return self, nil
}

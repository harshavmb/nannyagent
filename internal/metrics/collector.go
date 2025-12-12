package metrics

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"

	"nannyagentv2/internal/types"
)

// Collector handles system metrics collection
type Collector struct {
	agentVersion string
}

// NewCollector creates a new metrics collector
func NewCollector(agentVersion string) *Collector {
	return &Collector{
		agentVersion: agentVersion,
	}
}

// GatherSystemMetrics collects comprehensive system metrics
func (c *Collector) GatherSystemMetrics() (*types.SystemMetrics, error) {
	metrics := &types.SystemMetrics{
		Timestamp: time.Now(),
	}

	// System Information
	if hostInfo, err := host.Info(); err == nil {
		metrics.Hostname = hostInfo.Hostname
		metrics.Platform = hostInfo.Platform
		metrics.PlatformFamily = hostInfo.PlatformFamily
		metrics.PlatformVersion = hostInfo.PlatformVersion
		metrics.KernelVersion = hostInfo.KernelVersion
		metrics.KernelArch = hostInfo.KernelArch
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
	if loadAvg, err := load.Avg(); err == nil {
		metrics.LoadAvg1 = math.Round(loadAvg.Load1*100) / 100
		metrics.LoadAvg5 = math.Round(loadAvg.Load5*100) / 100
		metrics.LoadAvg15 = math.Round(loadAvg.Load15*100) / 100
	}

	// Process Count (simplified - using a constant for now)
	// Note: gopsutil doesn't have host.Processes(), would need process.Processes()
	metrics.ProcessCount = 0 // Placeholder

	// Network Metrics - convert cumulative bytes to Mbps (rounded to reasonable values)
	netInMbps, netOutMbps := c.getNetworkStatsMbps()
	metrics.NetworkInKbps = netInMbps * 1024 // Convert back to Kbps for field compatibility
	metrics.NetworkOutKbps = netOutMbps * 1024

	if netIOCounters, err := psnet.IOCounters(false); err == nil && len(netIOCounters) > 0 {
		netIO := netIOCounters[0]
		metrics.NetworkInBytes = netIO.BytesRecv
		metrics.NetworkOutBytes = netIO.BytesSent
	}

	// IP Address and Location
	metrics.IPAddress = c.getIPAddress()
	metrics.Location = c.getLocation() // Placeholder

	// Filesystem Information
	metrics.FilesystemInfo = c.getFilesystemInfo()

	// Block Devices
	metrics.BlockDevices = c.getBlockDevices()

	return metrics, nil
}

// getNetworkStatsMbps returns network rates in Mbps (safe values that won't overflow)
// Since we don't track deltas over time, we return 0 to avoid massive cumulative values
func (c *Collector) getNetworkStatsMbps() (float64, float64) {
	// Return 0 Mbps since we don't have proper rate calculation
	// To calculate actual rates, we would need:
	// 1. Store previous byte counts and timestamps
	// 2. Calculate delta bytes / delta time
	// 3. Convert to Mbps: (deltaBytes * 8) / (deltaSeconds * 1_000_000)
	return 0.0, 0.0
}

// getIPAddress returns the primary IP address of the system
func (c *Collector) getIPAddress() string {
	interfaces, err := psnet.Interfaces()
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

// SendMetrics sends system metrics to the agent-auth-api endpoint
func (c *Collector) SendMetrics(agentAuthURL, accessToken, agentID string, metrics *types.SystemMetrics) error {
	// Create flattened metrics request for agent-auth-api
	metricsReq := c.CreateMetricsRequest(agentID, metrics)

	return c.sendMetricsRequest(agentAuthURL, accessToken, metricsReq)
}

// CreateMetricsRequest converts SystemMetrics to the flattened format expected by agent-auth-api
func (c *Collector) CreateMetricsRequest(agentID string, systemMetrics *types.SystemMetrics) *types.MetricsRequest {
	return &types.MetricsRequest{
		AgentID:           agentID,
		Hostname:          systemMetrics.Hostname,
		CPUUsage:          systemMetrics.CPUUsage,
		MemoryUsage:       systemMetrics.MemoryUsage,
		DiskUsage:         systemMetrics.DiskUsage,
		NetworkInKbps:     systemMetrics.NetworkInKbps,
		NetworkOutKbps:    systemMetrics.NetworkOutKbps,
		IPAddress:         systemMetrics.IPAddress,
		Location:          systemMetrics.Location,
		AgentVersion:      c.agentVersion,
		KernelVersion:     systemMetrics.KernelVersion,
		DeviceFingerprint: c.generateDeviceFingerprint(systemMetrics),
		LoadAverages: map[string]float64{
			"load1":  systemMetrics.LoadAvg1,
			"load5":  systemMetrics.LoadAvg5,
			"load15": systemMetrics.LoadAvg15,
		},
		OSInfo: map[string]string{
			"cpu_cores":        fmt.Sprintf("%d", systemMetrics.CPUCores),
			"memory":           fmt.Sprintf("%.1fGi", float64(systemMetrics.MemoryTotal)/(1024*1024*1024)),
			"uptime":           "unknown", // Will be calculated by the server or client
			"platform":         systemMetrics.Platform,
			"platform_family":  systemMetrics.PlatformFamily,
			"platform_version": systemMetrics.PlatformVersion,
			"kernel_version":   systemMetrics.KernelVersion,
			"kernel_arch":      systemMetrics.KernelArch,
		},
		FilesystemInfo: systemMetrics.FilesystemInfo,
		BlockDevices:   systemMetrics.BlockDevices,
		NetworkStats: map[string]uint64{
			"bytes_sent":  c.safeCastUint64(systemMetrics.NetworkOutBytes),
			"bytes_recv":  c.safeCastUint64(systemMetrics.NetworkInBytes),
			"total_bytes": c.safeCastUint64(systemMetrics.NetworkInBytes + systemMetrics.NetworkOutBytes),
		},
	}
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

// sendMetricsRequest sends the metrics request to the agent-auth-api
func (c *Collector) sendMetricsRequest(agentAuthURL, accessToken string, metricsReq *types.MetricsRequest) error {
	// Wrap metrics in the expected payload structure
	payload := map[string]interface{}{
		"agent_id":  metricsReq.AgentID,
		"metrics":   metricsReq,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	// Send to /metrics endpoint
	metricsURL := fmt.Sprintf("%s/metrics", agentAuthURL)
	req, err := http.NewRequest("POST", metricsURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send metrics: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check response status
	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("unauthorized")
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("metrics request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// generateDeviceFingerprint creates a unique device identifier
func (c *Collector) generateDeviceFingerprint(metrics *types.SystemMetrics) string {
	fingerprint := fmt.Sprintf("%s-%s-%s", metrics.Hostname, metrics.Platform, metrics.KernelVersion)
	hasher := sha256.New()
	hasher.Write([]byte(fingerprint))
	return fmt.Sprintf("%x", hasher.Sum(nil))[:16]
}

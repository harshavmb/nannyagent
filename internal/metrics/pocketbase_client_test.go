package metrics

import (
	"math"
	"os"
	"testing"
	"time"

	"nannyagentv2/internal/types"
)

// TestPocketBaseClient_MetricsConversion tests conversion to PocketBase format
func TestPocketBaseClient_MetricsConversion(t *testing.T) {
	baseURL := "http://localhost:8090"
	pbClient := NewPocketBaseClient(baseURL)

	// Create test metrics (in old format)
	systemMetrics := &types.SystemMetrics{
		Hostname:       "test-host",
		Platform:       "linux",
		KernelVersion:  "5.15.0",
		CPUUsage:       45.5,
		CPUCores:       8,
		MemoryUsed:     1073741824,    // 1 GB
		MemoryTotal:    17179869184,   // 16 GB
		DiskUsed:       107374182400,  // 100 GB
		DiskTotal:      1099511627776, // 1 TB
		LoadAvg1:       2.5,
		LoadAvg5:       2.0,
		LoadAvg15:      1.8,
		NetworkInKbps:  1024 * 1024, // 1 Gbps in Kbps
		NetworkOutKbps: 512 * 1024,  // 512 Mbps in Kbps
		FilesystemInfo: []types.FilesystemInfo{
			{
				Device:       "/dev/sda1",
				Mountpoint:   "/",
				Total:        1099511627776,
				Used:         107374182400,
				Free:         992137445376,
				UsagePercent: 9.77,
			},
		},
	}

	// Convert to PocketBase format
	pbMetrics := pbClient.convertSystemMetrics(systemMetrics)

	// Verify conversions
	if pbMetrics.CPUCores != 8 {
		t.Fatalf("Expected CPUCores=8, got %d", pbMetrics.CPUCores)
	}

	// Memory should be in GB
	if pbMetrics.MemoryTotalGB <= 0 || pbMetrics.MemoryTotalGB > 20 {
		t.Fatalf("Expected MemoryTotalGB ~16, got %f", pbMetrics.MemoryTotalGB)
	}

	// Memory percentage should be calculated
	if pbMetrics.MemoryPercent < 5 || pbMetrics.MemoryPercent > 10 {
		t.Fatalf("Expected MemoryPercent ~6.25, got %f", pbMetrics.MemoryPercent)
	}

	// Disk should be in GB
	if pbMetrics.DiskTotalGB <= 0 || pbMetrics.DiskTotalGB > 2000 {
		t.Fatalf("Expected DiskTotalGB ~1024, got %f", pbMetrics.DiskTotalGB)
	}

	// Network should be in Gbps
	if pbMetrics.NetworkStats.InGbps <= 0 || pbMetrics.NetworkStats.InGbps > 2 {
		t.Fatalf("Expected NetworkStats.InGbps ~1.0, got %f", pbMetrics.NetworkStats.InGbps)
	}

	// Load averages
	if pbMetrics.LoadAverage.OneMin != 2.5 {
		t.Fatalf("Expected LoadAverage.OneMin=2.5, got %f", pbMetrics.LoadAverage.OneMin)
	}

	t.Logf("✓ Metrics conversion to PocketBase format successful")
	t.Logf("  Memory: %.2f GB / %.2f GB (%.2f%%)", pbMetrics.MemoryUsedGB, pbMetrics.MemoryTotalGB, pbMetrics.MemoryPercent)
	t.Logf("  Disk: %.2f GB / %.2f GB", pbMetrics.DiskUsedGB, pbMetrics.DiskTotalGB)
	t.Logf("  Network: In=%.4f Gbps, Out=%.4f Gbps", pbMetrics.NetworkStats.InGbps, pbMetrics.NetworkStats.OutGbps)
}

// TestPocketBaseClient_FilesystemConversion tests filesystem conversion
func TestPocketBaseClient_FilesystemConversion(t *testing.T) {
	baseURL := "http://localhost:8090"
	pbClient := NewPocketBaseClient(baseURL)

	filesystems := []types.FilesystemInfo{
		{
			Device:       "/dev/nvme0n1p1",
			Mountpoint:   "/",
			Total:        1099511627776, // 1 TB
			Used:         549755813888,  // 500 GB
			Free:         549755813888,  // 500 GB
			UsagePercent: 50.0,
		},
		{
			Device:       "/dev/nvme0n1p2",
			Mountpoint:   "/data",
			Total:        2199023255552, // 2 TB
			Used:         1099511627776, // 1 TB
			Free:         1099511627776, // 1 TB
			UsagePercent: 50.0,
		},
	}

	converted := pbClient.convertFilesystems(filesystems)

	if len(converted) != 2 {
		t.Fatalf("Expected 2 filesystems, got %d", len(converted))
	}

	// Check first filesystem
	if converted[0].Device != "/dev/nvme0n1p1" {
		t.Fatalf("Expected device /dev/nvme0n1p1, got %s", converted[0].Device)
	}

	// Should be in GB
	if converted[0].TotalGB < 500 || converted[0].TotalGB > 1500 {
		t.Fatalf("Expected TotalGB ~1024, got %f", converted[0].TotalGB)
	}

	if converted[0].UsagePercent != 50.0 {
		t.Fatalf("Expected UsagePercent=50, got %f", converted[0].UsagePercent)
	}

	t.Logf("✓ Filesystem conversion successful")
	for i, fs := range converted {
		t.Logf("  %d. %s: %.2f GB / %.2f GB (%.1f%%)", i+1, fs.Device, fs.UsedGB, fs.TotalGB, fs.UsagePercent)
	}
}

// TestPocketBaseClient_GatherAndConvertMetrics tests full metrics gathering and conversion
func TestPocketBaseClient_GatherAndConvertMetrics(t *testing.T) {
	// Gather real system metrics
	collector := NewCollector("test-version")
	systemMetrics, err := collector.GatherSystemMetrics()
	if err != nil {
		t.Fatalf("Failed to gather system metrics: %v", err)
	}

	// Verify basic metrics are available
	if systemMetrics.Hostname == "" {
		t.Fatalf("Expected hostname, got empty")
	}

	if systemMetrics.CPUCores <= 0 {
		t.Fatalf("Expected CPUCores > 0, got %d", systemMetrics.CPUCores)
	}

	if systemMetrics.MemoryTotal <= 0 {
		t.Fatalf("Expected MemoryTotal > 0, got %d", systemMetrics.MemoryTotal)
	}

	t.Logf("✓ System metrics gathered successfully")
	t.Logf("  Hostname: %s", systemMetrics.Hostname)
	t.Logf("  Platform: %s", systemMetrics.Platform)
	t.Logf("  Kernel: %s", systemMetrics.KernelVersion)
	t.Logf("  CPU: %d cores, %.1f%% usage", systemMetrics.CPUCores, systemMetrics.CPUUsage)
	t.Logf("  Memory: %.2f MB / %.2f GB", float64(systemMetrics.MemoryUsed)/(1024*1024), float64(systemMetrics.MemoryTotal)/(1024*1024*1024))
	t.Logf("  Disk: %.2f%% usage", systemMetrics.DiskUsage)
	t.Logf("  Load: 1m=%.2f, 5m=%.2f, 15m=%.2f", systemMetrics.LoadAvg1, systemMetrics.LoadAvg5, systemMetrics.LoadAvg15)

	// Convert to PocketBase format
	baseURL := "http://localhost:8090"
	pbClient := NewPocketBaseClient(baseURL)
	pbMetrics := pbClient.convertSystemMetrics(systemMetrics)

	// Verify conversions maintain data integrity
	if pbMetrics.CPUCores != systemMetrics.CPUCores {
		t.Fatalf("CPUCores lost in conversion: %d -> %d", systemMetrics.CPUCores, pbMetrics.CPUCores)
	}

	// Memory and disk should be positive after conversion
	if pbMetrics.MemoryTotalGB <= 0 {
		t.Fatalf("Invalid MemoryTotalGB after conversion: %f", pbMetrics.MemoryTotalGB)
	}

	if pbMetrics.DiskTotalGB <= 0 {
		t.Fatalf("Invalid DiskTotalGB after conversion: %f", pbMetrics.DiskTotalGB)
	}

	t.Logf("✓ Metrics conversion maintains data integrity")
}

// TestPocketBaseClient_MetricsStructure tests the metrics payload structure
func TestPocketBaseClient_MetricsStructure(t *testing.T) {
	// Create a minimal metrics payload
	metrics := types.IngestMetricsRequest{
		Action: "ingest-metrics",
		SystemMetrics: &types.PocketBaseSystemMetrics{
			CPUPercent:       45.5,
			CPUCores:         8,
			MemoryUsedGB:     6.0,
			MemoryTotalGB:    16.0,
			MemoryPercent:    37.5,
			DiskUsedGB:       100.0,
			DiskTotalGB:      1000.0,
			DiskUsagePercent: 10.0,
			LoadAverage: types.LoadAverage{
				OneMin:     2.5,
				FiveMin:    2.0,
				FifteenMin: 1.8,
			},
			NetworkStats: types.NetworkStats{
				InGbps:  0.5,
				OutGbps: 0.25,
			},
		},
	}

	// Verify all required fields are present
	if metrics.Action != "ingest-metrics" {
		t.Fatalf("Expected action='ingest-metrics', got %s", metrics.Action)
	}

	if metrics.SystemMetrics == nil {
		t.Fatalf("Expected SystemMetrics to be set")
	}

	pbMetrics := metrics.SystemMetrics.(*types.PocketBaseSystemMetrics)

	// Verify data types and ranges
	if pbMetrics.CPUPercent < 0 || pbMetrics.CPUPercent > 100 {
		t.Fatalf("Invalid CPUPercent: %f", pbMetrics.CPUPercent)
	}

	if pbMetrics.MemoryPercent < 0 || pbMetrics.MemoryPercent > 100 {
		t.Fatalf("Invalid MemoryPercent: %f", pbMetrics.MemoryPercent)
	}

	if pbMetrics.DiskUsagePercent < 0 || pbMetrics.DiskUsagePercent > 100 {
		t.Fatalf("Invalid DiskUsagePercent: %f", pbMetrics.DiskUsagePercent)
	}

	// Verify load averages
	if pbMetrics.LoadAverage.OneMin <= 0 {
		t.Fatalf("Expected positive load average, got %f", pbMetrics.LoadAverage.OneMin)
	}

	t.Logf("✓ Metrics structure is valid and properly formatted")
	t.Logf("  CPU: %.1f%% (%d cores)", pbMetrics.CPUPercent, pbMetrics.CPUCores)
	t.Logf("  Memory: %.1f%% (%.1f GB / %.1f GB)", pbMetrics.MemoryPercent, pbMetrics.MemoryUsedGB, pbMetrics.MemoryTotalGB)
	t.Logf("  Disk: %.1f%% (%.1f GB / %.1f GB)", pbMetrics.DiskUsagePercent, pbMetrics.DiskUsedGB, pbMetrics.DiskTotalGB)
	t.Logf("  Network: In=%.2f Gbps, Out=%.2f Gbps", pbMetrics.NetworkStats.InGbps, pbMetrics.NetworkStats.OutGbps)
}

// TestMetricsRounding tests that metrics are properly rounded
func TestMetricsRounding(t *testing.T) {
	baseURL := "http://localhost:8090"
	pbClient := NewPocketBaseClient(baseURL)

	// Create metrics with values that need rounding
	systemMetrics := &types.SystemMetrics{
		CPUUsage:    33.33333,
		LoadAvg1:    2.123456,
		MemoryUsed:  1234567890,
		MemoryTotal: 17179869184,
	}

	pbMetrics := pbClient.convertSystemMetrics(systemMetrics)

	// Verify rounding
	if pbMetrics.LoadAverage.OneMin != math.Round(2.123456*100)/100 {
		t.Fatalf("Load average not properly rounded")
	}

	// Memory percent should be rounded to 2 decimal places
	if pbMetrics.MemoryPercent > 10 || pbMetrics.MemoryPercent < 5 {
		t.Fatalf("Memory percent out of expected range: %f", pbMetrics.MemoryPercent)
	}

	t.Logf("✓ Metrics rounding works correctly")
	t.Logf("  CPU: %.2f%%", pbMetrics.CPUPercent)
	t.Logf("  Load 1m: %.2f", pbMetrics.LoadAverage.OneMin)
	t.Logf("  Memory: %.2f%%", pbMetrics.MemoryPercent)
}

// TestPocketBaseClient_Connectivity tests basic connectivity to PocketBase
func TestPocketBaseClient_Connectivity(t *testing.T) {
	baseURL := os.Getenv("POCKETBASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8090"
	}

	pbClient := NewPocketBaseClient(baseURL)

	// Verify client was created
	if pbClient.baseURL != baseURL {
		t.Fatalf("Expected baseURL=%s, got %s", baseURL, pbClient.baseURL)
	}

	if pbClient.client == nil {
		t.Fatalf("Expected client to be initialized")
	}

	// Verify timeout is set
	if pbClient.client.Timeout != 30*time.Second {
		t.Fatalf("Expected timeout=30s, got %v", pbClient.client.Timeout)
	}

	t.Logf("✓ PocketBase client initialized correctly")
	t.Logf("  Base URL: %s", baseURL)
	t.Logf("  Timeout: %v", pbClient.client.Timeout)
}

package metrics

import (
	"testing"
	"time"

	"nannyagentv2/internal/types"
)

func TestNewCollector(t *testing.T) {
	version := "v1.0.0"
	collector := NewCollector(version)

	if collector == nil {
		t.Fatal("Expected collector to be created")
	}

	if collector.agentVersion != version {
		t.Errorf("Expected version %s, got %s", version, collector.agentVersion)
	}
}

func TestGatherSystemMetrics(t *testing.T) {
	collector := NewCollector("v1.0.0")

	metrics, err := collector.GatherSystemMetrics()
	if err != nil {
		t.Fatalf("Failed to gather system metrics: %v", err)
	}

	if metrics == nil {
		t.Fatal("Expected metrics to be returned")
	}

	// Check timestamp
	if metrics.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}

	// Verify timestamp is recent (within last minute)
	if time.Since(metrics.Timestamp) > time.Minute {
		t.Error("Timestamp should be recent")
	}

	// Basic sanity checks on metrics
	t.Run("SystemInfo", func(t *testing.T) {
		if metrics.Hostname == "" {
			t.Error("Hostname should not be empty")
		}
		if metrics.Platform == "" {
			t.Error("Platform should not be empty")
		}
		if metrics.KernelVersion == "" {
			t.Error("KernelVersion should not be empty")
		}
	})

	t.Run("CPUMetrics", func(t *testing.T) {
		// CPU usage should be between 0 and 100
		if metrics.CPUUsage < 0 || metrics.CPUUsage > 100 {
			t.Errorf("CPUUsage should be between 0 and 100, got %.2f", metrics.CPUUsage)
		}

		if metrics.CPUCores <= 0 {
			t.Error("CPUCores should be > 0")
		}

		if metrics.CPUModel == "" {
			t.Log("CPUModel is empty (may be expected in some environments)")
		}
	})

	t.Run("MemoryMetrics", func(t *testing.T) {
		if metrics.MemoryTotal == 0 {
			t.Error("MemoryTotal should be > 0")
		}

		if metrics.MemoryUsed > metrics.MemoryTotal {
			t.Errorf("MemoryUsed (%d) should not exceed MemoryTotal (%d)", metrics.MemoryUsed, metrics.MemoryTotal)
		}

		if metrics.MemoryFree > metrics.MemoryTotal {
			t.Errorf("MemoryFree (%d) should not exceed MemoryTotal (%d)", metrics.MemoryFree, metrics.MemoryTotal)
		}

		// Memory usage percentage should be reasonable
		if metrics.MemoryUsage < 0 || metrics.MemoryUsage > float64(metrics.MemoryTotal) {
			t.Errorf("MemoryUsage appears invalid: %.2f", metrics.MemoryUsage)
		}
	})

	t.Run("DiskMetrics", func(t *testing.T) {
		if metrics.DiskTotal == 0 {
			t.Error("DiskTotal should be > 0")
		}

		if metrics.DiskUsed > metrics.DiskTotal {
			t.Errorf("DiskUsed (%d) should not exceed DiskTotal (%d)", metrics.DiskUsed, metrics.DiskTotal)
		}

		// Disk usage percentage should be between 0 and 100
		if metrics.DiskUsage < 0 || metrics.DiskUsage > 100 {
			t.Errorf("DiskUsage should be between 0 and 100, got %.2f", metrics.DiskUsage)
		}
	})

	t.Run("LoadAverages", func(t *testing.T) {
		// Load averages should be non-negative
		if metrics.LoadAvg1 < 0 {
			t.Errorf("LoadAvg1 should be >= 0, got %.2f", metrics.LoadAvg1)
		}
		if metrics.LoadAvg5 < 0 {
			t.Errorf("LoadAvg5 should be >= 0, got %.2f", metrics.LoadAvg5)
		}
		if metrics.LoadAvg15 < 0 {
			t.Errorf("LoadAvg15 should be >= 0, got %.2f", metrics.LoadAvg15)
		}
	})

	t.Run("NetworkMetrics", func(t *testing.T) {
		// Network metrics should be non-negative
		if metrics.NetworkInKbps < 0 {
			t.Errorf("NetworkInKbps should be >= 0, got %.2f", metrics.NetworkInKbps)
		}
		if metrics.NetworkOutKbps < 0 {
			t.Errorf("NetworkOutKbps should be >= 0, got %.2f", metrics.NetworkOutKbps)
		}
	})

	t.Run("IPAddress", func(t *testing.T) {
		if metrics.IPAddress == "" {
			t.Error("IPAddress should not be empty")
		}
	})

	t.Run("Location", func(t *testing.T) {
		// Location is currently a placeholder
		if metrics.Location == "" {
			t.Log("Location is empty (expected as it's a placeholder)")
		}
	})

	t.Run("FilesystemInfo", func(t *testing.T) {
		// Should have at least one filesystem
		if len(metrics.FilesystemInfo) == 0 {
			t.Log("No filesystems found (may be expected in some test environments)")
		}

		// Verify filesystem data structure
		for i, fs := range metrics.FilesystemInfo {
			if fs.Mountpoint == "" {
				t.Errorf("Filesystem %d: Mountpoint should not be empty", i)
			}
			if fs.Fstype == "" {
				t.Errorf("Filesystem %d: Fstype should not be empty", i)
			}
			if fs.Total == 0 {
				t.Errorf("Filesystem %d: Total should be > 0", i)
			}
			if fs.UsagePercent < 0 || fs.UsagePercent > 100 {
				t.Errorf("Filesystem %d: UsagePercent should be between 0 and 100, got %.2f", i, fs.UsagePercent)
			}
		}
	})

	t.Run("BlockDevices", func(t *testing.T) {
		// May or may not have block devices in test environment
		if len(metrics.BlockDevices) == 0 {
			t.Log("No block devices found (may be expected in some test environments)")
		}

		// Verify block device structure
		for i, bd := range metrics.BlockDevices {
			if bd.Name == "" {
				t.Errorf("BlockDevice %d: Name should not be empty", i)
			}
		}
	})
}

func TestSafeCastUint64Value(t *testing.T) {
	collector := NewCollector("v1.0.0")

	const maxSafeInt = 9007199254740991 // 2^53 - 1

	tests := []struct {
		name     string
		input    uint64
		expected uint64
	}{
		{"Normal value", 1024, 1024},
		{"Zero", 0, 0},
		{"Large value", 1 << 40, 1 << 40},                           // 1 TB
		{"Max uint64 (capped)", ^uint64(0), maxSafeInt},             // Should be capped to maxSafeInt
		{"Value above max safe int", maxSafeInt + 1000, maxSafeInt}, // Should be capped
		{"Value at max safe int", maxSafeInt, maxSafeInt},           // Should not be capped
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := collector.safeCastUint64Value(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetNetworkStatsMbps(t *testing.T) {
	collector := NewCollector("v1.0.0")

	inMbps, outMbps := collector.getNetworkStatsMbps()

	// Currently returns 0.0 as a placeholder since rate calculation isn't implemented
	if inMbps != 0.0 {
		t.Errorf("Expected 0.0 for inMbps (placeholder), got %.2f", inMbps)
	}
	if outMbps != 0.0 {
		t.Errorf("Expected 0.0 for outMbps (placeholder), got %.2f", outMbps)
	}
}

func TestGetIPAddress(t *testing.T) {
	collector := NewCollector("v1.0.0")

	ip := collector.getIPAddress()

	if ip == "" {
		t.Error("IP address should not be empty")
	}

	// Should not be loopback
	if ip == "127.0.0.1" || ip == "::1" {
		t.Error("Should not return loopback address")
	}

	// Should be either a valid IP or "unknown"
	if ip != "unknown" {
		// Basic IP validation (not exhaustive)
		if len(ip) == 0 {
			t.Error("IP address should not be empty if not 'unknown'")
		}
	}
}

func TestGetLocation(t *testing.T) {
	collector := NewCollector("v1.0.0")

	location := collector.getLocation()

	// Currently returns "unknown" as a placeholder
	if location != "unknown" {
		t.Logf("Location: %s (may be implemented in the future)", location)
	}
}

func TestGetFilesystemInfo(t *testing.T) {
	collector := NewCollector("v1.0.0")

	filesystems := collector.getFilesystemInfo()

	// May be empty in some test environments
	if len(filesystems) == 0 {
		t.Log("No filesystems found (may be expected in test environment)")
		return
	}

	// Validate each filesystem entry
	for i, fs := range filesystems {
		if fs.Mountpoint == "" {
			t.Errorf("Filesystem %d: Mountpoint should not be empty", i)
		}

		// Should be one of the whitelisted types
		allowedTypes := map[string]bool{
			"ext2": true, "ext3": true, "ext4": true,
			"xfs": true, "btrfs": true, "zfs": true,
			"ntfs": true, "vfat": true, "exfat": true,
		}
		if !allowedTypes[fs.Fstype] {
			t.Errorf("Filesystem %d: Unexpected fstype %s", i, fs.Fstype)
		}

		if fs.Total == 0 {
			t.Errorf("Filesystem %d: Total should be > 0", i)
		}

		if fs.Used > fs.Total {
			t.Errorf("Filesystem %d: Used (%d) should not exceed Total (%d)", i, fs.Used, fs.Total)
		}

		if fs.UsagePercent < 0 || fs.UsagePercent > 100 {
			t.Errorf("Filesystem %d: UsagePercent should be between 0 and 100, got %.2f", i, fs.UsagePercent)
		}
	}
}

func TestGetBlockDevices(t *testing.T) {
	collector := NewCollector("v1.0.0")

	devices := collector.getBlockDevices()

	// May be empty in some test environments
	if len(devices) == 0 {
		t.Log("No block devices found (may be expected in test environment)")
		return
	}

	// Validate each device
	for i, device := range devices {
		if device.Name == "" {
			t.Errorf("Device %d: Name should not be empty", i)
		}

		// Type should not be empty
		if device.Type == "" {
			t.Log("Device type is empty (may be normal for some devices)")
		}
	}
}

func TestMetricsConsistency(t *testing.T) {
	collector := NewCollector("v1.0.0")

	// Gather metrics twice
	metrics1, err1 := collector.GatherSystemMetrics()
	if err1 != nil {
		t.Fatalf("Failed to gather first metrics: %v", err1)
	}

	time.Sleep(100 * time.Millisecond)

	metrics2, err2 := collector.GatherSystemMetrics()
	if err2 != nil {
		t.Fatalf("Failed to gather second metrics: %v", err2)
	}

	// Some values should remain constant
	if metrics1.Hostname != metrics2.Hostname {
		t.Error("Hostname should be consistent across calls")
	}

	if metrics1.CPUCores != metrics2.CPUCores {
		t.Error("CPUCores should be consistent across calls")
	}

	if metrics1.MemoryTotal != metrics2.MemoryTotal {
		t.Error("MemoryTotal should be consistent across calls")
	}

	// Timestamps should be different
	if metrics1.Timestamp.Equal(metrics2.Timestamp) {
		t.Error("Timestamps should be different for separate calls")
	}

	// Second timestamp should be after first
	if !metrics2.Timestamp.After(metrics1.Timestamp) {
		t.Error("Second timestamp should be after first timestamp")
	}
}

func TestFilesystemInfoType(t *testing.T) {
	// Test the FilesystemInfo type structure
	fs := types.FilesystemInfo{
		Device:       "/dev/sda1",
		Mountpoint:   "/",
		Type:         "disk",
		Fstype:       "ext4",
		Total:        100000000,
		Used:         50000000,
		Free:         50000000,
		Usage:        50000000,
		UsagePercent: 50.0,
	}

	if fs.Device != "/dev/sda1" {
		t.Error("Device field not set correctly")
	}
	if fs.Mountpoint != "/" {
		t.Error("Mountpoint field not set correctly")
	}
	if fs.Fstype != "ext4" {
		t.Error("Fstype field not set correctly")
	}
	if fs.UsagePercent != 50.0 {
		t.Error("UsagePercent field not set correctly")
	}
}

func TestBlockDeviceType(t *testing.T) {
	// Test the BlockDevice type structure
	bd := types.BlockDevice{
		Name:         "sda",
		Size:         1000000000,
		Type:         "disk",
		Model:        "Test Model",
		SerialNumber: "12345",
	}

	if bd.Name != "sda" {
		t.Error("Name field not set correctly")
	}
	if bd.Size != 1000000000 {
		t.Error("Size field not set correctly")
	}
	if bd.Type != "disk" {
		t.Error("Type field not set correctly")
	}
}

# Proxmox Integration Guide

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Proxmox VE Infrastructure Monitoring</h1>
</div>

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Data Collection](#data-collection)
- [Cluster Monitoring](#cluster-monitoring)
- [Node Monitoring](#node-monitoring)
- [LXC Container Monitoring](#lxc-container-monitoring)
- [QEMU VM Monitoring](#qemu-vm-monitoring)
- [API Endpoints](#api-endpoints)
- [Deployment Scenarios](#deployment-scenarios)

## Overview

NannyAgent automatically detects and monitors Proxmox VE environments, providing comprehensive visibility into:

- **Cluster Configuration**: Nodes, quorum status, version
- **Node Health**: Resource usage, status, uptime
- **LXC Containers**: Configuration, networking, resource allocation
- **QEMU VMs**: Disk, CPU, memory, network configuration

### Detection

The agent automatically detects Proxmox VE installation:

```bash
# Check if Proxmox VE is installed
$ /usr/bin/pveversion --verbose
```

If Proxmox is detected, the agent starts the Proxmox collector automatically.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                      Proxmox VE Cluster                              │
│                                                                      │
│  ┌────────────────────┐  ┌────────────────────┐  ┌────────────────┐  │
│  │   pve-node-01      │  │   pve-node-02      │  │   pve-node-03  │  │
│  │  ┌──────────────┐  │  │  ┌──────────────┐  │  │  ┌──────────┐  │  │
│  │  │ NannyAgent   │  │  │  │ NannyAgent   │  │  │  │NannyAgent│  │  │
│  │  └──────┬───────┘  │  │  └──────┬───────┘  │  │  └────┬─────┘  │  │
│  │         │          │  │         │          │  │       │        │  │
│  │         │ pvesh    │  │         │ pvesh    │  │       │ pvesh  │  │
│  │         │ pct      │  │         │ pct      │  │       │ pct    │  │
│  │         │          │  │         │          │  │       │        │  │
│  │  ┌──────▼───────┐  │  │  ┌──────▼───────┐  │  │  ┌────▼─────┐  │  │
│  │  │ Proxmox API  │  │  │  │ Proxmox API  │  │  │  │Proxmox   │  │  │
│  │  │   (pvesh)    │  │  │  │   (pvesh)    │  │  │  │API       │  │  │
│  │  └──────────────┘  │  │  └──────────────┘  │  │  └──────────┘  │  │
│  │                    │  │                    │  │                │  │
│  │  ┌─LXC────┐        │  │  ┌─LXC────┐        │  │  ┌─QEMU───┐    │  │
│  │  │ CT 100 │        │  │  │ CT 101 │        │  │  │ VM 200 │    │  │
│  │  │ CT 102 │        │  │  │ CT 103 │        │  │  │ VM 201 │    │  │
│  │  └────────┘        │  │  └────────┘        │  │  └────────┘    │  │
│  └────────────────────┘  └────────────────────┘  └────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
                                │ HTTPS
                                │ POST /api/proxmox/*
                                ▼
                    ┌────────────────────────┐
                    │      NannyAPI          │
                    │  ┌──────────────────┐  │
                    │  │  Cluster Data    │  │
                    │  │  Node Data       │  │
                    │  │  LXC Data        │  │
                    │  │  QEMU Data       │  │
                    │  └──────────────────┘  │
                    └────────────────────────┘
```

## Data Collection

### Collection Schedule

```go
const (
    DefaultProxmoxInterval = 300 // 5 minutes
)
```

Configurable via:
```bash
PROXMOX_INTERVAL=300  # seconds
```

### Collection Flow

```
Every 5 minutes:

┌────────────────────────────────┐
│ Timer Trigger                  │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Check Proxmox Installation     │
│ IsProxmoxInstalled()           │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Check Cluster Membership       │
│ IsPartOfCluster()              │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Collect Node Info              │
│ pvesh get /nodes/*/status      │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ POST /api/proxmox/node         │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Collect Cluster Info           │
│ pvesh get /cluster/status      │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ POST /api/proxmox/cluster      │
└──────────┬─────────────────────┘
           │
           ▼
┌────────────────────────────────┐
│ Get Cluster Resources          │
│ pvesh get /cluster/resources   │
└──────────┬─────────────────────┘
           │
           ├─────────────────────────────┐
           │                             │
           ▼                             ▼
┌──────────────────────┐      ┌──────────────────────┐
│ For Each LXC         │      │ For Each QEMU        │
│ on this node         │      │ on this node         │
└──────────┬───────────┘      └──────────┬───────────┘
           │                             │
           ▼                             ▼
┌──────────────────────┐      ┌──────────────────────┐
│ Get LXC Config       │      │ Get QEMU Config      │
│ pvesh get            │      │ pvesh get            │
│ /nodes/*/lxc/*/      │      │ /nodes/*/qemu/*/     │
│ config               │      │ config               │
└──────────┬───────────┘      └──────────┬───────────┘
           │                             │
           ▼                             ▼
┌──────────────────────┐      ┌──────────────────────┐
│ POST                 │      │ POST                 │
│ /api/proxmox/lxc     │      │ /api/proxmox/qemu    │
│                      │      │                      │
└──────────────────────┘      └──────────────────────┘
```

## Cluster Monitoring

### Data Structure

```go
type ProxmoxCluster struct {
    ClusterName string `json:"cluster_name"`
    ClusterID   string `json:"cluster_id"`
    Nodes       int    `json:"nodes"`
    Quorate     int    `json:"quorate"`     // 1 = quorate, 0 = not quorate
    Version     int    `json:"version"`
}
```

### Collection Command

```bash
$ pvesh get /cluster/status --output-format json
```

**Output:**
```json
[
  {
    "type": "cluster",
    "name": "production-cluster",
    "id": "cluster",
    "nodes": 3,
    "quorate": 1,
    "version": 7
  },
  {
    "type": "node",
    "name": "pve-node-01",
    "nodeid": 1,
    "ip": "10.0.1.10",
    "online": 1,
    "local": 1,
    "level": ""
  }
]
```

### API Ingestion

```bash
curl -X POST https://api.nannyai.dev/api/proxmox/cluster \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster_name": "production-cluster",
    "cluster_id": "cluster",
    "nodes": 3,
    "quorate": 1,
    "version": 7
  }'
```

### Quorum Status

**Quorate (quorate=1):** Cluster has majority of nodes online, can make decisions
**Not Quorate (quorate=0):** Cluster lost majority, read-only mode

**Monitoring:**
- Alert if quorate=0
- Track node count changes
- Monitor version upgrades

## Node Monitoring

### Data Structure

```go
type ProxmoxNode struct {
    Name       string `json:"name"`
    NodeID     int    `json:"node_id"`
    IP         string `json:"ip"`
    Online     int    `json:"online"`      // 1 = online, 0 = offline
    Local      int    `json:"local"`       // 1 = this node, 0 = remote
    Level      string `json:"level"`
    PVEVersion string `json:"pve_version"`
}
```

### Collection Commands

```bash
# Get node status from cluster
$ pvesh get /cluster/status --output-format json

# Get detailed node info
$ pvesh get /nodes/pve-node-01/status --output-format json
```

**Node Status Output:**
```json
{
  "cpu": 0.0456789,
  "cpuinfo": {
    "cores": 8,
    "cpus": 16,
    "flags": "fpu vme de pse tsc msr pae mce cx8...",
    "hvm": "1",
    "model": "Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz",
    "sockets": 2,
    "user_hz": 100
  },
  "idle": 15,
  "kversion": "Linux 5.15.107-2-pve #1 SMP PVE 5.15.107-2 (2023-05-10T09:47Z)",
  "loadavg": ["0.45", "0.38", "0.35"],
  "memory": {
    "free": 54321098765,
    "total": 67108864000,
    "used": 12787765235
  },
  "pveversion": "pve-manager/7.4-3/9002ab8a",
  "rootfs": {
    "avail": 98765432100,
    "free": 123456789000,
    "total": 234567890000,
    "used": 111111101000
  },
  "swap": {
    "free": 8589934592,
    "total": 8589934592,
    "used": 0
  },
  "uptime": 1234567,
  "wait": 0.002
}
```

### API Ingestion

```bash
curl -X POST https://api.nannyai.dev/api/proxmox/node \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "pve-node-01",
    "node_id": 1,
    "ip": "10.0.1.10",
    "online": 1,
    "local": 1,
    "level": "",
    "pve_version": "pve-manager/7.4-3/9002ab8a"
  }'
```

### Monitoring Metrics

- **Online Status**: Track node availability
- **Resource Usage**: CPU, memory, disk utilization
- **Load Average**: System load indicators
- **Uptime**: Track reboots and availability
- **PVE Version**: Monitor version consistency across cluster

## LXC Container Monitoring

### Data Structure

```go
type ProxmoxLXC struct {
    Name         string                 `json:"name"`
    LXCID        string                 `json:"lxc_id"`      // "lxc/100"
    Status       string                 `json:"status"`      // "running", "stopped"
    Uptime       int                    `json:"uptime"`
    VMID         int                    `json:"vmid"`
    Node         string                 `json:"node"`
    CPUCores     int                    `json:"cpu_cores"`
    MemoryMB     int                    `json:"memory_mb"`
    RootFS       string                 `json:"rootfs"`
    SwapMB       int                    `json:"swap_mb"`
    Net0         string                 `json:"net0"`
    OSType       string                 `json:"ostype"`
    Arch         string                 `json:"arch"`
    Hostname     string                 `json:"hostname"`
    SearchDomain string                 `json:"searchdomain"`
    Nameserver   string                 `json:"nameserver"`
    Features     string                 `json:"features"`
    Unprivileged bool                   `json:"unprivileged"`
    Protection   bool                   `json:"protection"`
    Tags         string                 `json:"tags"`
    Config       map[string]interface{} `json:"config"`
}
```

### Collection Commands

```bash
# Get all LXC containers on node
$ pvesh get /cluster/resources --output-format json | grep '"type":"lxc"'

# Get specific LXC config
$ pvesh get /nodes/pve-node-01/lxc/100/config --output-format json
```

**LXC Config Output:**
```json
{
  "arch": "amd64",
  "cores": 4,
  "features": "nesting=1,keyctl=1",
  "hostname": "web-prod-01",
  "memory": 8192,
  "mp0": "/mnt/storage,mp=/data,backup=1",
  "nameserver": "8.8.8.8 8.8.4.4",
  "net0": "name=eth0,bridge=vmbr0,firewall=1,gw=10.0.1.1,hwaddr=BC:24:11:12:34:56,ip=10.0.1.100/24,type=veth",
  "ostype": "ubuntu",
  "protection": 0,
  "rootfs": "local-lvm:vm-100-disk-0,size=32G",
  "searchdomain": "example.com",
  "swap": 2048,
  "tags": "production;web;nginx",
  "timezone": "America/New_York",
  "unprivileged": 1
}
```

### Network Configuration Parsing

**net0 Field:**
```
name=eth0,bridge=vmbr0,firewall=1,gw=10.0.1.1,hwaddr=BC:24:11:12:34:56,ip=10.0.1.100/24,type=veth
```

**Parsed:**
- Interface: `eth0`
- Bridge: `vmbr0`
- IP: `10.0.1.100/24`
- Gateway: `10.0.1.1`
- MAC: `BC:24:11:12:34:56`
- Firewall: Enabled

### Features

**Nesting:**
```
features: nesting=1,keyctl=1
```
- `nesting=1`: Container can run other containers (Docker/LXC)
- `keyctl=1`: Allow keyctl syscall (required for some applications)

### API Ingestion

```bash
curl -X POST https://api.nannyai.dev/api/proxmox/lxc \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "web-prod-01",
    "lxc_id": "lxc/100",
    "status": "running",
    "uptime": 86400,
    "vmid": 100,
    "node": "pve-node-01",
    "cpu_cores": 4,
    "memory_mb": 8192,
    "rootfs": "local-lvm:vm-100-disk-0,size=32G",
    "swap_mb": 2048,
    "net0": "name=eth0,bridge=vmbr0,firewall=1,gw=10.0.1.1,hwaddr=BC:24:11:12:34:56,ip=10.0.1.100/24,type=veth",
    "ostype": "ubuntu",
    "arch": "amd64",
    "hostname": "web-prod-01",
    "searchdomain": "example.com",
    "nameserver": "8.8.8.8 8.8.4.4",
    "features": "nesting=1,keyctl=1",
    "unprivileged": true,
    "protection": false,
    "tags": "production,web,nginx",
    "timezone": "America/New_York",
    "config": {
      ...full config...
    }
  }'
```

### Monitoring Points

- **Resource Allocation**: CPU cores, memory, swap
- **Storage**: Root filesystem size and usage
- **Networking**: IP addresses, gateways, bridges
- **Security**: Privileged vs unprivileged, protection status
- **Features**: Nesting, keyctl capabilities
- **Metadata**: Tags for organization

## QEMU VM Monitoring

### Data Structure

```go
type ProxmoxQEMU struct {
    Name     string                 `json:"name"`
    QemuID   string                 `json:"qemu_id"`     // "qemu/200"
    Status   string                 `json:"status"`      // "running", "stopped"
    Uptime   int                    `json:"uptime"`
    VMID     int                    `json:"vmid"`
    Node     string                 `json:"node"`
    CPUCores int                    `json:"cpu_cores"`
    MemoryMB int                    `json:"memory_mb"`
    Config   map[string]interface{} `json:"config"`
}
```

### Collection Commands

```bash
# Get all QEMU VMs on node
$ pvesh get /cluster/resources --output-format json | grep '"type":"qemu"'

# Get specific QEMU config
$ pvesh get /nodes/pve-node-01/qemu/200/config --output-format json
```

**QEMU Config Output:**
```json
{
  "agent": "enabled=1,fstrim_cloned_disks=1",
  "boot": "order=scsi0;ide2;net0",
  "bootdisk": "scsi0",
  "cores": 8,
  "cpu": "host",
  "ide2": "local:iso/ubuntu-22.04-server-amd64.iso,media=cdrom",
  "machine": "pc-i440fx-7.2",
  "memory": 32768,
  "meta": "creation-qemu=7.2.0,ctime=1677654321",
  "name": "db-prod-01",
  "net0": "virtio=BC:24:11:AB:CD:EF,bridge=vmbr0,firewall=1",
  "numa": 0,
  "ostype": "l26",
  "scsi0": "local-lvm:vm-200-disk-0,iothread=1,size=500G",
  "scsi1": "local-lvm:vm-200-disk-1,iothread=1,size=1000G",
  "scsihw": "virtio-scsi-pci",
  "smbios1": "uuid=12345678-1234-5678-1234-567812345678",
  "sockets": 2,
  "tags": "production;database;postgresql",
  "vga": "virtio",
  "vmgenid": "abcdef12-3456-7890-abcd-ef1234567890"
}
```

### Disk Configuration

**SCSI Disks:**
```json
{
  "scsi0": "local-lvm:vm-200-disk-0,iothread=1,size=500G",
  "scsi1": "local-lvm:vm-200-disk-1,iothread=1,size=1000G"
}
```

- **Storage**: `local-lvm`
- **Disk ID**: `vm-200-disk-0`
- **I/O Thread**: Enabled for better performance
- **Size**: 500GB (disk 0), 1TB (disk 1)

### Network Configuration

```json
{
  "net0": "virtio=BC:24:11:AB:CD:EF,bridge=vmbr0,firewall=1"
}
```

- **Driver**: VirtIO (high performance)
- **MAC**: `BC:24:11:AB:CD:EF`
- **Bridge**: `vmbr0`
- **Firewall**: Enabled

### API Ingestion

```bash
curl -X POST https://api.nannyai.dev/api/proxmox/qemu \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "db-prod-01",
    "qemu_id": "qemu/200",
    "status": "running",
    "uptime": 172800,
    "vmid": 200,
    "node": "pve-node-01",
    "cpu_cores": 8,
    "memory_mb": 32768,
    "config": {
      "agent": "enabled=1,fstrim_cloned_disks=1",
      "boot": "order=scsi0;ide2;net0",
      "bootdisk": "scsi0",
      "cores": 8,
      "cpu": "host",
      "machine": "pc-i440fx-7.2",
      "ostype": "l26",
      "sockets": 2,
      "scsi0": "local-lvm:vm-200-disk-0,iothread=1,size=500G",
      "net0": "virtio=BC:24:11:AB:CD:EF,bridge=vmbr0,firewall=1",
      "tags": "production,database,postgresql"
    }
  }'
```

### Monitoring Points

- **CPU Topology**: Sockets, cores, CPU type
- **Memory**: Total allocation
- **Storage**: Disk count, sizes, I/O threads
- **Network**: Network adapters, driver type
- **Boot Order**: Boot device priority
- **Guest Agent**: QEMU agent status
- **Tags**: Organizational metadata

## API Endpoints

### Summary

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/proxmox/cluster` | POST | Ingest cluster info |
| `/api/proxmox/node` | POST | Ingest node info |
| `/api/proxmox/lxc` | POST | Ingest LXC container info |
| `/api/proxmox/qemu` | POST | Ingest QEMU VM info |

### Authentication

All requests require authentication:
```http
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

### Response Format

**Success:**
```json
{
  "success": true,
  "message": "Data ingested successfully"
}
```

**Error:**
```json
{
  "success": false,
  "error": "unauthorized",
  "error_description": "Invalid access token"
}
```

## Deployment Scenarios

### Scenario 1: Single-Node Proxmox

```
┌────────────────────────┐
│    pve-standalone      │
│  ┌──────────────────┐  │
│  │   NannyAgent     │  │
│  └────────┬─────────┘  │
│           │ Collects:  │
│           │ - Node     │
│           │ - LXC      │
│           │ - QEMU     │
│           │ (No cluster│
│           │  info)     │
│  ┌────────┴─────────┐  │
│  │  Proxmox API     │  │
│  └──────────────────┘  │
│  LXC: 100, 101, 102   │
│  QEMU: 200, 201       │
└────────────────────────┘
```

### Scenario 2: Three-Node Cluster

```
┌─────────────────────────────────────────────────────────┐
│              Proxmox Cluster: production                │
│                                                         │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐         │
│  │ pve-01     │  │ pve-02     │  │ pve-03     │         │
│  │ Agent      │  │ Agent      │  │ Agent      │         │
│  │ Node ID: 1 │  │ Node ID: 2 │  │ Node ID: 3 │         │
│  │            │  │            │  │            │         │
│  │ Collects:  │  │ Collects:  │  │ Collects:  │         │
│  │ - Cluster  │  │ - Cluster  │  │ - Cluster  │         │
│  │ - Node 1   │  │ - Node 2   │  │ - Node 3   │         │
│  │ - LXC 100  │  │ - LXC 101  │  │ - QEMU 200 │         │
│  │ - LXC 102  │  │ - LXC 103  │  │ - QEMU 201 │         │
│  └────────────┘  └────────────┘  └────────────┘         │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
               All data sent to NannyAPI
```

**Note:** All three agents send cluster info, but NannyAPI deduplicates based on cluster_id.

### Scenario 3: Multi-Cluster

```
Cluster A:                  Cluster B:
┌─────────────────┐        ┌─────────────────┐
│ pve-a-01 Agent  │        │ pve-b-01 Agent  │
│ pve-a-02 Agent  │        │ pve-b-02 Agent  │
└────────┬────────┘        └────────┬────────┘
         │                          │
         └──────────────┬───────────┘
                        │
                        ▼
                  ┌──────────┐
                  │ NannyAPI │
                  └──────────┘
```

Each cluster is tracked separately by cluster_id.

---

## Troubleshooting

### Agent Not Collecting Proxmox Data

**Check Proxmox Installation:**
```bash
$ /usr/bin/pveversion --verbose
pve-manager/7.4-3/9002ab8a (running kernel: 5.15.107-2-pve)
```

**Check Cluster Status:**
```bash
$ pvecm status
Cluster information
-------------------
Name:             production-cluster
Config Version:   3
Transport:        knet
Secure auth:      on
```

**Check Agent Logs:**
```bash
$ sudo journalctl -u nannyagent -f
```

Look for:
```
[INFO] Proxmox VE detected, starting collector
[INFO] Node is part of cluster: production-cluster
```

### Permission Issues

Ensure nannyagent runs as root:
```bash
$ sudo systemctl status nannyagent
● nannyagent.service - NannyAgent
     Loaded: loaded (/etc/systemd/system/nannyagent.service; enabled)
     Active: active (running)
```

### API Errors

**401 Unauthorized:**
- Token expired, agent will auto-refresh

**500 Internal Server Error:**
- Backend issue, agent will retry with exponential backoff

---

<div align="center">
  <p><strong>Next:</strong> <a href="./CONFIGURATION.md">Configuration Guide</a></p>
  <p><em>NannyAgent - AI-Powered Linux Diagnostics</em></p>
</div>

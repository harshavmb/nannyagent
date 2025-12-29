package proxmox

// ProxmoxCluster represents the data structure for a Proxmox cluster.
// Ingestion is based on `pvesh get /cluster/status --output-format json`
type ProxmoxCluster struct {
	ID          string `json:"id,omitempty" db:"id"`
	ClusterName string `json:"name" db:"cluster_name"`
	Nodes       int    `json:"nodes" db:"nodes"`
	Quorate     int    `json:"quorate" db:"quorate"`
	Version     int    `json:"version" db:"version"`
	ClusterID   string `json:"px_cluster_id" db:"px_cluster_id"`
}

// ProxmoxNode represents a node in a Proxmox cluster.
// Ingestion is based on `pvesh get /cluster/status --output-format json`
// and `pvesh get /nodes/{node}/status --output-format json`
type ProxmoxNode struct {
	ID         string `json:"id,omitempty" db:"id"`
	AgentID    string `json:"agent_id" db:"agent_id"`
	ClusterID  string `json:"cluster_id,omitempty" db:"cluster_id"`
	IP         string `json:"ip" db:"ip"`
	Level      string `json:"level" db:"level"`
	Local      int    `json:"local" db:"local"`
	Name       string `json:"name" db:"name"`
	NodeID     int    `json:"nodeid" db:"px_node_id"`
	Online     int    `json:"online" db:"online"`
	PVEVersion string `json:"pveversion" db:"pve_version"`
}

// ProxmoxLXC represents a Linux Container in Proxmox.
// Ingestion is based on `pvesh get /cluster/resources --output-format json`
// and `pvesh get /nodes/{node}/lxc/{vmid}/config --output-format json`
type ProxmoxLXC struct {
	ID        string `json:"id,omitempty" db:"id"`
	AgentID   string `json:"agent_id" db:"agent_id"`
	ClusterID string `json:"cluster_id,omitempty" db:"cluster_id"`
	NodeID    string `json:"node_id" db:"node_id"`
	Name      string `json:"name" db:"name"`
	LXCID     string `json:"lxc_id" db:"lxc_id"` // from 'id' field in proxmox resources example lxc/100
	Status    string `json:"status" db:"status"`
	OSType    string `json:"ostype" db:"ostype"`
	Uptime    int    `json:"uptime" db:"uptime"`
	VMID      int    `json:"vmid" db:"vmid"` // from 'vmid' field in proxmox resources example 100
	Node      string `json:"node"`           // Used for matching
}

// ProxmoxQemu represents a QEMU/KVM virtual machine in Proxmox.
// Ingestion is based on `pvesh get /cluster/resources --output-format json`
// and `pvesh get /nodes/{node}/qemu/{vmid}/config --output-format json`
type ProxmoxQemu struct {
	ID        string `json:"id,omitempty" db:"id"`
	AgentID   string `json:"agent_id" db:"agent_id"`
	ClusterID string `json:"cluster_id,omitempty" db:"cluster_id"`
	NodeID    string `json:"node_id" db:"node_id"`
	Name      string `json:"name" db:"name"`
	QemuID    string `json:"qemu_id" db:"qemu_id"` // from 'id' field in resources
	Status    string `json:"status" db:"status"`
	OSType    string `json:"ostype" db:"ostype"`
	Uptime    int    `json:"uptime" db:"uptime"`
	VMID      int    `json:"vmid" db:"vmid"`
	VMGenID   string `json:"vmgenid,omitempty" db:"vmgenid"`
	KVM       int    `json:"kvm,omitempty" db:"kvm"`
	Boot      string `json:"boot,omitempty" db:"boot"`
	HostCPU   string `json:"cpu,omitempty" db:"host_cpu"`
	Node      string `json:"node"` // Used for matching
}

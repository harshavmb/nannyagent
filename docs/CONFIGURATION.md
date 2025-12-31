# Configuration Guide

<div align="center">
  <img src="https://avatars.githubusercontent.com/u/110624612" alt="NannyAI" width="120"/>
  <h1>Configuration Management</h1>
</div>

## Table of Contents

- [Overview](#overview)
- [Configuration Priority](#configuration-priority)
- [Configuration File](#configuration-file)
- [Environment Variables](#environment-variables)
- [Configuration Options](#configuration-options)
- [Usage Examples](#usage-examples)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

NannyAgent uses a simple, secure configuration system with two sources:

1. **YAML configuration file**: `/etc/nannyagent/config.yaml`
2. **Environment variables**: Override YAML settings

This design provides flexibility for different deployment scenarios while maintaining security.

## Configuration Priority

Configuration is loaded in the following order (later sources override earlier):

1. `/etc/nannyagent/config.yaml` (system-wide YAML config)
2. Environment variables (highest priority - overrides YAML)

**That's it!** There are no `.env` files, no local config files, no other configuration locations.

## Configuration File

### Location

**Only one location is supported:**

```text
/etc/nannyagent/config.yaml
```

### Format

```yaml
# Required: NannyAPI backend URL
nannyapi_url: https://api.nannyai.dev

# Optional: Portal URL for device authorization (default: https://nannyai.dev)
portal_url: https://nannyai.dev

# Optional: Token storage path (default: /var/lib/nannyagent/token.json)
token_path: /var/lib/nannyagent/token.json

# Optional: Metrics collection interval in seconds (default: 30)
metrics_interval: 30

# Optional: Proxmox data collection interval in seconds (default: 300)
proxmox_interval: 300

# Optional: Enable debug logging (default: false)
debug: false
```

### Creating Configuration File

```bash
# Create directory
sudo mkdir -p /etc/nannyagent

# Create configuration file
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
token_path: /var/lib/nannyagent/token.json
metrics_interval: 30
proxmox_interval: 300
debug: false
EOF

# Secure permissions (root only)
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

### Permissions

**Security is critical:**

```bash
# Configuration file should NOT be world-readable
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml

# Verify
ls -la /etc/nannyagent/config.yaml
# Should show: -rw------- 1 root root
```

## Environment Variables

Environment variables have **highest priority** and override values from `/etc/nannyagent/config.yaml`.

### Supported Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `NANNYAPI_URL` | string | **(required)** | NannyAPI backend URL |
| `NANNYAI_PORTAL_URL` | string | `https://nannyai.dev` | Portal URL for device auth |
| `TOKEN_PATH` | string | `/var/lib/nannyagent/token.json` | Token storage location |
| `DEBUG` | bool | `false` | Enable debug logging (`true` or `1`) |

### Using Environment Variables

```bash
# Override API URL for testing
export NANNYAPI_URL=http://localhost:3000
sudo nannyagent --status

# Enable debug mode temporarily
export DEBUG=true
sudo nannyagent --diagnose "check logs"

# Use custom token path
export TOKEN_PATH=/tmp/test-token.json
sudo nannyagent --register
```

### Systemd Service with Environment Variables

If using systemd, you can add environment variables to the service:

```bash
# Edit service file
sudo systemctl edit nannyagent

# Add override:
[Service]
Environment="NANNYAPI_URL=https://api.nannyai.dev"
Environment="DEBUG=false"

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart nannyagent
```

## Configuration Options

### Required Settings

#### `nannyapi_url` / `NANNYAPI_URL`

**Required.** The backend API endpoint.

**Examples:**
```yaml
nannyapi_url: https://api.nannyai.dev  # Production
nannyapi_url: http://localhost:3000    # Development
```

**Environment variable:**
```bash
export NANNYAPI_URL=https://api.nannyai.dev
```

### Optional Settings

#### `portal_url` / `NANNYAI_PORTAL_URL`

Portal URL for device authorization flow.

**Default:** `https://nannyai.dev`

**Examples:**
```yaml
portal_url: https://nannyai.dev  # Production
portal_url: http://localhost:3001  # Development
```

#### `token_path` / `TOKEN_PATH`

Path to store OAuth tokens.

**Default:** `/var/lib/nannyagent/token.json`

**Examples:**
```yaml
token_path: /var/lib/nannyagent/token.json  # Default
token_path: /custom/path/token.json          # Custom
```

#### `metrics_interval`

System metrics collection interval in seconds.

**Default:** `30` (30 seconds)

**Examples:**
```yaml
metrics_interval: 30   # Every 30 seconds (default)
metrics_interval: 60   # Every minute
metrics_interval: 300  # Every 5 minutes
```

**Note:** No environment variable override available for this setting.

#### `proxmox_interval`

Proxmox data collection interval in seconds.

**Default:** `300` (5 minutes)

**Examples:**
```yaml
proxmox_interval: 300   # Every 5 minutes (default)
proxmox_interval: 600   # Every 10 minutes
proxmox_interval: 1800  # Every 30 minutes
```

**Note:** No environment variable override available for this setting.

#### `debug` / `DEBUG`

Enable debug-level logging for troubleshooting.

**Default:** `false`

**Examples:**
```yaml
debug: false  # Normal logging (default)
debug: true   # Debug logging enabled
```

**Environment variable:**
```bash
export DEBUG=true  # or DEBUG=1
```

## Usage Examples

### Standard Configuration

**File:** `/etc/nannyagent/config.yaml`
```yaml
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
token_path: /var/lib/nannyagent/token.json
metrics_interval: 30
proxmox_interval: 300
debug: false
```

**Usage:**
```bash
# All commands use config file
sudo nannyagent --status
sudo nannyagent --register
sudo nannyagent --diagnose "nginx is down"
```

### Development Configuration

**File:** `/etc/nannyagent/config.yaml`
```yaml
nannyapi_url: http://localhost:3000
portal_url: http://localhost:3001
debug: true
metrics_interval: 60
proxmox_interval: 600
```

**Usage:**
```bash
# Test against local backend
sudo nannyagent --status
```

### Temporary Override

**File:** `/etc/nannyagent/config.yaml` (production settings)
```yaml
nannyapi_url: https://api.nannyai.dev
debug: false
```

**Override temporarily:**
```bash
# Use staging API for one command
export NANNYAPI_URL=https://staging-api.nannyai.dev
sudo nannyagent --status

# Or inline
sudo NANNYAPI_URL=https://staging-api.nannyai.dev nannyagent --status
```

### Systemd Service

The systemd service automatically loads `/etc/nannyagent/config.yaml`:

```bash
# Start daemon
sudo systemctl start nannyagent

# Check status
sudo systemctl status nannyagent

# View logs
sudo journalctl -u nannyagent -f
```

**Service file example:** `/etc/systemd/system/nannyagent.service`
```ini
[Unit]
Description=NannyAgent - AI-Powered Linux Diagnostic Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/nannyagent --daemon
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

# Optional: Override settings
# Environment="DEBUG=true"

[Install]
WantedBy=multi-user.target
```

## Security Best Practices

### 1. Protect Configuration Files

```bash
# YAML config should be root-only readable
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

### 2. Protect Token Storage

```bash
# Token file contains OAuth credentials
sudo mkdir -p /var/lib/nannyagent
sudo chmod 700 /var/lib/nannyagent
sudo chmod 600 /var/lib/nannyagent/token.json
```

### 3. Use HTTPS Only

```yaml
# ALWAYS use HTTPS for production
nannyapi_url: https://api.nannyai.dev  # ✓ Secure

# NEVER use HTTP in production
# nannyapi_url: http://api.nannyai.dev  # ✗ Insecure
```

### 4. Limit Debug Mode

```yaml
# Disable debug in production (avoid sensitive data in logs)
debug: false
```

### 5. Review Logs Regularly

```bash
# Check agent logs for suspicious activity
sudo journalctl -u nannyagent | grep -i "error\|auth\|failed"
```

## Troubleshooting

### "missing required configuration: NANNYAPI_URL must be set"

**Cause:** No configuration file or `NANNYAPI_URL` not set.

**Solution:**
```bash
# Create config file
sudo mkdir -p /etc/nannyagent
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
EOF
sudo chmod 600 /etc/nannyagent/config.yaml

# Or use environment variable
export NANNYAPI_URL=https://api.nannyai.dev
```

### Configuration File Not Found

**Check if file exists:**
```bash
ls -la /etc/nannyagent/config.yaml
```

**If missing, create it:**
```bash
sudo mkdir -p /etc/nannyagent
sudo tee /etc/nannyagent/config.yaml > /dev/null <<EOF
nannyapi_url: https://api.nannyai.dev
portal_url: https://nannyai.dev
EOF
sudo chmod 600 /etc/nannyagent/config.yaml
```

### Permission Denied Reading Config

**Check permissions:**
```bash
ls -la /etc/nannyagent/config.yaml
# Should be: -rw------- 1 root root
```

**Fix permissions:**
```bash
sudo chmod 600 /etc/nannyagent/config.yaml
sudo chown root:root /etc/nannyagent/config.yaml
```

**Run as root:**
```bash
# Agent requires root for eBPF
sudo nannyagent --status
```

### Invalid YAML Syntax

**Check YAML syntax:**
```bash
# Install yamllint
sudo apt-get install yamllint  # Ubuntu/Debian

# Validate syntax
yamllint /etc/nannyagent/config.yaml
```

**Common YAML mistakes:**
```yaml
# WRONG: Missing space after colon
nannyapi_url:https://api.nannyai.dev

# CORRECT: Space after colon
nannyapi_url: https://api.nannyai.dev

# WRONG: Using tabs for indentation
debug:	true

# CORRECT: Use spaces for indentation
debug: true
```

### View Loaded Configuration

**Check what the agent sees:**
```bash
# Run with debug to see config loading
sudo DEBUG=true nannyagent --status 2>&1 | grep -i config

# Expected output:
# INFO: Loaded configuration from /etc/nannyagent/config.yaml
```

### Verify Environment Variables

**Check what's set:**
```bash
# Show all NANNY* variables
env | grep NANNY

# Check specific variable
echo $NANNYAPI_URL
```

### Systemd Service Configuration Issues

**Check service environment:**
```bash
# View service environment
sudo systemctl show nannyagent --property=Environment

# View full service file
sudo systemctl cat nannyagent
```

**Check logs for config errors:**
```bash
# View agent logs
sudo journalctl -u nannyagent -n 50

# Filter for config-related messages
sudo journalctl -u nannyagent | grep -i "config\|load"
```

---

## Complete Configuration Example

**Production Configuration:**

```yaml
# /etc/nannyagent/config.yaml

# Backend API endpoint (required)
nannyapi_url: https://api.nannyai.dev

# Portal URL for device authorization
portal_url: https://nannyai.dev

# Token storage location
token_path: /var/lib/nannyagent/token.json

# Metrics collection every 30 seconds
metrics_interval: 30

# Proxmox data collection every 5 minutes
proxmox_interval: 300

# Disable debug logging in production
debug: false
```

**Permissions:**
```bash
-rw------- 1 root root /etc/nannyagent/config.yaml
```

---

**For more information:**
- [Installation Guide](INSTALLATION.md)
- [Architecture Documentation](ARCHITECTURE.md)
- [API Integration Guide](API_INTEGRATION.md)

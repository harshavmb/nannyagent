# Configuration Management

## Overview

NannyAgent uses a flexible configuration system that allows environment variables to be shared between:
- Systemd service (daemon mode)
- Manual CLI commands (diagnose, status, register)
- Development/testing

## Configuration Priority

Configuration is loaded in the following order (later overrides earlier):

1. `/etc/nannyagent/config.yaml` (system-wide YAML config)
2. `/etc/nannyagent/config.env` (system-wide environment file) ⭐ **Recommended**
3. `./config.yaml` (local YAML for development)
4. `./.env` (local .env for development)
5. Environment variables (highest priority)

## Shared Configuration File

### Location
`/etc/nannyagent/config.env`

### Purpose
This file is used by **both**:
- The systemd service (via `EnvironmentFile=-/etc/nannyagent/config.env`)
- Manual CLI commands (loaded automatically by the agent)

### Format
```bash
# NannyAgent Configuration
SUPABASE_PROJECT_URL=https://<supabase-project>.supabase.co

# Optional settings
# NANNYAI_PORTAL_URL=https://nannyai.dev
# TOKEN_PATH=/var/lib/nannyagent/token.json
# DEBUG=false
```

### Permissions
```bash
sudo chmod 600 /etc/nannyagent/config.env  # Root only
```

## Installation

### Automatic (via install.sh)
The installation script automatically creates `/etc/nannyagent/config.env` with default values:

```bash
curl -fsSL https://raw.githubusercontent.com/harshavmb/nannyagent/main/install.sh | sudo bash
```

### Manual (via Makefile)
```bash
make install-system
```

This will:
1. Copy the binary to `/usr/local/bin/nannyagent`
2. Create `/etc/nannyagent/config.env` with default configuration
3. Install the systemd service
4. Reload systemd

### Manual Configuration
```bash
sudo mkdir -p /etc/nannyagent
sudo nano /etc/nannyagent/config.env
# Add: SUPABASE_PROJECT_URL=https://your-project.supabase.co
sudo chmod 600 /etc/nannyagent/config.env
```

## Usage Examples

### Systemd Service
The service automatically loads `/etc/nannyagent/config.env`:

```bash
sudo systemctl start nannyagent
sudo systemctl status nannyagent
```

### Manual CLI Commands
Commands automatically load `/etc/nannyagent/config.env` - **no need to export env vars**:

```bash
# Status check
sudo nannyagent --status

# Diagnosis
sudo nannyagent --diagnose "disk is full on /var partition"

# Registration
sudo nannyagent --register
```

### Override Configuration
You can override the file configuration with environment variables:

```bash
sudo SUPABASE_PROJECT_URL=https://custom-url.supabase.co nannyagent --status
```

## Benefits

✅ **Single Source of Truth**: One config file for all operations  
✅ **No User Setup**: Manual commands work without exporting env vars  
✅ **Security**: File is root-only readable (`chmod 600`)  
✅ **Consistency**: Systemd service and CLI use identical configuration  
✅ **Audit Trail**: All operations logged to syslog via journalctl  

## Verification

Check that configuration is loaded correctly:

```bash
# View the config file
sudo cat /etc/nannyagent/config.env

# Test that commands load it
sudo env -i PATH="$PATH" nannyagent --version  # Should work
sudo env -i PATH="$PATH" nannyagent --status   # Should work
```

## Troubleshooting

### "missing required environment variable: SUPABASE_PROJECT_URL"

**Cause**: `/etc/nannyagent/config.env` doesn't exist or is empty

**Solution**:
```bash
sudo mkdir -p /etc/nannyagent
echo "SUPABASE_PROJECT_URL=https://<supabase-project>.supabase.co" | sudo tee /etc/nannyagent/config.env
sudo chmod 600 /etc/nannyagent/config.env
```

### Configuration not loading

**Check permissions**:
```bash
ls -la /etc/nannyagent/config.env
# Should show: -rw------- 1 root root
```

**Check systemd service**:
```bash
sudo systemctl cat nannyagent | grep EnvironmentFile
# Should show: EnvironmentFile=-/etc/nannyagent/config.env
```

### View loaded configuration

```bash
# Check what the service sees
sudo systemctl show nannyagent --property=Environment

# Check logs for config loading
sudo journalctl -t nannyagent | grep "Loaded configuration"
```

# GoReleaser Build Documentation

## Overview

This project uses [GoReleaser](https://goreleaser.com/) for building, packaging, and releasing nannyagent binaries.

## Local Development

### Prerequisites
```bash
go install github.com/goreleaser/goreleaser/v2@latest
```

### Build Snapshot (Local Testing)
```bash
# Build for your current platform only
goreleaser build --snapshot --clean --single-target

# Build for all platforms
goreleaser build --snapshot --clean
```

Binaries will be in `dist/` directory.

### Test Configuration
```bash
goreleaser check
```

## Release Process

### Automated Releases (Recommended)

1. Update VERSION file:
   ```bash
   echo "0.0.3" > VERSION
   ```

2. Commit and tag:
   ```bash
   git add VERSION
   git commit -m "Release v0.0.3"
   git tag v0.0.3
   git push origin main --tags
   ```

3. GitHub Actions will automatically:
   - Run tests
   - Build for linux/amd64 and linux/arm64
   - Generate SHA256 checksums
   - Create GitHub release with artifacts
   - Upload archives and checksums

### Manual Release (Not Recommended)

```bash
# Requires GITHUB_TOKEN environment variable
export GITHUB_TOKEN="your_github_token"
goreleaser release --clean
```

## Build Artifacts

GoReleaser generates:
- `nannyagent_VERSION_linux_amd64.tar.gz` - AMD64 binary + docs
- `nannyagent_VERSION_linux_arm64.tar.gz` - ARM64 binary + docs
- `checksums.txt` - SHA256 checksums for verification

## Installation

The `install.sh` script automatically:
1. Downloads the appropriate archive for your architecture
2. Downloads and verifies SHA256 checksum
3. Extracts and installs the binary

```bash
curl -fsSL https://raw.githubusercontent.com/harshavmb/nannyagent/main/install.sh | sudo bash
```

## Configuration

See `.goreleaser.yaml` for full configuration. Key features:
- CGO disabled for static binaries
- Version injected via ldflags
- Archives include LICENSE, README, config examples
- SHA256 checksum generation
- GitHub release automation

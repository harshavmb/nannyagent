.PHONY: build run clean test install build-prod build-release install-system fmt lint help

VERSION := 0.0.1
BUILD_DIR := ./build
BINARY_NAME := nannyagent

# Build the application
build:
	go build -o $(BINARY_NAME) .

# Run the application
run: build
	./$(BINARY_NAME)

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	go test ./...

# Install dependencies
install:
	go mod tidy
	go mod download

# Build for production with optimizations (current architecture)
build-prod:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
		-ldflags '-w -s -X main.Version=$(VERSION)' \
		-o $(BINARY_NAME) .

# Build release binaries for both architectures
build-release: clean
	@echo "Building release binaries for version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@echo "Building for linux/amd64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo \
		-ldflags '-w -s -X main.Version=$(VERSION)' \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Building for linux/arm64..."
	@CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -installsuffix cgo \
		-ldflags '-w -s -X main.Version=$(VERSION)' \
		-o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "Generating checksums..."
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)-linux-amd64 > $(BINARY_NAME)-linux-amd64.sha256
	@cd $(BUILD_DIR) && sha256sum $(BINARY_NAME)-linux-arm64 > $(BINARY_NAME)-linux-arm64.sha256
	@echo "Build complete! Artifacts in $(BUILD_DIR)/"
	@ls -lh $(BUILD_DIR)/

# Install system-wide (requires sudo)
install-system: build-prod
	sudo cp $(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)

# Format code
fmt:
	go fmt ./...

# Run linter (if golangci-lint is installed)
lint:
	golangci-lint run

# Show help
help:
	@echo "NannyAgent Makefile - Available commands:"
	@echo ""
	@echo "  make build           - Build the application for current platform"
	@echo "  make run             - Build and run the application"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make test            - Run tests"
	@echo "  make install         - Install Go dependencies"
	@echo "  make build-prod      - Build for production (optimized, current arch)"
	@echo "  make build-release   - Build release binaries for amd64 and arm64"
	@echo "  make install-system  - Install system-wide (requires sudo)"
	@echo "  make fmt             - Format code"
	@echo "  make lint            - Run linter"
	@echo "  make help            - Show this help"
	@echo ""
	@echo "Version: $(VERSION)"

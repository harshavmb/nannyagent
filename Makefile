.PHONY: build run clean test install

# Build the application
build:
	go build -o nanny-agent .

# Run the application
run: build
	./nanny-agent

# Clean build artifacts
clean:
	rm -f nanny-agent

# Run tests
test:
	go test ./...

# Install dependencies
install:
	go mod tidy
	go mod download

# Build for production with optimizations
build-prod:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o nanny-agent .

# Install system-wide (requires sudo)
install-system: build-prod
	sudo cp nanny-agent /usr/local/bin/
	sudo chmod +x /usr/local/bin/nanny-agent

# Format code
fmt:
	go fmt ./...

# Run linter (if golangci-lint is installed)
lint:
	golangci-lint run

# Show help
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  run           - Build and run the application"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  install       - Install dependencies"
	@echo "  build-prod    - Build for production"
	@echo "  install-system- Install system-wide (requires sudo)"
	@echo "  fmt           - Format code"
	@echo "  lint          - Run linter"
	@echo "  help          - Show this help"

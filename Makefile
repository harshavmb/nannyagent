.PHONY: build run clean test install snapshot release help

VERSION := $(shell cat VERSION)
BINARY_NAME := nannyagent

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o $(BINARY_NAME) .

run: build
	./$(BINARY_NAME)

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

test:
	go test -v ./...

install:
	go mod tidy
	go mod download

snapshot:
	goreleaser build --snapshot --clean

snapshot-single:
	goreleaser build --snapshot --clean --single-target

release:
	goreleaser release --clean

check:
	goreleaser check

install-system: build
	sudo cp $(BINARY_NAME) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(BINARY_NAME)
	sudo mkdir -p /etc/nannyagent
	sudo bash -c 'echo "SUPABASE_PROJECT_URL=https://<supabase-project>.supabase.co" > /etc/nannyagent/config.env'
	sudo chmod 600 /etc/nannyagent/config.env
	sudo cp nannyagent.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Service installed. Run: sudo systemctl start nannyagent"

fmt:
	go fmt ./...

lint:
	golangci-lint run

help:
	@echo "NannyAgent Build System (GoReleaser)"
	@echo ""
	@echo "Development:"
	@echo "  make build              - Build for current platform"
	@echo "  make run                - Build and run"
	@echo "  make test               - Run tests"
	@echo "  make clean              - Clean artifacts"
	@echo ""
	@echo "GoReleaser:"
	@echo "  make snapshot           - Build all platforms (snapshot)"
	@echo "  make snapshot-single    - Build current platform only"
	@echo "  make release            - Create GitHub release"
	@echo "  make check              - Validate goreleaser config"
	@echo ""
	@echo "Deployment:"
	@echo "  make install-system     - Install as systemd service"
	@echo ""
	@echo "Version: $(VERSION)"

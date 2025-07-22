.PHONY: all build test lint clean docker-build help

BINARY_NAME=tsdnsproxy
DOCKER_IMAGE=ghcr.io/rajsinghtech/tsdnsproxy
VERSION?=latest
GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)
GOARCH?=$(shell go env GOARCH)
GOOS?=$(shell go env GOOS)

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@go build -o $(GOBIN)/$(BINARY_NAME) ./cmd/tsdnsproxy

# Build for multiple architectures
build-all:
	@echo "Building for multiple architectures..."
	GOOS=linux GOARCH=amd64 go build -o $(GOBIN)/$(BINARY_NAME)-linux-amd64 ./cmd/tsdnsproxy
	GOOS=linux GOARCH=arm64 go build -o $(GOBIN)/$(BINARY_NAME)-linux-arm64 ./cmd/tsdnsproxy
	GOOS=darwin GOARCH=amd64 go build -o $(GOBIN)/$(BINARY_NAME)-darwin-amd64 ./cmd/tsdnsproxy
	GOOS=darwin GOARCH=arm64 go build -o $(GOBIN)/$(BINARY_NAME)-darwin-arm64 ./cmd/tsdnsproxy

# Run tests
test:
	@echo "Running tests..."
	@go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

# Run tests with coverage report
test-coverage: test
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.txt -o coverage.html
	@echo "Coverage report generated at coverage.html"

# Run linter
lint:
	@echo "Running linter..."
	@if ! which golangci-lint > /dev/null; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@golangci-lint run

# Format code
fmt:
	@echo "Formatting code..."
	@go fmt ./...
	@gofumpt -l -w .

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(GOBIN)
	@rm -f coverage.txt coverage.html

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	@docker build -t $(DOCKER_IMAGE):$(VERSION) .

# Build multi-arch Docker image
docker-buildx:
	@echo "Building multi-arch Docker image..."
	@docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE):$(VERSION) .

# Push Docker image
docker-push: docker-buildx
	@echo "Pushing Docker image..."
	@docker buildx build --platform linux/amd64,linux/arm64 -t $(DOCKER_IMAGE):$(VERSION) --push .

# Run locally
run: build
	@echo "Running $(BINARY_NAME)..."
	@$(GOBIN)/$(BINARY_NAME)

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

# Verify dependencies
verify:
	@echo "Verifying dependencies..."
	@go mod verify

# Generate mocks (if needed in future)
generate:
	@echo "Running go generate..."
	@go generate ./...

# Run all checks (lint, test, build)
all: deps lint test build

# Show help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for multiple architectures"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  clean         - Clean build artifacts"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-buildx - Build multi-arch Docker image"
	@echo "  docker-push   - Build and push multi-arch Docker image"
	@echo "  run           - Build and run locally"
	@echo "  deps          - Install dependencies"
	@echo "  verify        - Verify dependencies"
	@echo "  generate      - Run go generate"
	@echo "  all           - Run all checks (lint, test, build)"
	@echo "  help          - Show this help message"
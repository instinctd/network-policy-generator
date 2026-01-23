.PHONY: build build-linux build-darwin build-windows clean test install help

BINARY_NAME=hubble-collector

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

build:
	@echo "Building $(BINARY_NAME)..."
	$(GOBUILD) -o $(BINARY_NAME) hubble-collector.go
	@echo "Build complete: ./$(BINARY_NAME)"

build-linux:
	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-linux hubble-collector.go
	@echo "Build complete: ./$(BINARY_NAME)-linux"

build-darwin:
	@echo "Building for macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME)-darwin hubble-collector.go
	@echo "Build complete: ./$(BINARY_NAME)-darwin"

build-darwin-arm64:
	@echo "Building for macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BINARY_NAME)-darwin-arm64 hubble-collector.go
	@echo "Build complete: ./$(BINARY_NAME)-darwin-arm64"

build-windows:
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BINARY_NAME).exe hubble-collector.go
	@echo "Build complete: ./$(BINARY_NAME).exe"

build-all: build-linux build-darwin build-darwin-arm64 build-windows
	@echo "All builds complete"

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux
	rm -f $(BINARY_NAME)-darwin
	rm -f $(BINARY_NAME)-darwin-arm64
	rm -f $(BINARY_NAME).exe
	@echo "Clean complete"

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	@echo "Dependencies downloaded"

tidy:
	@echo "Tidying dependencies..."
	$(GOMOD) tidy
	@echo "Dependencies tidied"

install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete"

test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

help:
	@echo "Available targets:"
	@echo "  build              - Build for current platform"
	@echo "  build-linux        - Build for Linux (amd64)"
	@echo "  build-darwin       - Build for macOS (amd64)"
	@echo "  build-darwin-arm64 - Build for macOS (arm64/Apple Silicon)"
	@echo "  build-windows      - Build for Windows (amd64)"
	@echo "  build-all          - Build for all platforms"
	@echo "  clean              - Remove build artifacts"
	@echo "  deps               - Download dependencies"
	@echo "  tidy               - Tidy dependencies"
	@echo "  install            - Install binary to /usr/local/bin"
	@echo "  test               - Run tests"
	@echo "  help               - Display this help message"
	@echo ""
	@echo "Example usage:"
	@echo "  make build"
	@echo "  ./$(BINARY_NAME) -n production -o flows.json"

.DEFAULT_GOAL := help
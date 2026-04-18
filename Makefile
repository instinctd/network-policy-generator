.PHONY: build build-linux build-darwin build-darwin-arm64 build-windows build-all clean deps tidy test lint install release krew-manifest help

BINARY_NAME  = kubectl-hubble-collector
PLUGIN_NAME  = hubble-collector
BUILD_PKG    = ./cmd/collector
DIST_DIR     = dist
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "v0.0.0")
GITHUB_REPO  = instinctd/network-policy-generator

GOCMD  = go
GOTEST = $(GOCMD) test

build:
	@echo "Building $(BINARY_NAME)..."
	$(GOCMD) build -ldflags="-X main.version=$(VERSION)" -o $(BINARY_NAME) $(BUILD_PKG)
	@echo "Build complete: ./$(BINARY_NAME)"

build-linux:
	@echo "Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 $(GOCMD) build -ldflags="-X main.version=$(VERSION)" -o $(BINARY_NAME)-linux-amd64 $(BUILD_PKG)
	@echo "Build complete: ./$(BINARY_NAME)-linux-amd64"

build-darwin:
	@echo "Building for macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 $(GOCMD) build -ldflags="-X main.version=$(VERSION)" -o $(BINARY_NAME)-darwin-amd64 $(BUILD_PKG)
	@echo "Build complete: ./$(BINARY_NAME)-darwin-amd64"

build-darwin-arm64:
	@echo "Building for macOS (arm64)..."
	GOOS=darwin GOARCH=arm64 $(GOCMD) build -ldflags="-X main.version=$(VERSION)" -o $(BINARY_NAME)-darwin-arm64 $(BUILD_PKG)
	@echo "Build complete: ./$(BINARY_NAME)-darwin-arm64"

build-windows:
	@echo "Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 $(GOCMD) build -ldflags="-X main.version=$(VERSION)" -o $(BINARY_NAME)-windows-amd64.exe $(BUILD_PKG)
	@echo "Build complete: ./$(BINARY_NAME)-windows-amd64.exe"

build-all: build-linux build-darwin build-darwin-arm64 build-windows
	@echo "All platform builds complete"

release: build-all
	@echo "Packaging release $(VERSION)..."
	@mkdir -p $(DIST_DIR)
	@for target in linux-amd64 darwin-amd64 darwin-arm64; do \
		cp $(BINARY_NAME)-$$target $(DIST_DIR)/$(BINARY_NAME); \
		cp LICENSE $(DIST_DIR)/LICENSE; \
		tar -czf $(DIST_DIR)/$(BINARY_NAME)-$$target.tar.gz -C $(DIST_DIR) $(BINARY_NAME) LICENSE; \
		rm $(DIST_DIR)/$(BINARY_NAME) $(DIST_DIR)/LICENSE; \
		sha256sum $(DIST_DIR)/$(BINARY_NAME)-$$target.tar.gz | awk '{print $$1}' > $(DIST_DIR)/$(BINARY_NAME)-$$target.tar.gz.sha256; \
		echo "Packaged: $(DIST_DIR)/$(BINARY_NAME)-$$target.tar.gz"; \
	done
	@cp $(BINARY_NAME)-windows-amd64.exe $(DIST_DIR)/$(BINARY_NAME).exe
	@cp LICENSE $(DIST_DIR)/LICENSE
	@tar -czf $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.tar.gz -C $(DIST_DIR) $(BINARY_NAME).exe LICENSE
	@rm $(DIST_DIR)/$(BINARY_NAME).exe $(DIST_DIR)/LICENSE
	@sha256sum $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.tar.gz | awk '{print $$1}' > $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.tar.gz.sha256
	@echo "Packaged: $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.tar.gz"
	@echo "Release artifacts ready in $(DIST_DIR)/"

krew-manifest: release
	@echo "Generating krew manifest for $(VERSION)..."
	@VERSION=$(VERSION) GITHUB_REPO=$(GITHUB_REPO) \
		BINARY_NAME=$(BINARY_NAME) PLUGIN_NAME=$(PLUGIN_NAME) DIST_DIR=$(DIST_DIR) \
		bash scripts/gen-krew-manifest.sh
	@echo "Manifest written to $(DIST_DIR)/$(PLUGIN_NAME).yaml"

clean:
	@echo "Cleaning..."
	$(GOCMD) clean
	rm -f $(BINARY_NAME) $(BINARY_NAME)-linux-amd64 $(BINARY_NAME)-darwin-amd64 $(BINARY_NAME)-darwin-arm64 $(BINARY_NAME)-windows-amd64.exe
	rm -rf $(DIST_DIR)
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
	@echo "  release            - Build all platforms and package tarballs + SHA256"
	@echo "  krew-manifest      - Build release and generate krew plugin manifest"
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
	@echo "  make release VERSION=v1.0.0"
	@echo "  make krew-manifest VERSION=v1.0.0"

.DEFAULT_GOAL := help
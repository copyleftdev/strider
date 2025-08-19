# STRIDER Security Analysis Platform Makefile
# Provides automation for building, testing, and deployment tasks

# Variables
BINARY_NAME=strider
MOCKSERVER_BINARY=mockserver
CMD_DIR=./cmd
BUILD_DIR=./build
COVERAGE_DIR=./coverage
BENCHMARK_DIR=./benchmark-results
TEST_RESULTS_DIR=./test-results

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Build flags
LDFLAGS=-ldflags "-s -w"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Default target
.PHONY: all
all: clean deps fmt vet test build

# Help target
.PHONY: help
help: ## Show this help message
	@echo "STRIDER Security Analysis Platform - Available Make Targets:"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo ""

# Dependencies
.PHONY: deps
deps: ## Download and verify dependencies
	$(GOMOD) download
	$(GOMOD) verify
	$(GOMOD) tidy

# Formatting
.PHONY: fmt
fmt: ## Format Go code
	$(GOFMT) ./...

# Linting and vetting
.PHONY: vet
vet: ## Run go vet
	$(GOVET) ./...

.PHONY: lint
lint: ## Run golangci-lint (requires golangci-lint to be installed)
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Run: curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$$(go env GOPATH)/bin v1.54.2"; exit 1)
	golangci-lint run

# Building
.PHONY: build
build: ## Build STRIDER binary
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)/strider/main.go
	chmod +x $(BUILD_DIR)/$(BINARY_NAME)

.PHONY: build-mockserver
build-mockserver: ## Build mock server binary
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(MOCKSERVER_BINARY) $(CMD_DIR)/mockserver/main.go
	chmod +x $(BUILD_DIR)/$(MOCKSERVER_BINARY)

.PHONY: build-all
build-all: build build-mockserver ## Build all binaries

.PHONY: install
install: ## Install STRIDER to GOPATH/bin
	$(GOBUILD) $(BUILD_FLAGS) -o $(GOPATH)/bin/$(BINARY_NAME) $(CMD_DIR)/strider/main.go

# Cross-compilation
.PHONY: build-linux
build-linux: ## Build for Linux
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)/strider/main.go

.PHONY: build-windows
build-windows: ## Build for Windows
	mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)/strider/main.go

.PHONY: build-darwin
build-darwin: ## Build for macOS
	mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)/strider/main.go

.PHONY: build-cross
build-cross: build-linux build-windows build-darwin ## Build for all platforms

# Testing
.PHONY: test
test: ## Run unit tests (excluding integration tests)
	$(GOTEST) -v ./internal/... ./pkg/... ./cmd/...

.PHONY: test-all
test-all: build-all ## Run all tests including integration tests
	$(GOTEST) -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	mkdir -p $(COVERAGE_DIR)
	$(GOTEST) -v -coverprofile=$(COVERAGE_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(COVERAGE_DIR)/coverage.out -o $(COVERAGE_DIR)/coverage.html
	@echo "Coverage report generated: $(COVERAGE_DIR)/coverage.html"

.PHONY: test-race
test-race: ## Run tests with race detection
	$(GOTEST) -v -race ./...

.PHONY: test-integration
test-integration: build-all ## Run integration tests
	@echo "Starting mock server for integration tests..."
	./$(BUILD_DIR)/$(MOCKSERVER_BINARY) &
	@sleep 3
	$(GOTEST) -v ./test/...
	@pkill -f $(MOCKSERVER_BINARY) || true

.PHONY: test-comprehensive
test-comprehensive: build build-mockserver ## Run comprehensive security rule tests
	@echo "Running comprehensive security validation tests..."
	./comprehensive_test.sh

.PHONY: benchmark
benchmark: build build-mockserver ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	./benchmark_test.sh

# Development helpers
.PHONY: run
run: build ## Build and run STRIDER with default config
	./$(BUILD_DIR)/$(BINARY_NAME) --help

.PHONY: run-mockserver
run-mockserver: build-mockserver ## Build and run mock server
	./$(BUILD_DIR)/$(MOCKSERVER_BINARY)

.PHONY: dev-scan
dev-scan: build build-mockserver ## Run a development scan against mock server
	@echo "Starting mock server..."
	./$(BUILD_DIR)/$(MOCKSERVER_BINARY) &
	@sleep 3
	@echo "Running STRIDER scan..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan http://localhost:9999 --max-pages 5 --enable-ai --output ./dev-results
	@pkill -f $(MOCKSERVER_BINARY) || true

# Cleaning
.PHONY: clean
clean: ## Clean build artifacts and temporary files
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -rf ./test-results
	rm -rf ./test-reports
	rm -rf $(BENCHMARK_DIR)
	rm -rf $(TEST_RESULTS_DIR)
	rm -f $(BINARY_NAME)
	rm -f $(MOCKSERVER_BINARY)
	rm -f *.log
	rm -f *.db

.PHONY: clean-cache
clean-cache: ## Clean Go module cache
	$(GOCMD) clean -modcache

# Security and quality
.PHONY: security-scan
security-scan: ## Run security scan with gosec
	@which gosec > /dev/null || (echo "gosec not installed. Run: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; exit 1)
	gosec ./...

.PHONY: vuln-check
vuln-check: ## Check for known vulnerabilities
	@which govulncheck > /dev/null || (echo "govulncheck not installed. Run: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1)
	govulncheck ./...

# Documentation
.PHONY: docs
docs: ## Generate documentation
	@echo "Generating Go documentation..."
	$(GOCMD) doc -all ./... > docs/api.md

# Release preparation
.PHONY: pre-commit
pre-commit: clean deps fmt vet lint test security-scan ## Run all pre-commit checks

.PHONY: release-check
release-check: pre-commit test-comprehensive benchmark ## Full release validation

# Docker (if Dockerfile exists)
.PHONY: docker-build
docker-build: ## Build Docker image
	@if [ -f Dockerfile ]; then \
		docker build -t strider:latest .; \
	else \
		echo "Dockerfile not found. Skipping Docker build."; \
	fi

.PHONY: docker-run
docker-run: ## Run Docker container
	@if [ -f Dockerfile ]; then \
		docker run --rm -it strider:latest; \
	else \
		echo "Dockerfile not found. Skipping Docker run."; \
	fi

# Utility targets
.PHONY: version
version: ## Show Go version
	$(GOCMD) version

.PHONY: env
env: ## Show Go environment
	$(GOCMD) env

.PHONY: mod-graph
mod-graph: ## Show module dependency graph
	$(GOMOD) graph

.PHONY: mod-why
mod-why: ## Explain why modules are needed (usage: make mod-why MODULE=github.com/example/module)
	$(GOMOD) why $(MODULE)

# Quick development workflow
.PHONY: dev
dev: clean deps fmt vet test build ## Quick development build cycle

.PHONY: ci
ci: clean deps fmt vet lint test-race test-coverage security-scan vuln-check build-cross ## CI/CD pipeline simulation

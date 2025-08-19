<div align="center">
  <img src="media/logo.png" alt="STRIDER Logo" width="200"/>
  
  # STRIDER - Expert-Level Security Analysis Platform
  
  [![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](https://golang.org)
  [![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
  [![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://github.com/zuub-code/strider)
  [![Security](https://img.shields.io/badge/Security-100%25%20Coverage-green?style=for-the-badge)](https://github.com/zuub-code/strider)
  [![AI Powered](https://img.shields.io/badge/AI-Ollama%20Integration-purple?style=for-the-badge)](https://ollama.ai)
  [![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-lightgrey?style=for-the-badge)](https://github.com/zuub-code/strider)
</div>

STRIDER is a sophisticated, production-ready security analysis platform that combines advanced web crawling, intelligent network capture, static security analysis, and AI-powered risk assessment using local Ollama models.

## Features

- **Advanced Web Crawling**: Rod-based browser automation with stealth capabilities
- **Security Analysis**: Comprehensive rule-based vulnerability detection
- **AI-Powered Assessment**: Local Ollama integration for intelligent risk grading
- **Multiple Output Formats**: SARIF, JSON, HTML, Markdown, and CSV reports
- **SQLite Storage**: Persistent storage with caching and transaction support
- **Bloom Filter Deduplication**: Efficient URL deduplication for large-scale crawls
- **Rate Limiting**: Configurable request rate limiting
- **Template Engine**: Customizable report templates

## Quick Start

### Prerequisites

- Go 1.21 or later
- Ollama running locally (optional, for AI features)

### Installation

```bash
git clone https://github.com/zuub-code/strider.git
cd strider
go mod tidy
go build -o strider ./cmd/strider
```

### Basic Usage

```bash
# Scan a website
./strider scan https://example.com

# Scan with custom options
./strider scan https://example.com \
  --concurrency 5 \
  --max-pages 200 \
  --max-depth 3 \
  --output ./results \
  --enable-ai

# Initialize default configuration
./strider config init

# Validate configuration
./strider config validate
```

## Configuration

STRIDER uses a YAML configuration file (`.strider.yaml`) for default settings:

```yaml
# Server configuration
server:
  port: 8080
  host: "localhost"
  timeout: 30

# Crawler configuration
crawler:
  default_concurrency: 3
  default_max_pages: 100
  default_max_depth: 5
  default_timeout: 30
  user_agent: "STRIDER/1.0 Security Scanner"
  enable_stealth: false

# AI configuration
ai:
  enabled: true
  base_url: "http://localhost:11434"
  default_model: "llama3.1:8b"
  temperature: 0.1
  max_tokens: 2048
  timeout: 60
```

## Command Line Options

### Scan Command

```bash
strider scan [URL] [flags]
```

**Crawl Configuration:**
- `--concurrency`: Number of concurrent workers (default: 3)
- `--max-pages`: Maximum pages to crawl (default: 100)
- `--max-depth`: Maximum crawl depth (default: 5)
- `--request-timeout`: Request timeout duration
- `--idle-timeout`: Network idle timeout

**Analysis Configuration:**
- `--allow-third-party`: Allow third-party domain crawling
- `--max-body-kb`: Maximum response body size in KB (default: 256)
- `--enable-js`: Enable JavaScript execution (default: true)
- `--enable-images`: Enable image loading (default: false)

**AI Configuration:**
- `--ollama-model`: Ollama model for AI analysis (default: "llama3.1:8b")
- `--enable-ai`: Enable AI-powered analysis (default: true)

**Output Configuration:**
- `--output`: Output directory (default: "./output")
- `--sarif`: Generate SARIF output (default: true)
- `--json`: Generate JSON output (default: true)
- `--markdown`: Generate Markdown report (default: true)

**Advanced Options:**
- `--respect-robots`: Respect robots.txt (default: true)
- `--stealth`: Enable stealth mode
- `--fast-scan`: Enable fast scan mode

## Architecture

STRIDER follows a hexagonal architecture with clear separation of concerns:

```
├── cmd/strider/           # CLI entry point
├── internal/
│   ├── ai/               # AI service integration
│   ├── analysis/         # Security analysis engine
│   ├── app/              # Application orchestration
│   ├── config/           # Configuration management
│   ├── crawler/          # Web crawling engine
│   ├── reporting/        # Report generation
│   └── storage/          # Data persistence
├── pkg/
│   ├── logger/           # Logging utilities
│   └── types/            # Common types
└── docs/                 # Documentation
```

## Output Formats

### SARIF (Static Analysis Results Interchange Format)
Industry-standard format for security analysis results, compatible with GitHub Security tab and other security platforms.

### JSON
Structured JSON output with detailed findings, metadata, and statistics.

### HTML
Interactive HTML reports with charts, filtering, and detailed vulnerability information.

### Markdown
Human-readable Markdown reports suitable for documentation and issue tracking.

### CSV
Tabular format for data analysis and integration with spreadsheet applications.

## AI Integration

STRIDER integrates with Ollama for AI-powered security analysis:

1. **Install Ollama**: Follow instructions at https://ollama.ai
2. **Pull a model**: `ollama pull llama3.1:8b`
3. **Start Ollama**: `ollama serve`
4. **Configure STRIDER**: Set AI configuration in `.strider.yaml`

The AI service provides:
- Intelligent vulnerability grading
- Context-aware risk assessment
- Natural language descriptions
- Remediation suggestions

## Development

### Building from Source

```bash
git clone https://github.com/zuub-code/strider.git
cd strider
make deps
make build
```

### Using the Makefile

STRIDER includes a comprehensive Makefile for development automation:

```bash
# Show all available targets
make help

# Quick development cycle
make dev                    # Clean, deps, format, vet, test, build

# Building
make build                  # Build STRIDER binary
make build-all             # Build STRIDER and mock server
make build-cross           # Cross-compile for Linux, Windows, macOS

# Testing
make test                  # Run unit tests (fast, excludes integration tests)
make test-all              # Run all tests including integration tests
make test-integration      # Run integration tests with mock server
make test-comprehensive    # Run full security rule validation
make test-coverage         # Generate test coverage reports
make benchmark             # Run performance benchmarks

# Code quality
make fmt                   # Format code
make vet                   # Run go vet
make lint                  # Run golangci-lint
make security-scan         # Run gosec security scanner
make vuln-check           # Check for known vulnerabilities

# Development helpers
make dev-scan             # Quick scan against mock server
make run-mockserver       # Start vulnerable mock server

# CI/CD simulation
make ci                   # Full CI pipeline (format, test, build, security)

# Cleaning
make clean                # Clean build artifacts, reports, and temporary files
make clean-cache          # Clean Go module cache
```

### Running Tests

```bash
# Fast unit tests only
make test

# All tests including integration tests
make test-all

# Integration tests with mock server
make test-integration

# Performance benchmarks
make benchmark
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation in the `docs/` directory
- Review the configuration examples

## Performance Benchmarking

STRIDER includes comprehensive performance benchmarking tools to measure and optimize scan performance.

### Running Benchmarks

```bash
# Run comprehensive performance benchmark suite
./benchmark_test.sh

# The script will automatically:
# - Build STRIDER and mock server
# - Run various scan scenarios
# - Measure timing, memory, and throughput metrics
# - Generate detailed performance reports
```

### Benchmark Scenarios

The benchmark suite tests multiple scenarios:

1. **Single Page Scans**
   - Without AI: Fast baseline performance
   - With AI: AI-enhanced analysis performance

2. **Multi-Page Scans**
   - Low concurrency (1 worker): Sequential processing
   - High concurrency (5 workers): Parallel processing
   - With/without AI: Performance comparison

3. **Stress Testing**
   - Large page counts (25+ pages)
   - High concurrency scenarios
   - Memory usage under load

4. **Individual Vulnerability Tests**
   - Per-endpoint performance metrics
   - Rule-specific analysis timing
   - AI grading performance per vulnerability type

### Performance Metrics

The benchmarking system tracks:

- **Timing Metrics**: Duration for each scan phase
- **Throughput Metrics**: Pages/second, findings/second
- **Memory Metrics**: Peak memory usage, GC cycles
- **Resource Utilization**: CPU and memory efficiency

### Sample Performance Results

Typical performance on modern hardware:

```
Single Page (no AI):     ~2-3 seconds, 20+ findings
Single Page (with AI):   ~20-25 seconds, enhanced analysis
Multi-Page (10 pages):   ~15-30 seconds, 200+ findings
Stress Test (25 pages):  ~45-60 seconds, 500+ findings

Throughput:
- Pages/second: 0.5-2.0 (depending on AI usage)
- Findings/second: 8-15 (static analysis)
- Memory usage: 50-200MB peak
```

### Performance Optimization

For optimal performance:

1. **Disable AI for fast scans**: Use `--enable-ai=false` for speed
2. **Adjust concurrency**: Higher values for I/O-bound workloads
3. **Limit page depth**: Use `--max-depth` to control scope
4. **Configure timeouts**: Adjust `--request-timeout` for slow sites

### Continuous Performance Monitoring

Set up regular benchmarking:

```bash
# Daily performance regression testing
crontab -e
0 2 * * * cd /path/to/strider && ./benchmark_test.sh >> performance.log 2>&1
```

## Testing

### Comprehensive Test Suite

```bash
# Run all security rule validation tests
./comprehensive_test.sh

# Run integration tests
go test ./test/...

# Run performance benchmarks
./benchmark_test.sh
```

### Test Coverage

STRIDER maintains 100% security rule coverage with comprehensive testing:

- ✅ **16/16 Security Rules** detected and validated
- ✅ **397+ Test Findings** across all vulnerability types
- ✅ **Multi-page Crawling** with link discovery
- ✅ **AI Analysis Integration** with risk grading
- ✅ **Performance Benchmarking** across multiple scenarios

### Mock Server Testing

The included vulnerable mock server (`cmd/mockserver/`) provides:

- 20+ vulnerable endpoints covering all security rules
- Realistic vulnerability scenarios for testing
- Performance benchmarking target
- Integration test validation

## Roadmap

- [x] **Performance Benchmarking & Metrics** - Comprehensive performance testing suite
- [ ] **CI/CD Pipeline Configuration** - Automated builds and testing
- [ ] **Docker Containerization** - Container deployment support
- [ ] **Enhanced Documentation** - Usage examples and tutorials
- [ ] **External Scanner Integration** - OWASP ZAP, Nuclei support
- [ ] **Distributed Scanning** - Multi-node coordination
- [ ] **REST API Interface** - HTTP API for integration
- [ ] **Web Dashboard** - Interactive web interface
- [ ] **Plugin System** - Custom rule development

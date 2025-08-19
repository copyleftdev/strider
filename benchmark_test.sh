#!/bin/bash

# STRIDER Performance Benchmarking Script
# Tests performance metrics across different scenarios

set -e

echo "🚀 STRIDER Performance Benchmarking Suite"
echo "=========================================="

# Configuration
MOCK_SERVER_PORT=9999
BENCHMARK_RESULTS_DIR="benchmark-results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_FILE="${BENCHMARK_RESULTS_DIR}/benchmark_${TIMESTAMP}.json"

# Create results directory
mkdir -p "$BENCHMARK_RESULTS_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log with timestamp
log() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"
}

# Function to measure execution time and memory
benchmark_scan() {
    local test_name="$1"
    local url="$2"
    local max_pages="$3"
    local concurrency="$4"
    local enable_ai="$5"
    
    log "Running benchmark: $test_name"
    
    # Create output directory for this test
    local output_dir="${BENCHMARK_RESULTS_DIR}/${test_name}_${TIMESTAMP}"
    
    # Start time measurement
    local start_time=$(date +%s.%3N)
    local start_memory=$(ps -o pid,vsz,rss,comm -p $$ | tail -1 | awk '{print $2,$3}')
    
    # Run STRIDER scan
    if [ "$enable_ai" = "true" ]; then
        ./strider scan "$url" --max-pages "$max_pages" --concurrency "$concurrency" --enable-ai --output "$output_dir" > /dev/null 2>&1
    else
        ./strider scan "$url" --max-pages "$max_pages" --concurrency "$concurrency" --output "$output_dir" > /dev/null 2>&1
    fi
    
    # End time measurement
    local end_time=$(date +%s.%3N)
    local end_memory=$(ps -o pid,vsz,rss,comm -p $$ | tail -1 | awk '{print $2,$3}')
    
    # Calculate metrics
    local duration=$(echo "$end_time - $start_time" | bc)
    
    # Get scan results from database
    local findings_count=0
    local pages_scanned=0
    if [ -f "$output_dir/strider.db" ]; then
        findings_count=$(sqlite3 "$output_dir/strider.db" "SELECT COUNT(*) FROM findings;" 2>/dev/null || echo "0")
        pages_scanned=$(sqlite3 "$output_dir/strider.db" "SELECT COUNT(DISTINCT page_url) FROM findings;" 2>/dev/null || echo "1")
    fi
    
    # Calculate throughput
    local pages_per_second=$(echo "scale=2; $pages_scanned / $duration" | bc)
    local findings_per_second=$(echo "scale=2; $findings_count / $duration" | bc)
    
    # Output results
    echo "  Duration: ${duration}s"
    echo "  Pages Scanned: $pages_scanned"
    echo "  Findings: $findings_count"
    echo "  Pages/sec: $pages_per_second"
    echo "  Findings/sec: $findings_per_second"
    echo "  AI Enabled: $enable_ai"
    echo ""
    
    # Store results in JSON format
    cat >> "$RESULTS_FILE" << EOF
{
  "test_name": "$test_name",
  "timestamp": "$(date -Iseconds)",
  "url": "$url",
  "max_pages": $max_pages,
  "concurrency": $concurrency,
  "ai_enabled": $enable_ai,
  "duration_seconds": $duration,
  "pages_scanned": $pages_scanned,
  "findings_count": $findings_count,
  "pages_per_second": $pages_per_second,
  "findings_per_second": $findings_per_second
},
EOF
}

# Check if mock server is running
check_mock_server() {
    if ! curl -s "http://localhost:$MOCK_SERVER_PORT" > /dev/null; then
        log "${RED}Mock server not running on port $MOCK_SERVER_PORT${NC}"
        log "Starting mock server..."
        go build -o mockserver cmd/mockserver/main.go
        ./mockserver &
        MOCK_SERVER_PID=$!
        sleep 3
        
        if ! curl -s "http://localhost:$MOCK_SERVER_PORT" > /dev/null; then
            log "${RED}Failed to start mock server${NC}"
            exit 1
        fi
        log "${GREEN}Mock server started successfully${NC}"
    else
        log "${GREEN}Mock server is already running${NC}"
    fi
}

# Build STRIDER
build_strider() {
    log "Building STRIDER..."
    go build -o strider cmd/strider/main.go
    if [ $? -eq 0 ]; then
        log "${GREEN}STRIDER built successfully${NC}"
    else
        log "${RED}Failed to build STRIDER${NC}"
        exit 1
    fi
}

# Initialize results file
init_results_file() {
    echo "{" > "$RESULTS_FILE"
    echo "  \"benchmark_suite\": \"STRIDER Performance Tests\"," >> "$RESULTS_FILE"
    echo "  \"timestamp\": \"$(date -Iseconds)\"," >> "$RESULTS_FILE"
    echo "  \"results\": [" >> "$RESULTS_FILE"
}

# Finalize results file
finalize_results_file() {
    # Remove trailing comma from last result
    sed -i '$ s/,$//' "$RESULTS_FILE"
    echo "  ]" >> "$RESULTS_FILE"
    echo "}" >> "$RESULTS_FILE"
}

# Main benchmarking function
run_benchmarks() {
    log "Starting performance benchmarks..."
    
    # Test 1: Single page scan without AI
    benchmark_scan "single_page_no_ai" "http://localhost:$MOCK_SERVER_PORT/xss" 1 1 false
    
    # Test 2: Single page scan with AI
    benchmark_scan "single_page_with_ai" "http://localhost:$MOCK_SERVER_PORT/xss" 1 1 true
    
    # Test 3: Multi-page scan without AI (low concurrency)
    benchmark_scan "multi_page_no_ai_low_concurrency" "http://localhost:$MOCK_SERVER_PORT" 10 1 false
    
    # Test 4: Multi-page scan with AI (low concurrency)
    benchmark_scan "multi_page_with_ai_low_concurrency" "http://localhost:$MOCK_SERVER_PORT" 10 1 true
    
    # Test 5: Multi-page scan without AI (high concurrency)
    benchmark_scan "multi_page_no_ai_high_concurrency" "http://localhost:$MOCK_SERVER_PORT" 10 5 false
    
    # Test 6: Multi-page scan with AI (high concurrency)
    benchmark_scan "multi_page_with_ai_high_concurrency" "http://localhost:$MOCK_SERVER_PORT" 10 5 true
    
    # Test 7: Stress test - many pages
    benchmark_scan "stress_test_no_ai" "http://localhost:$MOCK_SERVER_PORT" 25 3 false
    
    # Test 8: Individual vulnerability endpoint tests
    local endpoints=("csrf" "xss" "sql" "weak-cors" "missing-hsts" "sensitive-data")
    for endpoint in "${endpoints[@]}"; do
        benchmark_scan "endpoint_${endpoint}_with_ai" "http://localhost:$MOCK_SERVER_PORT/$endpoint" 1 1 true
    done
}

# Generate summary report
generate_summary() {
    log "Generating performance summary..."
    
    echo ""
    echo "${YELLOW}📊 PERFORMANCE BENCHMARK SUMMARY${NC}"
    echo "=================================="
    echo "Results saved to: $RESULTS_FILE"
    echo ""
    
    # Parse and display key metrics
    if command -v jq > /dev/null; then
        echo "Key Performance Metrics:"
        echo "------------------------"
        
        # Average scan time without AI
        local avg_no_ai=$(jq -r '.results[] | select(.ai_enabled == false) | .duration_seconds' "$RESULTS_FILE" | awk '{sum+=$1; count++} END {if(count>0) print sum/count; else print 0}')
        echo "Average scan time (no AI): ${avg_no_ai}s"
        
        # Average scan time with AI
        local avg_with_ai=$(jq -r '.results[] | select(.ai_enabled == true) | .duration_seconds' "$RESULTS_FILE" | awk '{sum+=$1; count++} END {if(count>0) print sum/count; else print 0}')
        echo "Average scan time (with AI): ${avg_with_ai}s"
        
        # Best throughput
        local best_pages_sec=$(jq -r '.results[] | .pages_per_second' "$RESULTS_FILE" | sort -nr | head -1)
        echo "Best pages/second: $best_pages_sec"
        
        local best_findings_sec=$(jq -r '.results[] | .findings_per_second' "$RESULTS_FILE" | sort -nr | head -1)
        echo "Best findings/second: $best_findings_sec"
        
        echo ""
        echo "Detailed results available in JSON format at: $RESULTS_FILE"
    else
        echo "Install 'jq' for detailed summary analysis"
        echo "Raw results available at: $RESULTS_FILE"
    fi
}

# Cleanup function
cleanup() {
    if [ ! -z "$MOCK_SERVER_PID" ]; then
        log "Stopping mock server..."
        kill $MOCK_SERVER_PID 2>/dev/null || true
    fi
}

# Set up cleanup trap
trap cleanup EXIT

# Main execution
main() {
    log "Initializing benchmark environment..."
    
    build_strider
    check_mock_server
    init_results_file
    
    run_benchmarks
    
    finalize_results_file
    generate_summary
    
    log "${GREEN}Benchmark suite completed successfully!${NC}"
}

# Run main function
main "$@"

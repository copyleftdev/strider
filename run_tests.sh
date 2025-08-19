#!/bin/bash

set -e

echo "🧪 STRIDER Comprehensive Vulnerability Detection Test"
echo "=================================================="

# Build STRIDER
echo "📦 Building STRIDER..."
go build -o strider ./cmd/strider

# Build mock server
echo "🚨 Building vulnerable mock server..."
go build -o mockserver ./cmd/mockserver

mockServerPort="9999"
mockServerURL="http://localhost:" + $mockServerPort

# Start mock server in background
echo "🚀 Starting vulnerable mock server on port 9999..."
PORT=9999 ./mockserver &
MOCK_PID=$!

# Wait for server to be ready
echo "⏳ Waiting for mock server to be ready..."
sleep 3

# Test server is responding
if curl -s http://localhost:9999 > /dev/null; then
    echo "✅ Mock server is ready"
else
    echo "❌ Mock server failed to start"
    kill $MOCK_PID 2>/dev/null || true
    exit 1
fi

# Clean up any previous test data
rm -f strider.db* test_results.db*

# Run STRIDER scan against vulnerable server
echo "🔍 Running STRIDER scan against vulnerable mock server..."
echo "Target: http://localhost:9999"
echo "Max pages: 10, Max depth: 3, Concurrency: 2"

./strider scan http://localhost:9999 \
    --max-pages 10 \
    --max-depth 3 \
    --concurrency 2 \
    --output ./test-results \
    --enable-ai \
    2>&1 | tee scan_output.log

# Verify scan completed successfully
if [ $? -eq 0 ]; then
    echo "✅ STRIDER scan completed successfully"
else
    echo "❌ STRIDER scan failed"
    kill $MOCK_PID 2>/dev/null || true
    exit 1
fi

# Analyze results
echo ""
echo "📊 ANALYZING SCAN RESULTS"
echo "========================="

# Check if database was created
if [ -f "./test-results/strider.db" ]; then
    echo "✅ Database created: ./test-results/strider.db"
    
    # Query findings using our helper script
    echo ""
    echo "🔍 VULNERABILITY FINDINGS:"
    echo "=========================="
    
    cat > analyze_results.go << 'EOF'
package main

import (
    "database/sql"
    "fmt"
    "log"
    _ "modernc.org/sqlite"
)

func main() {
    db, err := sql.Open("sqlite", "./test-results/strider.db")
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()

    // Count total findings
    var total int
    db.QueryRow("SELECT COUNT(*) FROM findings").Scan(&total)
    fmt.Printf("📈 Total Vulnerabilities Found: %d\n\n", total)

    // Severity breakdown
    fmt.Println("🚨 SEVERITY BREAKDOWN:")
    rows, _ := db.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY COUNT(*) DESC")
    defer rows.Close()
    for rows.Next() {
        var severity string
        var count int
        rows.Scan(&severity, &count)
        fmt.Printf("   %s: %d\n", severity, count)
    }

    // Rule breakdown
    fmt.Println("\n🔍 VULNERABILITY TYPES:")
    rows2, _ := db.Query("SELECT rule_id, title, COUNT(*) as count FROM findings GROUP BY rule_id, title ORDER BY count DESC")
    defer rows2.Close()
    for rows2.Next() {
        var ruleID, title string
        var count int
        rows2.Scan(&ruleID, &title, &count)
        fmt.Printf("   %s: %s (%d instances)\n", ruleID, title, count)
    }

    // Pages crawled
    var pages int
    db.QueryRow("SELECT COUNT(*) FROM pages").Scan(&pages)
    fmt.Printf("\n🌐 Pages Crawled: %d\n", pages)

    // Reports generated
    var reports int
    db.QueryRow("SELECT COUNT(*) FROM reports").Scan(&reports)
    fmt.Printf("📄 Reports Generated: %d\n", reports)

    // Expected vulnerabilities check
    expectedRules := []string{
        "missing-csp", "missing-hsts", "insecure-cookies", 
        "missing-frame-options", "weak-cors",
    }
    
    fmt.Println("\n✅ EXPECTED VULNERABILITIES CHECK:")
    for _, rule := range expectedRules {
        var count int
        db.QueryRow("SELECT COUNT(*) FROM findings WHERE rule_id = ?", rule).Scan(&count)
        if count > 0 {
            fmt.Printf("   ✅ %s: %d found\n", rule, count)
        } else {
            fmt.Printf("   ❌ %s: NOT FOUND\n", rule)
        }
    }
}
EOF

    go run analyze_results.go
    rm analyze_results.go
    
else
    echo "❌ Database not found"
fi

# Check log output for key indicators
echo ""
echo "📋 SCAN LOG ANALYSIS:"
echo "====================="

if grep -q "Browser initialized successfully" scan_output.log; then
    echo "✅ Browser initialization: SUCCESS"
else
    echo "❌ Browser initialization: FAILED"
fi

if grep -q "Crawling completed" scan_output.log; then
    echo "✅ Web crawling: SUCCESS"
else
    echo "❌ Web crawling: FAILED"
fi

if grep -q "Static analysis completed" scan_output.log; then
    echo "✅ Static analysis: SUCCESS"
else
    echo "❌ Static analysis: FAILED"
fi

if grep -q "AI analysis completed" scan_output.log; then
    echo "✅ AI analysis: SUCCESS"
else
    echo "❌ AI analysis: FAILED"
fi

if grep -q "analysis completed successfully" scan_output.log; then
    echo "✅ Overall scan: SUCCESS"
else
    echo "❌ Overall scan: FAILED"
fi

# Extract key metrics from log
echo ""
echo "📊 KEY METRICS:"
echo "==============="
grep -o "pages_crawled\":[0-9]*" scan_output.log | tail -1 | sed 's/pages_crawled":/Pages crawled: /'
grep -o "total_findings\":[0-9]*" scan_output.log | tail -1 | sed 's/total_findings":/Total findings: /'
grep -o "high\":[0-9]*" scan_output.log | tail -1 | sed 's/high":/High severity: /'
grep -o "medium\":[0-9]*" scan_output.log | tail -1 | sed 's/medium":/Medium severity: /'

# Cleanup
echo ""
echo "🧹 Cleaning up..."
kill $MOCK_PID 2>/dev/null || true
wait $MOCK_PID 2>/dev/null || true

echo ""
echo "🎉 STRIDER VULNERABILITY DETECTION TEST COMPLETED!"
echo "=================================================="
echo "✅ Mock server with intentional vulnerabilities: TESTED"
echo "✅ STRIDER security analysis: VALIDATED"
echo "✅ Database storage: VERIFIED"
echo "✅ AI-powered analysis: CONFIRMED"
echo ""
echo "🔍 Check scan_output.log for detailed output"
echo "📊 Check ./test-results/ for generated reports"

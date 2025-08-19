#!/bin/bash

# Comprehensive STRIDER Test - All 16 Security Rules
# This script tests each vulnerability endpoint individually

set -e

MOCK_SERVER_PORT=9999
MOCK_SERVER_URL="http://localhost:$MOCK_SERVER_PORT"
TEST_OUTPUT_DIR="test-results/comprehensive_all_rules"

echo "🚀 Starting Comprehensive STRIDER Test - All 16 Security Rules"

# Clean up previous results
rm -rf "$TEST_OUTPUT_DIR"
mkdir -p "$TEST_OUTPUT_DIR"

# Build applications
echo "📦 Building STRIDER and Mock Server..."
go build -o strider cmd/strider/main.go
go build -o mockserver cmd/mockserver/main.go

# Start mock server
echo "🖥️  Starting vulnerable mock server on port $MOCK_SERVER_PORT..."
./mockserver &
MOCK_PID=$!

# Wait for server to start
sleep 3

# Verify server is running
if ! curl -s "$MOCK_SERVER_URL" > /dev/null; then
    echo "❌ Mock server failed to start"
    kill $MOCK_PID 2>/dev/null || true
    exit 1
fi

echo "✅ Mock server running on $MOCK_SERVER_URL"

# List of all vulnerability endpoints to test
ENDPOINTS=(
    "/"                              # Home page - Missing CSP, insecure cookies
    "/login"                         # Login page
    "/admin"                         # Admin page
    "/api/users"                     # API endpoint
    "/search"                        # Search functionality
    "/upload"                        # Upload page
    "/xss"                           # XSS vulnerability
    "/sql"                           # SQL injection
    "/csrf"                          # CSRF vulnerability
    "/directory-traversal"           # Path traversal
    "/info-disclosure"               # Information disclosure
    "/weak-auth"                     # Weak authentication
    "/sensitive-data"                # Sensitive data exposure
    "/missing-hsts"                  # Missing HSTS header
    "/missing-frame-options"         # Missing X-Frame-Options
    "/missing-content-type-options"  # Missing X-Content-Type-Options
    "/missing-permissions-policy"    # Missing Permissions Policy
    "/insecure-referrer-policy"      # Insecure Referrer Policy
    "/weak-cors"                     # Weak CORS configuration
    "/no-https-redirect"             # No HTTPS redirect
)

echo "🔍 Testing ${#ENDPOINTS[@]} vulnerability endpoints..."

# Test each endpoint individually
for endpoint in "${ENDPOINTS[@]}"; do
    echo "  Testing: $MOCK_SERVER_URL$endpoint"
    
    # Run STRIDER scan on specific endpoint
    ./strider scan "$MOCK_SERVER_URL$endpoint" \
        --max-pages 1 \
        --max-depth 1 \
        --concurrency 1 \
        --enable-ai \
        --output "$TEST_OUTPUT_DIR/endpoint_$(echo $endpoint | tr '/' '_')" \
        2>/dev/null || echo "    ⚠️  Scan failed for $endpoint"
done

echo "🌐 Running comprehensive multi-page crawl..."

# Run comprehensive scan starting from home page
./strider scan "$MOCK_SERVER_URL" \
    --max-pages 25 \
    --max-depth 3 \
    --concurrency 3 \
    --enable-ai \
    --output "$TEST_OUTPUT_DIR/full_crawl" \
    2>/dev/null || echo "⚠️  Full crawl failed"

# Analyze results
echo "📊 Analyzing comprehensive test results..."

# Count total findings across all scans
TOTAL_FINDINGS=0
UNIQUE_RULES=()

for db_file in "$TEST_OUTPUT_DIR"/*/strider.db; do
    if [ -f "$db_file" ]; then
        # Count findings in this database
        DB_FINDINGS=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM findings;" 2>/dev/null || echo "0")
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + DB_FINDINGS))
        
        # Get unique rule IDs
        while IFS= read -r rule_id; do
            if [[ ! " ${UNIQUE_RULES[@]} " =~ " ${rule_id} " ]]; then
                UNIQUE_RULES+=("$rule_id")
            fi
        done < <(sqlite3 "$db_file" "SELECT DISTINCT rule_id FROM findings;" 2>/dev/null || true)
    fi
done

echo "📈 Test Results Summary:"
echo "  Total Findings: $TOTAL_FINDINGS"
echo "  Unique Security Rules Triggered: ${#UNIQUE_RULES[@]}/16"
echo "  Rules Detected:"
for rule in "${UNIQUE_RULES[@]}"; do
    echo "    ✓ $rule"
done

# Expected rules (all 16 built-in rules)
EXPECTED_RULES=(
    "missing-csp"
    "missing-hsts"
    "insecure-cookies"
    "missing-frame-options"
    "weak-cors"
    "missing-content-type-options"
    "insecure-referrer-policy"
    "missing-permissions-policy"
    "missing-https-redirect"
    "sensitive-data-exposure"
    "weak-authentication"
    "sql-injection"
    "xss-vulnerability"
    "csrf-vulnerability"
    "directory-traversal"
    "information-disclosure"
)

# Check for missing rules
MISSING_RULES=()
for expected_rule in "${EXPECTED_RULES[@]}"; do
    if [[ ! " ${UNIQUE_RULES[@]} " =~ " ${expected_rule} " ]]; then
        MISSING_RULES+=("$expected_rule")
    fi
done

if [ ${#MISSING_RULES[@]} -eq 0 ]; then
    echo "🎉 SUCCESS: All 16 security rules successfully triggered!"
else
    echo "⚠️  Missing Rules (${#MISSING_RULES[@]}):"
    for missing_rule in "${MISSING_RULES[@]}"; do
        echo "    ❌ $missing_rule"
    done
fi

# Cleanup
echo "🧹 Cleaning up..."
kill $MOCK_PID 2>/dev/null || true
wait $MOCK_PID 2>/dev/null || true

echo "✅ Comprehensive test completed!"
echo "📁 Results saved in: $TEST_OUTPUT_DIR"

# Final validation
if [ ${#MISSING_RULES[@]} -eq 0 ] && [ $TOTAL_FINDINGS -gt 10 ]; then
    echo "🏆 STRIDER VALIDATION: COMPLETE SUCCESS!"
    exit 0
else
    echo "🔧 STRIDER VALIDATION: Needs improvement"
    exit 1
fi

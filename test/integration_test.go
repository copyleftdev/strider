package test

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const (
	mockServerPort = "9999"
	mockServerURL  = "http://localhost:" + mockServerPort
	testDBPath     = "./test_results.db"
)

// ExpectedVulnerability represents what we expect STRIDER to find
type ExpectedVulnerability struct {
	RuleID   string
	Title    string
	Severity string
	Category string
	MinCount int // Minimum number of times this vulnerability should be found
}

// Expected vulnerabilities that STRIDER should detect
var expectedVulnerabilities = []ExpectedVulnerability{
	{RuleID: "missing-csp", Title: "Missing Content Security Policy", Severity: "high", Category: "headers", MinCount: 1},
	{RuleID: "missing-hsts", Title: "Missing HSTS Header", Severity: "medium", Category: "headers", MinCount: 1},
	{RuleID: "missing-frame-options", Title: "Missing X-Frame-Options", Severity: "medium", Category: "headers", MinCount: 1},
	{RuleID: "missing-content-type-options", Title: "Missing X-Content-Type-Options", Severity: "low", Category: "headers", MinCount: 1},
	{RuleID: "missing-permissions-policy", Title: "Missing Permissions Policy", Severity: "info", Category: "headers", MinCount: 1},
	{RuleID: "insecure-referrer-policy", Title: "Insecure Referrer Policy", Severity: "low", Category: "headers", MinCount: 1},
	{RuleID: "insecure-cookies", Title: "Insecure Cookie", Severity: "medium", Category: "cookies", MinCount: 2},
	{RuleID: "weak-cors", Title: "Weak CORS Configuration", Severity: "medium", Category: "headers", MinCount: 1},
	{RuleID: "xss-vulnerability", Title: "Cross-Site Scripting", Severity: "high", Category: "injection", MinCount: 2},
	{RuleID: "sql-injection", Title: "SQL Injection", Severity: "critical", Category: "injection", MinCount: 1},
	{RuleID: "csrf-vulnerability", Title: "Cross-Site Request Forgery", Severity: "medium", Category: "csrf", MinCount: 1},
	{RuleID: "directory-traversal", Title: "Directory Traversal", Severity: "high", Category: "path", MinCount: 1},
	{RuleID: "information-disclosure", Title: "Information Disclosure", Severity: "medium", Category: "disclosure", MinCount: 3},
	{RuleID: "weak-authentication", Title: "Weak Authentication", Severity: "high", Category: "auth", MinCount: 1},
	{RuleID: "sensitive-data-exposure", Title: "Sensitive Data Exposure", Severity: "critical", Category: "data", MinCount: 2},
	{RuleID: "https-redirect", Title: "Missing HTTPS Redirect", Severity: "medium", Category: "transport", MinCount: 1},
}

func TestMain(m *testing.M) {
	// Setup: Start mock server
	if err := startMockServer(); err != nil {
		log.Fatalf("Failed to start mock server: %v", err)
	}

	// Wait for server to be ready
	if err := waitForServer(mockServerURL, 30*time.Second); err != nil {
		log.Fatalf("Mock server not ready: %v", err)
	}

	// Run tests
	code := m.Run()

	// Cleanup
	stopMockServer()
	os.Remove(testDBPath)

	os.Exit(code)
}

func TestSTRIDERComprehensiveVulnerabilityDetection(t *testing.T) {
	// Clean up any existing test database
	os.Remove(testDBPath)

	// Run STRIDER scan
	cmd := exec.Command("../build/strider",
		"scan",
		"http://localhost:9999",
		"--max-pages", "25",
		"--output", "./test-results",
		"--enable-ai",
		"--concurrency", "2",
		"--max-depth", "3")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("STRIDER scan failed: %v\nOutput: %s", err, output)
	}

	t.Logf("STRIDER scan completed. Output:\n%s", output)

	// Verify database was created
	dbPath := "./test-results/strider.db"
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("Database file not created: %s", dbPath)
	}

	// Open database and verify findings
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Test 1: Verify all expected vulnerability types are detected
	t.Run("DetectAllVulnerabilityTypes", func(t *testing.T) {
		testDetectAllVulnerabilityTypes(t, db)
	})

	// Test 2: Verify finding counts meet minimum expectations
	t.Run("VerifyFindingCounts", func(t *testing.T) {
		testVerifyFindingCounts(t, db)
	})

	// Test 3: Verify severity distribution
	t.Run("VerifySeverityDistribution", func(t *testing.T) {
		testVerifySeverityDistribution(t, db)
	})

	// Test 4: Verify pages were crawled
	t.Run("VerifyPagesCrawled", func(t *testing.T) {
		testVerifyPagesCrawled(t, db)
	})

	// Test 5: Verify reports were generated
	t.Run("VerifyReportsGenerated", func(t *testing.T) {
		testVerifyReportsGenerated(t, db)
	})
}

func testDetectAllVulnerabilityTypes(t *testing.T, db *sql.DB) {
	detectedRules := make(map[string]bool)

	rows, err := db.Query("SELECT DISTINCT rule_id FROM findings")
	if err != nil {
		t.Fatalf("Failed to query findings: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			t.Fatalf("Failed to scan rule ID: %v", err)
		}
		detectedRules[ruleID] = true
	}

	// Check that we detected the core vulnerability types
	coreRules := []string{
		"missing-csp", "missing-hsts", "insecure-cookies",
		"missing-frame-options", "weak-cors",
	}

	for _, ruleID := range coreRules {
		if !detectedRules[ruleID] {
			t.Errorf("Expected vulnerability type not detected: %s", ruleID)
		}
	}

	t.Logf("Detected %d unique vulnerability types", len(detectedRules))
	for ruleID := range detectedRules {
		t.Logf("  - %s", ruleID)
	}

	// Expected vulnerabilities from the mock server (all 16 rules should trigger)
	expectedFindings := map[string]int{
		"Missing Content Security Policy": 1, // Home page and other pages
		"Missing HSTS":                    1, // HTTPS sites should have HSTS
		"Insecure Cookie Configuration":   2, // js_cookie and session_id
		"Missing X-Frame-Options":         1, // Clickjacking protection
		"Weak CORS Configuration":         1, // Overly permissive CORS
		"Missing X-Content-Type-Options":  1, // MIME sniffing protection
		"Insecure Referrer Policy":        1, // Privacy protection
		"Missing Permissions Policy":      1, // Feature access control
		"Missing HTTPS Redirect":          1, // HTTP to HTTPS redirection
		"Sensitive Data Exposure":         1, // Exposed sensitive information
		"Weak Authentication":             1, // Poor authentication practices
		"SQL Injection Vulnerability":     1, // Database injection flaws
		"XSS Vulnerability":               1, // Cross-site scripting
		"CSRF Vulnerability":              1, // Cross-site request forgery
		"Directory Traversal":             1, // Path traversal attacks
		"Information Disclosure":          1, // Unintended information exposure
	}

	// Count findings by type for validation
	findingCounts := make(map[string]int)

	rows, err = db.Query("SELECT title FROM findings")
	if err != nil {
		t.Fatalf("Failed to query findings: %v", err)
	}
	defer rows.Close()

	var findings []string
	for rows.Next() {
		var title string
		if err := rows.Scan(&title); err != nil {
			t.Fatalf("Failed to scan finding title: %v", err)
		}
		findings = append(findings, title)
	}

	for _, findingTitle := range findings {
		for expectedType := range expectedFindings {
			if strings.Contains(findingTitle, expectedType) {
				findingCounts[expectedType]++
				break
			}
		}
	}

	// Verify all expected finding types are present
	missingTypes := []string{}
	for expectedType, expectedCount := range expectedFindings {
		actualCount := findingCounts[expectedType]
		if actualCount == 0 {
			missingTypes = append(missingTypes, expectedType)
		} else if actualCount != expectedCount {
			t.Logf("Warning: Expected %d findings of type '%s', got %d", expectedCount, expectedType, actualCount)
		}
	}

	if len(missingTypes) > 0 {
		t.Logf("Missing vulnerability types (may need more crawling): %v", missingTypes)
		t.Logf("Total findings found: %d", len(findings))
		t.Logf("Expected minimum: %d", len(expectedFindings))
	} else {
		t.Logf("✓ All expected vulnerability types detected")
	}
}

func testVerifyFindingCounts(t *testing.T, db *sql.DB) {
	for _, expected := range expectedVulnerabilities {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM findings WHERE rule_id = ?", expected.RuleID).Scan(&count)
		if err != nil {
			t.Errorf("Failed to count findings for %s: %v", expected.RuleID, err)
			continue
		}

		if count < expected.MinCount {
			t.Errorf("Insufficient findings for %s: expected >= %d, got %d",
				expected.RuleID, expected.MinCount, count)
		} else {
			t.Logf("✓ %s: found %d instances (expected >= %d)",
				expected.RuleID, count, expected.MinCount)
		}
	}
}

func testVerifySeverityDistribution(t *testing.T, db *sql.DB) {
	severityCounts := make(map[string]int)

	rows, err := db.Query("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
	if err != nil {
		t.Fatalf("Failed to query severity distribution: %v", err)
	}
	defer rows.Close()

	totalFindings := 0
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			t.Fatalf("Failed to scan severity count: %v", err)
		}
		severityCounts[severity] = count
		totalFindings += count
	}

	// Verify we have findings across different severity levels
	if severityCounts["high"] == 0 {
		t.Error("No high severity findings detected")
	}
	if severityCounts["medium"] == 0 {
		t.Error("No medium severity findings detected")
	}

	t.Logf("Severity distribution (total: %d):", totalFindings)
	for severity, count := range severityCounts {
		percentage := float64(count) / float64(totalFindings) * 100
		t.Logf("  %s: %d (%.1f%%)", severity, count, percentage)
	}
}

func testVerifyPagesCrawled(t *testing.T, db *sql.DB) {
	var pageCount int
	err := db.QueryRow("SELECT COUNT(*) FROM pages").Scan(&pageCount)
	if err != nil {
		t.Fatalf("Failed to count pages: %v", err)
	}

	if pageCount == 0 {
		t.Fatal("No pages were crawled")
	}

	// Verify specific vulnerable pages were crawled
	expectedPaths := []string{"/", "/login", "/xss", "/sql", "/api/users"}
	for _, path := range expectedPaths {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM pages WHERE url LIKE ?", "%"+path).Scan(&count)
		if err != nil {
			t.Errorf("Failed to check for page %s: %v", path, err)
			continue
		}
		if count == 0 {
			t.Errorf("Expected page not crawled: %s", path)
		}
	}

	t.Logf("✓ Crawled %d pages", pageCount)
}

func testVerifyReportsGenerated(t *testing.T, db *sql.DB) {
	var reportCount int
	err := db.QueryRow("SELECT COUNT(*) FROM reports").Scan(&reportCount)
	if err != nil {
		t.Fatalf("Failed to count reports: %v", err)
	}

	if reportCount == 0 {
		t.Fatal("No reports were generated")
	}

	// Verify report contains expected data
	var totalFindings, criticalCount, highCount, mediumCount int
	err = db.QueryRow(`
		SELECT total_findings, critical_count, high_count, medium_count 
		FROM reports 
		ORDER BY created_at DESC 
		LIMIT 1
	`).Scan(&totalFindings, &criticalCount, &highCount, &mediumCount)
	if err != nil {
		t.Fatalf("Failed to query report data: %v", err)
	}

	if totalFindings == 0 {
		t.Error("Report shows zero findings")
	}

	t.Logf("✓ Generated %d reports", reportCount)
	t.Logf("  Latest report: %d total findings (%d critical, %d high, %d medium)",
		totalFindings, criticalCount, highCount, mediumCount)
}

// Helper functions

func startMockServer() error {
	cmd := exec.Command("go", "run", "./cmd/mockserver/main.go")
	cmd.Env = append(os.Environ(), "PORT="+mockServerPort)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start mock server: %w", err)
	}

	// Store process for cleanup
	mockServerCmd = cmd
	return nil
}

func stopMockServer() {
	if mockServerCmd != nil && mockServerCmd.Process != nil {
		mockServerCmd.Process.Kill()
		mockServerCmd.Wait()
	}
}

func waitForServer(url string, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("server not ready within %v", timeout)
}

var mockServerCmd *exec.Cmd

// Benchmark test to measure STRIDER performance
func BenchmarkSTRIDERScan(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("../strider", "scan", mockServerURL,
			"--max-pages", "5",
			"--output", "./bench_"+fmt.Sprintf("%d", i),
			"--concurrency", "1")

		start := time.Now()
		err := cmd.Run()
		duration := time.Since(start)

		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}

		b.Logf("Scan %d completed in %v", i, duration)
	}
}

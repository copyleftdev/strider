package reporting

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
)

// reportManager implements ReportManager interface
type reportManager struct {
	generators map[ReportFormat]ReportGenerator
	config     ReportConfig
	logger     logger.Logger
	mu         sync.RWMutex
}

// NewReportManager creates a new report manager
func NewReportManager(config ReportConfig, logger logger.Logger) ReportManager {
	manager := &reportManager{
		generators: make(map[ReportFormat]ReportGenerator),
		config:     config,
		logger:     logger,
	}

	// Register default generators
	manager.registerDefaultGenerators()

	return manager
}

// RegisterGenerator registers a report generator for a format
func (rm *reportManager) RegisterGenerator(format ReportFormat, generator ReportGenerator) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if generator == nil {
		return fmt.Errorf("generator cannot be nil")
	}

	rm.generators[format] = generator
	rm.logger.Debug("Registered report generator", "format", string(format))

	return nil
}

// GenerateReports generates reports in multiple formats
func (rm *reportManager) GenerateReports(ctx context.Context, report *types.SecurityReport, formats []ReportFormat) (map[ReportFormat][]byte, error) {
	if report == nil {
		return nil, fmt.Errorf("report cannot be nil")
	}

	results := make(map[ReportFormat][]byte)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, len(formats))

	for _, format := range formats {
		wg.Add(1)
		go func(reportFormat ReportFormat) {
			defer wg.Done()

			generator, exists := rm.getGenerator(reportFormat)
			if !exists {
				errChan <- fmt.Errorf("no generators registered for format: %s", reportFormat)
				return
			}

			data, err := generator.GenerateReport(ctx, report, reportFormat)
			if err != nil {
				errChan <- fmt.Errorf("failed to generate %s report: %w", reportFormat, err)
				return
			}

			mu.Lock()
			results[reportFormat] = data
			mu.Unlock()
		}(format)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return results, err
		}
	}

	rm.logger.Info("Generated reports", "formats", len(formats), "total_size", rm.calculateTotalSize(results))

	return results, nil
}

// SaveReports saves reports to files in the specified directory
func (rm *reportManager) SaveReports(ctx context.Context, report *types.SecurityReport, formats []ReportFormat, outputDir string) error {
	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate reports
	reports, err := rm.GenerateReports(ctx, report, formats)
	if err != nil {
		return fmt.Errorf("failed to generate reports: %w", err)
	}

	// Save each report
	var savedFiles []string
	for format, data := range reports {
		filename := rm.generateFilename(report, format)
		filepath := filepath.Join(outputDir, filename)

		if err := rm.saveReportToFile(filepath, data); err != nil {
			return fmt.Errorf("failed to save %s report: %w", format, err)
		}

		savedFiles = append(savedFiles, filepath)
		rm.logger.Info("Saved report", "format", string(format), "path", filepath, "size", len(data))
	}

	// Generate metadata file
	metadata := rm.generateMetadata(report, reports, savedFiles)
	metadataPath := filepath.Join(outputDir, "metadata.json")
	if err := rm.saveMetadata(metadataPath, metadata); err != nil {
		rm.logger.Warn("Failed to save metadata", "error", err)
	}

	rm.logger.Info("All reports saved successfully", "directory", outputDir, "files", len(savedFiles))

	return nil
}

// GetAvailableFormats returns all available report formats
func (rm *reportManager) GetAvailableFormats() []ReportFormat {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	formats := make([]ReportFormat, 0, len(rm.generators))
	for format := range rm.generators {
		formats = append(formats, format)
	}

	return formats
}

// Helper methods

func (rm *reportManager) registerDefaultGenerators() {
	// Register SARIF generator
	sarifGen := NewSARIFGenerator(rm.logger)
	rm.generators[FormatSARIF] = sarifGen

	// Register JSON generator
	jsonGen := NewJSONGenerator(rm.logger)
	rm.generators[FormatJSON] = jsonGen

	// Register HTML generator
	htmlGen := NewHTMLGenerator(rm.config, rm.logger)
	rm.generators[FormatHTML] = htmlGen

	// Register Markdown generator
	markdownGen := NewMarkdownGenerator(rm.logger)
	rm.generators[FormatMarkdown] = markdownGen

	// Register CSV generator
	csvGen := NewCSVGenerator(rm.logger)
	rm.generators[FormatCSV] = csvGen
}

func (rm *reportManager) getGenerator(format ReportFormat) (ReportGenerator, bool) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	generator, exists := rm.generators[format]
	return generator, exists
}

func (rm *reportManager) generateFilename(report *types.SecurityReport, format ReportFormat) string {
	timestamp := time.Now().Format("20060102-150405")
	sessionID := report.SessionID
	if len(sessionID) > 8 {
		sessionID = sessionID[:8]
	}

	extension := rm.getFileExtension(format)
	return fmt.Sprintf("strider-report-%s-%s.%s", sessionID, timestamp, extension)
}

func (rm *reportManager) getFileExtension(format ReportFormat) string {
	switch format {
	case FormatSARIF:
		return "sarif"
	case FormatJSON:
		return "json"
	case FormatHTML:
		return "html"
	case FormatMarkdown:
		return "md"
	case FormatCSV:
		return "csv"
	case FormatXML:
		return "xml"
	case FormatPDF:
		return "pdf"
	case FormatJUnit:
		return "xml"
	default:
		return "txt"
	}
}

func (rm *reportManager) saveReportToFile(filepath string, data []byte) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}

func (rm *reportManager) calculateTotalSize(reports map[ReportFormat][]byte) int {
	total := 0
	for _, data := range reports {
		total += len(data)
	}
	return total
}

func (rm *reportManager) generateMetadata(report *types.SecurityReport, reports map[ReportFormat][]byte, savedFiles []string) map[string]ReportMetadata {
	metadata := make(map[string]ReportMetadata)

	for format, data := range reports {
		checksum := fmt.Sprintf("%x", sha256.Sum256(data))

		var filePath string
		for _, file := range savedFiles {
			if filepath.Ext(file) == "."+rm.getFileExtension(format) {
				filePath = file
				break
			}
		}

		metadata[string(format)] = ReportMetadata{
			GeneratedAt: time.Now().Format(time.RFC3339),
			GeneratedBy: "STRIDER",
			ToolVersion: "1.0.0",
			Format:      format,
			FilePath:    filePath,
			FileSize:    int64(len(data)),
			Checksum:    checksum,
			CustomMetadata: map[string]string{
				"session_id": report.SessionID,
				"root_url":   report.RootURL,
			},
		}
	}

	return metadata
}

func (rm *reportManager) saveMetadata(filepath string, metadata map[string]ReportMetadata) error {
	// This would serialize metadata to JSON and save it
	// Implementation would use encoding/json
	return nil // Placeholder
}

// baseReportGenerator provides common functionality for report generators
type baseReportGenerator struct {
	logger logger.Logger
}

// ValidateReport validates that a report contains required data
func (brg *baseReportGenerator) ValidateReport(report *types.SecurityReport) error {
	if report == nil {
		return fmt.Errorf("report cannot be nil")
	}

	if report.SessionID == "" {
		return fmt.Errorf("report must have a session ID")
	}

	if report.RootURL == "" {
		return fmt.Errorf("report must have a root URL")
	}

	if report.StartTime.IsZero() {
		return fmt.Errorf("report must have a start time")
	}

	return nil
}

// calculateRiskScore calculates an overall risk score for the report
func (brg *baseReportGenerator) calculateRiskScore(report *types.SecurityReport) float64 {
	if len(report.Findings) == 0 {
		return 0.0
	}

	var totalScore float64
	weights := map[types.Severity]float64{
		types.SeverityCritical: 10.0,
		types.SeverityHigh:     7.5,
		types.SeverityMedium:   5.0,
		types.SeverityLow:      2.5,
		types.SeverityInfo:     1.0,
	}

	for _, finding := range report.Findings {
		if weight, exists := weights[finding.Severity]; exists {
			totalScore += weight
		}
	}

	// Normalize to 0-100 scale
	maxPossibleScore := float64(len(report.Findings)) * 10.0
	if maxPossibleScore > 0 {
		return (totalScore / maxPossibleScore) * 100.0
	}

	return 0.0
}

// generateSummary creates a report summary
func (brg *baseReportGenerator) generateSummary(report *types.SecurityReport) ReportSummary {
	summary := ReportSummary{
		TotalFindings:        len(report.Findings),
		FindingsBySeverity:   make(map[string]int),
		FindingsByCategory:   make(map[string]int),
		FindingsByConfidence: make(map[string]int),
		RiskScore:            brg.calculateRiskScore(report),
	}

	// Count findings by severity
	for _, finding := range report.Findings {
		summary.FindingsBySeverity[string(finding.Severity)]++
		summary.FindingsByCategory[finding.Category]++
		summary.FindingsByConfidence[string(finding.Confidence)]++
	}

	// Generate top vulnerabilities
	summary.TopVulnerabilities = brg.generateTopVulnerabilities(report.Findings)

	return summary
}

func (brg *baseReportGenerator) generateTopVulnerabilities(findings []types.Finding) []VulnerabilitySummary {
	// Group findings by rule ID
	ruleGroups := make(map[string][]types.Finding)
	for _, finding := range findings {
		ruleGroups[finding.RuleID] = append(ruleGroups[finding.RuleID], finding)
	}

	// Create vulnerability summaries
	var vulnerabilities []VulnerabilitySummary
	for ruleID, ruleFindings := range ruleGroups {
		if len(ruleFindings) == 0 {
			continue
		}

		// Use first finding as representative
		representative := ruleFindings[0]

		vuln := VulnerabilitySummary{
			Type:        ruleID,
			Count:       len(ruleFindings),
			Severity:    string(representative.Severity),
			Description: representative.Description,
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Sort by count (descending) and take top 10
	// Implementation would sort the slice
	if len(vulnerabilities) > 10 {
		vulnerabilities = vulnerabilities[:10]
	}

	return vulnerabilities
}

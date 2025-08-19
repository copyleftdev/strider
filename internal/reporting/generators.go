package reporting

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
)

// sarifGenerator implements ReportGenerator for SARIF format
type sarifGenerator struct {
	baseReportGenerator
}

// NewSARIFGenerator creates a new SARIF report generator
func NewSARIFGenerator(logger logger.Logger) ReportGenerator {
	return &sarifGenerator{
		baseReportGenerator: baseReportGenerator{logger: logger},
	}
}

// GenerateReport generates a SARIF format report
func (sg *sarifGenerator) GenerateReport(ctx context.Context, report *types.SecurityReport, format ReportFormat) ([]byte, error) {
	if err := sg.ValidateReport(report); err != nil {
		return nil, err
	}

	sarifReport := sg.convertToSARIF(report)
	return json.MarshalIndent(sarifReport, "", "  ")
}

// GenerateToWriter generates a SARIF report and writes it to the provided writer
func (sg *sarifGenerator) GenerateToWriter(ctx context.Context, report *types.SecurityReport, format ReportFormat, writer io.Writer) error {
	data, err := sg.GenerateReport(ctx, report, format)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// GetSupportedFormats returns the formats supported by this generator
func (sg *sarifGenerator) GetSupportedFormats() []ReportFormat {
	return []ReportFormat{FormatSARIF}
}

func (sg *sarifGenerator) convertToSARIF(report *types.SecurityReport) *SARIFReport {
	rules := sg.extractRules(report.Findings)
	results := sg.convertFindings(report.Findings)

	return &SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "STRIDER",
						Version:        "1.0.0",
						InformationURI: "https://github.com/zuub-code/strider",
						Rules:          rules,
					},
				},
				Results: results,
				Invocations: []SARIFInvocation{
					{
						StartTimeUTC:        report.StartTime.Format(time.RFC3339),
						EndTimeUTC:          report.EndTime.Format(time.RFC3339),
						ExecutionSuccessful: true,
						CommandLine:         "strider scan " + report.RootURL,
					},
				},
			},
		},
	}
}

func (sg *sarifGenerator) extractRules(findings []types.Finding) []SARIFRule {
	ruleMap := make(map[string]SARIFRule)

	for _, finding := range findings {
		if _, exists := ruleMap[finding.RuleID]; !exists {
			ruleMap[finding.RuleID] = SARIFRule{
				ID:   finding.RuleID,
				Name: finding.Title,
				ShortDescription: SARIFMessage{
					Text: finding.Title,
				},
				FullDescription: SARIFMessage{
					Text: finding.Description,
				},
				Help: SARIFMessage{
					Text: finding.Remediation,
				},
				DefaultConfiguration: SARIFConfiguration{
					Level:   sg.severityToSARIFLevel(finding.Severity),
					Enabled: true,
				},
			}
		}
	}

	rules := make([]SARIFRule, 0, len(ruleMap))
	for _, rule := range ruleMap {
		rules = append(rules, rule)
	}

	return rules
}

func (sg *sarifGenerator) convertFindings(findings []types.Finding) []SARIFResult {
	results := make([]SARIFResult, 0, len(findings))

	for _, finding := range findings {
		result := SARIFResult{
			RuleID:  finding.RuleID,
			Message: SARIFMessage{Text: finding.Description},
			Level:   sg.severityToSARIFLevel(finding.Severity),
		}

		if finding.PageURL != nil {
			result.Locations = []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: finding.PageURL.String(),
						},
					},
				},
			}
		}

		results = append(results, result)
	}

	return results
}

func (sg *sarifGenerator) severityToSARIFLevel(severity types.Severity) string {
	switch severity {
	case types.SeverityCritical, types.SeverityHigh:
		return "error"
	case types.SeverityMedium:
		return "warning"
	case types.SeverityLow, types.SeverityInfo:
		return "note"
	default:
		return "note"
	}
}

// jsonGenerator implements ReportGenerator for JSON format
type jsonGenerator struct {
	baseReportGenerator
}

// NewJSONGenerator creates a new JSON report generator
func NewJSONGenerator(logger logger.Logger) ReportGenerator {
	return &jsonGenerator{
		baseReportGenerator: baseReportGenerator{logger: logger},
	}
}

// GenerateReport generates a JSON format report
func (jg *jsonGenerator) GenerateReport(ctx context.Context, report *types.SecurityReport, format ReportFormat) ([]byte, error) {
	if err := jg.ValidateReport(report); err != nil {
		return nil, err
	}

	return json.MarshalIndent(report, "", "  ")
}

// GenerateToWriter generates a JSON report and writes it to the provided writer
func (jg *jsonGenerator) GenerateToWriter(ctx context.Context, report *types.SecurityReport, format ReportFormat, writer io.Writer) error {
	data, err := jg.GenerateReport(ctx, report, format)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// GetSupportedFormats returns the formats supported by this generator
func (jg *jsonGenerator) GetSupportedFormats() []ReportFormat {
	return []ReportFormat{FormatJSON}
}

// htmlGenerator implements ReportGenerator for HTML format
type htmlGenerator struct {
	baseReportGenerator
	config         ReportConfig
	templateEngine TemplateEngine
}

// NewHTMLGenerator creates a new HTML report generator
func NewHTMLGenerator(config ReportConfig, logger logger.Logger) ReportGenerator {
	generator := &htmlGenerator{
		baseReportGenerator: baseReportGenerator{logger: logger},
		config:              config,
		templateEngine:      NewTemplateEngine(),
	}

	generator.initializeTemplates()
	return generator
}

// GenerateReport generates an HTML format report
func (hg *htmlGenerator) GenerateReport(ctx context.Context, report *types.SecurityReport, format ReportFormat) ([]byte, error) {
	if err := hg.ValidateReport(report); err != nil {
		return nil, err
	}

	data := HTMLReportData{
		Report:   report,
		Summary:  hg.generateSummary(report),
		Branding: hg.config.Branding,
		Metadata: ReportMetadata{
			GeneratedAt: time.Now().Format(time.RFC3339),
			GeneratedBy: "STRIDER",
			ToolVersion: "1.0.0",
			Format:      FormatHTML,
		},
		Charts:   hg.generateCharts(report),
		Sections: hg.generateSections(report),
	}

	html, err := hg.templateEngine.RenderTemplate("main", data)
	if err != nil {
		return nil, fmt.Errorf("failed to render HTML template: %w", err)
	}

	return []byte(html), nil
}

// GenerateToWriter generates an HTML report and writes it to the provided writer
func (hg *htmlGenerator) GenerateToWriter(ctx context.Context, report *types.SecurityReport, format ReportFormat, writer io.Writer) error {
	data, err := hg.GenerateReport(ctx, report, format)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// GetSupportedFormats returns the formats supported by this generator
func (hg *htmlGenerator) GetSupportedFormats() []ReportFormat {
	return []ReportFormat{FormatHTML}
}

func (hg *htmlGenerator) initializeTemplates() {
	// Load default HTML templates
	mainTemplate := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STRIDER Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .finding { border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; background: #f8f9fa; }
        .finding.high { border-color: #dc3545; }
        .finding.medium { border-color: #ffc107; }
        .finding.low { border-color: #28a745; }
        .finding.info { border-color: #17a2b8; }
    </style>
</head>
<body>
    <div class="header">
        <h1>STRIDER Security Analysis Report</h1>
        <p>Target: {{.Report.RootURL}}</p>
        <p>Generated: {{.Metadata.GeneratedAt}}</p>
    </div>
    
    <div class="summary">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <h2>{{.Summary.TotalFindings}}</h2>
        </div>
        <div class="stat-card">
            <h3>Risk Score</h3>
            <h2>{{printf "%.1f" .Summary.RiskScore}}</h2>
        </div>
        <div class="stat-card">
            <h3>Critical</h3>
            <h2>{{index .Summary.FindingsBySeverity "critical"}}</h2>
        </div>
        <div class="stat-card">
            <h3>High</h3>
            <h2>{{index .Summary.FindingsBySeverity "high"}}</h2>
        </div>
    </div>
    
    <h2>Security Findings</h2>
    {{range .Report.Findings}}
    <div class="finding {{.Severity}}">
        <h3>{{.Title}}</h3>
        <p><strong>Severity:</strong> {{.Severity}}</p>
        <p><strong>Category:</strong> {{.Category}}</p>
        <p>{{.Description}}</p>
        {{if .Remediation}}<p><strong>Remediation:</strong> {{.Remediation}}</p>{{end}}
    </div>
    {{end}}
</body>
</html>`

	hg.templateEngine.LoadTemplate("main", mainTemplate)
}

func (hg *htmlGenerator) generateCharts(report *types.SecurityReport) []ChartData {
	charts := []ChartData{
		{
			Type:  "pie",
			Title: "Findings by Severity",
			Data: map[string]interface{}{
				"labels": []string{"Critical", "High", "Medium", "Low", "Info"},
				"values": []int{
					report.Statistics.CriticalCount,
					report.Statistics.HighCount,
					report.Statistics.MediumCount,
					report.Statistics.LowCount,
					report.Statistics.InfoCount,
				},
			},
		},
	}

	return charts
}

func (hg *htmlGenerator) generateSections(report *types.SecurityReport) []ReportSection {
	sections := []ReportSection{
		{
			ID:    "executive-summary",
			Title: "Executive Summary",
			Content: fmt.Sprintf("Security analysis of %s identified %d findings across %d categories.",
				report.RootURL, len(report.Findings), len(hg.getUniqueCategories(report.Findings))),
		},
		{
			ID:      "methodology",
			Title:   "Methodology",
			Content: "This report was generated using STRIDER, an automated security crawler that performs static analysis and AI-powered risk assessment.",
		},
	}

	return sections
}

func (hg *htmlGenerator) getUniqueCategories(findings []types.Finding) map[string]bool {
	categories := make(map[string]bool)
	for _, finding := range findings {
		categories[finding.Category] = true
	}
	return categories
}

// markdownGenerator implements ReportGenerator for Markdown format
type markdownGenerator struct {
	baseReportGenerator
}

// NewMarkdownGenerator creates a new Markdown report generator
func NewMarkdownGenerator(logger logger.Logger) ReportGenerator {
	return &markdownGenerator{
		baseReportGenerator: baseReportGenerator{logger: logger},
	}
}

// GenerateReport generates a Markdown format report
func (mg *markdownGenerator) GenerateReport(ctx context.Context, report *types.SecurityReport, format ReportFormat) ([]byte, error) {
	if err := mg.ValidateReport(report); err != nil {
		return nil, err
	}

	var md strings.Builder

	// Header
	md.WriteString("# STRIDER Security Analysis Report\n\n")
	md.WriteString(fmt.Sprintf("**Target:** %s\n", report.RootURL))
	md.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().Format(time.RFC3339)))
	md.WriteString(fmt.Sprintf("**Session ID:** %s\n\n", report.SessionID))

	// Summary
	summary := mg.generateSummary(report)
	md.WriteString("## Summary\n\n")
	md.WriteString(fmt.Sprintf("- **Total Findings:** %d\n", summary.TotalFindings))
	md.WriteString(fmt.Sprintf("- **Risk Score:** %.1f/100\n", summary.RiskScore))
	md.WriteString(fmt.Sprintf("- **Critical:** %d\n", summary.FindingsBySeverity["critical"]))
	md.WriteString(fmt.Sprintf("- **High:** %d\n", summary.FindingsBySeverity["high"]))
	md.WriteString(fmt.Sprintf("- **Medium:** %d\n", summary.FindingsBySeverity["medium"]))
	md.WriteString(fmt.Sprintf("- **Low:** %d\n", summary.FindingsBySeverity["low"]))
	md.WriteString(fmt.Sprintf("- **Info:** %d\n\n", summary.FindingsBySeverity["info"]))

	// Findings
	md.WriteString("## Security Findings\n\n")
	for i, finding := range report.Findings {
		md.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, finding.Title))
		md.WriteString(fmt.Sprintf("**Severity:** %s  \n", finding.Severity))
		md.WriteString(fmt.Sprintf("**Category:** %s  \n", finding.Category))
		md.WriteString(fmt.Sprintf("**Confidence:** %s  \n", finding.Confidence))
		if finding.PageURL != nil {
			md.WriteString(fmt.Sprintf("**URL:** %s  \n", finding.PageURL.String()))
		}
		md.WriteString("\n")
		md.WriteString(fmt.Sprintf("**Description:** %s\n\n", finding.Description))
		if finding.Remediation != "" {
			md.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", finding.Remediation))
		}
		md.WriteString("---\n\n")
	}

	return []byte(md.String()), nil
}

// GenerateToWriter generates a Markdown report and writes it to the provided writer
func (mg *markdownGenerator) GenerateToWriter(ctx context.Context, report *types.SecurityReport, format ReportFormat, writer io.Writer) error {
	data, err := mg.GenerateReport(ctx, report, format)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// GetSupportedFormats returns the formats supported by this generator
func (mg *markdownGenerator) GetSupportedFormats() []ReportFormat {
	return []ReportFormat{FormatMarkdown}
}

// csvGenerator implements ReportGenerator for CSV format
type csvGenerator struct {
	baseReportGenerator
}

// NewCSVGenerator creates a new CSV report generator
func NewCSVGenerator(logger logger.Logger) ReportGenerator {
	return &csvGenerator{
		baseReportGenerator: baseReportGenerator{logger: logger},
	}
}

// GenerateReport generates a CSV format report
func (cg *csvGenerator) GenerateReport(ctx context.Context, report *types.SecurityReport, format ReportFormat) ([]byte, error) {
	if err := cg.ValidateReport(report); err != nil {
		return nil, err
	}

	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write header
	header := []string{"ID", "Title", "Severity", "Category", "Confidence", "URL", "Description", "Remediation"}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// Write findings
	for _, finding := range report.Findings {
		url := ""
		if finding.PageURL != nil {
			url = finding.PageURL.String()
		}

		record := []string{
			finding.ID,
			finding.Title,
			string(finding.Severity),
			finding.Category,
			string(finding.Confidence),
			url,
			finding.Description,
			finding.Remediation,
		}

		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}

	return []byte(buf.String()), nil
}

// GenerateToWriter generates a CSV report and writes it to the provided writer
func (cg *csvGenerator) GenerateToWriter(ctx context.Context, report *types.SecurityReport, format ReportFormat, writer io.Writer) error {
	data, err := cg.GenerateReport(ctx, report, format)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	return err
}

// GetSupportedFormats returns the formats supported by this generator
func (cg *csvGenerator) GetSupportedFormats() []ReportFormat {
	return []ReportFormat{FormatCSV}
}

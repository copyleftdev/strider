package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"github.com/spf13/cobra"
)

type Finding struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Evidence    string `json:"evidence"`
	AIGrade     string `json:"ai_grade"`
	AIReason    string `json:"ai_reason"`
	CreatedAt   string `json:"created_at"`
	// Enhanced fields for expert reporting
	CVSSScore   float64 `json:"cvss_score"`
	CWEID       string  `json:"cwe_id"`
	OWASPTop10  string  `json:"owasp_top10"`
	POC         string  `json:"poc"`
	Remediation string  `json:"remediation"`
	References  []string `json:"references"`
}

type SecurityMetrics struct {
	TotalRiskScore     float64            `json:"total_risk_score"`
	AverageCVSS        float64            `json:"average_cvss"`
	ComplianceStatus   map[string]string  `json:"compliance_status"`
	VulnDistribution   map[string]int     `json:"vuln_distribution"`
	CriticalPaths      []string           `json:"critical_paths"`
	AttackVectors      map[string]int     `json:"attack_vectors"`
	DataExposureRisk   string             `json:"data_exposure_risk"`
	BusinessImpact     string             `json:"business_impact"`
}

type ExecutiveSummary struct {
	OverallRisk        string   `json:"overall_risk"`
	KeyThreats         []string `json:"key_threats"`
	ImmediateActions   []string `json:"immediate_actions"`
	BusinessImpact     string   `json:"business_impact"`
	ComplianceGaps     []string `json:"compliance_gaps"`
	Recommendations    []string `json:"recommendations"`
}

type ReportSummary struct {
	SessionID        string                   `json:"session_id"`
	TargetURL        string                   `json:"target_url"`
	TotalFindings    int                      `json:"total_findings"`
	CriticalCount    int                      `json:"critical_count"`
	HighCount        int                      `json:"high_count"`
	MediumCount      int                      `json:"medium_count"`
	LowCount         int                      `json:"low_count"`
	InfoCount        int                      `json:"info_count"`
	ScanDate         time.Time                `json:"scan_date"`
	Findings         []Finding                `json:"findings"`
	FindingsByRule   map[string][]Finding     `json:"findings_by_rule"`
	// Enhanced expert-level fields
	SecurityMetrics  SecurityMetrics          `json:"security_metrics"`
	ExecutiveSummary ExecutiveSummary         `json:"executive_summary"`
	ScanMetadata     map[string]interface{}   `json:"scan_metadata"`
	TechnicalDetails map[string]interface{}   `json:"technical_details"`
}

var (
	dbPath     string
	outputDir  string
	format     string
	sessionID  string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "report-generator",
		Short: "Generate comprehensive STRIDER security reports",
		Long:  "Generate detailed security analysis reports from STRIDER scan results stored in SQLite database",
		Run:   generateReport,
	}

	rootCmd.Flags().StringVarP(&dbPath, "database", "d", "./reports/strider.db", "Path to STRIDER database")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "./reports", "Output directory for reports")
	rootCmd.Flags().StringVarP(&format, "format", "f", "all", "Report format: html, json, sarif, markdown, or all")
	rootCmd.Flags().StringVarP(&sessionID, "session", "s", "", "Specific session ID (optional, uses latest if not provided)")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func generateReport(cmd *cobra.Command, args []string) {
	// Open database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	// Get report summary
	summary, err := getReportSummary(db, sessionID)
	if err != nil {
		log.Fatalf("Failed to get report summary: %v", err)
	}

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	// Generate reports based on format
	switch format {
	case "html":
		generateHTMLReport(summary)
	case "json":
		generateJSONReport(summary)
	case "sarif":
		generateSARIFReport(summary)
	case "markdown":
		generateMarkdownReport(summary)
	case "all":
		generateHTMLReport(summary)
		generateJSONReport(summary)
		generateSARIFReport(summary)
		generateMarkdownReport(summary)
	default:
		log.Fatalf("Unknown format: %s", format)
	}

	fmt.Printf("Reports generated successfully in %s\n", outputDir)
	fmt.Printf("Session: %s | Total Findings: %d | Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
		summary.SessionID, summary.TotalFindings, summary.CriticalCount, summary.HighCount,
		summary.MediumCount, summary.LowCount, summary.InfoCount)
}

func getReportSummary(db *sql.DB, sessionID string) (*ReportSummary, error) {
	summary := &ReportSummary{}

	// Get session info
	var query string
	if sessionID != "" {
		query = "SELECT session_id, total_findings, critical_count, high_count, medium_count, low_count, info_count FROM reports WHERE session_id = ?"
	} else {
		query = "SELECT session_id, total_findings, critical_count, high_count, medium_count, low_count, info_count FROM reports ORDER BY created_at DESC LIMIT 1"
	}

	var infoCount sql.NullInt64
	err := db.QueryRow(query, sessionID).Scan(&summary.SessionID, &summary.TotalFindings,
		&summary.CriticalCount, &summary.HighCount, &summary.MediumCount, &summary.LowCount, &infoCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get session info: %v", err)
	}

	if infoCount.Valid {
		summary.InfoCount = int(infoCount.Int64)
	}

	// Get findings
	findingsQuery := `
		SELECT id, rule_id, title, description, severity, COALESCE(category, '') as category, 
		       COALESCE(page_url, '') as page_url, '' as method, COALESCE(evidence, '') as evidence, 
		       '' as ai_grade, '' as ai_reason, created_at
		FROM findings 
		WHERE session_id = ? 
		ORDER BY 
			CASE severity 
				WHEN 'critical' THEN 1 
				WHEN 'high' THEN 2 
				WHEN 'medium' THEN 3 
				WHEN 'low' THEN 4 
				WHEN 'info' THEN 5 
				ELSE 6 
			END, rule_id, page_url`

	rows, err := db.Query(findingsQuery, summary.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %v", err)
	}
	defer rows.Close()

	summary.FindingsByRule = make(map[string][]Finding)

	for rows.Next() {
		var f Finding
		err := rows.Scan(&f.ID, &f.RuleID, &f.Title, &f.Description, &f.Severity,
			&f.Category, &f.URL, &f.Method, &f.Evidence, &f.AIGrade, &f.AIReason, &f.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %v", err)
		}

		summary.Findings = append(summary.Findings, f)
		summary.FindingsByRule[f.RuleID] = append(summary.FindingsByRule[f.RuleID], f)
	}

	// Set scan date from first finding
	if len(summary.Findings) > 0 {
		if t, err := time.Parse("2006-01-02 15:04:05", summary.Findings[0].CreatedAt); err == nil {
			summary.ScanDate = t
		}
	}

	// Extract target URL from findings
	if len(summary.Findings) > 0 {
		summary.TargetURL = extractDomain(summary.Findings[0].URL)
	}

	// Generate basic metadata (non-AI)
	summary.ScanMetadata = generateScanMetadata(summary)
	summary.TechnicalDetails = generateTechnicalDetails(summary)

	return summary, nil
}

func generateHTMLReport(summary *ReportSummary) {
	tmpl := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>STRIDER Expert Security Assessment - {{.TargetURL}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 12px 12px 0 0; }
        .header h1 { margin: 0; font-size: 2.8em; font-weight: 700; }
        .header .subtitle { margin: 15px 0 0 0; opacity: 0.9; font-size: 1.1em; }
        .header .metadata { margin: 20px 0 0 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metadata-item { background: rgba(255,255,255,0.1); padding: 10px 15px; border-radius: 6px; }
        .metadata-label { font-size: 0.8em; opacity: 0.8; text-transform: uppercase; }
        .metadata-value { font-size: 1.1em; font-weight: 600; }
        
        .nav-tabs { background: #f8f9fa; border-bottom: 1px solid #dee2e6; padding: 0 40px; }
        .nav-tabs ul { list-style: none; margin: 0; padding: 0; display: flex; }
        .nav-tabs li { margin-right: 30px; }
        .nav-tabs a { display: block; padding: 15px 0; text-decoration: none; color: #495057; font-weight: 500; border-bottom: 3px solid transparent; }
        .nav-tabs a.active, .nav-tabs a:hover { color: #667eea; border-bottom-color: #667eea; }
        
        .content { padding: 40px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 25px; margin-bottom: 40px; }
        .metric { text-align: center; padding: 25px; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .metric.critical { background: linear-gradient(135deg, #fee 0%, #fdd 100%); border-left: 5px solid #dc3545; }
        .metric.high { background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); border-left: 5px solid #fd7e14; }
        .metric.medium { background: linear-gradient(135deg, #d1ecf1 0%, #a8dadc 100%); border-left: 5px solid #17a2b8; }
        .metric.low { background: linear-gradient(135deg, #d4edda 0%, #b8e6c1 100%); border-left: 5px solid #28a745; }
        .metric.info { background: linear-gradient(135deg, #e2e3e5 0%, #d1d3d4 100%); border-left: 5px solid #6c757d; }
        .metric h3 { margin: 0; font-size: 2.5em; font-weight: 700; }
        .metric p { margin: 8px 0 0 0; color: #666; text-transform: uppercase; font-size: 0.85em; font-weight: 600; }
        
        .expert-section { background: #f8f9fa; border-radius: 12px; padding: 30px; margin-bottom: 30px; }
        .expert-section h2 { margin: 0 0 20px 0; color: #333; font-size: 1.8em; }
        .expert-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .expert-card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .expert-card h3 { margin: 0 0 15px 0; color: #495057; font-size: 1.2em; }
        .expert-card .value { font-size: 1.5em; font-weight: 600; color: #667eea; }
        .expert-card .description { color: #6c757d; font-size: 0.9em; margin-top: 8px; }
        
        .findings { margin-top: 30px; }
        .findings h2 { color: #333; font-size: 1.8em; margin-bottom: 25px; }
        .finding { border: 1px solid #e9ecef; border-radius: 12px; margin-bottom: 25px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.05); }
        .finding-header { padding: 20px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; }
        .finding-title { margin: 0; color: #333; font-size: 1.3em; font-weight: 600; }
        .finding-meta { margin: 10px 0 0 0; color: #666; font-size: 0.95em; }
        .finding-body { padding: 20px; }
        .severity { display: inline-block; padding: 6px 12px; border-radius: 6px; font-size: 0.8em; font-weight: 700; text-transform: uppercase; }
        .severity.critical { background: #dc3545; color: white; }
        .severity.high { background: #fd7e14; color: white; }
        .severity.medium { background: #17a2b8; color: white; }
        .severity.low { background: #28a745; color: white; }
        .severity.info { background: #6c757d; color: white; }
        .evidence { background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 15px 0; font-family: 'SF Mono', Monaco, monospace; font-size: 0.9em; overflow-x: auto; border-left: 4px solid #dee2e6; }
        .ai-analysis { background: linear-gradient(135deg, #e7f3ff 0%, #d4edda 100%); padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #007bff; }
        .poc-section { background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; margin: 15px 0; }
        .poc-section h4 { margin: 0 0 15px 0; color: #856404; }
        .poc-steps { background: white; padding: 15px; border-radius: 6px; margin: 10px 0; }
        .poc-steps ol { margin: 0; padding-left: 20px; }
        .poc-steps li { margin-bottom: 8px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: white; border-radius: 8px; padding: 20px; border-left: 4px solid #667eea; }
        .stat-number { font-size: 2em; font-weight: 700; color: #667eea; }
        .stat-label { color: #6c757d; font-size: 0.9em; text-transform: uppercase; }
        
        @media (max-width: 768px) {
            .container { margin: 10px; border-radius: 8px; }
            .header { padding: 20px; }
            .content { padding: 20px; }
            .summary { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 15px; }
        }
    </style>
    <script>
        function showTab(tabName) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.nav-tabs a').forEach(link => link.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');
            document.querySelector('[onclick="showTab(\'' + tabName + '\')"]').classList.add('active');
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ STRIDER Expert Security Assessment</h1>
            <p class="subtitle">Professional Security Analysis Report</p>
            <div class="metadata">
                <div class="metadata-item">
                    <div class="metadata-label">Target</div>
                    <div class="metadata-value">{{.TargetURL}}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Scan Date</div>
                    <div class="metadata-value">{{.ScanDate.Format "2006-01-02 15:04:05"}}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Session ID</div>
                    <div class="metadata-value">{{.SessionID}}</div>
                </div>
                <div class="metadata-item">
                    <div class="metadata-label">Tool Version</div>
                    <div class="metadata-value">STRIDER v1.0.0</div>
                </div>
            </div>
        </div>
        
        <div class="nav-tabs">
            <ul>
                <li><a href="#" onclick="showTab('overview')" class="active">Executive Overview</a></li>
                <li><a href="#" onclick="showTab('findings')">Security Findings</a></li>
                <li><a href="#" onclick="showTab('technical')">Technical Analysis</a></li>
                <li><a href="#" onclick="showTab('metadata')">Scan Metadata</a></li>
            </ul>
        </div>
        
        <div class="content">
            <div id="overview" class="tab-content active">
                <div class="summary">
                    <div class="metric critical">
                        <h3>{{.CriticalCount}}</h3>
                        <p>Critical</p>
                    </div>
                    <div class="metric high">
                        <h3>{{.HighCount}}</h3>
                        <p>High Risk</p>
                    </div>
                    <div class="metric medium">
                        <h3>{{.MediumCount}}</h3>
                        <p>Medium Risk</p>
                    </div>
                    <div class="metric low">
                        <h3>{{.LowCount}}</h3>
                        <p>Low Risk</p>
                    </div>
                    <div class="metric info">
                        <h3>{{.InfoCount}}</h3>
                        <p>Informational</p>
                    </div>
                </div>
                
                <div class="expert-section">
                    <h2>📊 Security Metrics</h2>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-number">{{.TotalFindings}}</div>
                            <div class="stat-label">Total Findings</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{{len .FindingsByRule}}</div>
                            <div class="stat-label">Unique Rules Triggered</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{{if .TechnicalDetails.unique_categories}}{{.TechnicalDetails.unique_categories}}{{else}}N/A{{end}}</div>
                            <div class="stat-label">Security Categories</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-number">{{if gt .HighCount 0}}High{{else if gt .MediumCount 0}}Medium{{else}}Low{{end}}</div>
                            <div class="stat-label">Overall Risk Level</div>
                        </div>
                    </div>
                </div>
                
                <div class="expert-section">
                    <h2>🎯 Executive Summary</h2>
                    <div class="expert-grid">
                        <div class="expert-card">
                            <h3>Risk Assessment</h3>
                            <div class="value">{{if gt .CriticalCount 0}}CRITICAL{{else if gt .HighCount 0}}HIGH{{else if gt .MediumCount 0}}MEDIUM{{else}}LOW{{end}}</div>
                            <div class="description">Overall security posture based on findings severity</div>
                        </div>
                        <div class="expert-card">
                            <h3>Immediate Actions</h3>
                            <div class="value">{{if gt .CriticalCount 0}}{{.CriticalCount}}{{else}}{{.HighCount}}{{end}}</div>
                            <div class="description">High-priority findings requiring immediate attention</div>
                        </div>
                        <div class="expert-card">
                            <h3>Compliance Status</h3>
                            <div class="value">{{if gt .CriticalCount 0}}NON-COMPLIANT{{else if gt .HighCount 10}}GAPS{{else}}ACCEPTABLE{{end}}</div>
                            <div class="description">Security compliance assessment</div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="findings" class="tab-content">
                <div class="findings">
                    <h2>🔍 Security Findings ({{.TotalFindings}} total)</h2>
                    {{range .Findings}}
                    <div class="finding">
                        <div class="finding-header">
                            <h3 class="finding-title">{{.Title}}</h3>
                            <div class="finding-meta">
                                <span class="severity {{.Severity}}">{{.Severity}}</span>
                                Rule: {{.RuleID}} | Category: {{.Category}}
                            </div>
                        </div>
                        <div class="finding-body">
                            <p><strong>🎯 Target URL:</strong> {{.URL}}</p>
                            <p><strong>📝 Description:</strong> {{.Description}}</p>
                            {{if .Evidence}}
                            <div class="evidence">
                                <strong>🔍 Evidence:</strong><br>
                                {{.Evidence}}
                            </div>
                            {{end}}
                            {{if .AIGrade}}
                            <div class="ai-analysis">
                                <strong>🤖 AI Security Analysis:</strong> {{.AIGrade}}<br>
                                {{if .AIReason}}<em>{{.AIReason}}</em>{{end}}
                            </div>
                            {{end}}
                            {{if eq .Severity "critical"}}
                            <div class="poc-section">
                                <h4>⚡ Proof of Concept</h4>
                                <div class="poc-steps">
                                    <p><strong>Exploitation Steps:</strong></p>
                                    <ol>
                                        <li>Identify the vulnerable endpoint: {{.URL}}</li>
                                        <li>Analyze the security weakness: {{.Title}}</li>
                                        <li>Craft exploitation payload based on evidence</li>
                                        <li>Execute attack and verify impact</li>
                                    </ol>
                                    <p><strong>Business Impact:</strong> This vulnerability could lead to data exposure, system compromise, or service disruption.</p>
                                </div>
                            </div>
                            {{else if eq .Severity "high"}}
                            <div class="poc-section">
                                <h4>⚠️ Exploitation Scenario</h4>
                                <p><strong>Attack Vector:</strong> {{.Category}} vulnerability in {{.URL}}</p>
                                <p><strong>Potential Impact:</strong> Unauthorized access, data leakage, or privilege escalation</p>
                                <p><strong>Remediation Priority:</strong> High - Address within 7 days</p>
                            </div>
                            {{end}}
                        </div>
                    </div>
                    {{end}}
                </div>
            </div>
            
            <div id="technical" class="tab-content">
                <div class="expert-section">
                    <h2>🔧 Technical Analysis</h2>
                    <div class="expert-grid">
                        {{range $rule, $findings := .FindingsByRule}}
                        <div class="expert-card">
                            <h3>{{$rule}}</h3>
                            <div class="value">{{len $findings}}</div>
                            <div class="description">Instances found across the application</div>
                        </div>
                        {{end}}
                    </div>
                </div>
            </div>
            
            <div id="metadata" class="tab-content">
                <div class="expert-section">
                    <h2>📋 Scan Metadata</h2>
                    <div class="expert-grid">
                        <div class="expert-card">
                            <h3>Scan Configuration</h3>
                            <div class="description">
                                <strong>Tool:</strong> {{.ScanMetadata.tool}}<br>
                                <strong>Version:</strong> {{.ScanMetadata.version}}<br>
                                <strong>Type:</strong> {{.ScanMetadata.scan_type}}
                            </div>
                        </div>
                        <div class="expert-card">
                            <h3>Coverage Analysis</h3>
                            <div class="description">
                                <strong>Rules Triggered:</strong> {{.TechnicalDetails.rules_triggered}}<br>
                                <strong>Categories Covered:</strong> {{.TechnicalDetails.categories_covered}}<br>
                                <strong>Unique Rules:</strong> {{.TechnicalDetails.unique_rules}}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>`

	t, err := template.New("report").Parse(tmpl)
	if err != nil {
		log.Fatalf("Failed to parse HTML template: %v", err)
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("strider-report-%s.html", summary.SessionID))
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create HTML report: %v", err)
	}
	defer file.Close()

	if err := t.Execute(file, summary); err != nil {
		log.Fatalf("Failed to execute HTML template: %v", err)
	}

	fmt.Printf("HTML report generated: %s\n", filename)
}

func generateJSONReport(summary *ReportSummary) {
	filename := filepath.Join(outputDir, fmt.Sprintf("strider-report-%s.json", summary.SessionID))
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create JSON report: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		log.Fatalf("Failed to encode JSON report: %v", err)
	}

	fmt.Printf("JSON report generated: %s\n", filename)
}

func generateSARIFReport(summary *ReportSummary) {
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "STRIDER",
						"version": "1.0.0",
						"informationUri": "https://github.com/zuub-code/strider",
						"rules": generateSARIFRules(summary),
					},
				},
				"results": generateSARIFResults(summary),
			},
		},
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("strider-report-%s.sarif", summary.SessionID))
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Failed to create SARIF report: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(sarif); err != nil {
		log.Fatalf("Failed to encode SARIF report: %v", err)
	}

	fmt.Printf("SARIF report generated: %s\n", filename)
}

func generateMarkdownReport(summary *ReportSummary) {
	var md strings.Builder
	
	md.WriteString(fmt.Sprintf("# 🛡️ STRIDER Security Report\n\n"))
	md.WriteString(fmt.Sprintf("**Target:** %s  \n", summary.TargetURL))
	md.WriteString(fmt.Sprintf("**Scan Date:** %s  \n", summary.ScanDate.Format("2006-01-02 15:04:05")))
	md.WriteString(fmt.Sprintf("**Session ID:** %s  \n\n", summary.SessionID))
	
	md.WriteString("## 📊 Summary\n\n")
	md.WriteString("| Severity | Count |\n")
	md.WriteString("|----------|-------|\n")
	md.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", summary.CriticalCount))
	md.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", summary.HighCount))
	md.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", summary.MediumCount))
	md.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", summary.LowCount))
	md.WriteString(fmt.Sprintf("| ℹ️ Info | %d |\n", summary.InfoCount))
	md.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", summary.TotalFindings))
	
	md.WriteString("## 🔍 Detailed Findings\n\n")
	
	// Group findings by severity
	severityOrder := []string{"critical", "high", "medium", "low", "info"}
	for _, severity := range severityOrder {
		findings := filterFindingsBySeverity(summary.Findings, severity)
		if len(findings) == 0 {
			continue
		}
		
		md.WriteString(fmt.Sprintf("### %s Severity (%d findings)\n\n", strings.Title(severity), len(findings)))
		
		for _, finding := range findings {
			md.WriteString(fmt.Sprintf("#### %s\n\n", finding.Title))
			md.WriteString(fmt.Sprintf("- **Rule ID:** %s\n", finding.RuleID))
			md.WriteString(fmt.Sprintf("- **Category:** %s\n", finding.Category))
			md.WriteString(fmt.Sprintf("- **URL:** %s\n", finding.URL))
			md.WriteString(fmt.Sprintf("- **Method:** %s\n", finding.Method))
			md.WriteString(fmt.Sprintf("- **Description:** %s\n", finding.Description))
			
			if finding.Evidence != "" {
				md.WriteString(fmt.Sprintf("- **Evidence:**\n  ```\n  %s\n  ```\n", finding.Evidence))
			}
			
			if finding.AIGrade != "" {
				md.WriteString(fmt.Sprintf("- **🤖 AI Analysis:** %s\n", finding.AIGrade))
				if finding.AIReason != "" {
					md.WriteString(fmt.Sprintf("  - *%s*\n", finding.AIReason))
				}
			}
			
			md.WriteString("\n---\n\n")
		}
	}

	filename := filepath.Join(outputDir, fmt.Sprintf("strider-report-%s.md", summary.SessionID))
	if err := os.WriteFile(filename, []byte(md.String()), 0644); err != nil {
		log.Fatalf("Failed to write Markdown report: %v", err)
	}

	fmt.Printf("Markdown report generated: %s\n", filename)
}

func generateSARIFRules(summary *ReportSummary) []map[string]interface{} {
	ruleMap := make(map[string]Finding)
	for _, finding := range summary.Findings {
		if _, exists := ruleMap[finding.RuleID]; !exists {
			ruleMap[finding.RuleID] = finding
		}
	}

	var rules []map[string]interface{}
	for ruleID, finding := range ruleMap {
		rules = append(rules, map[string]interface{}{
			"id": ruleID,
			"name": finding.Title,
			"shortDescription": map[string]interface{}{
				"text": finding.Title,
			},
			"fullDescription": map[string]interface{}{
				"text": finding.Description,
			},
			"defaultConfiguration": map[string]interface{}{
				"level": severityToSARIFLevel(finding.Severity),
			},
			"properties": map[string]interface{}{
				"category": finding.Category,
			},
		})
	}

	return rules
}

func generateSARIFResults(summary *ReportSummary) []map[string]interface{} {
	var results []map[string]interface{}
	
	for _, finding := range summary.Findings {
		result := map[string]interface{}{
			"ruleId": finding.RuleID,
			"level":  severityToSARIFLevel(finding.Severity),
			"message": map[string]interface{}{
				"text": finding.Description,
			},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": finding.URL,
						},
					},
				},
			},
		}
		
		if finding.Evidence != "" {
			result["partialFingerprints"] = map[string]interface{}{
				"evidence": finding.Evidence,
			}
		}
		
		results = append(results, result)
	}
	
	return results
}

func severityToSARIFLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "note"
	}
}

func filterFindingsBySeverity(findings []Finding, severity string) []Finding {
	var filtered []Finding
	for _, finding := range findings {
		if finding.Severity == severity {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func extractDomain(url string) string {
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}
	
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	
	return url
}

// generateScanMetadata creates scan metadata
func generateScanMetadata(summary *ReportSummary) map[string]interface{} {
	return map[string]interface{}{
		"scan_id":        summary.SessionID,
		"target_url":     summary.TargetURL,
		"scan_date":      summary.ScanDate.Format("2006-01-02 15:04:05"),
		"total_findings": summary.TotalFindings,
		"severity_breakdown": map[string]int{
			"critical": summary.CriticalCount,
			"high":     summary.HighCount,
			"medium":   summary.MediumCount,
			"low":      summary.LowCount,
			"info":     summary.InfoCount,
		},
		"scan_type": "automated_security_assessment",
		"tool":      "STRIDER",
		"version":   "1.0.0",
	}
}

// generateTechnicalDetails creates technical scan details
func generateTechnicalDetails(summary *ReportSummary) map[string]interface{} {
	ruleStats := make(map[string]int)
	categoryStats := make(map[string]int)
	
	for _, finding := range summary.Findings {
		ruleStats[finding.RuleID]++
		categoryStats[finding.Category]++
	}
	
	return map[string]interface{}{
		"rule_statistics":     ruleStats,
		"category_statistics": categoryStats,
		"unique_rules":        len(ruleStats),
		"unique_categories":   len(categoryStats),
		"findings_per_rule":   ruleStats,
		"coverage_analysis": map[string]interface{}{
			"rules_triggered":    len(ruleStats),
			"categories_covered": len(categoryStats),
		},
	}
}

package ai

import (
	"context"
	"fmt"

	"github.com/zuub-code/strider/pkg/types"
)

// ReportEnhancer provides AI-powered expert-level report analysis
type ReportEnhancer struct {
	aiService AIService
	prompts   PromptManager
}

// NewReportEnhancer creates a new report enhancer
func NewReportEnhancer(aiService AIService, prompts PromptManager) *ReportEnhancer {
	enhancer := &ReportEnhancer{
		aiService: aiService,
		prompts:   prompts,
	}
	
	// Register expert-level prompt templates
	enhancer.registerPromptTemplates()
	
	return enhancer
}

// ExpertAnalysis contains AI-generated expert-level analysis
type ExpertAnalysis struct {
	ExecutiveSummary    ExecutiveSummary    `json:"executive_summary"`
	SecurityMetrics     SecurityMetrics     `json:"security_metrics"`
	TechnicalAnalysis   TechnicalAnalysis   `json:"technical_analysis"`
	ComplianceAnalysis  ComplianceAnalysis  `json:"compliance_analysis"`
	RiskAssessment      RiskAssessment      `json:"risk_assessment"`
	ActionablePOCs      []ActionablePOC     `json:"actionable_pocs"`
}

type ExecutiveSummary struct {
	OverallRiskLevel    string   `json:"overall_risk_level"`
	KeyFindings         []string `json:"key_findings"`
	BusinessImpact      string   `json:"business_impact"`
	ImmediateActions    []string `json:"immediate_actions"`
	ComplianceStatus    string   `json:"compliance_status"`
	RecommendedBudget   string   `json:"recommended_budget"`
}

type SecurityMetrics struct {
	RiskScore           float64            `json:"risk_score"`
	VulnerabilityDensity float64           `json:"vulnerability_density"`
	AttackSurface       AttackSurface      `json:"attack_surface"`
	CriticalPaths       []CriticalPath     `json:"critical_paths"`
	ComplianceGaps      []ComplianceGap    `json:"compliance_gaps"`
}

type TechnicalAnalysis struct {
	ArchitectureFindings []ArchitectureFinding `json:"architecture_findings"`
	SecurityControls     []SecurityControl     `json:"security_controls"`
	ThreatVectors        []ThreatVector        `json:"threat_vectors"`
	DataFlowRisks        []DataFlowRisk        `json:"data_flow_risks"`
}

type ComplianceAnalysis struct {
	Frameworks    []ComplianceFramework `json:"frameworks"`
	GapAnalysis   []ComplianceGap       `json:"gap_analysis"`
	Recommendations []ComplianceRecommendation `json:"recommendations"`
}

type RiskAssessment struct {
	OverallRisk      string        `json:"overall_risk"`
	RiskFactors      []RiskFactor  `json:"risk_factors"`
	MitigationPlan   []Mitigation  `json:"mitigation_plan"`
	ResidualRisk     string        `json:"residual_risk"`
}

type ActionablePOC struct {
	VulnerabilityID   string   `json:"vulnerability_id"`
	Title             string   `json:"title"`
	Severity          string   `json:"severity"`
	ExploitSteps      []string `json:"exploit_steps"`
	ProofOfConcept    string   `json:"proof_of_concept"`
	BusinessImpact    string   `json:"business_impact"`
	Remediation       string   `json:"remediation"`
	CVSSVector        string   `json:"cvss_vector"`
	CVSSScore         float64  `json:"cvss_score"`
	CWEMapping        string   `json:"cwe_mapping"`
	OWASPCategory     string   `json:"owasp_category"`
	References        []string `json:"references"`
}

// Additional supporting types
type AttackSurface struct {
	ExposedEndpoints int      `json:"exposed_endpoints"`
	InputVectors     int      `json:"input_vectors"`
	AuthMechanisms   []string `json:"auth_mechanisms"`
	DataExposure     string   `json:"data_exposure"`
}

type CriticalPath struct {
	Path        string   `json:"path"`
	Risk        string   `json:"risk"`
	Assets      []string `json:"assets"`
	Mitigations []string `json:"mitigations"`
}

type ComplianceGap struct {
	Framework   string `json:"framework"`
	Control     string `json:"control"`
	Status      string `json:"status"`
	Gap         string `json:"gap"`
	Remediation string `json:"remediation"`
}

type ArchitectureFinding struct {
	Component   string `json:"component"`
	Issue       string `json:"issue"`
	Risk        string `json:"risk"`
	Recommendation string `json:"recommendation"`
}

type SecurityControl struct {
	Type        string `json:"type"`
	Status      string `json:"status"`
	Effectiveness string `json:"effectiveness"`
	Gaps        []string `json:"gaps"`
}

type ThreatVector struct {
	Vector      string   `json:"vector"`
	Likelihood  string   `json:"likelihood"`
	Impact      string   `json:"impact"`
	Mitigations []string `json:"mitigations"`
}

type DataFlowRisk struct {
	Flow        string `json:"flow"`
	Sensitivity string `json:"sensitivity"`
	Protection  string `json:"protection"`
	Risk        string `json:"risk"`
}

type ComplianceFramework struct {
	Name        string  `json:"name"`
	Coverage    float64 `json:"coverage"`
	Status      string  `json:"status"`
	Priority    string  `json:"priority"`
}

type ComplianceRecommendation struct {
	Framework   string `json:"framework"`
	Action      string `json:"action"`
	Priority    string `json:"priority"`
	Timeline    string `json:"timeline"`
	Cost        string `json:"cost"`
}

type RiskFactor struct {
	Factor      string `json:"factor"`
	Impact      string `json:"impact"`
	Likelihood  string `json:"likelihood"`
	Mitigation  string `json:"mitigation"`
}

type Mitigation struct {
	Risk        string `json:"risk"`
	Action      string `json:"action"`
	Priority    string `json:"priority"`
	Timeline    string `json:"timeline"`
	Owner       string `json:"owner"`
}

// GenerateExpertAnalysis creates comprehensive expert-level analysis
func (re *ReportEnhancer) GenerateExpertAnalysis(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) (*ExpertAnalysis, error) {
	analysis := &ExpertAnalysis{}
	
	// Generate executive summary
	execSummary, err := re.generateExecutiveSummary(ctx, findings, scanContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate executive summary: %w", err)
	}
	analysis.ExecutiveSummary = *execSummary
	
	// Generate security metrics
	metrics, err := re.generateSecurityMetrics(ctx, findings, scanContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate security metrics: %w", err)
	}
	analysis.SecurityMetrics = *metrics
	
	// Generate technical analysis
	techAnalysis, err := re.generateTechnicalAnalysis(ctx, findings, scanContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate technical analysis: %w", err)
	}
	analysis.TechnicalAnalysis = *techAnalysis
	
	// Generate compliance analysis
	complianceAnalysis, err := re.generateComplianceAnalysis(ctx, findings, scanContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance analysis: %w", err)
	}
	analysis.ComplianceAnalysis = *complianceAnalysis
	
	// Generate risk assessment
	riskAssessment, err := re.generateRiskAssessment(ctx, findings, scanContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate risk assessment: %w", err)
	}
	analysis.RiskAssessment = *riskAssessment
	
	// Generate actionable POCs
	pocs, err := re.generateActionablePOCs(ctx, findings, scanContext)
	if err != nil {
		return nil, fmt.Errorf("failed to generate POCs: %w", err)
	}
	analysis.ActionablePOCs = pocs
	
	return analysis, nil
}

// generateExecutiveSummary creates executive-level summary
func (re *ReportEnhancer) generateExecutiveSummary(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) (*ExecutiveSummary, error) {
	_, err := re.prompts.RenderTemplate("executive_summary", map[string]interface{}{
		"findings":     findings,
		"scanContext": scanContext,
		"totalCount":  len(findings),
	})
	if err != nil {
		return nil, err
	}
	
	_, err = re.aiService.AnalyzeFindings(ctx, findings, scanContext)
	if err != nil {
		return nil, err
	}
	
	// Parse AI response into structured executive summary
	summary := &ExecutiveSummary{}
	// Implementation would parse the AI response
	
	return summary, nil
}

// generateActionablePOCs creates detailed proof-of-concept exploits
func (re *ReportEnhancer) generateActionablePOCs(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) ([]ActionablePOC, error) {
	var pocs []ActionablePOC
	
	// Focus on high and critical severity findings for POC generation
	criticalFindings := filterBySeverity(findings, []string{"critical", "high"})
	
	for _, finding := range criticalFindings {
		poc, err := re.generateSinglePOC(ctx, finding, scanContext)
		if err != nil {
			continue // Skip if POC generation fails
		}
		pocs = append(pocs, *poc)
	}
	
	return pocs, nil
}

// generateSinglePOC creates a detailed POC for a specific finding
func (re *ReportEnhancer) generateSinglePOC(ctx context.Context, finding types.Finding, scanContext *types.AnalysisContext) (*ActionablePOC, error) {
	_, err := re.prompts.RenderTemplate("poc_generation", map[string]interface{}{
		"finding":     finding,
		"scanContext": scanContext,
	})
	if err != nil {
		return nil, err
	}
	
	// Generate POC using existing AI service methods
	_, err = re.aiService.GenerateRemediation(ctx, finding, scanContext)
	if err != nil {
		return nil, err
	}
	
	// Parse AI response into structured POC
	poc := &ActionablePOC{
		VulnerabilityID: finding.ID,
		Title:           finding.Title,
		Severity:        string(finding.Severity),
		// Parse other fields from AI response
	}
	
	return poc, nil
}

// registerPromptTemplates registers expert-level prompt templates
func (re *ReportEnhancer) registerPromptTemplates() {
	templates := []*PromptTemplate{
		{
			ID:          "executive_summary",
			Name:        "Executive Summary Generator",
			Description: "Generates executive-level security summary",
			Category:    "reporting",
			Template: `You are a senior cybersecurity consultant preparing an executive summary for a security assessment.

SCAN CONTEXT:
Target: {{.scanContext.TargetURL}}
Total Findings: {{.totalCount}}

FINDINGS SUMMARY:
{{range .findings}}
- {{.Severity}}: {{.Title}} ({{.RuleID}})
{{end}}

Generate a comprehensive executive summary that includes:
1. Overall risk level (Critical/High/Medium/Low)
2. Top 5 key security findings that matter to business
3. Business impact assessment
4. Immediate actions required (prioritized)
5. Compliance status overview
6. Recommended security budget allocation

Format as JSON with clear, business-focused language that executives can understand.`,
		},
		{
			ID:          "poc_generation",
			Name:        "Proof of Concept Generator",
			Description: "Generates detailed POC exploits for vulnerabilities",
			Category:    "exploitation",
			Template: `You are a senior penetration tester creating a detailed proof-of-concept for a security vulnerability.

VULNERABILITY DETAILS:
Title: {{.finding.Title}}
Severity: {{.finding.Severity}}
Category: {{.finding.Category}}
URL: {{.finding.URL}}
Evidence: {{.finding.Evidence}}

TARGET CONTEXT:
{{.scanContext}}

Create a comprehensive POC that includes:
1. Step-by-step exploitation instructions
2. Actual proof-of-concept code/commands
3. Business impact explanation
4. CVSS vector and score calculation
5. CWE mapping
6. OWASP Top 10 category
7. Detailed remediation steps
8. Security references

Make it actionable for both technical teams and management. Include realistic attack scenarios.

Format as JSON with all fields properly structured.`,
		},
		{
			ID:          "security_metrics",
			Name:        "Security Metrics Calculator",
			Description: "Calculates comprehensive security metrics",
			Category:    "analysis",
			Template: `You are a security metrics analyst calculating comprehensive security posture metrics.

FINDINGS DATA:
{{range .findings}}
- {{.Severity}}: {{.Title}} (Category: {{.Category}})
{{end}}

Calculate and provide:
1. Overall risk score (0-100)
2. Vulnerability density metrics
3. Attack surface analysis
4. Critical path identification
5. Compliance gap analysis
6. Security control effectiveness

Provide quantitative metrics with clear explanations and benchmarking context.

Format as structured JSON with numerical scores and detailed breakdowns.`,
		},
	}
	
	for _, template := range templates {
		re.prompts.RegisterTemplate(template)
	}
}

// Helper functions
func filterBySeverity(findings []types.Finding, severities []string) []types.Finding {
	var filtered []types.Finding
	severityMap := make(map[string]bool)
	for _, s := range severities {
		severityMap[s] = true
	}
	
	for _, finding := range findings {
		if severityMap[string(finding.Severity)] {
			filtered = append(filtered, finding)
		}
	}
	
	return filtered
}

// Placeholder implementations for other analysis methods
func (re *ReportEnhancer) generateSecurityMetrics(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) (*SecurityMetrics, error) {
	// Implementation would use AI to calculate comprehensive metrics
	return &SecurityMetrics{}, nil
}

func (re *ReportEnhancer) generateTechnicalAnalysis(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) (*TechnicalAnalysis, error) {
	// Implementation would use AI for technical deep-dive
	return &TechnicalAnalysis{}, nil
}

func (re *ReportEnhancer) generateComplianceAnalysis(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) (*ComplianceAnalysis, error) {
	// Implementation would use AI for compliance mapping
	return &ComplianceAnalysis{}, nil
}

func (re *ReportEnhancer) generateRiskAssessment(ctx context.Context, findings []types.Finding, scanContext *types.AnalysisContext) (*RiskAssessment, error) {
	// Implementation would use AI for risk analysis
	return &RiskAssessment{}, nil
}

package reporting

import (
	"context"
	"io"

	"github.com/zuub-code/strider/pkg/types"
)

// ReportGenerator defines the interface for generating security reports
type ReportGenerator interface {
	// GenerateReport generates a report in the specified format
	GenerateReport(ctx context.Context, report *types.SecurityReport, format ReportFormat) ([]byte, error)

	// GenerateToWriter generates a report and writes it to the provided writer
	GenerateToWriter(ctx context.Context, report *types.SecurityReport, format ReportFormat, writer io.Writer) error

	// GetSupportedFormats returns the formats supported by this generator
	GetSupportedFormats() []ReportFormat

	// ValidateReport validates that a report contains required data
	ValidateReport(report *types.SecurityReport) error
}

// ReportManager manages multiple report generators and output
type ReportManager interface {
	// RegisterGenerator registers a report generator for a format
	RegisterGenerator(format ReportFormat, generator ReportGenerator) error

	// GenerateReports generates reports in multiple formats
	GenerateReports(ctx context.Context, report *types.SecurityReport, formats []ReportFormat) (map[ReportFormat][]byte, error)

	// SaveReports saves reports to files in the specified directory
	SaveReports(ctx context.Context, report *types.SecurityReport, formats []ReportFormat, outputDir string) error

	// GetAvailableFormats returns all available report formats
	GetAvailableFormats() []ReportFormat
}

// TemplateEngine handles report template rendering
type TemplateEngine interface {
	// LoadTemplate loads a template from file or string
	LoadTemplate(name string, content string) error

	// RenderTemplate renders a template with provided data
	RenderTemplate(templateName string, data interface{}) (string, error)

	// RegisterHelper registers a template helper function
	RegisterHelper(name string, helper interface{}) error

	// ListTemplates returns available template names
	ListTemplates() []string
}

// ReportFormat represents different report output formats
type ReportFormat string

const (
	FormatSARIF    ReportFormat = "sarif"
	FormatJSON     ReportFormat = "json"
	FormatHTML     ReportFormat = "html"
	FormatMarkdown ReportFormat = "markdown"
	FormatCSV      ReportFormat = "csv"
	FormatXML      ReportFormat = "xml"
	FormatPDF      ReportFormat = "pdf"
	FormatJUnit    ReportFormat = "junit"
)

// ReportConfig contains reporting configuration
type ReportConfig struct {
	OutputDirectory string            `json:"output_directory"`
	Formats         []ReportFormat    `json:"formats"`
	TemplateDir     string            `json:"template_directory"`
	CustomTemplates map[string]string `json:"custom_templates"`
	IncludeRawData  bool              `json:"include_raw_data"`
	CompressOutput  bool              `json:"compress_output"`
	Branding        BrandingConfig    `json:"branding"`
}

// BrandingConfig contains branding information for reports
type BrandingConfig struct {
	CompanyName string `json:"company_name"`
	LogoPath    string `json:"logo_path"`
	Colors      struct {
		Primary   string `json:"primary"`
		Secondary string `json:"secondary"`
		Accent    string `json:"accent"`
	} `json:"colors"`
	Footer string `json:"footer"`
}

// ReportMetadata contains metadata about generated reports
type ReportMetadata struct {
	GeneratedAt    string            `json:"generated_at"`
	GeneratedBy    string            `json:"generated_by"`
	ToolVersion    string            `json:"tool_version"`
	Format         ReportFormat      `json:"format"`
	FilePath       string            `json:"file_path"`
	FileSize       int64             `json:"file_size"`
	Checksum       string            `json:"checksum"`
	CustomMetadata map[string]string `json:"custom_metadata"`
}

// SARIFReport represents a SARIF format report structure
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a SARIF run
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Artifacts   []SARIFArtifact   `json:"artifacts,omitempty"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
}

// SARIFTool represents the tool information in SARIF
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver represents the tool driver in SARIF
type SARIFDriver struct {
	Name           string              `json:"name"`
	Version        string              `json:"version"`
	InformationURI string              `json:"informationUri,omitempty"`
	Rules          []SARIFRule         `json:"rules,omitempty"`
	Notifications  []SARIFNotification `json:"notifications,omitempty"`
}

// SARIFRule represents a rule in SARIF
type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     SARIFMessage           `json:"shortDescription"`
	FullDescription      SARIFMessage           `json:"fullDescription,omitempty"`
	Help                 SARIFMessage           `json:"help,omitempty"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
	DefaultConfiguration SARIFConfiguration     `json:"defaultConfiguration,omitempty"`
}

// SARIFResult represents a result in SARIF
type SARIFResult struct {
	RuleID       string                 `json:"ruleId"`
	RuleIndex    int                    `json:"ruleIndex,omitempty"`
	Message      SARIFMessage           `json:"message"`
	Level        string                 `json:"level,omitempty"`
	Locations    []SARIFLocation        `json:"locations,omitempty"`
	Fingerprints map[string]string      `json:"fingerprints,omitempty"`
	Properties   map[string]interface{} `json:"properties,omitempty"`
}

// SARIFLocation represents a location in SARIF
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation,omitempty"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

// SARIFPhysicalLocation represents a physical location in SARIF
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

// SARIFArtifactLocation represents an artifact location in SARIF
type SARIFArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// SARIFRegion represents a region in SARIF
type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// SARIFLogicalLocation represents a logical location in SARIF
type SARIFLogicalLocation struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}

// SARIFMessage represents a message in SARIF
type SARIFMessage struct {
	Text       string                 `json:"text"`
	Markdown   string                 `json:"markdown,omitempty"`
	Arguments  []string               `json:"arguments,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFArtifact represents an artifact in SARIF
type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
	Length   int64                 `json:"length,omitempty"`
	MimeType string                `json:"mimeType,omitempty"`
	Contents SARIFArtifactContent  `json:"contents,omitempty"`
	Hashes   map[string]string     `json:"hashes,omitempty"`
}

// SARIFArtifactContent represents artifact content in SARIF
type SARIFArtifactContent struct {
	Text   string `json:"text,omitempty"`
	Binary string `json:"binary,omitempty"`
}

// SARIFInvocation represents an invocation in SARIF
type SARIFInvocation struct {
	CommandLine         string                  `json:"commandLine,omitempty"`
	Arguments           []string                `json:"arguments,omitempty"`
	ResponseFiles       []SARIFArtifactLocation `json:"responseFiles,omitempty"`
	StartTimeUTC        string                  `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string                  `json:"endTimeUtc,omitempty"`
	ExitCode            int                     `json:"exitCode,omitempty"`
	ExecutionSuccessful bool                    `json:"executionSuccessful"`
	Properties          map[string]interface{}  `json:"properties,omitempty"`
}

// SARIFNotification represents a notification in SARIF
type SARIFNotification struct {
	Level      string                 `json:"level,omitempty"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SARIFConfiguration represents a configuration in SARIF
type SARIFConfiguration struct {
	Level      string                 `json:"level,omitempty"`
	Enabled    bool                   `json:"enabled,omitempty"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// HTMLReportData contains data for HTML report generation
type HTMLReportData struct {
	Report   *types.SecurityReport `json:"report"`
	Metadata ReportMetadata        `json:"metadata"`
	Branding BrandingConfig        `json:"branding"`
	Summary  ReportSummary         `json:"summary"`
	Charts   []ChartData           `json:"charts"`
	Sections []ReportSection       `json:"sections"`
}

// ReportSummary contains summary statistics for reports
type ReportSummary struct {
	TotalFindings        int                    `json:"total_findings"`
	FindingsBySeverity   map[string]int         `json:"findings_by_severity"`
	FindingsByCategory   map[string]int         `json:"findings_by_category"`
	FindingsByConfidence map[string]int         `json:"findings_by_confidence"`
	TopVulnerabilities   []VulnerabilitySummary `json:"top_vulnerabilities"`
	RiskScore            float64                `json:"risk_score"`
	ComplianceStatus     map[string]string      `json:"compliance_status"`
}

// VulnerabilitySummary contains summary of a vulnerability type
type VulnerabilitySummary struct {
	Type        string  `json:"type"`
	Count       int     `json:"count"`
	Severity    string  `json:"severity"`
	RiskScore   float64 `json:"risk_score"`
	Description string  `json:"description"`
}

// ChartData represents data for charts in reports
type ChartData struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Data   map[string]interface{} `json:"data"`
	Config map[string]interface{} `json:"config"`
}

// ReportSection represents a section in a report
type ReportSection struct {
	ID       string                 `json:"id"`
	Title    string                 `json:"title"`
	Content  string                 `json:"content"`
	Data     map[string]interface{} `json:"data"`
	Template string                 `json:"template"`
}

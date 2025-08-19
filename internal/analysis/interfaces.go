package analysis

import (
	"context"

	"github.com/zuub-code/strider/pkg/types"
)

// AnalysisEngine defines the interface for security analysis
type AnalysisEngine interface {
	// Analyze performs comprehensive security analysis on crawl results
	Analyze(ctx context.Context, results *types.CrawlResults) ([]types.Finding, error)

	// AnalyzePage performs analysis on a single page
	AnalyzePage(ctx context.Context, page *types.PageResult) ([]types.Finding, error)

	// RegisterRule registers a new analysis rule
	RegisterRule(rule Rule) error

	// GetRules returns all registered rules
	GetRules() []Rule

	// EnableRule enables a specific rule by ID
	EnableRule(ruleID string) error

	// DisableRule disables a specific rule by ID
	DisableRule(ruleID string) error
}

// Rule defines the interface for security analysis rules
type Rule interface {
	// ID returns the unique identifier for this rule
	ID() string

	// Name returns the human-readable name of the rule
	Name() string

	// Description returns a detailed description of what this rule checks
	Description() string

	// Category returns the rule category (e.g., "headers", "cookies", "content")
	Category() string

	// Severity returns the default severity level for findings from this rule
	Severity() types.Severity

	// Analyze performs the actual analysis and returns findings
	Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error)

	// IsEnabled returns whether this rule is currently enabled
	IsEnabled() bool

	// SetEnabled sets the enabled state of this rule
	SetEnabled(enabled bool)

	// GetMetadata returns rule metadata for reporting
	GetMetadata() RuleMetadata
}

// RuleMetadata contains metadata about a rule
type RuleMetadata struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    types.Severity         `json:"severity"`
	STRIDE      []types.STRIDECategory `json:"stride,omitempty"`
	MITREAttck  []types.MITRETechnique `json:"mitre_attck,omitempty"`
	OWASP       []string               `json:"owasp,omitempty"`
	CWE         []int                  `json:"cwe,omitempty"`
	References  []string               `json:"references,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Enabled     bool                   `json:"enabled"`
}

// RuleRegistry manages rule registration and discovery
type RuleRegistry interface {
	// Register registers a new rule
	Register(rule Rule) error

	// Unregister removes a rule by ID
	Unregister(ruleID string) error

	// Get retrieves a rule by ID
	Get(ruleID string) (Rule, bool)

	// List returns all registered rules
	List() []Rule

	// ListByCategory returns rules filtered by category
	ListByCategory(category string) []Rule

	// ListEnabled returns only enabled rules
	ListEnabled() []Rule

	// EnableAll enables all rules
	EnableAll()

	// DisableAll disables all rules
	DisableAll()
}

// RuleExecutor handles parallel rule execution
type RuleExecutor interface {
	// Execute runs rules against a page with parallelization
	Execute(ctx context.Context, page *types.PageResult, rules []Rule) ([]types.Finding, error)

	// ExecuteRule runs a single rule against a page
	ExecuteRule(ctx context.Context, page *types.PageResult, rule Rule) ([]types.Finding, error)

	// SetMaxWorkers sets the maximum number of concurrent workers
	SetMaxWorkers(workers int)

	// GetStats returns execution statistics
	GetStats() ExecutionStats
}

// ExecutionStats contains rule execution statistics
type ExecutionStats struct {
	TotalRules    int        `json:"total_rules"`
	ExecutedRules int        `json:"executed_rules"`
	FailedRules   int        `json:"failed_rules"`
	TotalFindings int        `json:"total_findings"`
	ExecutionTime int64      `json:"execution_time_ms"`
	RuleStats     []RuleStat `json:"rule_stats"`
}

// RuleStat contains statistics for a single rule
type RuleStat struct {
	RuleID        string `json:"rule_id"`
	ExecutionTime int64  `json:"execution_time_ms"`
	FindingsCount int    `json:"findings_count"`
	Success       bool   `json:"success"`
	Error         string `json:"error,omitempty"`
}

// FindingFilter provides filtering and deduplication of findings
type FindingFilter interface {
	// Filter applies filtering rules to findings
	Filter(findings []types.Finding) []types.Finding

	// Deduplicate removes duplicate findings
	Deduplicate(findings []types.Finding) []types.Finding

	// Merge combines similar findings
	Merge(findings []types.Finding) []types.Finding

	// Sort sorts findings by severity and confidence
	Sort(findings []types.Finding) []types.Finding
}

// ContextAnalyzer provides context-aware analysis
type ContextAnalyzer interface {
	// AnalyzeContext extracts context information from crawl results
	AnalyzeContext(results *types.CrawlResults) *types.AnalysisContext

	// DetectApplicationType attempts to identify the application type
	DetectApplicationType(results *types.CrawlResults) string

	// ExtractAPIEndpoints identifies API endpoints from the crawl
	ExtractAPIEndpoints(results *types.CrawlResults) []string

	// IdentifyFrameworks detects web frameworks and technologies
	IdentifyFrameworks(results *types.CrawlResults) []string
}

// RuleCache provides caching for rule execution results
type RuleCache interface {
	// Get retrieves cached results for a rule and page
	Get(ruleID string, pageHash string) ([]types.Finding, bool)

	// Set stores results in cache
	Set(ruleID string, pageHash string, findings []types.Finding)

	// Invalidate removes cached results
	Invalidate(ruleID string, pageHash string)

	// Clear clears all cached results
	Clear()

	// GetStats returns cache statistics
	GetStats() CacheStats
}

// CacheStats contains cache performance statistics
type CacheStats struct {
	Hits    int64   `json:"hits"`
	Misses  int64   `json:"misses"`
	HitRate float64 `json:"hit_rate"`
	Size    int     `json:"size"`
	MaxSize int     `json:"max_size"`
}

// RuleLoader handles loading rules from various sources
type RuleLoader interface {
	// LoadFromDirectory loads rules from a directory
	LoadFromDirectory(path string) ([]Rule, error)

	// LoadFromFile loads a rule from a file
	LoadFromFile(path string) (Rule, error)

	// LoadBuiltinRules loads built-in security rules
	LoadBuiltinRules() ([]Rule, error)

	// ValidateRule validates a rule configuration
	ValidateRule(rule Rule) error
}

// RuleConfig represents rule configuration
type RuleConfig struct {
	ID          string                 `yaml:"id" json:"id"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description" json:"description"`
	Category    string                 `yaml:"category" json:"category"`
	Severity    types.Severity         `yaml:"severity" json:"severity"`
	Enabled     bool                   `yaml:"enabled" json:"enabled"`
	STRIDE      []types.STRIDECategory `yaml:"stride,omitempty" json:"stride,omitempty"`
	MITREAttck  []types.MITRETechnique `yaml:"mitre_attck,omitempty" json:"mitre_attck,omitempty"`
	OWASP       []string               `yaml:"owasp,omitempty" json:"owasp,omitempty"`
	CWE         []int                  `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	References  []string               `yaml:"references,omitempty" json:"references,omitempty"`
	Tags        []string               `yaml:"tags,omitempty" json:"tags,omitempty"`
	Parameters  map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
}

// BaseRule provides common functionality for rules
type BaseRule struct {
	metadata RuleMetadata
	enabled  bool
}

// ID returns the rule ID
func (br *BaseRule) ID() string {
	return br.metadata.ID
}

// Name returns the rule name
func (br *BaseRule) Name() string {
	return br.metadata.Name
}

// Description returns the rule description
func (br *BaseRule) Description() string {
	return br.metadata.Description
}

// Category returns the rule category
func (br *BaseRule) Category() string {
	return br.metadata.Category
}

// Severity returns the rule severity
func (br *BaseRule) Severity() types.Severity {
	return br.metadata.Severity
}

// IsEnabled returns whether the rule is enabled
func (br *BaseRule) IsEnabled() bool {
	return br.enabled
}

// SetEnabled sets the enabled state
func (br *BaseRule) SetEnabled(enabled bool) {
	br.enabled = enabled
	br.metadata.Enabled = enabled
}

// GetMetadata returns rule metadata
func (br *BaseRule) GetMetadata() RuleMetadata {
	return br.metadata
}

// NewBaseRule creates a new base rule
func NewBaseRule(config RuleConfig) *BaseRule {
	return &BaseRule{
		metadata: RuleMetadata{
			ID:          config.ID,
			Name:        config.Name,
			Description: config.Description,
			Category:    config.Category,
			Severity:    config.Severity,
			STRIDE:      config.STRIDE,
			MITREAttck:  config.MITREAttck,
			OWASP:       config.OWASP,
			CWE:         config.CWE,
			References:  config.References,
			Tags:        config.Tags,
			Enabled:     config.Enabled,
		},
		enabled: config.Enabled,
	}
}

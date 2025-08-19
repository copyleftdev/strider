package analysis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
)

// analysisEngine implements AnalysisEngine interface
type analysisEngine struct {
	registry        RuleRegistry
	executor        RuleExecutor
	filter          FindingFilter
	cache           RuleCache
	contextAnalyzer ContextAnalyzer
	logger          logger.Logger

	// Configuration
	maxWorkers  int
	enableCache bool

	// Statistics
	stats EngineStats
	mu    sync.RWMutex
}

// EngineStats contains analysis engine statistics
type EngineStats struct {
	TotalAnalyses int64         `json:"total_analyses"`
	TotalFindings int64         `json:"total_findings"`
	AverageTime   time.Duration `json:"average_time"`
	CacheHitRate  float64       `json:"cache_hit_rate"`
	RulesExecuted int64         `json:"rules_executed"`
	RulesFailed   int64         `json:"rules_failed"`
}

// NewAnalysisEngine creates a new analysis engine
func NewAnalysisEngine(logger logger.Logger) AnalysisEngine {
	engine := &analysisEngine{
		registry:        NewRuleRegistry(),
		executor:        NewRuleExecutor(4), // Default 4 workers
		filter:          NewFindingFilter(),
		cache:           NewRuleCache(1000), // Default cache size
		contextAnalyzer: NewContextAnalyzer(),
		logger:          logger,
		maxWorkers:      4,
		enableCache:     true,
	}

	// Load built-in rules
	if err := engine.loadBuiltinRules(); err != nil {
		logger.Error("Failed to load built-in rules", "error", err)
	}

	return engine
}

// Analyze performs comprehensive security analysis on crawl results
func (e *analysisEngine) Analyze(ctx context.Context, results *types.CrawlResults) ([]types.Finding, error) {
	startTime := time.Now()

	e.logger.Info("Starting security analysis",
		"session_id", results.SessionID,
		"pages", len(results.Pages),
		"rules", len(e.registry.ListEnabled()))

	// Extract analysis context
	analysisContext := e.contextAnalyzer.AnalyzeContext(results)

	// Analyze each page
	var allFindings []types.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use semaphore to limit concurrent page analysis
	semaphore := make(chan struct{}, e.maxWorkers)

	for _, page := range results.Pages {
		wg.Add(1)
		go func(p *types.PageResult) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			findings, err := e.AnalyzePage(ctx, p)
			if err != nil {
				e.logger.Error("Failed to analyze page", "error", err, "url", p.URL.String())
				return
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(page)
	}

	wg.Wait()

	// Apply context-aware filtering
	allFindings = e.applyContextualFiltering(allFindings, analysisContext)

	// Filter and deduplicate findings
	allFindings = e.filter.Filter(allFindings)
	allFindings = e.filter.Deduplicate(allFindings)
	allFindings = e.filter.Merge(allFindings)
	allFindings = e.filter.Sort(allFindings)

	// Update statistics
	e.updateStats(len(allFindings), time.Since(startTime))

	e.logger.Info("Analysis completed",
		"findings", len(allFindings),
		"duration", time.Since(startTime))

	return allFindings, nil
}

// AnalyzePage performs analysis on a single page
func (e *analysisEngine) AnalyzePage(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	rules := e.registry.ListEnabled()
	if len(rules) == 0 {
		return []types.Finding{}, nil
	}

	findings, err := e.executor.Execute(ctx, page, rules)
	if err != nil {
		return nil, fmt.Errorf("rule execution failed: %w", err)
	}

	// Set page URL and source for all findings
	for i := range findings {
		findings[i].PageURL = page.URL
		if findings[i].Source == "" {
			findings[i].Source = types.SourceStatic
		}
		if findings[i].CreatedAt.IsZero() {
			findings[i].CreatedAt = time.Now()
		}
	}

	return findings, nil
}

// RegisterRule registers a new analysis rule
func (e *analysisEngine) RegisterRule(rule Rule) error {
	return e.registry.Register(rule)
}

// GetRules returns all registered rules
func (e *analysisEngine) GetRules() []Rule {
	return e.registry.List()
}

// EnableRule enables a specific rule by ID
func (e *analysisEngine) EnableRule(ruleID string) error {
	rule, exists := e.registry.Get(ruleID)
	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	rule.SetEnabled(true)
	e.logger.Info("Rule enabled", "rule_id", ruleID)
	return nil
}

// DisableRule disables a specific rule by ID
func (e *analysisEngine) DisableRule(ruleID string) error {
	rule, exists := e.registry.Get(ruleID)
	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	rule.SetEnabled(false)
	e.logger.Info("Rule disabled", "rule_id", ruleID)
	return nil
}

// loadBuiltinRules loads the built-in security rules
func (e *analysisEngine) loadBuiltinRules() error {
	loader := NewRuleLoader()
	rules, err := loader.LoadBuiltinRules()
	if err != nil {
		return fmt.Errorf("failed to load built-in rules: %w", err)
	}

	for _, rule := range rules {
		if err := e.RegisterRule(rule); err != nil {
			e.logger.Error("Failed to register rule", "rule_id", rule.ID(), "error", err)
		}
	}

	e.logger.Info("Loaded built-in rules", "count", len(rules))
	return nil
}

// applyContextualFiltering applies context-aware filtering to findings
func (e *analysisEngine) applyContextualFiltering(findings []types.Finding, context *types.AnalysisContext) []types.Finding {
	// Apply application-specific filtering based on detected app type
	switch context.ApplicationType {
	case "spa":
		// Single Page Applications might have different security considerations
		findings = e.filterSPAFindings(findings)
	case "api":
		// API endpoints have different security requirements
		findings = e.filterAPIFindings(findings)
	case "cms":
		// Content Management Systems have specific vulnerabilities
		findings = e.filterCMSFindings(findings)
	}

	// Apply industry-specific compliance filtering
	if context.Industry != "" {
		findings = e.applyIndustryFiltering(findings, context.Industry)
	}

	return findings
}

// filterSPAFindings applies SPA-specific filtering
func (e *analysisEngine) filterSPAFindings(findings []types.Finding) []types.Finding {
	// SPAs might not need certain traditional security headers
	filtered := make([]types.Finding, 0, len(findings))

	for _, finding := range findings {
		// Example: CSP might be less critical for SPAs that don't serve user content
		if finding.RuleID == "missing-csp" && finding.Severity == types.SeverityHigh {
			// Downgrade severity for SPAs
			finding.Severity = types.SeverityMedium
		}
		filtered = append(filtered, finding)
	}

	return filtered
}

// filterAPIFindings applies API-specific filtering
func (e *analysisEngine) filterAPIFindings(findings []types.Finding) []types.Finding {
	// APIs have different security requirements than web applications
	filtered := make([]types.Finding, 0, len(findings))

	for _, finding := range findings {
		// Example: Frame options are not relevant for APIs
		if finding.RuleID == "missing-frame-options" {
			continue // Skip this finding for APIs
		}
		filtered = append(filtered, finding)
	}

	return filtered
}

// filterCMSFindings applies CMS-specific filtering
func (e *analysisEngine) filterCMSFindings(findings []types.Finding) []types.Finding {
	// CMSs often have specific security considerations
	return findings // Placeholder implementation
}

// applyIndustryFiltering applies industry-specific compliance filtering
func (e *analysisEngine) applyIndustryFiltering(findings []types.Finding, industry string) []types.Finding {
	switch industry {
	case "healthcare":
		// HIPAA compliance requirements
		return e.applyHIPAAFiltering(findings)
	case "finance":
		// PCI DSS and other financial regulations
		return e.applyFinancialFiltering(findings)
	case "government":
		// Government security standards
		return e.applyGovernmentFiltering(findings)
	}

	return findings
}

// applyHIPAAFiltering applies HIPAA-specific filtering
func (e *analysisEngine) applyHIPAAFiltering(findings []types.Finding) []types.Finding {
	// Upgrade severity for encryption and access control findings
	for i := range findings {
		if findings[i].Category == "encryption" || findings[i].Category == "access_control" {
			if findings[i].Severity == types.SeverityMedium {
				findings[i].Severity = types.SeverityHigh
			}
		}
	}
	return findings
}

// applyFinancialFiltering applies financial industry filtering
func (e *analysisEngine) applyFinancialFiltering(findings []types.Finding) []types.Finding {
	// PCI DSS requirements are strict about data protection
	for i := range findings {
		if findings[i].Category == "data_protection" {
			if findings[i].Severity == types.SeverityLow {
				findings[i].Severity = types.SeverityMedium
			}
		}
	}
	return findings
}

// applyGovernmentFiltering applies government security filtering
func (e *analysisEngine) applyGovernmentFiltering(findings []types.Finding) []types.Finding {
	// Government standards often require higher security
	for i := range findings {
		// Upgrade all medium findings to high for government
		if findings[i].Severity == types.SeverityMedium {
			findings[i].Severity = types.SeverityHigh
		}
	}
	return findings
}

// updateStats updates engine statistics
func (e *analysisEngine) updateStats(findingsCount int, duration time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stats.TotalAnalyses++
	e.stats.TotalFindings += int64(findingsCount)

	// Update average time (simple moving average)
	if e.stats.TotalAnalyses == 1 {
		e.stats.AverageTime = duration
	} else {
		e.stats.AverageTime = (e.stats.AverageTime + duration) / 2
	}

	// Update cache hit rate if cache is enabled
	if e.enableCache {
		cacheStats := e.cache.GetStats()
		if cacheStats.Hits+cacheStats.Misses > 0 {
			e.stats.CacheHitRate = cacheStats.HitRate
		}
	}
}

// GetStats returns current engine statistics
func (e *analysisEngine) GetStats() EngineStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// SetMaxWorkers sets the maximum number of concurrent workers
func (e *analysisEngine) SetMaxWorkers(workers int) {
	e.maxWorkers = workers
	e.executor.SetMaxWorkers(workers)
}

// EnableCache enables or disables result caching
func (e *analysisEngine) EnableCache(enable bool) {
	e.enableCache = enable
	if !enable {
		e.cache.Clear()
	}
}

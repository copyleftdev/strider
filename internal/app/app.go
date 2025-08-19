package app

import (
	"context"
	"fmt"
	"time"

	"github.com/zuub-code/strider/internal/ai"
	"github.com/zuub-code/strider/internal/analysis"
	"github.com/zuub-code/strider/internal/crawler"
	"github.com/zuub-code/strider/internal/storage"
	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
)

// ScanOptions contains all configuration options for a scan
type ScanOptions struct {
	// Target configuration
	RootURL string

	// Crawl configuration
	Concurrency    int
	MaxPages       int
	MaxDepth       int
	RequestTimeout time.Duration
	IdleTimeout    time.Duration

	// Analysis configuration
	AllowThirdParty  bool
	MaxBodySize      int64
	EnableJavaScript bool
	EnableImages     bool

	// AI configuration
	OllamaModel string
	EnableAI    bool

	// Output configuration
	OutputDir        string
	GenerateSARIF    bool
	GenerateJSON     bool
	GenerateMarkdown bool

	// Advanced options
	RespectRobots bool
	EnableStealth bool
	FastScan      bool
}

// Application represents the main STRIDER application
type Application struct {
	opts     ScanOptions
	logger   logger.Logger
	crawler  crawler.Crawler
	analyzer analysis.AnalysisEngine
	ai       ai.AIService
	storage  storage.Storage
}

// New creates a new Application instance
func New(opts ScanOptions, log logger.Logger) (*Application, error) {
	// Initialize storage
	storageService := storage.NewSQLiteStorage(storage.StorageConfig{
		Type:         "sqlite",
		DatabasePath: fmt.Sprintf("%s/strider.db", opts.OutputDir),
		MaxConns:     10,
		Timeout:      30 * time.Second,
		WALMode:      true,
		CacheSize:    64000,
		BusyTimeout:  5 * time.Second,
		EnableCache:  true,
		CacheTTL:     5 * time.Minute,
	}, log)

	// Initialize crawler
	crawlerService := crawler.NewRodCrawler(log)

	// Initialize analysis engine
	analysisService := analysis.NewAnalysisEngine(log)

	// Initialize AI service
	var aiService ai.AIService
	if opts.EnableAI {
		aiConfig := ai.AIConfig{
			Enabled:        true,
			BaseURL:        "http://localhost:11434",
			DefaultModel:   opts.OllamaModel,
			Temperature:    0.1,
			MaxTokens:      2048,
			RetryAttempts:  3,
			Timeout:        60,
			EnableCache:    true,
			CacheSize:      1000,
			FallbackModels: []string{"llama3.1:8b", "mistral"},
		}

		aiService = ai.NewAIService(aiConfig, log)
	}

	// Initialize storage
	if err := storageService.Initialize(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	return &Application{
		opts:     opts,
		logger:   log,
		crawler:  crawlerService,
		analyzer: analysisService,
		ai:       aiService,
		storage:  storageService,
	}, nil
}

// Run executes the security analysis scan
func (a *Application) Run(ctx context.Context) error {
	a.logger.Info("Starting STRIDER security analysis",
		"url", a.opts.RootURL,
		"concurrency", a.opts.Concurrency,
		"max_pages", a.opts.MaxPages,
	)

	// Phase 1: Crawling
	a.logger.Info("Phase 1: Starting web crawling")
	crawlResults, err := a.crawler.Crawl(ctx, types.CrawlConfig{
		RootURL:          a.opts.RootURL,
		MaxPages:         a.opts.MaxPages,
		MaxDepth:         a.opts.MaxDepth,
		Concurrency:      a.opts.Concurrency,
		RequestTimeout:   a.opts.RequestTimeout,
		IdleTimeout:      a.opts.IdleTimeout,
		MaxBodySize:      a.opts.MaxBodySize,
		EnableJavaScript: a.opts.EnableJavaScript,
		EnableImages:     a.opts.EnableImages,
		RespectRobots:    a.opts.RespectRobots,
		EnableStealth:    a.opts.EnableStealth,
	})
	if err != nil {
		return fmt.Errorf("crawling failed: %w", err)
	}

	a.logger.Info("Crawling completed",
		"pages_crawled", len(crawlResults.Pages),
		"requests_captured", crawlResults.TotalRequests,
		"responses_captured", crawlResults.TotalResponses,
	)

	// Phase 2: Static Analysis
	a.logger.Info("Phase 2: Starting static security analysis")
	var allFindings []types.Finding

	for _, page := range crawlResults.Pages {
		findings, err := a.analyzer.AnalyzePage(ctx, page)
		if err != nil {
			a.logger.Warn("Failed to analyze page", "url", page.URL, "error", err)
			continue
		}
		allFindings = append(allFindings, findings...)
	}

	a.logger.Info("Static analysis completed", "findings", len(allFindings))

	// Phase 3: AI Enhancement (if enabled)
	if a.ai != nil {
		a.logger.Info("Phase 3: Starting AI-powered analysis enhancement")

		for _, page := range crawlResults.Pages {
			pageFindings := filterFindingsByPage(allFindings, page.URL.String())
			enhancedFindings, err := a.ai.GradeFindings(ctx, pageFindings, &types.AnalysisContext{
				Domain:          page.Domain,
				ApplicationType: detectApplicationType(page),
				APIEndpoints:    extractAPIEndpoints(page),
			})
			if err != nil {
				a.logger.Warn("AI analysis failed for page", "url", page.URL, "error", err)
				continue
			}

			// Replace findings for this page
			allFindings = replaceFindingsForPage(allFindings, enhancedFindings, page.URL.String())
		}

		a.logger.Info("AI analysis completed", "total_findings", len(allFindings))
	}

	// Phase 4: Storage
	a.logger.Info("Phase 4: Storing results")

	// Create session
	session := &storage.CrawlSession{
		ID:            crawlResults.SessionID,
		RootURL:       a.opts.RootURL,
		StartTime:     crawlResults.StartTime,
		EndTime:       &crawlResults.EndTime,
		Status:        "completed",
		PagesCount:    len(crawlResults.Pages),
		FindingsCount: len(allFindings),
		Config:        "{}", // JSON config would go here
		Metadata:      "{}",
	}

	if err := a.storage.CreateSession(ctx, session); err != nil {
		a.logger.Warn("Failed to store session", "error", err)
	}

	// Store pages
	for _, page := range crawlResults.Pages {
		if err := a.storage.StorePage(ctx, crawlResults.SessionID, page); err != nil {
			a.logger.Warn("Failed to store page", "url", page.URL, "error", err)
		}
	}

	// Store findings
	if err := a.storage.StoreFindings(ctx, crawlResults.SessionID, allFindings); err != nil {
		a.logger.Warn("Failed to store findings", "error", err)
	}

	// Phase 5: Reporting
	a.logger.Info("Phase 5: Generating reports")
	report := &types.SecurityReport{
		SessionID:    crawlResults.SessionID,
		RootURL:      a.opts.RootURL,
		StartTime:    crawlResults.StartTime,
		EndTime:      time.Now(),
		Findings:     allFindings,
		Statistics:   calculateStatistics(allFindings),
		CrawlMetrics: crawlResults.Metrics,
	}

	if err := a.storage.StoreReport(ctx, report); err != nil {
		a.logger.Warn("Failed to store report", "error", err)
	}

	// Summary
	stats := report.Statistics
	a.logger.Info("STRIDER analysis completed successfully",
		"total_findings", stats.TotalFindings,
		"critical", stats.CriticalCount,
		"high", stats.HighCount,
		"medium", stats.MediumCount,
		"low", stats.LowCount,
		"info", stats.InfoCount,
		"output_dir", a.opts.OutputDir,
	)

	return nil
}

// Helper functions
func filterFindingsByPage(findings []types.Finding, pageURL string) []types.Finding {
	var result []types.Finding
	for _, finding := range findings {
		if finding.PageURL.String() == pageURL {
			result = append(result, finding)
		}
	}
	return result
}

func replaceFindingsForPage(allFindings, newFindings []types.Finding, pageURL string) []types.Finding {
	var result []types.Finding

	// Add findings from other pages
	for _, finding := range allFindings {
		if finding.PageURL.String() != pageURL {
			result = append(result, finding)
		}
	}

	// Add new findings for this page
	result = append(result, newFindings...)

	return result
}

func detectApplicationType(page *types.PageResult) string {
	// Simple heuristics for application type detection
	if containsAPIEndpoints(page) {
		return "api"
	}
	if containsSPAFramework(page) {
		return "spa"
	}
	return "web"
}

func extractAPIEndpoints(page *types.PageResult) []string {
	var endpoints []string
	for _, response := range page.Responses {
		if isAPIEndpoint(response) {
			endpoints = append(endpoints, response.URL.String())
		}
	}
	return endpoints
}

func containsAPIEndpoints(page *types.PageResult) bool {
	for _, response := range page.Responses {
		if isAPIEndpoint(response) {
			return true
		}
	}
	return false
}

func containsSPAFramework(page *types.PageResult) bool {
	for _, response := range page.Responses {
		if response.MIMEType == "application/javascript" {
			// Check for common SPA framework signatures
			// This would be implemented with actual detection logic
			return true
		}
	}
	return false
}

func isAPIEndpoint(response types.ResponseRecord) bool {
	return response.MIMEType == "application/json" ||
		response.MIMEType == "application/xml" ||
		response.URL.Path == "/api" ||
		response.URL.Path == "/graphql"
}

func calculateStatistics(findings []types.Finding) types.SecurityStatistics {
	stats := types.SecurityStatistics{
		TotalFindings: len(findings),
	}

	for _, finding := range findings {
		switch finding.Severity {
		case types.SeverityCritical:
			stats.CriticalCount++
		case types.SeverityHigh:
			stats.HighCount++
		case types.SeverityMedium:
			stats.MediumCount++
		case types.SeverityLow:
			stats.LowCount++
		case types.SeverityInfo:
			stats.InfoCount++
		}
	}

	return stats
}

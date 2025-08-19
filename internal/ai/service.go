package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
)

// aiService implements AIService interface
type aiService struct {
	client        OllamaClient
	promptManager PromptManager
	modelSelector ModelSelector
	validator     ResponseValidator
	fallback      FallbackStrategy
	cache         AICache
	metrics       AIMetrics
	logger        logger.Logger

	// Configuration
	config       AIConfig
	currentModel string

	// State
	mu              sync.RWMutex
	isHealthy       bool
	lastHealthCheck time.Time
}

// NewAIService creates a new AI service
func NewAIService(config AIConfig, logger logger.Logger) AIService {
	service := &aiService{
		client:        NewOllamaClient(config.BaseURL, config.Timeout),
		promptManager: NewPromptManager(),
		modelSelector: NewModelSelector(),
		validator:     NewResponseValidator(),
		fallback:      NewFallbackStrategy(config.FallbackModels),
		cache:         NewAICache(config.CacheSize),
		metrics:       NewAIMetrics(),
		logger:        logger,
		config:        config,
		currentModel:  config.DefaultModel,
	}

	// Initialize prompt templates
	if err := service.initializePrompts(); err != nil {
		logger.Error("Failed to initialize AI prompts", "error", err)
	}

	return service
}

// AnalyzeFindings performs AI analysis on security findings
func (s *aiService) AnalyzeFindings(ctx context.Context, findings []types.Finding, context *types.AnalysisContext) ([]types.Finding, error) {
	if !s.config.Enabled || len(findings) == 0 {
		return findings, nil
	}

	s.logger.Info("Starting AI analysis of findings", "count", len(findings))

	// Select appropriate model for analysis task
	task := AITask{
		Type:       TaskAnalysis,
		Complexity: s.determineComplexity(len(findings)),
		Domain:     "security",
		Context:    map[string]interface{}{"findings_count": len(findings)},
	}

	model, err := s.modelSelector.SelectModel(ctx, task, context)
	if err != nil {
		s.logger.Error("Failed to select model", "error", err)
		model = s.currentModel // Fallback to default
	}

	// Process findings in batches to avoid token limits
	batchSize := s.calculateBatchSize(model)
	var enhancedFindings []types.Finding

	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]
		enhanced, err := s.analyzeFindingsBatch(ctx, batch, context, model)
		if err != nil {
			s.logger.Error("Failed to analyze findings batch", "error", err, "batch_start", i)
			// Continue with original findings for this batch
			enhancedFindings = append(enhancedFindings, batch...)
			continue
		}

		enhancedFindings = append(enhancedFindings, enhanced...)
	}

	s.logger.Info("Completed AI analysis", "original_count", len(findings), "enhanced_count", len(enhancedFindings))
	return enhancedFindings, nil
}

// GradeFindings assigns risk scores and priorities to findings
func (s *aiService) GradeFindings(ctx context.Context, findings []types.Finding, context *types.AnalysisContext) ([]types.Finding, error) {
	if !s.config.Enabled || len(findings) == 0 {
		return findings, nil
	}

	s.logger.Info("Starting AI grading of findings", "count", len(findings))

	task := AITask{
		Type:       TaskGrading,
		Complexity: ComplexityMedium,
		Domain:     "security",
	}

	model, err := s.modelSelector.SelectModel(ctx, task, context)
	if err != nil {
		model = s.currentModel
	}

	// Generate grading prompt
	prompt, err := s.promptManager.RenderTemplate("grade_findings", map[string]interface{}{
		"findings":              findings,
		"context":               context,
		"application_type":      context.ApplicationType,
		"industry":              context.Industry,
		"compliance_frameworks": context.ComplianceFrameworks,
	})
	if err != nil {
		return findings, fmt.Errorf("failed to render grading prompt: %w", err)
	}

	// Check cache first
	cacheKey := s.generateCacheKey("grade", prompt, model)
	if s.config.EnableCache {
		if cached, found := s.cache.Get(cacheKey); found {
			s.logger.Debug("Using cached grading result")
			return s.parseGradedFindings(cached, findings)
		}
	}

	// Make AI request
	request := &AIRequest{
		Model:       model,
		Prompt:      prompt,
		Temperature: 0.1, // Low temperature for consistent grading
		MaxTokens:   s.config.MaxTokens,
	}

	response, err := s.makeRequestWithRetry(ctx, request)
	if err != nil {
		return findings, fmt.Errorf("AI grading failed: %w", err)
	}

	// Cache the response
	if s.config.EnableCache {
		s.cache.Set(cacheKey, response, 3600) // 1 hour TTL
	}

	// Parse and apply grades
	gradedFindings, err := s.parseGradedFindings(response, findings)
	if err != nil {
		s.logger.Error("Failed to parse graded findings", "error", err)
		return findings, nil // Return original findings on parse error
	}

	s.logger.Info("Completed AI grading", "count", len(gradedFindings))
	return gradedFindings, nil
}

// GenerateRemediation creates detailed remediation guidance
func (s *aiService) GenerateRemediation(ctx context.Context, finding types.Finding, context *types.AnalysisContext) (string, error) {
	if !s.config.Enabled {
		return finding.Remediation, nil
	}

	task := AITask{
		Type:       TaskRemediation,
		Complexity: ComplexityMedium,
		Domain:     "security",
	}

	model, err := s.modelSelector.SelectModel(ctx, task, context)
	if err != nil {
		model = s.currentModel
	}

	prompt, err := s.promptManager.RenderTemplate("generate_remediation", map[string]interface{}{
		"finding":          finding,
		"context":          context,
		"application_type": context.ApplicationType,
		"frameworks":       context.ComplianceFrameworks,
	})
	if err != nil {
		return finding.Remediation, fmt.Errorf("failed to render remediation prompt: %w", err)
	}

	request := &AIRequest{
		Model:       model,
		Prompt:      prompt,
		Temperature: 0.3, // Slightly higher for more creative solutions
		MaxTokens:   1024,
	}

	response, err := s.makeRequestWithRetry(ctx, request)
	if err != nil {
		s.logger.Error("Failed to generate remediation", "error", err)
		return finding.Remediation, nil
	}

	return response.Content, nil
}

// AnalyzeContext performs contextual analysis of the application
func (s *aiService) AnalyzeContext(ctx context.Context, results *types.CrawlResults) (*types.AnalysisContext, error) {
	if !s.config.Enabled {
		return &types.AnalysisContext{}, nil
	}

	task := AITask{
		Type:       TaskAnalysis,
		Complexity: ComplexityHigh,
		Domain:     "application_analysis",
	}

	model, err := s.modelSelector.SelectModel(ctx, task, nil)
	if err != nil {
		model = s.currentModel
	}

	prompt, err := s.promptManager.RenderTemplate("analyze_context", map[string]interface{}{
		"root_url":       results.RootURL,
		"pages_count":    len(results.Pages),
		"sample_pages":   s.getSamplePages(results.Pages, 5),
		"total_requests": results.TotalRequests,
	})
	if err != nil {
		return &types.AnalysisContext{}, fmt.Errorf("failed to render context prompt: %w", err)
	}

	request := &AIRequest{
		Model:       model,
		Prompt:      prompt,
		Temperature: 0.2,
		MaxTokens:   2048,
	}

	response, err := s.makeRequestWithRetry(ctx, request)
	if err != nil {
		s.logger.Error("Failed to analyze context", "error", err)
		return &types.AnalysisContext{}, nil
	}

	// Parse the AI response into AnalysisContext
	context, err := s.parseAnalysisContext(response)
	if err != nil {
		s.logger.Error("Failed to parse analysis context", "error", err)
		return &types.AnalysisContext{}, nil
	}

	return context, nil
}

// IsAvailable checks if the AI service is available
func (s *aiService) IsAvailable(ctx context.Context) bool {
	if !s.config.Enabled {
		return false
	}

	s.mu.RLock()
	if time.Since(s.lastHealthCheck) < 30*time.Second {
		defer s.mu.RUnlock()
		return s.isHealthy
	}
	s.mu.RUnlock()

	// Perform health check
	s.mu.Lock()
	defer s.mu.Unlock()

	s.isHealthy = s.client.IsHealthy(ctx)
	s.lastHealthCheck = time.Now()

	return s.isHealthy
}

// GetModels returns available AI models
func (s *aiService) GetModels(ctx context.Context) ([]AIModel, error) {
	if !s.config.Enabled {
		return []AIModel{}, nil
	}

	return s.client.ListModels(ctx)
}

// SetModel sets the active AI model
func (s *aiService) SetModel(modelName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.currentModel = modelName
	s.logger.Info("AI model changed", "model", modelName)
	return nil
}

// Helper methods

func (s *aiService) initializePrompts() error {
	templates := []*PromptTemplate{
		{
			ID:       "analyze_findings",
			Name:     "Analyze Security Findings",
			Category: "analysis",
			Template: `You are a cybersecurity expert analyzing security findings from a web application scan.

Application Context:
- Type: {{.application_type}}
- Domain: {{.domain}}
- Industry: {{.industry}}

Please analyze these security findings and provide enhanced insights:
{{range .findings}}
- Finding: {{.Title}}
  Severity: {{.Severity}}
  Description: {{.Description}}
  Evidence: {{.Evidence}}
{{end}}

For each finding, provide:
1. Risk assessment in the given context
2. Potential attack scenarios
3. Business impact analysis
4. Priority recommendation

Respond in JSON format with enhanced findings.`,
		},
		{
			ID:       "grade_findings",
			Name:     "Grade Security Findings",
			Category: "grading",
			Template: `You are a security analyst grading findings based on risk and business impact.

Context:
- Application Type: {{.application_type}}
- Industry: {{.industry}}
- Compliance: {{.compliance_frameworks}}

Grade these findings on a scale of 1-10 for:
- Risk Level (1=low, 10=critical)
- Business Impact (1=minimal, 10=severe)
- Exploitability (1=difficult, 10=trivial)

{{range .findings}}
Finding: {{.Title}} ({{.Severity}})
Description: {{.Description}}
{{end}}

Respond with JSON array of grades and justifications.`,
		},
		{
			ID:       "generate_remediation",
			Name:     "Generate Remediation Guidance",
			Category: "remediation",
			Template: `Generate detailed remediation guidance for this security finding:

Finding: {{.finding.Title}}
Severity: {{.finding.Severity}}
Description: {{.finding.Description}}
Category: {{.finding.Category}}

Application Context:
- Type: {{.application_type}}
- Frameworks: {{.frameworks}}

Provide:
1. Step-by-step remediation instructions
2. Code examples where applicable
3. Configuration changes needed
4. Testing recommendations
5. Prevention strategies

Make it actionable and specific to the application context.`,
		},
		{
			ID:       "analyze_context",
			Name:     "Analyze Application Context",
			Category: "context",
			Template: `Analyze this web application and determine its characteristics:

Root URL: {{.root_url}}
Pages Scanned: {{.pages_count}}
Total Requests: {{.total_requests}}

Sample Pages:
{{range .sample_pages}}
- {{.URL}} ({{.StatusCode}}) - {{.Title}}
{{end}}

Determine:
1. Application type (SPA, traditional web app, API, etc.)
2. Technology stack and frameworks
3. Industry/domain
4. Compliance requirements
5. Security posture

Respond in JSON format with analysis results.`,
		},
	}

	for _, template := range templates {
		if err := s.promptManager.RegisterTemplate(template); err != nil {
			return fmt.Errorf("failed to register template %s: %w", template.ID, err)
		}
	}

	return nil
}

func (s *aiService) determineComplexity(findingsCount int) TaskComplexity {
	if findingsCount <= 5 {
		return ComplexityLow
	} else if findingsCount <= 20 {
		return ComplexityMedium
	}
	return ComplexityHigh
}

func (s *aiService) calculateBatchSize(model string) int {
	// Adjust batch size based on model capabilities
	// This is a simplified implementation
	switch model {
	case "llama3.1:8b":
		return 10
	case "llama3.1:70b":
		return 5
	default:
		return 8
	}
}

func (s *aiService) analyzeFindingsBatch(ctx context.Context, findings []types.Finding, context *types.AnalysisContext, model string) ([]types.Finding, error) {
	prompt, err := s.promptManager.RenderTemplate("analyze_findings", map[string]interface{}{
		"findings":         findings,
		"context":          context,
		"application_type": context.ApplicationType,
		"domain":           context.Domain,
		"industry":         context.Industry,
	})
	if err != nil {
		return findings, err
	}

	request := &AIRequest{
		Model:       model,
		Prompt:      prompt,
		Temperature: s.config.Temperature,
		MaxTokens:   s.config.MaxTokens,
	}

	response, err := s.makeRequestWithRetry(ctx, request)
	if err != nil {
		return findings, err
	}

	// Parse enhanced findings from response
	enhanced, err := s.parseEnhancedFindings(response, findings)
	if err != nil {
		s.logger.Error("Failed to parse enhanced findings", "error", err)
		return findings, nil
	}

	return enhanced, nil
}

func (s *aiService) makeRequestWithRetry(ctx context.Context, request *AIRequest) (*AIResponse, error) {
	var lastErr error

	for attempt := 0; attempt < s.config.RetryAttempts; attempt++ {
		startTime := time.Now()

		response, err := s.client.Generate(ctx, request)
		duration := time.Since(startTime).Milliseconds()

		if err == nil {
			// Record successful request
			s.metrics.RecordRequest(request.Model, response.TokensUsed, duration)
			return response, nil
		}

		lastErr = err
		s.metrics.RecordError(request.Model, "generation_error")

		// Check if we should try fallback
		if s.fallback.ShouldFallback(err, attempt) {
			if fallbackModel, fbErr := s.fallback.GetFallbackModel(request.Model, attempt); fbErr == nil {
				s.logger.Info("Trying fallback model", "original", request.Model, "fallback", fallbackModel, "attempt", attempt+1)
				request.Model = fallbackModel
				continue
			}
		}

		// Wait before retry
		if attempt < s.config.RetryAttempts-1 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	return nil, fmt.Errorf("AI request failed after %d attempts: %w", s.config.RetryAttempts, lastErr)
}

func (s *aiService) generateCacheKey(operation, prompt, model string) string {
	// Simple cache key generation - in production, use proper hashing
	return fmt.Sprintf("%s:%s:%s", operation, model, prompt[:min(50, len(prompt))])
}

func (s *aiService) getSamplePages(pages []*types.PageResult, limit int) []*types.PageResult {
	if len(pages) <= limit {
		return pages
	}
	return pages[:limit]
}

func (s *aiService) parseGradedFindings(response *AIResponse, originalFindings []types.Finding) ([]types.Finding, error) {
	// TODO: Implement JSON parsing of graded findings
	// This would parse the AI response and apply grades to findings
	return originalFindings, nil
}

func (s *aiService) parseEnhancedFindings(response *AIResponse, originalFindings []types.Finding) ([]types.Finding, error) {
	// TODO: Implement JSON parsing of enhanced findings
	// This would parse the AI response and enhance the original findings
	return originalFindings, nil
}

func (s *aiService) parseAnalysisContext(response *AIResponse) (*types.AnalysisContext, error) {
	// TODO: Implement JSON parsing of analysis context
	// This would parse the AI response into AnalysisContext struct
	return &types.AnalysisContext{}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

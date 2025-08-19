package ai

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/zuub-code/strider/pkg/types"
)

// promptManager implements PromptManager interface
type promptManager struct {
	templates map[string]*PromptTemplate
	mu        sync.RWMutex
}

// NewPromptManager creates a new prompt manager
func NewPromptManager() PromptManager {
	return &promptManager{
		templates: make(map[string]*PromptTemplate),
	}
}

// GetTemplate retrieves a prompt template by ID
func (pm *promptManager) GetTemplate(templateID string) (*PromptTemplate, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	template, exists := pm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateID)
	}

	return template, nil
}

// RenderTemplate renders a template with provided variables
func (pm *promptManager) RenderTemplate(templateID string, variables map[string]interface{}) (string, error) {
	promptTemplate, err := pm.GetTemplate(templateID)
	if err != nil {
		return "", err
	}

	tmpl, err := template.New(templateID).Parse(promptTemplate.Template)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, variables); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// RegisterTemplate registers a new prompt template
func (pm *promptManager) RegisterTemplate(template *PromptTemplate) error {
	if template == nil {
		return fmt.Errorf("template cannot be nil")
	}

	if template.ID == "" {
		return fmt.Errorf("template ID cannot be empty")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.templates[template.ID] = template
	return nil
}

// ListTemplates returns all available templates
func (pm *promptManager) ListTemplates() []*PromptTemplate {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	templates := make([]*PromptTemplate, 0, len(pm.templates))
	for _, template := range pm.templates {
		templates = append(templates, template)
	}

	return templates
}

// ListByCategory returns templates filtered by category
func (pm *promptManager) ListByCategory(category string) []*PromptTemplate {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var templates []*PromptTemplate
	for _, template := range pm.templates {
		if template.Category == category {
			templates = append(templates, template)
		}
	}

	return templates
}

// modelSelector implements ModelSelector interface
type modelSelector struct {
	modelCapabilities map[string][]string
	preferences       map[TaskType]string
}

// NewModelSelector creates a new model selector
func NewModelSelector() ModelSelector {
	return &modelSelector{
		modelCapabilities: map[string][]string{
			"llama3.1:8b":  {"text-generation", "chat", "analysis", "code"},
			"llama3.1:70b": {"text-generation", "chat", "analysis", "code", "reasoning"},
			"codellama":    {"code", "text-generation", "analysis"},
			"mistral":      {"text-generation", "chat", "analysis"},
		},
		preferences: map[TaskType]string{
			TaskAnalysis:       "llama3.1:70b",
			TaskGrading:        "llama3.1:8b",
			TaskRemediation:    "llama3.1:8b",
			TaskClassification: "llama3.1:8b",
			TaskGeneration:     "llama3.1:70b",
		},
	}
}

// SelectModel chooses the best model for a given task
func (ms *modelSelector) SelectModel(ctx context.Context, task AITask, context *types.AnalysisContext) (string, error) {
	// Check preferences first
	if preferred, exists := ms.preferences[task.Type]; exists {
		if ms.IsModelSuitable(preferred, task) {
			return preferred, nil
		}
	}

	// Find suitable model based on capabilities
	for model, capabilities := range ms.modelCapabilities {
		if ms.hasRequiredCapabilities(capabilities, task) {
			return model, nil
		}
	}

	// Fallback to default
	return "llama3.1:8b", nil
}

// GetModelCapabilities returns capabilities of a model
func (ms *modelSelector) GetModelCapabilities(modelName string) ([]string, error) {
	capabilities, exists := ms.modelCapabilities[modelName]
	if !exists {
		return nil, fmt.Errorf("unknown model: %s", modelName)
	}

	return capabilities, nil
}

// IsModelSuitable checks if a model is suitable for a task
func (ms *modelSelector) IsModelSuitable(modelName string, task AITask) bool {
	capabilities, err := ms.GetModelCapabilities(modelName)
	if err != nil {
		return false
	}

	return ms.hasRequiredCapabilities(capabilities, task)
}

func (ms *modelSelector) hasRequiredCapabilities(capabilities []string, task AITask) bool {
	required := ms.getRequiredCapabilities(task)

	for _, req := range required {
		found := false
		for _, cap := range capabilities {
			if cap == req {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (ms *modelSelector) getRequiredCapabilities(task AITask) []string {
	switch task.Type {
	case TaskAnalysis:
		return []string{"analysis", "text-generation"}
	case TaskGrading:
		return []string{"text-generation"}
	case TaskRemediation:
		return []string{"text-generation"}
	case TaskClassification:
		return []string{"text-generation"}
	case TaskGeneration:
		return []string{"text-generation"}
	default:
		return []string{"text-generation"}
	}
}

// responseValidator implements ResponseValidator interface
type responseValidator struct{}

// NewResponseValidator creates a new response validator
func NewResponseValidator() ResponseValidator {
	return &responseValidator{}
}

// ValidateResponse checks if an AI response is valid and useful
func (rv *responseValidator) ValidateResponse(response *AIResponse, expectedFormat string) error {
	if response == nil {
		return fmt.Errorf("response is nil")
	}

	if response.Content == "" {
		return fmt.Errorf("response content is empty")
	}

	// Validate based on expected format
	switch expectedFormat {
	case "json":
		return rv.validateJSON(response.Content)
	case "yaml":
		return rv.validateYAML(response.Content)
	case "text":
		return rv.validateText(response.Content)
	default:
		return nil // No specific validation
	}
}

// ParseStructuredResponse parses structured responses
func (rv *responseValidator) ParseStructuredResponse(response *AIResponse, target interface{}) error {
	// TODO: Implement JSON/YAML parsing
	return fmt.Errorf("not implemented")
}

// ExtractFindings extracts security findings from AI response
func (rv *responseValidator) ExtractFindings(response *AIResponse) ([]types.Finding, error) {
	// TODO: Implement finding extraction from AI response
	return []types.Finding{}, nil
}

func (rv *responseValidator) validateJSON(content string) error {
	// Simple JSON validation
	if !strings.HasPrefix(strings.TrimSpace(content), "{") && !strings.HasPrefix(strings.TrimSpace(content), "[") {
		return fmt.Errorf("content does not appear to be JSON")
	}
	return nil
}

func (rv *responseValidator) validateYAML(content string) error {
	// Simple YAML validation
	if strings.Contains(content, "\t") {
		return fmt.Errorf("YAML should not contain tabs")
	}
	return nil
}

func (rv *responseValidator) validateText(content string) error {
	if len(strings.TrimSpace(content)) < 10 {
		return fmt.Errorf("text content too short")
	}
	return nil
}

// fallbackStrategy implements FallbackStrategy interface
type fallbackStrategy struct {
	fallbackModels []string
	maxAttempts    int
}

// NewFallbackStrategy creates a new fallback strategy
func NewFallbackStrategy(fallbackModels []string) FallbackStrategy {
	return &fallbackStrategy{
		fallbackModels: fallbackModels,
		maxAttempts:    3,
	}
}

// ShouldFallback determines if fallback should be used
func (fs *fallbackStrategy) ShouldFallback(err error, attempt int) bool {
	if attempt >= fs.maxAttempts {
		return false
	}

	// Check error type to determine if fallback is appropriate
	errStr := strings.ToLower(err.Error())

	// Network errors, model not found, etc. are good candidates for fallback
	fallbackErrors := []string{
		"connection refused",
		"timeout",
		"model not found",
		"model not loaded",
		"context length exceeded",
	}

	for _, fbErr := range fallbackErrors {
		if strings.Contains(errStr, fbErr) {
			return true
		}
	}

	return false
}

// GetFallbackModel returns an alternative model to try
func (fs *fallbackStrategy) GetFallbackModel(originalModel string, attempt int) (string, error) {
	if attempt >= len(fs.fallbackModels) {
		return "", fmt.Errorf("no more fallback models available")
	}

	return fs.fallbackModels[attempt], nil
}

// GetFallbackResponse provides a default response when AI fails
func (fs *fallbackStrategy) GetFallbackResponse(task AITask) (*AIResponse, error) {
	content := "AI analysis unavailable. Please review findings manually."

	switch task.Type {
	case TaskAnalysis:
		content = "Automated analysis unavailable. Manual security review recommended."
	case TaskGrading:
		content = "Risk grading unavailable. Use default severity levels."
	case TaskRemediation:
		content = "Automated remediation guidance unavailable. Consult security documentation."
	}

	return &AIResponse{
		Content:    content,
		Model:      "fallback",
		TokensUsed: 0,
		Duration:   0,
		Metadata: map[string]interface{}{
			"fallback": true,
		},
	}, nil
}

// aiCache implements AICache interface
type aiCache struct {
	cache   map[string]cacheEntry
	mu      sync.RWMutex
	maxSize int
	stats   AICacheStats
}

type cacheEntry struct {
	response  *AIResponse
	timestamp time.Time
	ttl       int64
}

// NewAICache creates a new AI cache
func NewAICache(maxSize int) AICache {
	return &aiCache{
		cache:   make(map[string]cacheEntry),
		maxSize: maxSize,
	}
}

// Get retrieves cached AI response
func (ac *aiCache) Get(key string) (*AIResponse, bool) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	entry, exists := ac.cache[key]
	if !exists {
		ac.stats.Misses++
		return nil, false
	}

	// Check TTL
	if entry.ttl > 0 && time.Since(entry.timestamp).Seconds() > float64(entry.ttl) {
		ac.stats.Misses++
		delete(ac.cache, key)
		return nil, false
	}

	ac.stats.Hits++
	ac.updateHitRate()

	return entry.response, true
}

// Set stores AI response in cache
func (ac *aiCache) Set(key string, response *AIResponse, ttl int64) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Evict if at capacity
	if len(ac.cache) >= ac.maxSize {
		ac.evictOldest()
	}

	ac.cache[key] = cacheEntry{
		response:  response,
		timestamp: time.Now(),
		ttl:       ttl,
	}

	ac.stats.Size = len(ac.cache)
	ac.stats.TokensSaved += int64(response.TokensUsed)
}

// Invalidate removes cached response
func (ac *aiCache) Invalidate(key string) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	delete(ac.cache, key)
	ac.stats.Size = len(ac.cache)
}

// Clear clears all cached responses
func (ac *aiCache) Clear() {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.cache = make(map[string]cacheEntry)
	ac.stats = AICacheStats{}
}

// GetStats returns cache statistics
func (ac *aiCache) GetStats() AICacheStats {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	return ac.stats
}

func (ac *aiCache) evictOldest() {
	if len(ac.cache) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range ac.cache {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(ac.cache, oldestKey)
	}
}

func (ac *aiCache) updateHitRate() {
	total := ac.stats.Hits + ac.stats.Misses
	if total > 0 {
		ac.stats.HitRate = float64(ac.stats.Hits) / float64(total)
	}
}

// aiMetrics implements AIMetrics interface
type aiMetrics struct {
	stats AIStats
	mu    sync.RWMutex
}

// NewAIMetrics creates a new AI metrics tracker
func NewAIMetrics() AIMetrics {
	return &aiMetrics{
		stats: AIStats{
			ModelStats:   make(map[string]ModelStats),
			ErrorsByType: make(map[string]int64),
		},
	}
}

// RecordRequest records an AI request
func (am *aiMetrics) RecordRequest(model string, tokens int, duration int64) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.stats.TotalRequests++
	am.stats.TotalTokens += int64(tokens)

	// Update average latency
	if am.stats.TotalRequests == 1 {
		am.stats.AverageLatency = duration
	} else {
		am.stats.AverageLatency = (am.stats.AverageLatency + duration) / 2
	}

	// Update model stats
	modelStats := am.stats.ModelStats[model]
	modelStats.Requests++
	modelStats.Tokens += int64(tokens)

	if modelStats.Requests == 1 {
		modelStats.AverageLatency = duration
	} else {
		modelStats.AverageLatency = (modelStats.AverageLatency + duration) / 2
	}

	modelStats.SuccessRate = float64(modelStats.Requests-modelStats.Errors) / float64(modelStats.Requests)
	am.stats.ModelStats[model] = modelStats
}

// RecordError records an AI error
func (am *aiMetrics) RecordError(model string, errorType string) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.stats.TotalErrors++
	am.stats.ErrorsByType[errorType]++

	// Update model error stats
	modelStats := am.stats.ModelStats[model]
	modelStats.Errors++
	modelStats.SuccessRate = float64(modelStats.Requests-modelStats.Errors) / float64(modelStats.Requests)
	am.stats.ModelStats[model] = modelStats
}

// GetStats returns AI usage statistics
func (am *aiMetrics) GetStats() AIStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return am.stats
}

// GetModelStats returns statistics for a specific model
func (am *aiMetrics) GetModelStats(model string) ModelStats {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return am.stats.ModelStats[model]
}

package ai

import (
	"context"

	"github.com/zuub-code/strider/pkg/types"
)

// AIService defines the interface for AI-powered security analysis
type AIService interface {
	// AnalyzeFindings performs AI analysis on security findings
	AnalyzeFindings(ctx context.Context, findings []types.Finding, context *types.AnalysisContext) ([]types.Finding, error)

	// GradeFindings assigns risk scores and priorities to findings
	GradeFindings(ctx context.Context, findings []types.Finding, context *types.AnalysisContext) ([]types.Finding, error)

	// GenerateRemediation creates detailed remediation guidance
	GenerateRemediation(ctx context.Context, finding types.Finding, context *types.AnalysisContext) (string, error)

	// AnalyzeContext performs contextual analysis of the application
	AnalyzeContext(ctx context.Context, results *types.CrawlResults) (*types.AnalysisContext, error)

	// IsAvailable checks if the AI service is available
	IsAvailable(ctx context.Context) bool

	// GetModels returns available AI models
	GetModels(ctx context.Context) ([]AIModel, error)

	// SetModel sets the active AI model
	SetModel(modelName string) error
}

// AIModel represents an available AI model
type AIModel struct {
	Name         string                 `json:"name"`
	Size         string                 `json:"size"`
	Description  string                 `json:"description"`
	Capabilities []string               `json:"capabilities"`
	Parameters   map[string]interface{} `json:"parameters"`
	IsLoaded     bool                   `json:"is_loaded"`
}

// PromptTemplate defines a template for AI prompts
type PromptTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Template    string   `json:"template"`
	Variables   []string `json:"variables"`
	Category    string   `json:"category"`
	Model       string   `json:"model,omitempty"`
}

// AIRequest represents a request to the AI service
type AIRequest struct {
	Model       string                 `json:"model"`
	Prompt      string                 `json:"prompt"`
	Temperature float32                `json:"temperature,omitempty"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
	Stream      bool                   `json:"stream,omitempty"`
}

// AIResponse represents a response from the AI service
type AIResponse struct {
	Content    string                 `json:"content"`
	Model      string                 `json:"model"`
	TokensUsed int                    `json:"tokens_used"`
	Duration   int64                  `json:"duration_ms"`
	Confidence float32                `json:"confidence,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PromptManager handles AI prompt templates and generation
type PromptManager interface {
	// GetTemplate retrieves a prompt template by ID
	GetTemplate(templateID string) (*PromptTemplate, error)

	// RenderTemplate renders a template with provided variables
	RenderTemplate(templateID string, variables map[string]interface{}) (string, error)

	// RegisterTemplate registers a new prompt template
	RegisterTemplate(template *PromptTemplate) error

	// ListTemplates returns all available templates
	ListTemplates() []*PromptTemplate

	// ListByCategory returns templates filtered by category
	ListByCategory(category string) []*PromptTemplate
}

// ModelSelector handles intelligent model selection
type ModelSelector interface {
	// SelectModel chooses the best model for a given task
	SelectModel(ctx context.Context, task AITask, context *types.AnalysisContext) (string, error)

	// GetModelCapabilities returns capabilities of a model
	GetModelCapabilities(modelName string) ([]string, error)

	// IsModelSuitable checks if a model is suitable for a task
	IsModelSuitable(modelName string, task AITask) bool
}

// AITask represents different types of AI tasks
type AITask struct {
	Type         TaskType               `json:"type"`
	Complexity   TaskComplexity         `json:"complexity"`
	Domain       string                 `json:"domain"`
	Context      map[string]interface{} `json:"context"`
	Requirements []string               `json:"requirements"`
}

// TaskType defines different AI task types
type TaskType string

const (
	TaskAnalysis       TaskType = "analysis"
	TaskGrading        TaskType = "grading"
	TaskRemediation    TaskType = "remediation"
	TaskSummarization  TaskType = "summarization"
	TaskClassification TaskType = "classification"
	TaskGeneration     TaskType = "generation"
)

// TaskComplexity defines task complexity levels
type TaskComplexity string

const (
	ComplexityLow    TaskComplexity = "low"
	ComplexityMedium TaskComplexity = "medium"
	ComplexityHigh   TaskComplexity = "high"
)

// ResponseValidator validates AI responses
type ResponseValidator interface {
	// ValidateResponse checks if an AI response is valid and useful
	ValidateResponse(response *AIResponse, expectedFormat string) error

	// ParseStructuredResponse parses structured responses (JSON, YAML, etc.)
	ParseStructuredResponse(response *AIResponse, target interface{}) error

	// ExtractFindings extracts security findings from AI response
	ExtractFindings(response *AIResponse) ([]types.Finding, error)
}

// FallbackStrategy defines fallback behavior when AI fails
type FallbackStrategy interface {
	// ShouldFallback determines if fallback should be used
	ShouldFallback(err error, attempt int) bool

	// GetFallbackModel returns an alternative model to try
	GetFallbackModel(originalModel string, attempt int) (string, error)

	// GetFallbackResponse provides a default response when AI fails
	GetFallbackResponse(task AITask) (*AIResponse, error)
}

// AICache provides caching for AI responses
type AICache interface {
	// Get retrieves cached AI response
	Get(key string) (*AIResponse, bool)

	// Set stores AI response in cache
	Set(key string, response *AIResponse, ttl int64)

	// Invalidate removes cached response
	Invalidate(key string)

	// Clear clears all cached responses
	Clear()

	// GetStats returns cache statistics
	GetStats() AICacheStats
}

// AICacheStats contains AI cache statistics
type AICacheStats struct {
	Hits        int64   `json:"hits"`
	Misses      int64   `json:"misses"`
	HitRate     float64 `json:"hit_rate"`
	Size        int     `json:"size"`
	TokensSaved int64   `json:"tokens_saved"`
}

// AIMetrics tracks AI service performance
type AIMetrics interface {
	// RecordRequest records an AI request
	RecordRequest(model string, tokens int, duration int64)

	// RecordError records an AI error
	RecordError(model string, errorType string)

	// GetStats returns AI usage statistics
	GetStats() AIStats

	// GetModelStats returns statistics for a specific model
	GetModelStats(model string) ModelStats
}

// AIStats contains overall AI service statistics
type AIStats struct {
	TotalRequests  int64                 `json:"total_requests"`
	TotalTokens    int64                 `json:"total_tokens"`
	TotalErrors    int64                 `json:"total_errors"`
	AverageLatency int64                 `json:"average_latency_ms"`
	ModelStats     map[string]ModelStats `json:"model_stats"`
	ErrorsByType   map[string]int64      `json:"errors_by_type"`
}

// ModelStats contains statistics for a specific model
type ModelStats struct {
	Requests       int64   `json:"requests"`
	Tokens         int64   `json:"tokens"`
	Errors         int64   `json:"errors"`
	AverageLatency int64   `json:"average_latency_ms"`
	SuccessRate    float64 `json:"success_rate"`
}

// OllamaClient defines the interface for Ollama API client
type OllamaClient interface {
	// Generate generates text using Ollama
	Generate(ctx context.Context, request *AIRequest) (*AIResponse, error)

	// Chat performs chat-based interaction
	Chat(ctx context.Context, messages []ChatMessage, model string) (*AIResponse, error)

	// ListModels lists available models
	ListModels(ctx context.Context) ([]AIModel, error)

	// PullModel downloads a model
	PullModel(ctx context.Context, modelName string) error

	// ShowModel gets model information
	ShowModel(ctx context.Context, modelName string) (*AIModel, error)

	// IsHealthy checks if Ollama service is healthy
	IsHealthy(ctx context.Context) bool
}

// ChatMessage represents a chat message
type ChatMessage struct {
	Role    string `json:"role"` // "system", "user", "assistant"
	Content string `json:"content"`
}

// AIConfig contains AI service configuration
type AIConfig struct {
	Enabled          bool                `json:"enabled"`
	BaseURL          string              `json:"base_url"`
	DefaultModel     string              `json:"default_model"`
	Temperature      float32             `json:"temperature"`
	MaxTokens        int                 `json:"max_tokens"`
	Timeout          int                 `json:"timeout_seconds"`
	RetryAttempts    int                 `json:"retry_attempts"`
	EnableCache      bool                `json:"enable_cache"`
	CacheSize        int                 `json:"cache_size"`
	FallbackModels   []string            `json:"fallback_models"`
	ModelPreferences map[TaskType]string `json:"model_preferences"`
}

package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ollamaClient implements OllamaClient interface
type ollamaClient struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// NewOllamaClient creates a new Ollama API client
func NewOllamaClient(baseURL string, timeoutSeconds int) OllamaClient {
	return &ollamaClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
		timeout: time.Duration(timeoutSeconds) * time.Second,
	}
}

// Generate generates text using Ollama
func (c *ollamaClient) Generate(ctx context.Context, request *AIRequest) (*AIResponse, error) {
	startTime := time.Now()

	// Prepare Ollama API request
	ollamaReq := map[string]interface{}{
		"model":  request.Model,
		"prompt": request.Prompt,
		"stream": false,
	}

	if request.Temperature > 0 {
		ollamaReq["options"] = map[string]interface{}{
			"temperature": request.Temperature,
		}
	}

	if request.MaxTokens > 0 {
		if options, ok := ollamaReq["options"].(map[string]interface{}); ok {
			options["num_predict"] = request.MaxTokens
		} else {
			ollamaReq["options"] = map[string]interface{}{
				"num_predict": request.MaxTokens,
			}
		}
	}

	// Marshal request
	reqBody, err := json.Marshal(ollamaReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := c.baseURL + "/api/generate"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var ollamaResp struct {
		Model           string `json:"model"`
		Response        string `json:"response"`
		Done            bool   `json:"done"`
		Context         []int  `json:"context,omitempty"`
		TotalDuration   int64  `json:"total_duration,omitempty"`
		LoadDuration    int64  `json:"load_duration,omitempty"`
		PromptEvalCount int    `json:"prompt_eval_count,omitempty"`
		EvalCount       int    `json:"eval_count,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	duration := time.Since(startTime).Milliseconds()

	return &AIResponse{
		Content:    ollamaResp.Response,
		Model:      ollamaResp.Model,
		TokensUsed: ollamaResp.EvalCount + ollamaResp.PromptEvalCount,
		Duration:   duration,
		Metadata: map[string]interface{}{
			"total_duration":    ollamaResp.TotalDuration,
			"load_duration":     ollamaResp.LoadDuration,
			"prompt_tokens":     ollamaResp.PromptEvalCount,
			"completion_tokens": ollamaResp.EvalCount,
		},
	}, nil
}

// Chat performs chat-based interaction
func (c *ollamaClient) Chat(ctx context.Context, messages []ChatMessage, model string) (*AIResponse, error) {
	startTime := time.Now()

	// Prepare chat request
	chatReq := map[string]interface{}{
		"model":    model,
		"messages": messages,
		"stream":   false,
	}

	reqBody, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chat request: %w", err)
	}

	// Create HTTP request
	url := c.baseURL + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create chat request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Make request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("chat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("chat API error %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var chatResp struct {
		Model           string      `json:"model"`
		Message         ChatMessage `json:"message"`
		Done            bool        `json:"done"`
		TotalDuration   int64       `json:"total_duration,omitempty"`
		LoadDuration    int64       `json:"load_duration,omitempty"`
		PromptEvalCount int         `json:"prompt_eval_count,omitempty"`
		EvalCount       int         `json:"eval_count,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("failed to decode chat response: %w", err)
	}

	duration := time.Since(startTime).Milliseconds()

	return &AIResponse{
		Content:    chatResp.Message.Content,
		Model:      chatResp.Model,
		TokensUsed: chatResp.EvalCount + chatResp.PromptEvalCount,
		Duration:   duration,
		Metadata: map[string]interface{}{
			"total_duration":    chatResp.TotalDuration,
			"load_duration":     chatResp.LoadDuration,
			"prompt_tokens":     chatResp.PromptEvalCount,
			"completion_tokens": chatResp.EvalCount,
		},
	}, nil
}

// ListModels lists available models
func (c *ollamaClient) ListModels(ctx context.Context) ([]AIModel, error) {
	url := c.baseURL + "/api/tags"

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create list models request: %w", err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("list models request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list models API error %d: %s", resp.StatusCode, string(body))
	}

	var modelsResp struct {
		Models []struct {
			Name       string    `json:"name"`
			Size       int64     `json:"size"`
			Digest     string    `json:"digest"`
			ModifiedAt time.Time `json:"modified_at"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&modelsResp); err != nil {
		return nil, fmt.Errorf("failed to decode models response: %w", err)
	}

	models := make([]AIModel, len(modelsResp.Models))
	for i, model := range modelsResp.Models {
		models[i] = AIModel{
			Name:         model.Name,
			Size:         formatSize(model.Size),
			Description:  fmt.Sprintf("Ollama model %s", model.Name),
			Capabilities: []string{"text-generation", "chat"},
			Parameters: map[string]interface{}{
				"size_bytes":  model.Size,
				"digest":      model.Digest,
				"modified_at": model.ModifiedAt,
			},
			IsLoaded: true, // Assume loaded if in list
		}
	}

	return models, nil
}

// PullModel downloads a model
func (c *ollamaClient) PullModel(ctx context.Context, modelName string) error {
	pullReq := map[string]interface{}{
		"name":   modelName,
		"stream": false,
	}

	reqBody, err := json.Marshal(pullReq)
	if err != nil {
		return fmt.Errorf("failed to marshal pull request: %w", err)
	}

	url := c.baseURL + "/api/pull"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("pull request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull API error %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// ShowModel gets model information
func (c *ollamaClient) ShowModel(ctx context.Context, modelName string) (*AIModel, error) {
	showReq := map[string]interface{}{
		"name": modelName,
	}

	reqBody, err := json.Marshal(showReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal show request: %w", err)
	}

	url := c.baseURL + "/api/show"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create show request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("show request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("show API error %d: %s", resp.StatusCode, string(body))
	}

	var showResp struct {
		License    string `json:"license"`
		Modelfile  string `json:"modelfile"`
		Parameters string `json:"parameters"`
		Template   string `json:"template"`
		Details    struct {
			Format            string   `json:"format"`
			Family            string   `json:"family"`
			Families          []string `json:"families"`
			ParameterSize     string   `json:"parameter_size"`
			QuantizationLevel string   `json:"quantization_level"`
		} `json:"details"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&showResp); err != nil {
		return nil, fmt.Errorf("failed to decode show response: %w", err)
	}

	return &AIModel{
		Name:         modelName,
		Size:         showResp.Details.ParameterSize,
		Description:  fmt.Sprintf("%s model (%s family)", modelName, showResp.Details.Family),
		Capabilities: []string{"text-generation", "chat"},
		Parameters: map[string]interface{}{
			"format":             showResp.Details.Format,
			"family":             showResp.Details.Family,
			"parameter_size":     showResp.Details.ParameterSize,
			"quantization_level": showResp.Details.QuantizationLevel,
			"template":           showResp.Template,
		},
		IsLoaded: true,
	}, nil
}

// IsHealthy checks if Ollama service is healthy
func (c *ollamaClient) IsHealthy(ctx context.Context) bool {
	// Create a simple health check request
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := c.baseURL + "/api/tags"
	httpReq, err := http.NewRequestWithContext(healthCtx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// formatSize converts bytes to human-readable format
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

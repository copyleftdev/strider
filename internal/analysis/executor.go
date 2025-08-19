package analysis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zuub-code/strider/pkg/types"
)

// ruleExecutor implements RuleExecutor interface
type ruleExecutor struct {
	maxWorkers int
	stats      ExecutionStats
	mu         sync.RWMutex
}

// NewRuleExecutor creates a new rule executor
func NewRuleExecutor(maxWorkers int) RuleExecutor {
	return &ruleExecutor{
		maxWorkers: maxWorkers,
		stats: ExecutionStats{
			RuleStats: make([]RuleStat, 0),
		},
	}
}

// Execute runs rules against a page with parallelization
func (e *ruleExecutor) Execute(ctx context.Context, page *types.PageResult, rules []Rule) ([]types.Finding, error) {
	if len(rules) == 0 {
		return []types.Finding{}, nil
	}

	startTime := time.Now()

	// Create worker pool
	semaphore := make(chan struct{}, e.maxWorkers)
	var wg sync.WaitGroup

	// Results collection
	resultsChan := make(chan ruleResult, len(rules))

	// Execute rules in parallel
	for _, rule := range rules {
		wg.Add(1)
		go func(r Rule) {
			defer wg.Done()

			// Acquire worker slot
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Execute rule
			findings, err := e.ExecuteRule(ctx, page, r)

			resultsChan <- ruleResult{
				RuleID:   r.ID(),
				Findings: findings,
				Error:    err,
				Duration: time.Since(startTime),
			}
		}(rule)
	}

	// Wait for all rules to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	var allFindings []types.Finding
	var ruleStats []RuleStat
	executedRules := 0
	failedRules := 0

	for result := range resultsChan {
		executedRules++

		stat := RuleStat{
			RuleID:        result.RuleID,
			ExecutionTime: result.Duration.Milliseconds(),
			Success:       result.Error == nil,
		}

		if result.Error != nil {
			failedRules++
			stat.Error = result.Error.Error()
		} else {
			allFindings = append(allFindings, result.Findings...)
			stat.FindingsCount = len(result.Findings)
		}

		ruleStats = append(ruleStats, stat)
	}

	// Update statistics
	e.updateStats(ExecutionStats{
		TotalRules:    len(rules),
		ExecutedRules: executedRules,
		FailedRules:   failedRules,
		TotalFindings: len(allFindings),
		ExecutionTime: time.Since(startTime).Milliseconds(),
		RuleStats:     ruleStats,
	})

	return allFindings, nil
}

// ExecuteRule runs a single rule against a page
func (e *ruleExecutor) ExecuteRule(ctx context.Context, page *types.PageResult, rule Rule) ([]types.Finding, error) {
	if !rule.IsEnabled() {
		return []types.Finding{}, nil
	}

	// Create timeout context
	ruleCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Execute rule with timeout protection
	findings, err := rule.Analyze(ruleCtx, page)
	if err != nil {
		return nil, fmt.Errorf("rule %s failed: %w", rule.ID(), err)
	}

	// Validate findings
	for i := range findings {
		if findings[i].RuleID == "" {
			findings[i].RuleID = rule.ID()
		}
		if findings[i].ID == "" {
			findings[i].ID = fmt.Sprintf("%s-%d", rule.ID(), i)
		}
		if findings[i].Severity == "" {
			findings[i].Severity = rule.Severity()
		}
	}

	return findings, nil
}

// SetMaxWorkers sets the maximum number of concurrent workers
func (e *ruleExecutor) SetMaxWorkers(workers int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxWorkers = workers
}

// GetStats returns execution statistics
func (e *ruleExecutor) GetStats() ExecutionStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stats
}

// updateStats updates execution statistics
func (e *ruleExecutor) updateStats(newStats ExecutionStats) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stats = newStats
}

// ruleResult represents the result of executing a single rule
type ruleResult struct {
	RuleID   string
	Findings []types.Finding
	Error    error
	Duration time.Duration
}

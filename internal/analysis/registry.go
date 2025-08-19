package analysis

import (
	"fmt"
	"sync"
)

// ruleRegistry implements RuleRegistry interface
type ruleRegistry struct {
	rules map[string]Rule
	mu    sync.RWMutex
}

// NewRuleRegistry creates a new rule registry
func NewRuleRegistry() RuleRegistry {
	return &ruleRegistry{
		rules: make(map[string]Rule),
	}
}

// Register registers a new rule
func (r *ruleRegistry) Register(rule Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if rule.ID() == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.rules[rule.ID()]; exists {
		return fmt.Errorf("rule with ID %s already exists", rule.ID())
	}

	r.rules[rule.ID()] = rule
	return nil
}

// Unregister removes a rule by ID
func (r *ruleRegistry) Unregister(ruleID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.rules[ruleID]; !exists {
		return fmt.Errorf("rule with ID %s not found", ruleID)
	}

	delete(r.rules, ruleID)
	return nil
}

// Get retrieves a rule by ID
func (r *ruleRegistry) Get(ruleID string) (Rule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, exists := r.rules[ruleID]
	return rule, exists
}

// List returns all registered rules
func (r *ruleRegistry) List() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rules := make([]Rule, 0, len(r.rules))
	for _, rule := range r.rules {
		rules = append(rules, rule)
	}

	return rules
}

// ListByCategory returns rules filtered by category
func (r *ruleRegistry) ListByCategory(category string) []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var rules []Rule
	for _, rule := range r.rules {
		if rule.Category() == category {
			rules = append(rules, rule)
		}
	}

	return rules
}

// ListEnabled returns only enabled rules
func (r *ruleRegistry) ListEnabled() []Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var rules []Rule
	for _, rule := range r.rules {
		if rule.IsEnabled() {
			rules = append(rules, rule)
		}
	}

	return rules
}

// EnableAll enables all rules
func (r *ruleRegistry) EnableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rule := range r.rules {
		rule.SetEnabled(true)
	}
}

// DisableAll disables all rules
func (r *ruleRegistry) DisableAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, rule := range r.rules {
		rule.SetEnabled(false)
	}
}

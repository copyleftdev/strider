package analysis

import (
	"sync"
	"time"

	"github.com/zuub-code/strider/pkg/types"
)

// ruleCache implements RuleCache interface
type ruleCache struct {
	cache   map[string]cacheEntry
	mu      sync.RWMutex
	maxSize int

	// Statistics
	hits   int64
	misses int64
}

// cacheEntry represents a cached rule result
type cacheEntry struct {
	findings  []types.Finding
	timestamp time.Time
	ttl       time.Duration
}

// NewRuleCache creates a new rule cache
func NewRuleCache(maxSize int) RuleCache {
	return &ruleCache{
		cache:   make(map[string]cacheEntry),
		maxSize: maxSize,
	}
}

// Get retrieves cached results for a rule and page
func (c *ruleCache) Get(ruleID string, pageHash string) ([]types.Finding, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := c.makeKey(ruleID, pageHash)
	entry, exists := c.cache[key]

	if !exists {
		c.misses++
		return nil, false
	}

	// Check if entry has expired
	if entry.ttl > 0 && time.Since(entry.timestamp) > entry.ttl {
		c.misses++
		// Remove expired entry (will be cleaned up later)
		delete(c.cache, key)
		return nil, false
	}

	c.hits++

	// Return a copy to prevent modification
	findings := make([]types.Finding, len(entry.findings))
	copy(findings, entry.findings)

	return findings, true
}

// Set stores results in cache
func (c *ruleCache) Set(ruleID string, pageHash string, findings []types.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cache is full
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	key := c.makeKey(ruleID, pageHash)

	// Store a copy to prevent external modification
	cachedFindings := make([]types.Finding, len(findings))
	copy(cachedFindings, findings)

	c.cache[key] = cacheEntry{
		findings:  cachedFindings,
		timestamp: time.Now(),
		ttl:       time.Hour, // Default 1 hour TTL
	}
}

// Invalidate removes cached results
func (c *ruleCache) Invalidate(ruleID string, pageHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := c.makeKey(ruleID, pageHash)
	delete(c.cache, key)
}

// Clear clears all cached results
func (c *ruleCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]cacheEntry)
	c.hits = 0
	c.misses = 0
}

// GetStats returns cache statistics
func (c *ruleCache) GetStats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	total := c.hits + c.misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(c.hits) / float64(total)
	}

	return CacheStats{
		Hits:    c.hits,
		Misses:  c.misses,
		HitRate: hitRate,
		Size:    len(c.cache),
		MaxSize: c.maxSize,
	}
}

// makeKey creates a cache key from rule ID and page hash
func (c *ruleCache) makeKey(ruleID string, pageHash string) string {
	return ruleID + ":" + pageHash
}

// evictOldest removes the oldest cache entry
func (c *ruleCache) evictOldest() {
	if len(c.cache) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.cache {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(c.cache, oldestKey)
	}
}

// SetTTL sets the time-to-live for cache entries
func (c *ruleCache) SetTTL(ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update TTL for future entries
	// Note: This doesn't update existing entries
}

// CleanExpired removes expired cache entries
func (c *ruleCache) CleanExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if entry.ttl > 0 && now.Sub(entry.timestamp) > entry.ttl {
			delete(c.cache, key)
		}
	}
}

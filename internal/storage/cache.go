package storage

import (
	"context"
	"sync"
	"time"
)

// memoryCache implements Cache interface using in-memory storage
type memoryCache struct {
	data    map[string]memoryCacheEntry
	mu      sync.RWMutex
	maxSize int
	stats   CacheStats
}

type memoryCacheEntry struct {
	value     interface{}
	timestamp time.Time
	ttl       time.Duration
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(maxSize int) Cache {
	return &memoryCache{
		data:    make(map[string]memoryCacheEntry),
		maxSize: maxSize,
	}
}

// Get retrieves cached data
func (mc *memoryCache) Get(ctx context.Context, key string) (interface{}, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	entry, exists := mc.data[key]
	if !exists {
		mc.stats.Misses++
		mc.updateHitRate()
		return nil, false
	}

	// Check TTL
	if entry.ttl > 0 && time.Since(entry.timestamp) > entry.ttl {
		delete(mc.data, key)
		mc.stats.Misses++
		mc.updateHitRate()
		return nil, false
	}

	mc.stats.Hits++
	mc.updateHitRate()
	return entry.value, true
}

// Set stores data in cache
func (mc *memoryCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Evict if at capacity
	if len(mc.data) >= mc.maxSize {
		mc.evictOldest()
	}

	mc.data[key] = memoryCacheEntry{
		value:     value,
		timestamp: time.Now(),
		ttl:       ttl,
	}

	mc.stats.Size = len(mc.data)
}

// Delete removes data from cache
func (mc *memoryCache) Delete(ctx context.Context, key string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	delete(mc.data, key)
	mc.stats.Size = len(mc.data)
}

// Clear clears all cached data
func (mc *memoryCache) Clear(ctx context.Context) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.data = make(map[string]memoryCacheEntry)
	mc.stats = CacheStats{MaxSize: mc.maxSize}
}

// Stats returns cache statistics
func (mc *memoryCache) Stats() CacheStats {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.stats
}

func (mc *memoryCache) evictOldest() {
	if len(mc.data) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range mc.data {
		if first || entry.timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.timestamp
			first = false
		}
	}

	if oldestKey != "" {
		delete(mc.data, oldestKey)
		mc.stats.Evictions++
	}
}

func (mc *memoryCache) updateHitRate() {
	total := mc.stats.Hits + mc.stats.Misses
	if total > 0 {
		mc.stats.HitRate = float64(mc.stats.Hits) / float64(total)
	}
}

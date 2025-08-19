package crawler

import (
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"strings"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/zuub-code/strider/pkg/types"
)

// bloomDeduplicationService implements DeduplicationService using bloom filters
type bloomDeduplicationService struct {
	filter            *bloom.BloomFilter
	mu                sync.RWMutex
	elementCount      uint64
	expectedElements  uint64
	falsePositiveRate float64
	hashFunctions     uint
}

// NewBloomDeduplicationService creates a new bloom filter-based deduplication service
func NewBloomDeduplicationService() DeduplicationService {
	return &bloomDeduplicationService{}
}

// Initialize sets up the bloom filter with expected parameters
func (b *bloomDeduplicationService) Initialize(expectedElements uint64, falsePositiveRate float64) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if expectedElements == 0 {
		expectedElements = 100000 // Default to 100k elements
	}
	if falsePositiveRate == 0 {
		falsePositiveRate = 0.01 // Default to 1% false positive rate
	}

	// Estimate optimal parameters
	m, k := bloom.EstimateParameters(uint(expectedElements), falsePositiveRate)

	b.filter = bloom.New(m, k)
	b.expectedElements = expectedElements
	b.falsePositiveRate = falsePositiveRate
	b.hashFunctions = k
	b.elementCount = 0

	return nil
}

// HasSeen checks if a URL has been seen before
func (b *bloomDeduplicationService) HasSeen(u *url.URL) bool {
	if b.filter == nil {
		return false
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	urlHash := b.hashURL(u)
	return b.filter.Test(urlHash)
}

// MarkSeen marks a URL as seen
func (b *bloomDeduplicationService) MarkSeen(u *url.URL) {
	if b.filter == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	urlHash := b.hashURL(u)
	if !b.filter.Test(urlHash) {
		b.filter.Add(urlHash)
		b.elementCount++
	}
}

// GetStats returns bloom filter statistics
func (b *bloomDeduplicationService) GetStats() types.BloomStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.filter == nil {
		return types.BloomStats{}
	}

	// Calculate current false positive rate based on filter capacity
	currentFPRate := b.falsePositiveRate

	return types.BloomStats{
		ElementCount:    b.elementCount,
		EstimatedFPRate: currentFPRate,
		BitArraySize:    uint64(b.filter.Cap()),
		HashFunctions:   b.hashFunctions,
	}
}

// Reset clears the bloom filter
func (b *bloomDeduplicationService) Reset() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.filter != nil {
		b.filter.ClearAll()
		b.elementCount = 0
	}

	return nil
}

// hashURL creates a consistent hash for a URL
func (b *bloomDeduplicationService) hashURL(u *url.URL) []byte {
	// Normalize URL for consistent hashing
	normalized := b.normalizeURL(u)

	// Create SHA-256 hash
	hash := sha256.Sum256([]byte(normalized))
	return hash[:]
}

// normalizeURL normalizes a URL for consistent comparison
func (b *bloomDeduplicationService) normalizeURL(u *url.URL) string {
	// Create a copy to avoid modifying the original
	normalized := *u

	// Remove fragment
	normalized.Fragment = ""

	// Normalize path
	if normalized.Path == "" {
		normalized.Path = "/"
	}

	// Sort query parameters for consistency
	if normalized.RawQuery != "" {
		values := normalized.Query()
		normalized.RawQuery = values.Encode()
	}

	// Convert to lowercase for case-insensitive comparison
	normalized.Host = strings.ToLower(normalized.Host)
	normalized.Scheme = strings.ToLower(normalized.Scheme)

	return normalized.String()
}

// adaptiveBloomService extends the basic bloom service with adaptive resizing
type adaptiveBloomService struct {
	*bloomDeduplicationService
	maxFalsePositiveRate float64
	resizeThreshold      float64
	autoResize           bool
}

// NewAdaptiveBloomDeduplicationService creates an adaptive bloom filter service
func NewAdaptiveBloomDeduplicationService(maxFPRate, resizeThreshold float64) DeduplicationService {
	base := NewBloomDeduplicationService().(*bloomDeduplicationService)

	return &adaptiveBloomService{
		bloomDeduplicationService: base,
		maxFalsePositiveRate:      maxFPRate,
		resizeThreshold:           resizeThreshold,
		autoResize:                true,
	}
}

// MarkSeen overrides the base implementation to check for resize needs
func (a *adaptiveBloomService) MarkSeen(u *url.URL) {
	// Call base implementation
	a.bloomDeduplicationService.MarkSeen(u)

	// Check if we need to resize
	if a.autoResize && a.shouldResize() {
		a.resize()
	}
}

// shouldResize determines if the bloom filter should be resized
func (a *adaptiveBloomService) shouldResize() bool {
	stats := a.GetStats()

	// Resize if false positive rate exceeds threshold
	if stats.EstimatedFPRate > a.maxFalsePositiveRate {
		return true
	}

	// Resize if we've exceeded expected capacity
	capacityRatio := float64(stats.ElementCount) / float64(a.expectedElements)
	if capacityRatio > a.resizeThreshold {
		return true
	}

	return false
}

// resize creates a new larger bloom filter and rehashes existing elements
func (a *adaptiveBloomService) resize() {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Calculate new parameters (double the capacity)
	newExpectedElements := a.expectedElements * 2

	// Create new filter
	m, k := bloom.EstimateParameters(uint(newExpectedElements), a.falsePositiveRate)
	newFilter := bloom.New(m, k)

	// Note: We can't rehash existing elements from a bloom filter
	// This is a limitation - in a production system, you might want to
	// maintain a separate log of URLs for rehashing, or use a different
	// data structure like a Cuckoo filter that supports deletion

	// Replace the filter (existing elements are lost - trade-off for memory efficiency)
	a.filter = newFilter
	a.expectedElements = newExpectedElements
	a.hashFunctions = k
	a.elementCount = 0
}

// urlCanonicalizer provides URL canonicalization utilities
type urlCanonicalizer struct{}

// NewURLCanonicalizer creates a new URL canonicalizer
func NewURLCanonicalizer() *urlCanonicalizer {
	return &urlCanonicalizer{}
}

// Canonicalize normalizes a URL to its canonical form
func (c *urlCanonicalizer) Canonicalize(u *url.URL) *url.URL {
	canonical := *u

	// Remove default ports
	if canonical.Port() == "80" && canonical.Scheme == "http" {
		canonical.Host = canonical.Hostname()
	} else if canonical.Port() == "443" && canonical.Scheme == "https" {
		canonical.Host = canonical.Hostname()
	}

	// Remove fragment
	canonical.Fragment = ""

	// Normalize path
	if canonical.Path == "" {
		canonical.Path = "/"
	}

	// Remove trailing slash for non-root paths
	if len(canonical.Path) > 1 && canonical.Path[len(canonical.Path)-1] == '/' {
		canonical.Path = canonical.Path[:len(canonical.Path)-1]
	}

	// Sort query parameters
	if canonical.RawQuery != "" {
		values := canonical.Query()
		canonical.RawQuery = values.Encode()
	}

	return &canonical
}

// GetURLHash returns a hash for the URL suitable for bloom filter storage
func (c *urlCanonicalizer) GetURLHash(u *url.URL) uint64 {
	canonical := c.Canonicalize(u)
	hash := sha256.Sum256([]byte(canonical.String()))

	// Convert first 8 bytes to uint64
	return binary.BigEndian.Uint64(hash[:8])
}

package crawler

import (
	"context"
	"net/url"

	"github.com/zuub-code/strider/pkg/types"
)

// Crawler defines the interface for web crawling
type Crawler interface {
	// Crawl performs a complete crawl starting from the root URL
	Crawl(ctx context.Context, config types.CrawlConfig) (*types.CrawlResults, error)

	// CrawlPage crawls a single page and returns its analysis
	CrawlPage(ctx context.Context, pageURL *url.URL, depth int) (*types.PageResult, error)

	// SetupBrowser initializes the browser instance
	SetupBrowser(ctx context.Context, config types.CrawlConfig) error

	// Cleanup releases browser resources
	Cleanup() error

	// GetMetrics returns current crawling metrics
	GetMetrics() types.CrawlMetrics
}

// URLFilter defines interface for URL filtering and prioritization
type URLFilter interface {
	// ShouldCrawl determines if a URL should be crawled
	ShouldCrawl(u *url.URL, depth int, config types.CrawlConfig) bool

	// GetPriority returns the priority score for a URL (higher = more important)
	GetPriority(u *url.URL, depth int, context map[string]interface{}) int

	// IsAllowedDomain checks if the domain is in the allowed list
	IsAllowedDomain(domain string, config types.CrawlConfig) bool

	// IsBlockedDomain checks if the domain is in the blocked list
	IsBlockedDomain(domain string, config types.CrawlConfig) bool
}

// DeduplicationService handles URL deduplication using bloom filters
type DeduplicationService interface {
	// Initialize sets up the bloom filter with expected parameters
	Initialize(expectedElements uint64, falsePositiveRate float64) error

	// HasSeen checks if a URL has been seen before
	HasSeen(u *url.URL) bool

	// MarkSeen marks a URL as seen
	MarkSeen(u *url.URL)

	// GetStats returns bloom filter statistics
	GetStats() types.BloomStats

	// Reset clears the bloom filter
	Reset() error
}

// NetworkCapture handles network request/response capture
type NetworkCapture interface {
	// StartCapture begins capturing network traffic
	StartCapture(ctx context.Context) error

	// StopCapture stops capturing and returns collected data
	StopCapture() ([]types.RequestRecord, []types.ResponseRecord, []types.WebSocketRecord, error)

	// GetRequests returns captured requests
	GetRequests() []types.RequestRecord

	// GetResponses returns captured responses
	GetResponses() []types.ResponseRecord

	// GetWebSockets returns captured WebSocket connections
	GetWebSockets() []types.WebSocketRecord
}

// BrowserManager handles browser lifecycle and configuration
type BrowserManager interface {
	// Launch starts a new browser instance
	Launch(ctx context.Context, config types.CrawlConfig) error

	// NewPage creates a new page/tab
	NewPage(ctx context.Context) (Page, error)

	// Close shuts down the browser
	Close() error

	// GetVersion returns browser version info
	GetVersion() (string, error)
}

// Page represents a browser page/tab
type Page interface {
	// Navigate navigates to a URL
	Navigate(ctx context.Context, u *url.URL) error

	// WaitForLoad waits for page to finish loading
	WaitForLoad(ctx context.Context) error

	// GetContent returns page content and metadata
	GetContent(ctx context.Context) (*types.PageResult, error)

	// GetConsole returns console logs
	GetConsole() []types.ConsoleRecord

	// GetCookies returns page cookies
	GetCookies() []types.CookieRecord

	// GetStorage returns browser storage snapshot
	GetStorage() *types.StorageSnapshot

	// Screenshot takes a screenshot
	Screenshot(ctx context.Context) ([]byte, error)

	// Close closes the page
	Close() error
}

// RateLimiter controls request rate limiting
type RateLimiter interface {
	// Wait blocks until the next request is allowed
	Wait(ctx context.Context, domain string) error

	// Allow checks if a request is currently allowed
	Allow(domain string) bool

	// SetRate updates the rate limit for a domain
	SetRate(domain string, requestsPerSecond float64, burstSize int)
}

// FrontierManager manages the crawl frontier with prioritization
type FrontierManager interface {
	// Add adds URLs to the frontier with priority
	Add(urls []*url.URL, priority int, depth int)

	// Next returns the next URL to crawl
	Next() (*FrontierItem, bool)

	// Size returns the current frontier size
	Size() int

	// IsEmpty returns true if frontier is empty
	IsEmpty() bool

	// Clear empties the frontier
	Clear()
}

// FrontierItem represents an item in the crawl frontier
type FrontierItem struct {
	URL      *url.URL
	Priority int
	Depth    int
	Added    int64 // timestamp
}

// CrawlSession manages a complete crawl session
type CrawlSession interface {
	// Start begins the crawl session
	Start(ctx context.Context, config types.CrawlConfig) error

	// Stop gracefully stops the crawl session
	Stop() error

	// GetResults returns current crawl results
	GetResults() *types.CrawlResults

	// GetProgress returns crawl progress information
	GetProgress() CrawlProgress
}

// CrawlProgress represents crawl progress information
type CrawlProgress struct {
	PagesCompleted int
	PagesRemaining int
	CurrentDepth   int
	ElapsedTime    int64
	EstimatedTime  int64
	ErrorCount     int
}

package crawler

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/google/uuid"
	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
)

// rodCrawler implements Crawler interface using Rod browser automation
type rodCrawler struct {
	browser *rod.Browser
	logger  logger.Logger

	// Services
	deduplication DeduplicationService
	filter        URLFilter
	rateLimiter   RateLimiter
	frontier      FrontierManager

	// Configuration
	config types.CrawlConfig

	// State
	results   *types.CrawlResults
	metrics   types.CrawlMetrics
	startTime time.Time
	mu        sync.RWMutex

	// Worker management
	workerPool chan struct{}
	wg         sync.WaitGroup
}

// NewRodCrawler creates a new Rod-based crawler
func NewRodCrawler(logger logger.Logger) Crawler {
	return &rodCrawler{
		logger:        logger,
		deduplication: NewBloomDeduplicationService(),
		filter:        NewURLFilter(),
		frontier:      NewDomainFrontierManager(),
	}
}

// SetupBrowser initializes the browser instance
func (c *rodCrawler) SetupBrowser(ctx context.Context, config types.CrawlConfig) error {
	c.config = config

	// Initialize services
	if err := c.initializeServices(); err != nil {
		return fmt.Errorf("failed to initialize services: %w", err)
	}

	// Setup browser launcher
	launcher := launcher.New().
		Headless(true).
		NoSandbox(true).
		Set("disable-web-security").
		Set("disable-features", "VizDisplayCompositor")

	if config.EnableStealth {
		launcher = launcher.Set("disable-blink-features", "AutomationControlled")
	}

	// Launch browser
	url, err := launcher.Launch()
	if err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}

	c.browser = rod.New().ControlURL(url)
	if err := c.browser.Connect(); err != nil {
		return fmt.Errorf("failed to connect to browser: %w", err)
	}

	c.logger.Info("Browser initialized successfully")
	return nil
}

// Crawl performs a complete crawl starting from the root URL
func (c *rodCrawler) Crawl(ctx context.Context, config types.CrawlConfig) (*types.CrawlResults, error) {
	c.startTime = time.Now()
	c.config = config

	// Setup browser first
	if err := c.SetupBrowser(ctx, config); err != nil {
		return nil, fmt.Errorf("failed to setup browser: %w", err)
	}
	defer func() {
		if c.browser != nil {
			c.browser.Close()
		}
	}()

	// Initialize results
	c.results = &types.CrawlResults{
		SessionID: uuid.New().String(),
		RootURL:   config.RootURL,
		StartTime: c.startTime,
		Pages:     make([]*types.PageResult, 0),
	}

	// Parse root URL
	rootURL, err := url.Parse(config.RootURL)
	if err != nil {
		return nil, fmt.Errorf("invalid root URL: %w", err)
	}

	// Initialize worker pool
	c.workerPool = make(chan struct{}, config.Concurrency)

	// Initialize rate limiter
	if config.RateLimit != nil {
		c.rateLimiter = NewPolitenessRateLimiter(
			config.RateLimit.RequestsPerSecond,
			config.RateLimit.BurstSize,
		)
	} else {
		c.rateLimiter = NewRateLimiter(2.0, 5, true) // Default: 2 req/sec, burst 5
	}

	// Add root URL to frontier
	c.frontier.Add([]*url.URL{rootURL}, 100, 0)

	c.logger.Info("Starting crawl", "root_url", config.RootURL, "max_pages", config.MaxPages)

	// Main crawl loop
	pagesProcessed := 0
	for !c.frontier.IsEmpty() && pagesProcessed < config.MaxPages {
		select {
		case <-ctx.Done():
			c.logger.Info("Crawl cancelled by context")
			return c.finalizeCrawl(), ctx.Err()
		default:
		}

		// Get next URL from frontier
		item, hasNext := c.frontier.Next()
		if !hasNext {
			break
		}

		// Check if already seen
		if c.deduplication.HasSeen(item.URL) {
			continue
		}

		// Mark as seen
		c.deduplication.MarkSeen(item.URL)

		// Acquire worker slot
		c.workerPool <- struct{}{}
		c.wg.Add(1)

		// Process page in goroutine
		go func(pageURL *url.URL, depth int) {
			defer func() {
				<-c.workerPool
				c.wg.Done()
			}()

			if err := c.rateLimiter.Wait(ctx, pageURL.Hostname()); err != nil {
				c.logger.Error("Rate limiter error", "error", err, "url", pageURL.String())
				return
			}

			pageResult, err := c.CrawlPage(ctx, pageURL, depth)
			if err != nil {
				c.logger.Error("Failed to crawl page", "error", err, "url", pageURL.String())
				return
			}

			c.addPageResult(pageResult)

			// Extract and queue new URLs
			c.extractAndQueueURLs(pageResult, depth)

		}(item.URL, item.Depth)

		pagesProcessed++
	}

	// Wait for all workers to complete
	c.wg.Wait()

	c.logger.Info("Crawl completed", "pages_processed", pagesProcessed)
	return c.finalizeCrawl(), nil
}

// CrawlPage crawls a single page and returns its analysis
func (c *rodCrawler) CrawlPage(ctx context.Context, pageURL *url.URL, depth int) (*types.PageResult, error) {
	startTime := time.Now()

	// Create new page
	page, err := c.browser.Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}
	defer page.Close()

	// Configure page
	if err := c.configurePage(page); err != nil {
		return nil, fmt.Errorf("failed to configure page: %w", err)
	}

	// Setup network capture
	networkCapture := NewNetworkCapture(page)
	if err := networkCapture.StartCapture(ctx); err != nil {
		return nil, fmt.Errorf("failed to start network capture: %w", err)
	}

	// Navigate to page
	if err := page.Navigate(pageURL.String()); err != nil {
		return nil, fmt.Errorf("failed to navigate to page: %w", err)
	}

	// Wait for page load
	if err := c.waitForPageLoad(ctx, page); err != nil {
		return nil, fmt.Errorf("page load timeout: %w", err)
	}

	// Stop network capture and get data
	requests, responses, websockets, err := networkCapture.StopCapture()
	if err != nil {
		return nil, fmt.Errorf("failed to stop network capture: %w", err)
	}

	// Get page content and metadata
	pageResult, err := c.extractPageData(page, pageURL, depth, startTime)
	if err != nil {
		return nil, fmt.Errorf("failed to extract page data: %w", err)
	}

	// Add network data
	pageResult.Requests = requests
	pageResult.Responses = responses
	pageResult.WebSockets = websockets

	return pageResult, nil
}

// Cleanup releases browser resources
func (c *rodCrawler) Cleanup() error {
	if c.browser != nil {
		c.browser.Close()
	}
	return nil
}

// GetMetrics returns current crawling metrics
func (c *rodCrawler) GetMetrics() types.CrawlMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// initializeServices initializes crawler services
func (c *rodCrawler) initializeServices() error {
	// Initialize bloom filter
	expectedElements := uint64(c.config.MaxPages * 10) // Estimate 10 URLs per page
	if c.config.BloomFilter != nil {
		expectedElements = c.config.BloomFilter.ExpectedElements
	}

	if err := c.deduplication.Initialize(expectedElements, 0.01); err != nil {
		return fmt.Errorf("failed to initialize deduplication: %w", err)
	}

	return nil
}

// configurePage sets up page configuration
func (c *rodCrawler) configurePage(page *rod.Page) error {
	// Set viewport
	if err := page.SetViewport(&proto.EmulationSetDeviceMetricsOverride{
		Width:  int(c.config.ViewportWidth),
		Height: int(c.config.ViewportHeight),
	}); err != nil {
		return err
	}

	// Set user agent
	if c.config.UserAgent != "" {
		if err := page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
			UserAgent: c.config.UserAgent,
		}); err != nil {
			return err
		}
	}

	// Configure JavaScript - Rod v0.114+ uses different API
	if !c.config.EnableJavaScript {
		// JavaScript is enabled by default in Rod, disable if needed
		_, err := page.Eval(`() => { window.navigator.javaEnabled = () => false; }`)
		if err != nil {
			return err
		}
	}

	// Configure images
	if !c.config.EnableImages {
		// Block image requests to save bandwidth
		router := page.HijackRequests()
		router.MustAdd("*.png", func(ctx *rod.Hijack) {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
		})
		router.MustAdd("*.jpg", func(ctx *rod.Hijack) {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
		})
		router.MustAdd("*.jpeg", func(ctx *rod.Hijack) {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
		})
		router.MustAdd("*.gif", func(ctx *rod.Hijack) {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
		})
		go router.Run()
	}

	return nil
}

// waitForPageLoad waits for page to finish loading
func (c *rodCrawler) waitForPageLoad(ctx context.Context, page *rod.Page) error {
	// Apply timeout
	timeout := c.config.RequestTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	// Set timeout context for page load
	page = page.Timeout(timeout)

	// Simple wait for page load - compatible with current Rod API
	err := page.WaitLoad()
	if err != nil {
		return err
	}

	// Additional wait for network stability
	time.Sleep(2 * time.Second)

	return nil
}

// extractPageData extracts comprehensive page data
func (c *rodCrawler) extractPageData(page *rod.Page, pageURL *url.URL, depth int, startTime time.Time) (*types.PageResult, error) {
	endTime := time.Now()

	// Get basic page info
	info, err := page.Info()
	if err != nil {
		return nil, err
	}

	// Get page content
	html, err := page.HTML()
	if err != nil {
		return nil, err
	}

	// Get console logs
	console := c.getConsoleLogs(page)

	// Get cookies
	cookies := c.getCookies(page)

	// Get storage
	storage := c.getStorage(page)

	// Calculate bloom hash for deduplication
	canonicalizer := NewURLCanonicalizer()
	bloomHash := canonicalizer.GetURLHash(pageURL)

	pageResult := &types.PageResult{
		URL:          pageURL,
		Domain:       pageURL.Hostname(),
		StatusCode:   200, // Default, will be updated from network capture
		Title:        info.Title,
		ResponseTime: endTime.Sub(startTime),
		BodySize:     int64(len(html)),
		Console:      console,
		Storage:      storage,
		Cookies:      cookies,
		CrawlDepth:   depth,
		StartedAt:    startTime,
		FinishedAt:   endTime,
		BloomHash:    int64(bloomHash),
	}

	return pageResult, nil
}

// getConsoleLogs extracts console logs from the page
func (c *rodCrawler) getConsoleLogs(page *rod.Page) []types.ConsoleRecord {
	// TODO: Implement console log capture
	// This would involve listening to Runtime.consoleAPICalled events
	return []types.ConsoleRecord{}
}

// getCookies extracts cookies from the page
func (c *rodCrawler) getCookies(page *rod.Page) []types.CookieRecord {
	cookies, err := page.Cookies([]string{})
	if err != nil {
		return []types.CookieRecord{}
	}

	result := make([]types.CookieRecord, len(cookies))
	for i, cookie := range cookies {
		result[i] = types.CookieRecord{
			Name:     cookie.Name,
			Value:    cookie.Value,
			Domain:   cookie.Domain,
			Path:     cookie.Path,
			Secure:   cookie.Secure,
			HttpOnly: cookie.HTTPOnly,
			SameSite: string(cookie.SameSite),
		}

		if cookie.Expires > 0 {
			result[i].Expires = time.Unix(int64(cookie.Expires), 0)
		}
	}

	return result
}

// getStorage extracts browser storage data
func (c *rodCrawler) getStorage(page *rod.Page) *types.StorageSnapshot {
	// TODO: Implement storage extraction
	// This would involve calling DOM Storage APIs
	return &types.StorageSnapshot{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
		IndexedDB:      []string{},
	}
}

// extractAndQueueURLs extracts URLs from page and adds them to frontier
func (c *rodCrawler) extractAndQueueURLs(pageResult *types.PageResult, currentDepth int) {
	if currentDepth >= c.config.MaxDepth {
		return
	}

	// TODO: Implement URL extraction from page content
	// This would involve:
	// 1. Parsing HTML for <a> tags
	// 2. Extracting href attributes
	// 3. Resolving relative URLs
	// 4. Filtering URLs based on rules
	// 5. Calculating priorities
	// 6. Adding to frontier

	// For now, this is a placeholder
	urls := []*url.URL{} // Extract URLs from pageResult

	for _, u := range urls {
		if c.filter.ShouldCrawl(u, currentDepth+1, c.config) {
			priority := c.filter.GetPriority(u, currentDepth+1, nil)
			c.frontier.Add([]*url.URL{u}, priority, currentDepth+1)
		}
	}
}

// addPageResult safely adds a page result to the crawl results
func (c *rodCrawler) addPageResult(pageResult *types.PageResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results.Pages = append(c.results.Pages, pageResult)
	c.results.TotalRequests += len(pageResult.Requests)
	c.results.TotalResponses += len(pageResult.Responses)

	// Update metrics
	c.updateMetrics()
}

// updateMetrics calculates current crawling metrics
func (c *rodCrawler) updateMetrics() {
	if len(c.results.Pages) == 0 {
		return
	}

	elapsed := time.Since(c.startTime)
	pagesCount := len(c.results.Pages)

	c.metrics.PagesPerSecond = float64(pagesCount) / elapsed.Seconds()

	// Calculate average page time
	var totalTime time.Duration
	for _, page := range c.results.Pages {
		totalTime += page.ResponseTime
	}
	c.metrics.AveragePageTime = totalTime / time.Duration(pagesCount)

	// Get bloom filter stats
	c.metrics.BloomFilterStats = c.deduplication.GetStats()
}

// finalizeCrawl finalizes the crawl results
func (c *rodCrawler) finalizeCrawl() *types.CrawlResults {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results.EndTime = time.Now()
	c.updateMetrics()
	c.results.Metrics = c.metrics

	return c.results
}

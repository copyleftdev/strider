package crawler

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/zuub-code/strider/pkg/types"
)

// urlFilter implements URLFilter interface
type urlFilter struct {
	priorityCalc *priorityCalculator

	// Compiled regex patterns for efficiency
	staticResourceRegex *regexp.Regexp
	excludePatterns     []*regexp.Regexp
	includePatterns     []*regexp.Regexp
}

// NewURLFilter creates a new URL filter
func NewURLFilter() URLFilter {
	// Compile static resource regex
	staticResourcePattern := `\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|tar|gz|mp4|mp3|avi|mov)$`
	staticRegex, _ := regexp.Compile(staticResourcePattern)

	return &urlFilter{
		priorityCalc:        NewPriorityCalculator(),
		staticResourceRegex: staticRegex,
		excludePatterns:     make([]*regexp.Regexp, 0),
		includePatterns:     make([]*regexp.Regexp, 0),
	}
}

// ShouldCrawl determines if a URL should be crawled
func (f *urlFilter) ShouldCrawl(u *url.URL, depth int, config types.CrawlConfig) bool {
	// Check depth limit
	if depth > config.MaxDepth {
		return false
	}

	// Check scheme
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Check domain restrictions
	if !f.IsAllowedDomain(u.Hostname(), config) {
		return false
	}

	if f.IsBlockedDomain(u.Hostname(), config) {
		return false
	}

	// Skip static resources unless specifically needed
	if f.isStaticResource(u) {
		return false
	}

	// Skip common non-content URLs
	if f.isNonContentURL(u) {
		return false
	}

	// Check custom exclude patterns
	if f.matchesExcludePatterns(u) {
		return false
	}

	// Check custom include patterns (if any are defined)
	if len(f.includePatterns) > 0 && !f.matchesIncludePatterns(u) {
		return false
	}

	return true
}

// GetPriority returns the priority score for a URL
func (f *urlFilter) GetPriority(u *url.URL, depth int, context map[string]interface{}) int {
	return f.priorityCalc.CalculatePriority(u, depth, context)
}

// IsAllowedDomain checks if the domain is in the allowed list
func (f *urlFilter) IsAllowedDomain(domain string, config types.CrawlConfig) bool {
	if len(config.AllowedDomains) == 0 {
		return true // No restrictions
	}

	domain = strings.ToLower(domain)

	for _, allowed := range config.AllowedDomains {
		allowed = strings.ToLower(allowed)

		// Exact match
		if domain == allowed {
			return true
		}

		// Subdomain match (if allowed domain starts with .)
		if strings.HasPrefix(allowed, ".") && strings.HasSuffix(domain, allowed) {
			return true
		}

		// Wildcard subdomain match
		if strings.HasPrefix(allowed, "*.") {
			baseDomain := allowed[2:]
			if domain == baseDomain || strings.HasSuffix(domain, "."+baseDomain) {
				return true
			}
		}
	}

	return false
}

// IsBlockedDomain checks if the domain is in the blocked list
func (f *urlFilter) IsBlockedDomain(domain string, config types.CrawlConfig) bool {
	if len(config.BlockedDomains) == 0 {
		return false // No blocks
	}

	domain = strings.ToLower(domain)

	for _, blocked := range config.BlockedDomains {
		blocked = strings.ToLower(blocked)

		// Exact match
		if domain == blocked {
			return true
		}

		// Subdomain match (if blocked domain starts with .)
		if strings.HasPrefix(blocked, ".") && strings.HasSuffix(domain, blocked) {
			return true
		}

		// Wildcard subdomain match
		if strings.HasPrefix(blocked, "*.") {
			baseDomain := blocked[2:]
			if domain == baseDomain || strings.HasSuffix(domain, "."+baseDomain) {
				return true
			}
		}
	}

	return false
}

// isStaticResource checks if URL points to a static resource
func (f *urlFilter) isStaticResource(u *url.URL) bool {
	return f.staticResourceRegex.MatchString(u.Path)
}

// isNonContentURL checks for URLs that typically don't contain useful content
func (f *urlFilter) isNonContentURL(u *url.URL) bool {
	path := strings.ToLower(u.Path)

	// Skip logout URLs
	if strings.Contains(path, "logout") || strings.Contains(path, "signout") {
		return true
	}

	// Skip download URLs
	if strings.Contains(path, "download") && (strings.Contains(path, ".zip") ||
		strings.Contains(path, ".tar") || strings.Contains(path, ".gz")) {
		return true
	}

	// Skip print versions
	if strings.Contains(path, "print") || strings.Contains(u.RawQuery, "print=1") {
		return true
	}

	// Skip RSS/XML feeds (unless we specifically want them)
	if strings.HasSuffix(path, ".rss") || strings.HasSuffix(path, ".xml") ||
		strings.Contains(path, "/feed") {
		return true
	}

	// Skip calendar/date-specific URLs that might create infinite loops
	if f.isDateBasedURL(u) {
		return true
	}

	return false
}

// isDateBasedURL checks for URLs with date parameters that might create loops
func (f *urlFilter) isDateBasedURL(u *url.URL) bool {
	query := u.RawQuery

	// Common date parameters that might create infinite pagination
	dateParams := []string{"date=", "year=", "month=", "day=", "timestamp="}

	for _, param := range dateParams {
		if strings.Contains(query, param) {
			return true
		}
	}

	return false
}

// matchesExcludePatterns checks if URL matches any exclude patterns
func (f *urlFilter) matchesExcludePatterns(u *url.URL) bool {
	fullURL := u.String()

	for _, pattern := range f.excludePatterns {
		if pattern.MatchString(fullURL) {
			return true
		}
	}

	return false
}

// matchesIncludePatterns checks if URL matches any include patterns
func (f *urlFilter) matchesIncludePatterns(u *url.URL) bool {
	fullURL := u.String()

	for _, pattern := range f.includePatterns {
		if pattern.MatchString(fullURL) {
			return true
		}
	}

	return false
}

// AddExcludePattern adds a regex pattern to exclude URLs
func (f *urlFilter) AddExcludePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	f.excludePatterns = append(f.excludePatterns, regex)
	return nil
}

// AddIncludePattern adds a regex pattern to include URLs
func (f *urlFilter) AddIncludePattern(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	f.includePatterns = append(f.includePatterns, regex)
	return nil
}

// robotsFilter implements robots.txt filtering
type robotsFilter struct {
	robotsCache map[string]*robotsRules
	userAgent   string
}

type robotsRules struct {
	disallowed []string
	allowed    []string
	crawlDelay int
}

// NewRobotsFilter creates a new robots.txt filter
func NewRobotsFilter(userAgent string) *robotsFilter {
	return &robotsFilter{
		robotsCache: make(map[string]*robotsRules),
		userAgent:   userAgent,
	}
}

// IsAllowed checks if a URL is allowed by robots.txt
func (rf *robotsFilter) IsAllowed(u *url.URL) bool {
	// Get robots rules for this domain
	rules := rf.getRobotsRules(u.Hostname())
	if rules == nil {
		return true // No robots.txt or failed to fetch - allow by default
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	// Check disallowed paths first (more restrictive)
	for _, disallowed := range rules.disallowed {
		if rf.pathMatches(path, disallowed) {
			// Check if there's a more specific allow rule
			for _, allowed := range rules.allowed {
				if rf.pathMatches(path, allowed) && len(allowed) > len(disallowed) {
					return true
				}
			}
			return false
		}
	}

	return true
}

// GetCrawlDelay returns the crawl delay for a domain
func (rf *robotsFilter) GetCrawlDelay(domain string) int {
	rules := rf.getRobotsRules(domain)
	if rules != nil {
		return rules.crawlDelay
	}
	return 0
}

// getRobotsRules fetches and parses robots.txt for a domain
func (rf *robotsFilter) getRobotsRules(domain string) *robotsRules {
	// Check cache first
	if rules, exists := rf.robotsCache[domain]; exists {
		return rules
	}

	// TODO: Implement robots.txt fetching and parsing
	// This would involve:
	// 1. HTTP GET to http(s)://domain/robots.txt
	// 2. Parse the robots.txt format
	// 3. Extract rules for our user agent
	// 4. Cache the results

	// For now, return nil (no restrictions)
	return nil
}

// pathMatches checks if a path matches a robots.txt pattern
func (rf *robotsFilter) pathMatches(path, pattern string) bool {
	// Simple prefix matching for now
	// Full implementation would handle wildcards (* and $)
	return strings.HasPrefix(path, pattern)
}

// smartFilter combines multiple filtering strategies
type smartFilter struct {
	urlFilter    URLFilter
	robotsFilter *robotsFilter

	// Learning components for adaptive filtering
	crawlHistory map[string]filterDecision

	// Configuration
	respectRobots bool
	learningMode  bool
}

type filterDecision struct {
	allowed   bool
	timestamp int64
	reason    string
}

// NewSmartFilter creates an intelligent filter that learns from crawl patterns
func NewSmartFilter(userAgent string, respectRobots bool) URLFilter {
	return &smartFilter{
		urlFilter:     NewURLFilter(),
		robotsFilter:  NewRobotsFilter(userAgent),
		crawlHistory:  make(map[string]filterDecision),
		respectRobots: respectRobots,
		learningMode:  true,
	}
}

// ShouldCrawl implements intelligent URL filtering
func (sf *smartFilter) ShouldCrawl(u *url.URL, depth int, config types.CrawlConfig) bool {
	// First check basic URL filter
	if !sf.urlFilter.ShouldCrawl(u, depth, config) {
		sf.recordDecision(u, false, "basic_filter")
		return false
	}

	// Check robots.txt if enabled
	if sf.respectRobots && !sf.robotsFilter.IsAllowed(u) {
		sf.recordDecision(u, false, "robots_txt")
		return false
	}

	// Check learning history for patterns
	if sf.learningMode && sf.shouldSkipBasedOnHistory(u) {
		sf.recordDecision(u, false, "learning_filter")
		return false
	}

	sf.recordDecision(u, true, "allowed")
	return true
}

// GetPriority delegates to the base URL filter
func (sf *smartFilter) GetPriority(u *url.URL, depth int, context map[string]interface{}) int {
	return sf.urlFilter.GetPriority(u, depth, context)
}

// IsAllowedDomain delegates to the base URL filter
func (sf *smartFilter) IsAllowedDomain(domain string, config types.CrawlConfig) bool {
	return sf.urlFilter.IsAllowedDomain(domain, config)
}

// IsBlockedDomain delegates to the base URL filter
func (sf *smartFilter) IsBlockedDomain(domain string, config types.CrawlConfig) bool {
	return sf.urlFilter.IsBlockedDomain(domain, config)
}

// recordDecision records a filtering decision for learning
func (sf *smartFilter) recordDecision(u *url.URL, allowed bool, reason string) {
	if !sf.learningMode {
		return
	}

	key := u.String()
	sf.crawlHistory[key] = filterDecision{
		allowed:   allowed,
		timestamp: 0, // TODO: Add timestamp
		reason:    reason,
	}
}

// shouldSkipBasedOnHistory checks if URL should be skipped based on learning
func (sf *smartFilter) shouldSkipBasedOnHistory(u *url.URL) bool {
	// TODO: Implement machine learning-based filtering
	// This could include:
	// - Pattern recognition for non-useful URLs
	// - Content quality prediction
	// - Duplicate content detection
	// - Performance-based filtering

	return false
}

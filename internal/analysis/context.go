package analysis

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/zuub-code/strider/pkg/types"
)

// contextAnalyzer implements ContextAnalyzer interface
type contextAnalyzer struct {
	// Framework detection patterns
	frameworkPatterns map[string]*regexp.Regexp

	// Application type detection patterns
	appTypePatterns map[string]*regexp.Regexp

	// API endpoint patterns
	apiPatterns []*regexp.Regexp
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() ContextAnalyzer {
	ca := &contextAnalyzer{
		frameworkPatterns: make(map[string]*regexp.Regexp),
		appTypePatterns:   make(map[string]*regexp.Regexp),
		apiPatterns:       make([]*regexp.Regexp, 0),
	}

	ca.initializePatterns()
	return ca
}

// AnalyzeContext extracts context information from crawl results
func (ca *contextAnalyzer) AnalyzeContext(results *types.CrawlResults) *types.AnalysisContext {
	if results == nil || len(results.Pages) == 0 {
		return &types.AnalysisContext{}
	}

	// Extract domain from root URL
	rootURL, _ := url.Parse(results.RootURL)
	domain := ""
	if rootURL != nil {
		domain = rootURL.Hostname()
	}

	context := &types.AnalysisContext{
		Domain:               domain,
		ApplicationType:      ca.DetectApplicationType(results),
		Industry:             ca.detectIndustry(results),
		ComplianceFrameworks: ca.detectComplianceFrameworks(results),
		CustomRules:          []string{},
		APIEndpoints:         ca.ExtractAPIEndpoints(results),
	}

	return context
}

// DetectApplicationType attempts to identify the application type
func (ca *contextAnalyzer) DetectApplicationType(results *types.CrawlResults) string {
	if results == nil || len(results.Pages) == 0 {
		return "unknown"
	}

	// Analyze page content and URLs to determine app type
	scores := map[string]int{
		"spa":       0,
		"api":       0,
		"cms":       0,
		"ecommerce": 0,
		"blog":      0,
		"webapp":    0,
	}

	for _, page := range results.Pages {
		ca.scoreApplicationType(page, scores)
	}

	// Find the highest scoring type
	maxScore := 0
	appType := "webapp" // Default

	for typ, score := range scores {
		if score > maxScore {
			maxScore = score
			appType = typ
		}
	}

	return appType
}

// ExtractAPIEndpoints identifies API endpoints from the crawl
func (ca *contextAnalyzer) ExtractAPIEndpoints(results *types.CrawlResults) []string {
	if results == nil {
		return []string{}
	}

	endpoints := make(map[string]bool)

	for _, page := range results.Pages {
		// Check page URL
		if ca.isAPIEndpoint(page.URL) {
			endpoints[page.URL.String()] = true
		}

		// Check request URLs
		for _, request := range page.Requests {
			if ca.isAPIEndpoint(request.URL) {
				endpoints[request.URL.String()] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		result = append(result, endpoint)
	}

	return result
}

// IdentifyFrameworks detects web frameworks and technologies
func (ca *contextAnalyzer) IdentifyFrameworks(results *types.CrawlResults) []string {
	if results == nil {
		return []string{}
	}

	frameworks := make(map[string]bool)

	for _, page := range results.Pages {
		// Check response headers
		for _, response := range page.Responses {
			ca.analyzeHeaders(response.Headers, frameworks)
		}

		// Check for framework-specific patterns in URLs
		ca.analyzeURLPatterns(page.URL, frameworks)

		// Check requests for framework indicators
		for _, request := range page.Requests {
			ca.analyzeURLPatterns(request.URL, frameworks)
		}
	}

	// Convert to slice
	result := make([]string, 0, len(frameworks))
	for framework := range frameworks {
		result = append(result, framework)
	}

	return result
}

// initializePatterns sets up detection patterns
func (ca *contextAnalyzer) initializePatterns() {
	// Framework patterns
	ca.frameworkPatterns["react"] = regexp.MustCompile(`(?i)(react|jsx|__REACT_DEVTOOLS__)`)
	ca.frameworkPatterns["angular"] = regexp.MustCompile(`(?i)(angular|ng-|@angular)`)
	ca.frameworkPatterns["vue"] = regexp.MustCompile(`(?i)(vue\.js|vuejs|__VUE__)`)
	ca.frameworkPatterns["django"] = regexp.MustCompile(`(?i)(django|csrftoken)`)
	ca.frameworkPatterns["rails"] = regexp.MustCompile(`(?i)(rails|ruby|authenticity_token)`)
	ca.frameworkPatterns["laravel"] = regexp.MustCompile(`(?i)(laravel|_token)`)
	ca.frameworkPatterns["wordpress"] = regexp.MustCompile(`(?i)(wp-content|wordpress|wp-admin)`)
	ca.frameworkPatterns["drupal"] = regexp.MustCompile(`(?i)(drupal|sites/default)`)
	ca.frameworkPatterns["joomla"] = regexp.MustCompile(`(?i)(joomla|com_content)`)

	// Application type patterns
	ca.appTypePatterns["spa"] = regexp.MustCompile(`(?i)(single.page|spa|app\.js|bundle\.js)`)
	ca.appTypePatterns["api"] = regexp.MustCompile(`(?i)(/api/|/rest/|/graphql|\.json|\.xml)`)
	ca.appTypePatterns["cms"] = regexp.MustCompile(`(?i)(wp-|drupal|joomla|admin|content)`)
	ca.appTypePatterns["ecommerce"] = regexp.MustCompile(`(?i)(shop|cart|checkout|product|order|payment)`)
	ca.appTypePatterns["blog"] = regexp.MustCompile(`(?i)(blog|post|article|category|tag)`)

	// API endpoint patterns
	ca.apiPatterns = append(ca.apiPatterns, regexp.MustCompile(`/api/v?\d+/`))
	ca.apiPatterns = append(ca.apiPatterns, regexp.MustCompile(`/rest/`))
	ca.apiPatterns = append(ca.apiPatterns, regexp.MustCompile(`/graphql/?`))
	ca.apiPatterns = append(ca.apiPatterns, regexp.MustCompile(`\.json$`))
	ca.apiPatterns = append(ca.apiPatterns, regexp.MustCompile(`\.xml$`))
}

// scoreApplicationType scores different application types based on page analysis
func (ca *contextAnalyzer) scoreApplicationType(page *types.PageResult, scores map[string]int) {
	url := page.URL.String()

	// Check URL patterns
	for appType, pattern := range ca.appTypePatterns {
		if pattern.MatchString(url) {
			scores[appType] += 10
		}
	}

	// Check content type
	for _, response := range page.Responses {
		contentType := response.Headers.Get("Content-Type")

		if strings.Contains(contentType, "application/json") {
			scores["api"] += 15
		} else if strings.Contains(contentType, "text/html") {
			scores["webapp"] += 5
		}

		// Check for SPA indicators in headers
		if response.Headers.Get("X-Requested-With") == "XMLHttpRequest" {
			scores["spa"] += 10
		}
	}

	// Check for API-like request patterns
	jsonRequests := 0
	totalRequests := len(page.Requests)

	for _, request := range page.Requests {
		if strings.Contains(request.Headers.Get("Accept"), "application/json") {
			jsonRequests++
		}

		if ca.isAPIEndpoint(request.URL) {
			scores["api"] += 5
		}
	}

	// High ratio of JSON requests suggests SPA or API
	if totalRequests > 0 {
		jsonRatio := float64(jsonRequests) / float64(totalRequests)
		if jsonRatio > 0.5 {
			scores["spa"] += 20
		}
	}
}

// isAPIEndpoint checks if a URL looks like an API endpoint
func (ca *contextAnalyzer) isAPIEndpoint(u *url.URL) bool {
	if u == nil {
		return false
	}

	path := u.Path

	for _, pattern := range ca.apiPatterns {
		if pattern.MatchString(path) {
			return true
		}
	}

	return false
}

// analyzeHeaders looks for framework indicators in HTTP headers
func (ca *contextAnalyzer) analyzeHeaders(headers map[string][]string, frameworks map[string]bool) {
	for name, values := range headers {
		headerLine := name + ": " + strings.Join(values, " ")

		for framework, pattern := range ca.frameworkPatterns {
			if pattern.MatchString(headerLine) {
				frameworks[framework] = true
			}
		}
	}
}

// analyzeURLPatterns looks for framework indicators in URLs
func (ca *contextAnalyzer) analyzeURLPatterns(u *url.URL, frameworks map[string]bool) {
	if u == nil {
		return
	}

	urlStr := u.String()

	for framework, pattern := range ca.frameworkPatterns {
		if pattern.MatchString(urlStr) {
			frameworks[framework] = true
		}
	}
}

// detectIndustry attempts to detect the industry based on content
func (ca *contextAnalyzer) detectIndustry(results *types.CrawlResults) string {
	if results == nil {
		return ""
	}

	// Industry keywords
	industryKeywords := map[string][]string{
		"healthcare": {"health", "medical", "hospital", "clinic", "patient", "hipaa"},
		"finance":    {"bank", "financial", "payment", "credit", "loan", "pci"},
		"education":  {"school", "university", "student", "course", "ferpa"},
		"government": {"gov", ".gov", "government", "public", "citizen"},
		"retail":     {"shop", "store", "product", "cart", "ecommerce"},
		"technology": {"software", "tech", "api", "developer", "code"},
	}

	scores := make(map[string]int)

	// Check domain and URLs for industry indicators
	rootURL, _ := url.Parse(results.RootURL)
	if rootURL != nil {
		domain := rootURL.Hostname()

		for industry, keywords := range industryKeywords {
			for _, keyword := range keywords {
				if strings.Contains(strings.ToLower(domain), keyword) {
					scores[industry] += 10
				}
			}
		}
	}

	// Find highest scoring industry
	maxScore := 0
	industry := ""

	for ind, score := range scores {
		if score > maxScore {
			maxScore = score
			industry = ind
		}
	}

	return industry
}

// detectComplianceFrameworks identifies relevant compliance frameworks
func (ca *contextAnalyzer) detectComplianceFrameworks(results *types.CrawlResults) []string {
	if results == nil {
		return []string{}
	}

	frameworks := make(map[string]bool)

	// Detect based on industry
	industry := ca.detectIndustry(results)

	switch industry {
	case "healthcare":
		frameworks["HIPAA"] = true
	case "finance":
		frameworks["PCI DSS"] = true
		frameworks["SOX"] = true
	case "government":
		frameworks["FedRAMP"] = true
		frameworks["FISMA"] = true
	}

	// Check for GDPR indicators (European domains or privacy policies)
	rootURL, _ := url.Parse(results.RootURL)
	if rootURL != nil {
		domain := rootURL.Hostname()

		// European TLDs
		euTLDs := []string{".eu", ".de", ".fr", ".uk", ".it", ".es", ".nl", ".be"}
		for _, tld := range euTLDs {
			if strings.HasSuffix(domain, tld) {
				frameworks["GDPR"] = true
				break
			}
		}
	}

	// Check for privacy policy or GDPR mentions in URLs
	for _, page := range results.Pages {
		path := strings.ToLower(page.URL.Path)
		if strings.Contains(path, "privacy") || strings.Contains(path, "gdpr") {
			frameworks["GDPR"] = true
		}
	}

	// Convert to slice
	result := make([]string, 0, len(frameworks))
	for framework := range frameworks {
		result = append(result, framework)
	}

	return result
}

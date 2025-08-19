package types

import (
	"net/http"
	"net/url"
	"time"
)

// Severity levels for findings
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Confidence levels for findings
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// STRIDE threat categories
type STRIDECategory string

const (
	STRIDESpoofing              STRIDECategory = "spoofing"
	STRIDETampering             STRIDECategory = "tampering"
	STRIDERepudiation           STRIDECategory = "repudiation"
	STRIDEInformationDisclosure STRIDECategory = "information_disclosure"
	STRIDEDenialOfService       STRIDECategory = "denial_of_service"
	STRIDEElevationOfPrivilege  STRIDECategory = "elevation_of_privilege"
)

// Analysis source types
type AnalysisSource string

const (
	SourceStatic  AnalysisSource = "static"
	SourceDynamic AnalysisSource = "dynamic"
	SourceAI      AnalysisSource = "ai"
	SourceHybrid  AnalysisSource = "hybrid"
)

// Resource types for network requests
type ResourceType string

const (
	ResourceDocument   ResourceType = "document"
	ResourceStylesheet ResourceType = "stylesheet"
	ResourceScript     ResourceType = "script"
	ResourceImage      ResourceType = "image"
	ResourceFont       ResourceType = "font"
	ResourceXHR        ResourceType = "xhr"
	ResourceFetch      ResourceType = "fetch"
	ResourceWebSocket  ResourceType = "websocket"
	ResourceOther      ResourceType = "other"
)

// PageResult represents a complete page analysis result
type PageResult struct {
	URL          *url.URL      `json:"url" validate:"required,url"`
	Domain       string        `json:"domain" validate:"required,hostname"`
	StatusCode   int           `json:"status_code" validate:"min=100,max=599"`
	Title        string        `json:"title" validate:"max=200"`
	ContentType  string        `json:"content_type"`
	ResponseTime time.Duration `json:"response_time_ms"`
	BodySize     int64         `json:"body_size_bytes"`

	// Network activity
	Requests   []RequestRecord   `json:"requests"`
	Responses  []ResponseRecord  `json:"responses"`
	WebSockets []WebSocketRecord `json:"websockets,omitempty"`

	// Browser state
	Console []ConsoleRecord  `json:"console,omitempty"`
	Storage *StorageSnapshot `json:"storage,omitempty"`
	Cookies []CookieRecord   `json:"cookies,omitempty"`

	// Metadata
	CrawlDepth int       `json:"crawl_depth"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	BloomHash  int64     `json:"bloom_hash"` // For deduplication
}

// RequestRecord with enhanced metadata
type RequestRecord struct {
	ID             string       `json:"id" validate:"required,uuid4"`
	URL            *url.URL     `json:"url" validate:"required,url"`
	Method         string       `json:"method" validate:"required,oneof=GET POST PUT DELETE PATCH HEAD OPTIONS"`
	Type           ResourceType `json:"type"`
	Initiator      string       `json:"initiator"`
	Priority       string       `json:"priority"`
	Headers        http.Header  `json:"headers"`
	PostData       []byte       `json:"post_data,omitempty"`
	IsThirdParty   bool         `json:"is_third_party"`
	IsCrossOrigin  bool         `json:"is_cross_origin"`
	HasCredentials bool         `json:"has_credentials"`
	Timestamp      time.Time    `json:"timestamp"`
}

// ResponseRecord with security analysis
type ResponseRecord struct {
	RequestID       string           `json:"request_id" validate:"required,uuid4"`
	URL             *url.URL         `json:"url" validate:"required,url"`
	StatusCode      int              `json:"status_code" validate:"min=100,max=599"`
	StatusText      string           `json:"status_text"`
	MIMEType        string           `json:"mime_type"`
	Headers         http.Header      `json:"headers"`
	BodySample      []byte           `json:"body_sample,omitempty"`
	BodyHash        string           `json:"body_hash,omitempty"` // SHA-256
	SecurityHeaders *SecurityHeaders `json:"security_headers,omitempty"`
	ResponseTime    time.Duration    `json:"response_time"`
	BodySize        int64            `json:"body_size"`
	Timestamp       time.Time        `json:"timestamp"`
}

// WebSocketRecord for WebSocket connections
type WebSocketRecord struct {
	ID            string             `json:"id"`
	URL           *url.URL           `json:"url"`
	Protocol      string             `json:"protocol"`
	Extensions    []string           `json:"extensions"`
	EstablishedAt time.Time          `json:"established_at"`
	ClosedAt      *time.Time         `json:"closed_at,omitempty"`
	CloseReason   string             `json:"close_reason,omitempty"`
	Messages      []WebSocketMessage `json:"messages"`
}

// WebSocketMessage represents a WebSocket message
type WebSocketMessage struct {
	ConnectionID string    `json:"connection_id"`
	Direction    string    `json:"direction"` // "sent" or "received"
	Type         string    `json:"type"`      // "text", "binary", "ping", "pong"
	Data         []byte    `json:"data"`
	Timestamp    time.Time `json:"timestamp"`
	Size         int64     `json:"size"`
}

// ConsoleRecord for browser console logs
type ConsoleRecord struct {
	Level     string        `json:"level"`
	Message   string        `json:"message"`
	Source    string        `json:"source"`
	Line      int           `json:"line"`
	Column    int           `json:"column"`
	Args      []interface{} `json:"args,omitempty"`
	Timestamp time.Time     `json:"timestamp"`
}

// StorageSnapshot captures browser storage state
type StorageSnapshot struct {
	LocalStorage   map[string]string `json:"local_storage,omitempty"`
	SessionStorage map[string]string `json:"session_storage,omitempty"`
	IndexedDB      []string          `json:"indexed_db,omitempty"`
}

// CookieRecord represents HTTP cookies
type CookieRecord struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires,omitempty"`
	MaxAge   int       `json:"max_age,omitempty"`
	Secure   bool      `json:"secure"`
	HttpOnly bool      `json:"http_only"`
	SameSite string    `json:"same_site"`
}

// SecurityHeaders analysis results
type SecurityHeaders struct {
	CSP                *CSPAnalysis                `json:"csp,omitempty"`
	HSTS               *HSTSAnalysis               `json:"hsts,omitempty"`
	CORS               *CORSAnalysis               `json:"cors,omitempty"`
	FrameOptions       *FrameOptionsAnalysis       `json:"frame_options,omitempty"`
	ContentTypeOptions *ContentTypeOptionsAnalysis `json:"content_type_options,omitempty"`
	ReferrerPolicy     *ReferrerPolicyAnalysis     `json:"referrer_policy,omitempty"`
	PermissionsPolicy  *PermissionsPolicyAnalysis  `json:"permissions_policy,omitempty"`
}

// CSPAnalysis for Content Security Policy
type CSPAnalysis struct {
	Present      bool                `json:"present"`
	Directives   map[string][]string `json:"directives"`
	UnsafeInline bool                `json:"unsafe_inline"`
	UnsafeEval   bool                `json:"unsafe_eval"`
	Wildcards    []string            `json:"wildcards"`
	Violations   []string            `json:"violations"`
	Score        int                 `json:"score"` // 0-100 security score
}

// HSTSAnalysis for HTTP Strict Transport Security
type HSTSAnalysis struct {
	Present           bool `json:"present"`
	MaxAge            int  `json:"max_age"`
	IncludeSubDomains bool `json:"include_sub_domains"`
	Preload           bool `json:"preload"`
}

// CORSAnalysis for Cross-Origin Resource Sharing
type CORSAnalysis struct {
	AllowOrigin      string          `json:"allow_origin"`
	AllowCredentials bool            `json:"allow_credentials"`
	AllowMethods     []string        `json:"allow_methods"`
	AllowHeaders     []string        `json:"allow_headers"`
	ExposeHeaders    []string        `json:"expose_headers"`
	MaxAge           int             `json:"max_age"`
	Violations       []CORSViolation `json:"violations"`
}

// CORSViolation represents a CORS security violation
type CORSViolation struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    Severity               `json:"severity"`
	Evidence    map[string]interface{} `json:"evidence"`
}

// FrameOptionsAnalysis for X-Frame-Options
type FrameOptionsAnalysis struct {
	Present bool   `json:"present"`
	Value   string `json:"value"`
	Valid   bool   `json:"valid"`
}

// ContentTypeOptionsAnalysis for X-Content-Type-Options
type ContentTypeOptionsAnalysis struct {
	Present bool `json:"present"`
	NoSniff bool `json:"no_sniff"`
}

// ReferrerPolicyAnalysis for Referrer-Policy
type ReferrerPolicyAnalysis struct {
	Present bool   `json:"present"`
	Policy  string `json:"policy"`
	Secure  bool   `json:"secure"`
}

// PermissionsPolicyAnalysis for Permissions-Policy
type PermissionsPolicyAnalysis struct {
	Present     bool              `json:"present"`
	Directives  map[string]string `json:"directives"`
	Restrictive bool              `json:"restrictive"`
}

// Finding represents a security finding
type Finding struct {
	ID          string                 `json:"id" validate:"required"`
	RuleID      string                 `json:"rule_id" validate:"required"`
	Title       string                 `json:"title" validate:"required,max=200"`
	Description string                 `json:"description" validate:"required,max=1000"`
	Remediation string                 `json:"remediation" validate:"required,max=500"`
	Severity    Severity               `json:"severity" validate:"required,oneof=info low medium high critical"`
	Confidence  Confidence             `json:"confidence" validate:"required,oneof=low medium high"`
	Category    string                 `json:"category"`
	STRIDE      []STRIDECategory       `json:"stride,omitempty"`
	MITREAttck  []MITRETechnique       `json:"mitre_attck,omitempty"`
	OWASP       []string               `json:"owasp,omitempty"`
	CWE         []int                  `json:"cwe,omitempty"`
	PageURL     *url.URL               `json:"page_url" validate:"required,url"`
	Evidence    map[string]interface{} `json:"evidence,omitempty"`
	Source      AnalysisSource         `json:"source"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty"`
}

// MITRETechnique represents a MITRE ATT&CK technique
type MITRETechnique struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// CrawlConfig contains crawling configuration
type CrawlConfig struct {
	RootURL          string           `json:"root_url" validate:"required,url"`
	AllowedDomains   []string         `json:"allowed_domains,omitempty"`
	BlockedDomains   []string         `json:"blocked_domains,omitempty"`
	MaxPages         int              `json:"max_pages" validate:"min=1,max=100000"`
	MaxDepth         int              `json:"max_depth" validate:"min=1,max=20"`
	Concurrency      int              `json:"concurrency" validate:"min=1,max=50"`
	RequestTimeout   time.Duration    `json:"request_timeout"`
	IdleTimeout      time.Duration    `json:"idle_timeout"`
	MaxBodySize      int64            `json:"max_body_size"`
	UserAgent        string           `json:"user_agent,omitempty"`
	ViewportWidth    int              `json:"viewport_width"`
	ViewportHeight   int              `json:"viewport_height"`
	EnableJavaScript bool             `json:"enable_javascript"`
	EnableImages     bool             `json:"enable_images"`
	RespectRobots    bool             `json:"respect_robots_txt"`
	FollowRedirects  bool             `json:"follow_redirects"`
	EnableStealth    bool             `json:"enable_stealth"`
	RateLimit        *RateLimitConfig `json:"rate_limit,omitempty"`
	BloomFilter      *BloomConfig     `json:"bloom_filter,omitempty"`
}

// RateLimitConfig for polite crawling
type RateLimitConfig struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	BurstSize         int     `json:"burst_size"`
	PerHost           bool    `json:"per_host"`
}

// BloomConfig for bloom filter configuration
type BloomConfig struct {
	ExpectedElements  uint64  `json:"expected_elements"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	HashFunctions     uint    `json:"hash_functions"`
	BitArraySize      uint64  `json:"bit_array_size"`
}

// AnalysisContext for AI grading
type AnalysisContext struct {
	Domain               string   `json:"domain"`
	ApplicationType      string   `json:"application_type,omitempty"`
	Industry             string   `json:"industry,omitempty"`
	ComplianceFrameworks []string `json:"compliance_frameworks,omitempty"`
	CustomRules          []string `json:"custom_rules,omitempty"`
	APIEndpoints         []string `json:"api_endpoints,omitempty"`
}

// CrawlResults contains the results of a crawl session
type CrawlResults struct {
	SessionID      string        `json:"session_id"`
	RootURL        string        `json:"root_url"`
	StartTime      time.Time     `json:"start_time"`
	EndTime        time.Time     `json:"end_time"`
	Pages          []*PageResult `json:"pages"`
	TotalRequests  int           `json:"total_requests"`
	TotalResponses int           `json:"total_responses"`
	Metrics        CrawlMetrics  `json:"metrics"`
}

// CrawlMetrics contains performance metrics from crawling
type CrawlMetrics struct {
	PagesPerSecond   float64       `json:"pages_per_second"`
	AveragePageTime  time.Duration `json:"average_page_time"`
	ErrorRate        float64       `json:"error_rate"`
	MemoryUsage      int64         `json:"memory_usage_bytes"`
	BloomFilterStats BloomStats    `json:"bloom_filter_stats"`
}

// BloomStats contains bloom filter statistics
type BloomStats struct {
	ElementCount    uint64  `json:"element_count"`
	EstimatedFPRate float64 `json:"estimated_fp_rate"`
	BitArraySize    uint64  `json:"bit_array_size"`
	HashFunctions   uint    `json:"hash_functions"`
}

// SecurityReport represents the final security analysis report
type SecurityReport struct {
	SessionID    string             `json:"session_id"`
	RootURL      string             `json:"root_url"`
	StartTime    time.Time          `json:"start_time"`
	EndTime      time.Time          `json:"end_time"`
	Findings     []Finding          `json:"findings"`
	Statistics   SecurityStatistics `json:"statistics"`
	CrawlMetrics CrawlMetrics       `json:"crawl_metrics"`
}

// SecurityStatistics contains summary statistics
type SecurityStatistics struct {
	TotalFindings   int `json:"total_findings"`
	CriticalCount   int `json:"critical_count"`
	HighCount       int `json:"high_count"`
	MediumCount     int `json:"medium_count"`
	LowCount        int `json:"low_count"`
	InfoCount       int `json:"info_count"`
	AIFindings      int `json:"ai_findings"`
	StaticFindings  int `json:"static_findings"`
	DynamicFindings int `json:"dynamic_findings"`
}

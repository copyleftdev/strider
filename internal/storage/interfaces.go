package storage

import (
	"context"
	"time"

	"github.com/zuub-code/strider/pkg/types"
)

// Storage defines the interface for data persistence
type Storage interface {
	// Initialize sets up the storage backend
	Initialize(ctx context.Context) error

	// Close closes the storage connection
	Close() error

	// Health checks storage health
	Health(ctx context.Context) error

	// Sessions
	CreateSession(ctx context.Context, session *CrawlSession) error
	GetSession(ctx context.Context, sessionID string) (*CrawlSession, error)
	ListSessions(ctx context.Context, filter SessionFilter) ([]*CrawlSession, error)
	UpdateSession(ctx context.Context, session *CrawlSession) error
	DeleteSession(ctx context.Context, sessionID string) error

	// Pages
	StorePage(ctx context.Context, sessionID string, page *types.PageResult) error
	GetPage(ctx context.Context, sessionID, pageID string) (*types.PageResult, error)
	ListPages(ctx context.Context, sessionID string, filter PageFilter) ([]*types.PageResult, error)

	// Findings
	StoreFindings(ctx context.Context, sessionID string, findings []types.Finding) error
	GetFindings(ctx context.Context, sessionID string, filter FindingFilter) ([]types.Finding, error)
	UpdateFinding(ctx context.Context, finding *types.Finding) error
	DeleteFinding(ctx context.Context, findingID string) error

	// Reports
	StoreReport(ctx context.Context, report *types.SecurityReport) error
	GetReport(ctx context.Context, sessionID string) (*types.SecurityReport, error)
	ListReports(ctx context.Context, filter ReportFilter) ([]*types.SecurityReport, error)

	// Analytics and Queries
	GetSessionStats(ctx context.Context, sessionID string) (*SessionStats, error)
	GetFindingStats(ctx context.Context, filter FindingStatsFilter) (*FindingStats, error)
	SearchFindings(ctx context.Context, query SearchQuery) ([]types.Finding, error)

	// Bulk Operations
	BulkInsertPages(ctx context.Context, sessionID string, pages []*types.PageResult) error
	BulkInsertFindings(ctx context.Context, sessionID string, findings []types.Finding) error

	// Maintenance
	Vacuum(ctx context.Context) error
	GetStorageStats(ctx context.Context) (*StorageStats, error)
}

// CrawlSession represents a crawl session in storage
type CrawlSession struct {
	ID            string     `json:"id" db:"id"`
	RootURL       string     `json:"root_url" db:"root_url"`
	StartTime     time.Time  `json:"start_time" db:"start_time"`
	EndTime       *time.Time `json:"end_time,omitempty" db:"end_time"`
	Status        string     `json:"status" db:"status"`
	PagesCount    int        `json:"pages_count" db:"pages_count"`
	FindingsCount int        `json:"findings_count" db:"findings_count"`
	Config        string     `json:"config" db:"config"`               // JSON serialized config
	Metadata      string     `json:"metadata,omitempty" db:"metadata"` // JSON metadata
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
}

// SessionFilter for filtering sessions
type SessionFilter struct {
	Status    string     `json:"status,omitempty"`
	RootURL   string     `json:"root_url,omitempty"`
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
	OrderBy   string     `json:"order_by,omitempty"`
	OrderDesc bool       `json:"order_desc,omitempty"`
}

// PageFilter for filtering pages
type PageFilter struct {
	Domain     string `json:"domain,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	MinDepth   int    `json:"min_depth,omitempty"`
	MaxDepth   int    `json:"max_depth,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// FindingFilter for filtering findings
type FindingFilter struct {
	Severity   []types.Severity       `json:"severity,omitempty"`
	Category   []string               `json:"category,omitempty"`
	RuleID     []string               `json:"rule_id,omitempty"`
	Source     []types.AnalysisSource `json:"source,omitempty"`
	Confidence []types.Confidence     `json:"confidence,omitempty"`
	Limit      int                    `json:"limit,omitempty"`
	Offset     int                    `json:"offset,omitempty"`
	OrderBy    string                 `json:"order_by,omitempty"`
	OrderDesc  bool                   `json:"order_desc,omitempty"`
}

// ReportFilter for filtering reports
type ReportFilter struct {
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`
	RootURL   string     `json:"root_url,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// FindingStatsFilter for finding statistics
type FindingStatsFilter struct {
	SessionID string     `json:"session_id,omitempty"`
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`
	GroupBy   string     `json:"group_by,omitempty"` // severity, category, rule_id
}

// SearchQuery for full-text search
type SearchQuery struct {
	Query     string   `json:"query"`
	Fields    []string `json:"fields,omitempty"` // title, description, remediation
	SessionID string   `json:"session_id,omitempty"`
	Limit     int      `json:"limit,omitempty"`
	Offset    int      `json:"offset,omitempty"`
}

// SessionStats contains session statistics
type SessionStats struct {
	SessionID          string         `json:"session_id"`
	TotalPages         int            `json:"total_pages"`
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByCategory map[string]int `json:"findings_by_category"`
	CrawlDuration      time.Duration  `json:"crawl_duration"`
	DomainsScanned     int            `json:"domains_scanned"`
	RequestsTotal      int            `json:"requests_total"`
	ResponsesTotal     int            `json:"responses_total"`
}

// FindingStats contains finding statistics
type FindingStats struct {
	TotalFindings int            `json:"total_findings"`
	BySeverity    map[string]int `json:"by_severity"`
	ByCategory    map[string]int `json:"by_category"`
	BySource      map[string]int `json:"by_source"`
	ByConfidence  map[string]int `json:"by_confidence"`
	TopRules      []RuleStats    `json:"top_rules"`
	TrendData     []TrendPoint   `json:"trend_data,omitempty"`
}

// RuleStats contains statistics for a specific rule
type RuleStats struct {
	RuleID   string    `json:"rule_id"`
	Count    int       `json:"count"`
	Severity string    `json:"severity"`
	Category string    `json:"category"`
	LastSeen time.Time `json:"last_seen"`
}

// TrendPoint represents a data point in trend analysis
type TrendPoint struct {
	Date  time.Time `json:"date"`
	Count int       `json:"count"`
	Value float64   `json:"value,omitempty"`
}

// StorageStats contains storage performance statistics
type StorageStats struct {
	DatabaseSize  int64            `json:"database_size_bytes"`
	TableSizes    map[string]int64 `json:"table_sizes"`
	IndexSizes    map[string]int64 `json:"index_sizes"`
	TotalSessions int              `json:"total_sessions"`
	TotalPages    int              `json:"total_pages"`
	TotalFindings int              `json:"total_findings"`
	TotalReports  int              `json:"total_reports"`
	OldestSession *time.Time       `json:"oldest_session,omitempty"`
	NewestSession *time.Time       `json:"newest_session,omitempty"`
	QueryStats    QueryStats       `json:"query_stats"`
}

// QueryStats contains query performance statistics
type QueryStats struct {
	TotalQueries   int64         `json:"total_queries"`
	AverageTime    time.Duration `json:"average_time"`
	SlowestQueries []SlowQuery   `json:"slowest_queries"`
}

// SlowQuery represents a slow query
type SlowQuery struct {
	Query    string        `json:"query"`
	Duration time.Duration `json:"duration"`
	Count    int           `json:"count"`
}

// Transaction defines transaction interface
type Transaction interface {
	// Commit commits the transaction
	Commit() error

	// Rollback rolls back the transaction
	Rollback() error

	// Storage operations within transaction
	StorePage(ctx context.Context, sessionID string, page *types.PageResult) error
	StoreFindings(ctx context.Context, sessionID string, findings []types.Finding) error
	UpdateSession(ctx context.Context, session *CrawlSession) error
}

// TransactionManager manages database transactions
type TransactionManager interface {
	// BeginTransaction starts a new transaction
	BeginTransaction(ctx context.Context) (Transaction, error)

	// WithTransaction executes a function within a transaction
	WithTransaction(ctx context.Context, fn func(tx Transaction) error) error
}

// Migration defines database migration interface
type Migration interface {
	// Version returns the migration version
	Version() int

	// Up applies the migration
	Up(ctx context.Context, storage Storage) error

	// Down reverts the migration
	Down(ctx context.Context, storage Storage) error

	// Description returns migration description
	Description() string
}

// MigrationManager manages database migrations
type MigrationManager interface {
	// ApplyMigrations applies all pending migrations
	ApplyMigrations(ctx context.Context) error

	// GetCurrentVersion returns current schema version
	GetCurrentVersion(ctx context.Context) (int, error)

	// RegisterMigration registers a migration
	RegisterMigration(migration Migration)

	// ListMigrations returns all registered migrations
	ListMigrations() []Migration
}

// Cache defines caching interface for storage
type Cache interface {
	// Get retrieves cached data
	Get(ctx context.Context, key string) (interface{}, bool)

	// Set stores data in cache
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration)

	// Delete removes data from cache
	Delete(ctx context.Context, key string)

	// Clear clears all cached data
	Clear(ctx context.Context)

	// Stats returns cache statistics
	Stats() CacheStats
}

// CacheStats contains cache statistics
type CacheStats struct {
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	HitRate   float64 `json:"hit_rate"`
	Size      int     `json:"size"`
	MaxSize   int     `json:"max_size"`
	Evictions int64   `json:"evictions"`
}

// StorageConfig contains storage configuration
type StorageConfig struct {
	Type         string            `json:"type"`
	DatabasePath string            `json:"database_path"`
	MaxConns     int               `json:"max_connections"`
	Timeout      time.Duration     `json:"timeout"`
	WALMode      bool              `json:"wal_mode"`
	CacheSize    int               `json:"cache_size"`
	BusyTimeout  time.Duration     `json:"busy_timeout"`
	Pragmas      map[string]string `json:"pragmas"`
	EnableCache  bool              `json:"enable_cache"`
	CacheTTL     time.Duration     `json:"cache_ttl"`
}

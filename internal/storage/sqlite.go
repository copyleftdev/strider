package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zuub-code/strider/pkg/logger"
	"github.com/zuub-code/strider/pkg/types"
	_ "modernc.org/sqlite"
)

// sqliteStorage implements Storage interface using SQLite
type sqliteStorage struct {
	db     *sql.DB
	config StorageConfig
	logger logger.Logger
	cache  Cache
	mu     sync.RWMutex

	// Prepared statements
	stmts map[string]*sql.Stmt
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(config StorageConfig, logger logger.Logger) Storage {
	storage := &sqliteStorage{
		config: config,
		logger: logger,
		stmts:  make(map[string]*sql.Stmt),
	}

	if config.EnableCache {
		storage.cache = NewMemoryCache(config.CacheSize)
	}

	return storage
}

// Initialize sets up the SQLite database
func (s *sqliteStorage) Initialize(ctx context.Context) error {
	// Ensure directory exists
	if err := s.ensureDirectory(); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open database connection
	db, err := sql.Open("sqlite", s.config.DatabasePath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	s.db = db

	// Configure SQLite
	if err := s.configureSQLite(); err != nil {
		return fmt.Errorf("failed to configure SQLite: %w", err)
	}

	// Create tables
	if err := s.createTables(ctx); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Create indexes
	if err := s.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	// Prepare statements
	if err := s.prepareStatements(); err != nil {
		return fmt.Errorf("failed to prepare statements: %w", err)
	}

	s.logger.Info("SQLite storage initialized", "path", s.config.DatabasePath)
	return nil
}

// Close closes the database connection
func (s *sqliteStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close prepared statements
	for name, stmt := range s.stmts {
		if err := stmt.Close(); err != nil {
			s.logger.Error("Failed to close prepared statement", "name", name, "error", err)
		}
	}

	if s.db != nil {
		return s.db.Close()
	}

	return nil
}

// Health checks storage health
func (s *sqliteStorage) Health(ctx context.Context) error {
	if s.db == nil {
		return fmt.Errorf("database not initialized")
	}

	return s.db.PingContext(ctx)
}

// CreateSession creates a new crawl session
func (s *sqliteStorage) CreateSession(ctx context.Context, session *CrawlSession) error {
	query := `
		INSERT INTO sessions (id, root_url, start_time, end_time, status, pages_count, findings_count, config, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	session.CreatedAt = now
	session.UpdatedAt = now

	_, err := s.db.ExecContext(ctx, query,
		session.ID, session.RootURL, session.StartTime, session.EndTime,
		session.Status, session.PagesCount, session.FindingsCount,
		session.Config, session.Metadata, session.CreatedAt, session.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	s.logger.Info("Session created", "session_id", session.ID)
	return nil
}

// GetSession retrieves a session by ID
func (s *sqliteStorage) GetSession(ctx context.Context, sessionID string) (*CrawlSession, error) {
	// Check cache first
	if s.cache != nil {
		if cached, found := s.cache.Get(ctx, "session:"+sessionID); found {
			if session, ok := cached.(*CrawlSession); ok {
				return session, nil
			}
		}
	}

	query := `
		SELECT id, root_url, start_time, end_time, status, pages_count, findings_count, config, metadata, created_at, updated_at
		FROM sessions WHERE id = ?
	`

	session := &CrawlSession{}
	err := s.db.QueryRowContext(ctx, query, sessionID).Scan(
		&session.ID, &session.RootURL, &session.StartTime, &session.EndTime,
		&session.Status, &session.PagesCount, &session.FindingsCount,
		&session.Config, &session.Metadata, &session.CreatedAt, &session.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Cache the result
	if s.cache != nil {
		s.cache.Set(ctx, "session:"+sessionID, session, s.config.CacheTTL)
	}

	return session, nil
}

// ListSessions lists sessions with filtering
func (s *sqliteStorage) ListSessions(ctx context.Context, filter SessionFilter) ([]*CrawlSession, error) {
	query := "SELECT id, root_url, start_time, end_time, status, pages_count, findings_count, config, metadata, created_at, updated_at FROM sessions"
	args := []interface{}{}
	conditions := []string{}

	// Build WHERE clause
	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Status)
	}

	if filter.RootURL != "" {
		conditions = append(conditions, "root_url LIKE ?")
		args = append(args, "%"+filter.RootURL+"%")
	}

	if filter.StartDate != nil {
		conditions = append(conditions, "start_time >= ?")
		args = append(args, *filter.StartDate)
	}

	if filter.EndDate != nil {
		conditions = append(conditions, "start_time <= ?")
		args = append(args, *filter.EndDate)
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	// Add ORDER BY
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}

	query += " ORDER BY " + orderBy
	if filter.OrderDesc {
		query += " DESC"
	}

	// Add LIMIT and OFFSET
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*CrawlSession
	for rows.Next() {
		session := &CrawlSession{}
		err := rows.Scan(
			&session.ID, &session.RootURL, &session.StartTime, &session.EndTime,
			&session.Status, &session.PagesCount, &session.FindingsCount,
			&session.Config, &session.Metadata, &session.CreatedAt, &session.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}
		sessions = append(sessions, session)
	}

	return sessions, nil
}

// UpdateSession updates a session
func (s *sqliteStorage) UpdateSession(ctx context.Context, session *CrawlSession) error {
	query := `
		UPDATE sessions 
		SET root_url = ?, start_time = ?, end_time = ?, status = ?, pages_count = ?, findings_count = ?, config = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`

	session.UpdatedAt = time.Now()

	_, err := s.db.ExecContext(ctx, query,
		session.RootURL, session.StartTime, session.EndTime, session.Status,
		session.PagesCount, session.FindingsCount, session.Config, session.Metadata,
		session.UpdatedAt, session.ID)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Invalidate cache
	if s.cache != nil {
		s.cache.Delete(ctx, "session:"+session.ID)
	}

	return nil
}

// DeleteSession deletes a session and all related data
func (s *sqliteStorage) DeleteSession(ctx context.Context, sessionID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete in order due to foreign key constraints
	tables := []string{"findings", "requests", "responses", "websockets", "pages", "sessions"}

	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE session_id = ?", table)
		if table == "sessions" {
			query = "DELETE FROM sessions WHERE id = ?"
		}

		_, err := tx.ExecContext(ctx, query, sessionID)
		if err != nil {
			return fmt.Errorf("failed to delete from %s: %w", table, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Invalidate cache
	if s.cache != nil {
		s.cache.Delete(ctx, "session:"+sessionID)
	}

	s.logger.Info("Session deleted", "session_id", sessionID)
	return nil
}

// StorePage stores a page result
func (s *sqliteStorage) StorePage(ctx context.Context, sessionID string, page *types.PageResult) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Store page
	pageQuery := `
		INSERT INTO pages (id, session_id, url, domain, status_code, title, content_type, response_time, body_size, crawl_depth, started_at, finished_at, bloom_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	pageID := fmt.Sprintf("%s-%d", sessionID, time.Now().UnixNano())

	_, err = tx.ExecContext(ctx, pageQuery,
		pageID, sessionID, page.URL.String(), page.Domain, page.StatusCode,
		page.Title, page.ContentType, page.ResponseTime.Milliseconds(),
		page.BodySize, page.CrawlDepth, page.StartedAt, page.FinishedAt, page.BloomHash)

	if err != nil {
		return fmt.Errorf("failed to store page: %w", err)
	}

	// Store requests
	for _, request := range page.Requests {
		if err := s.storeRequest(ctx, tx, pageID, &request); err != nil {
			return fmt.Errorf("failed to store request: %w", err)
		}
	}

	// Store responses
	for _, response := range page.Responses {
		if err := s.storeResponse(ctx, tx, pageID, &response); err != nil {
			return fmt.Errorf("failed to store response: %w", err)
		}
	}

	// Store WebSocket connections
	for _, ws := range page.WebSockets {
		if err := s.storeWebSocket(ctx, tx, pageID, &ws); err != nil {
			return fmt.Errorf("failed to store websocket: %w", err)
		}
	}

	return tx.Commit()
}

// Helper methods for storing related data

func (s *sqliteStorage) storeRequest(ctx context.Context, tx *sql.Tx, pageID string, request *types.RequestRecord) error {
	query := `
		INSERT INTO requests (id, page_id, url, method, type, initiator, headers, post_data, is_third_party, is_cross_origin, has_credentials, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	headersJSON, _ := json.Marshal(request.Headers)

	_, err := tx.ExecContext(ctx, query,
		request.ID, pageID, request.URL.String(), request.Method, string(request.Type),
		request.Initiator, string(headersJSON), request.PostData,
		request.IsThirdParty, request.IsCrossOrigin, request.HasCredentials, request.Timestamp)

	return err
}

func (s *sqliteStorage) storeResponse(ctx context.Context, tx *sql.Tx, pageID string, response *types.ResponseRecord) error {
	query := `
		INSERT INTO responses (request_id, page_id, url, status_code, status_text, mime_type, headers, body_sample, body_hash, response_time, body_size, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	headersJSON, _ := json.Marshal(response.Headers)

	_, err := tx.ExecContext(ctx, query,
		response.RequestID, pageID, response.URL.String(), response.StatusCode,
		response.StatusText, response.MIMEType, string(headersJSON),
		response.BodySample, response.BodyHash, response.ResponseTime.Milliseconds(),
		response.BodySize, response.Timestamp)

	return err
}

func (s *sqliteStorage) storeWebSocket(ctx context.Context, tx *sql.Tx, pageID string, ws *types.WebSocketRecord) error {
	query := `
		INSERT INTO websockets (id, page_id, url, protocol, extensions, established_at, closed_at, close_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	extensionsJSON, _ := json.Marshal(ws.Extensions)

	_, err := tx.ExecContext(ctx, query,
		ws.ID, pageID, ws.URL.String(), ws.Protocol, string(extensionsJSON),
		ws.EstablishedAt, ws.ClosedAt, ws.CloseReason)

	return err
}

// StoreFindings stores security findings
func (s *sqliteStorage) StoreFindings(ctx context.Context, sessionID string, findings []types.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	query := `
		INSERT INTO findings (id, session_id, rule_id, title, description, remediation, severity, confidence, category, page_url, evidence, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, finding := range findings {
		evidenceJSON, _ := json.Marshal(finding.Evidence)
		pageURL := ""
		if finding.PageURL != nil {
			pageURL = finding.PageURL.String()
		}

		_, err := stmt.ExecContext(ctx,
			finding.ID, sessionID, finding.RuleID, finding.Title, finding.Description,
			finding.Remediation, string(finding.Severity), string(finding.Confidence),
			finding.Category, pageURL, string(evidenceJSON), string(finding.Source),
			finding.CreatedAt, finding.UpdatedAt)

		if err != nil {
			return fmt.Errorf("failed to store finding %s: %w", finding.ID, err)
		}
	}

	return tx.Commit()
}

// GetFindings retrieves findings with filtering
func (s *sqliteStorage) GetFindings(ctx context.Context, sessionID string, filter FindingFilter) ([]types.Finding, error) {
	query := "SELECT id, session_id, rule_id, title, description, remediation, severity, confidence, category, page_url, evidence, source, created_at, updated_at FROM findings WHERE session_id = ?"
	args := []interface{}{sessionID}
	conditions := []string{}

	// Build WHERE clause
	if len(filter.Severity) > 0 {
		placeholders := strings.Repeat("?,", len(filter.Severity))
		placeholders = placeholders[:len(placeholders)-1] // Remove trailing comma
		conditions = append(conditions, "severity IN ("+placeholders+")")
		for _, sev := range filter.Severity {
			args = append(args, string(sev))
		}
	}

	if len(filter.Category) > 0 {
		placeholders := strings.Repeat("?,", len(filter.Category))
		placeholders = placeholders[:len(placeholders)-1]
		conditions = append(conditions, "category IN ("+placeholders+")")
		for _, cat := range filter.Category {
			args = append(args, cat)
		}
	}

	if len(conditions) > 0 {
		query += " AND " + strings.Join(conditions, " AND ")
	}

	// Add ORDER BY
	orderBy := "created_at"
	if filter.OrderBy != "" {
		orderBy = filter.OrderBy
	}

	query += " ORDER BY " + orderBy
	if filter.OrderDesc {
		query += " DESC"
	}

	// Add LIMIT and OFFSET
	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)

		if filter.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filter.Offset)
		}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query findings: %w", err)
	}
	defer rows.Close()

	var findings []types.Finding
	for rows.Next() {
		var finding types.Finding
		var pageURL, evidenceJSON string

		err := rows.Scan(
			&finding.ID, &finding.RuleID, &finding.Title, &finding.Description,
			&finding.Remediation, &finding.Severity, &finding.Confidence,
			&finding.Category, &pageURL, &evidenceJSON, &finding.Source,
			&finding.CreatedAt, &finding.UpdatedAt)

		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}

		// Parse evidence JSON
		if evidenceJSON != "" {
			json.Unmarshal([]byte(evidenceJSON), &finding.Evidence)
		}

		findings = append(findings, finding)
	}

	return findings, nil
}

// Helper methods for database setup

func (s *sqliteStorage) ensureDirectory() error {
	dir := filepath.Dir(s.config.DatabasePath)
	return os.MkdirAll(dir, 0755)
}

func (s *sqliteStorage) configureSQLite() error {
	pragmas := map[string]string{
		"journal_mode": "WAL",
		"synchronous":  "NORMAL",
		"cache_size":   "-64000", // 64MB cache
		"temp_store":   "MEMORY",
		"mmap_size":    "268435456", // 256MB mmap
	}

	// Apply custom pragmas
	for key, value := range s.config.Pragmas {
		pragmas[key] = value
	}

	for pragma, value := range pragmas {
		query := fmt.Sprintf("PRAGMA %s = %s", pragma, value)
		if _, err := s.db.Exec(query); err != nil {
			return fmt.Errorf("failed to set pragma %s: %w", pragma, err)
		}
	}

	return nil
}

func (s *sqliteStorage) createTables(ctx context.Context) error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			root_url TEXT NOT NULL,
			start_time DATETIME NOT NULL,
			end_time DATETIME,
			status TEXT NOT NULL,
			pages_count INTEGER DEFAULT 0,
			findings_count INTEGER DEFAULT 0,
			config TEXT,
			metadata TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,

		`CREATE TABLE IF NOT EXISTS pages (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			url TEXT NOT NULL,
			domain TEXT NOT NULL,
			status_code INTEGER,
			title TEXT,
			content_type TEXT,
			response_time INTEGER,
			body_size INTEGER,
			crawl_depth INTEGER,
			started_at DATETIME,
			finished_at DATETIME,
			bloom_hash INTEGER,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS findings (
			id TEXT PRIMARY KEY,
			session_id TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			title TEXT NOT NULL,
			description TEXT NOT NULL,
			remediation TEXT,
			severity TEXT NOT NULL,
			confidence TEXT NOT NULL,
			category TEXT,
			page_url TEXT,
			evidence TEXT,
			source TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS requests (
			id TEXT PRIMARY KEY,
			page_id TEXT NOT NULL,
			url TEXT NOT NULL,
			method TEXT NOT NULL,
			type TEXT,
			initiator TEXT,
			headers TEXT,
			post_data BLOB,
			is_third_party BOOLEAN,
			is_cross_origin BOOLEAN,
			has_credentials BOOLEAN,
			timestamp DATETIME,
			FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS responses (
			request_id TEXT,
			page_id TEXT NOT NULL,
			url TEXT NOT NULL,
			status_code INTEGER,
			status_text TEXT,
			mime_type TEXT,
			headers TEXT,
			body_sample BLOB,
			body_hash TEXT,
			response_time INTEGER,
			body_size INTEGER,
			timestamp DATETIME,
			FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS reports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id TEXT NOT NULL,
			report_type TEXT NOT NULL,
			format TEXT NOT NULL,
			data TEXT NOT NULL,
			total_findings INTEGER NOT NULL DEFAULT 0,
			critical_count INTEGER NOT NULL DEFAULT 0,
			high_count INTEGER NOT NULL DEFAULT 0,
			medium_count INTEGER NOT NULL DEFAULT 0,
			low_count INTEGER NOT NULL DEFAULT 0,
			info_count INTEGER NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL,
			FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
		)`,

		`CREATE TABLE IF NOT EXISTS websockets (
			id TEXT PRIMARY KEY,
			page_id TEXT NOT NULL,
			url TEXT NOT NULL,
			protocol TEXT,
			extensions TEXT,
			established_at DATETIME,
			closed_at DATETIME,
			close_reason TEXT,
			FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE
		)`,
	}

	for _, table := range tables {
		if _, err := s.db.ExecContext(ctx, table); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	return nil
}

func (s *sqliteStorage) createIndexes(ctx context.Context) error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time)",
		"CREATE INDEX IF NOT EXISTS idx_pages_session_id ON pages(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_pages_domain ON pages(domain)",
		"CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
		"CREATE INDEX IF NOT EXISTS idx_findings_rule_id ON findings(rule_id)",
		"CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)",
		"CREATE INDEX IF NOT EXISTS idx_requests_page_id ON requests(page_id)",
		"CREATE INDEX IF NOT EXISTS idx_responses_page_id ON responses(page_id)",
	}

	for _, index := range indexes {
		if _, err := s.db.ExecContext(ctx, index); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	return nil
}

func (s *sqliteStorage) prepareStatements() error {
	// Prepare commonly used statements for better performance
	statements := map[string]string{
		"get_session":           "SELECT id, root_url, start_time, end_time, status, pages_count, findings_count, config, metadata, created_at, updated_at FROM sessions WHERE id = ?",
		"update_session_counts": "UPDATE sessions SET pages_count = ?, findings_count = ?, updated_at = ? WHERE id = ?",
	}

	for name, query := range statements {
		stmt, err := s.db.Prepare(query)
		if err != nil {
			return fmt.Errorf("failed to prepare statement %s: %w", name, err)
		}
		s.stmts[name] = stmt
	}

	return nil
}

// Placeholder implementations for remaining interface methods
func (s *sqliteStorage) GetPage(ctx context.Context, sessionID, pageID string) (*types.PageResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) ListPages(ctx context.Context, sessionID string, filter PageFilter) ([]*types.PageResult, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) UpdateFinding(ctx context.Context, finding *types.Finding) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStorage) DeleteFinding(ctx context.Context, findingID string) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStorage) StoreReport(ctx context.Context, report *types.SecurityReport) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Store report metadata
	reportData, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	query := `
		INSERT INTO reports (
			session_id, report_type, format, data, 
			total_findings, critical_count, high_count, 
			medium_count, low_count, info_count,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, query,
		report.SessionID,
		"security_scan",
		"json",
		reportData,
		len(report.Findings),
		report.Statistics.CriticalCount,
		report.Statistics.HighCount,
		report.Statistics.MediumCount,
		report.Statistics.LowCount,
		report.Statistics.InfoCount,
		time.Now(),
		time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to store report: %w", err)
	}

	return tx.Commit()
}

func (s *sqliteStorage) GetReport(ctx context.Context, sessionID string) (*types.SecurityReport, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) ListReports(ctx context.Context, filter ReportFilter) ([]*types.SecurityReport, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) GetSessionStats(ctx context.Context, sessionID string) (*SessionStats, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) GetFindingStats(ctx context.Context, filter FindingStatsFilter) (*FindingStats, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) SearchFindings(ctx context.Context, query SearchQuery) ([]types.Finding, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *sqliteStorage) BulkInsertPages(ctx context.Context, sessionID string, pages []*types.PageResult) error {
	return fmt.Errorf("not implemented")
}

func (s *sqliteStorage) BulkInsertFindings(ctx context.Context, sessionID string, findings []types.Finding) error {
	return s.StoreFindings(ctx, sessionID, findings)
}

func (s *sqliteStorage) Vacuum(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "VACUUM")
	return err
}

func (s *sqliteStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	return nil, fmt.Errorf("not implemented")
}

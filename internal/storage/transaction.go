package storage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/zuub-code/strider/pkg/types"
)

// sqliteTransaction implements Transaction interface
type sqliteTransaction struct {
	tx      *sql.Tx
	storage *sqliteStorage
}

// sqliteTransactionManager implements TransactionManager interface
type sqliteTransactionManager struct {
	storage *sqliteStorage
}

// NewTransactionManager creates a new transaction manager
func NewTransactionManager(storage *sqliteStorage) TransactionManager {
	return &sqliteTransactionManager{
		storage: storage,
	}
}

// BeginTransaction starts a new transaction
func (tm *sqliteTransactionManager) BeginTransaction(ctx context.Context) (Transaction, error) {
	tx, err := tm.storage.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &sqliteTransaction{
		tx:      tx,
		storage: tm.storage,
	}, nil
}

// WithTransaction executes a function within a transaction
func (tm *sqliteTransactionManager) WithTransaction(ctx context.Context, fn func(tx Transaction) error) error {
	tx, err := tm.BeginTransaction(ctx)
	if err != nil {
		return err
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

// Commit commits the transaction
func (st *sqliteTransaction) Commit() error {
	return st.tx.Commit()
}

// Rollback rolls back the transaction
func (st *sqliteTransaction) Rollback() error {
	return st.tx.Rollback()
}

// StorePage stores a page within the transaction
func (st *sqliteTransaction) StorePage(ctx context.Context, sessionID string, page *types.PageResult) error {
	// Store page
	pageQuery := `
		INSERT INTO pages (id, session_id, url, domain, status_code, title, content_type, response_time, body_size, crawl_depth, started_at, finished_at, bloom_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	pageID := fmt.Sprintf("%s-%d", sessionID, page.StartedAt.UnixNano())

	_, err := st.tx.ExecContext(ctx, pageQuery,
		pageID, sessionID, page.URL.String(), page.Domain, page.StatusCode,
		page.Title, page.ContentType, page.ResponseTime.Milliseconds(),
		page.BodySize, page.CrawlDepth, page.StartedAt, page.FinishedAt, page.BloomHash)

	if err != nil {
		return fmt.Errorf("failed to store page: %w", err)
	}

	// Store requests
	for _, request := range page.Requests {
		if err := st.storeRequest(ctx, pageID, &request); err != nil {
			return fmt.Errorf("failed to store request: %w", err)
		}
	}

	// Store responses
	for _, response := range page.Responses {
		if err := st.storeResponse(ctx, pageID, &response); err != nil {
			return fmt.Errorf("failed to store response: %w", err)
		}
	}

	// Store WebSocket connections
	for _, ws := range page.WebSockets {
		if err := st.storeWebSocket(ctx, pageID, &ws); err != nil {
			return fmt.Errorf("failed to store websocket: %w", err)
		}
	}

	return nil
}

// StoreFindings stores findings within the transaction
func (st *sqliteTransaction) StoreFindings(ctx context.Context, sessionID string, findings []types.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	query := `
		INSERT INTO findings (id, session_id, rule_id, title, description, remediation, severity, confidence, category, page_url, evidence, source, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := st.tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, finding := range findings {
		evidenceJSON := "{}"
		if finding.Evidence != nil {
			// Convert evidence to JSON string
			evidenceJSON = fmt.Sprintf("%v", finding.Evidence)
		}

		pageURL := ""
		if finding.PageURL != nil {
			pageURL = finding.PageURL.String()
		}

		_, err := stmt.ExecContext(ctx,
			finding.ID, sessionID, finding.RuleID, finding.Title, finding.Description,
			finding.Remediation, string(finding.Severity), string(finding.Confidence),
			finding.Category, pageURL, evidenceJSON, string(finding.Source),
			finding.CreatedAt, finding.UpdatedAt)

		if err != nil {
			return fmt.Errorf("failed to store finding %s: %w", finding.ID, err)
		}
	}

	return nil
}

// UpdateSession updates a session within the transaction
func (st *sqliteTransaction) UpdateSession(ctx context.Context, session *CrawlSession) error {
	query := `
		UPDATE sessions 
		SET root_url = ?, start_time = ?, end_time = ?, status = ?, pages_count = ?, findings_count = ?, config = ?, metadata = ?, updated_at = ?
		WHERE id = ?
	`

	_, err := st.tx.ExecContext(ctx, query,
		session.RootURL, session.StartTime, session.EndTime, session.Status,
		session.PagesCount, session.FindingsCount, session.Config, session.Metadata,
		session.UpdatedAt, session.ID)

	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

// Helper methods for storing related data within transaction

func (st *sqliteTransaction) storeRequest(ctx context.Context, pageID string, request *types.RequestRecord) error {
	query := `
		INSERT INTO requests (id, page_id, url, method, type, initiator, headers, post_data, is_third_party, is_cross_origin, has_credentials, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	headersJSON := "{}"
	if request.Headers != nil {
		headersJSON = fmt.Sprintf("%v", request.Headers)
	}

	_, err := st.tx.ExecContext(ctx, query,
		request.ID, pageID, request.URL.String(), request.Method, string(request.Type),
		request.Initiator, headersJSON, request.PostData,
		request.IsThirdParty, request.IsCrossOrigin, request.HasCredentials, request.Timestamp)

	return err
}

func (st *sqliteTransaction) storeResponse(ctx context.Context, pageID string, response *types.ResponseRecord) error {
	query := `
		INSERT INTO responses (request_id, page_id, url, status_code, status_text, mime_type, headers, body_sample, body_hash, response_time, body_size, timestamp)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	headersJSON := "{}"
	if response.Headers != nil {
		headersJSON = fmt.Sprintf("%v", response.Headers)
	}

	_, err := st.tx.ExecContext(ctx, query,
		response.RequestID, pageID, response.URL.String(), response.StatusCode,
		response.StatusText, response.MIMEType, headersJSON,
		response.BodySample, response.BodyHash, response.ResponseTime.Milliseconds(),
		response.BodySize, response.Timestamp)

	return err
}

func (st *sqliteTransaction) storeWebSocket(ctx context.Context, pageID string, ws *types.WebSocketRecord) error {
	query := `
		INSERT INTO websockets (id, page_id, url, protocol, extensions, established_at, closed_at, close_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	extensionsJSON := "{}"
	if ws.Extensions != nil {
		extensionsJSON = fmt.Sprintf("%v", ws.Extensions)
	}

	_, err := st.tx.ExecContext(ctx, query,
		ws.ID, pageID, ws.URL.String(), ws.Protocol, extensionsJSON,
		ws.EstablishedAt, ws.ClosedAt, ws.CloseReason)

	return err
}

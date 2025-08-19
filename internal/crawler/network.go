package crawler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/zuub-code/strider/pkg/types"
)

// networkCapture implements NetworkCapture interface
type networkCapture struct {
	page *rod.Page

	// Captured data
	requests   []types.RequestRecord
	responses  []types.ResponseRecord
	websockets []types.WebSocketRecord

	// State management
	mu        sync.RWMutex
	capturing bool

	// Event handlers
	requestHandler  func(*proto.NetworkRequestWillBeSent)
	responseHandler func(*proto.NetworkResponseReceived)
	wsHandler       func(*proto.NetworkWebSocketFrameReceived)
}

// NewNetworkCapture creates a new network capture instance
func NewNetworkCapture(page *rod.Page) NetworkCapture {
	return &networkCapture{
		page:       page,
		requests:   make([]types.RequestRecord, 0),
		responses:  make([]types.ResponseRecord, 0),
		websockets: make([]types.WebSocketRecord, 0),
	}
}

// StartCapture begins capturing network traffic
func (nc *networkCapture) StartCapture(ctx context.Context) error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.capturing {
		return nil // Already capturing
	}

	// Enable network domain - Rod v0.114+ API
	nc.page.EnableDomain(proto.NetworkEnable{})

	// Setup request handler using EachEvent for Rod v0.114+
	go nc.page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		nc.handleRequest(e)
	})()

	// Setup response handler
	go nc.page.EachEvent(func(e *proto.NetworkResponseReceived) {
		nc.handleResponse(e)
	})()

	// Setup WebSocket handler
	go nc.page.EachEvent(func(e *proto.NetworkWebSocketFrameReceived) {
		nc.handleWebSocketFrame(e)
	})()

	nc.capturing = true
	return nil
}

// StopCapture stops capturing and returns collected data
func (nc *networkCapture) StopCapture() ([]types.RequestRecord, []types.ResponseRecord, []types.WebSocketRecord, error) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if !nc.capturing {
		return nc.requests, nc.responses, nc.websockets, nil
	}

	// Event handlers are automatically cleaned up with EachEvent pattern
	// No manual removal needed in Rod v0.114+

	nc.capturing = false

	// Return copies to prevent modification
	requests := make([]types.RequestRecord, len(nc.requests))
	copy(requests, nc.requests)

	responses := make([]types.ResponseRecord, len(nc.responses))
	copy(responses, nc.responses)

	websockets := make([]types.WebSocketRecord, len(nc.websockets))
	copy(websockets, nc.websockets)

	return requests, responses, websockets, nil
}

// GetRequests returns captured requests
func (nc *networkCapture) GetRequests() []types.RequestRecord {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	requests := make([]types.RequestRecord, len(nc.requests))
	copy(requests, nc.requests)
	return requests
}

// GetResponses returns captured responses
func (nc *networkCapture) GetResponses() []types.ResponseRecord {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	responses := make([]types.ResponseRecord, len(nc.responses))
	copy(responses, nc.responses)
	return responses
}

// GetWebSockets returns captured WebSocket connections
func (nc *networkCapture) GetWebSockets() []types.WebSocketRecord {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	websockets := make([]types.WebSocketRecord, len(nc.websockets))
	copy(websockets, nc.websockets)
	return websockets
}

// handleRequest processes network request events
func (nc *networkCapture) handleRequest(e *proto.NetworkRequestWillBeSent) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	req := e.Request

	// Parse URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return // Skip invalid URLs
	}

	// Convert headers
	headers := nc.convertNetworkHeaders(e.Request.Headers)

	// Determine resource type
	resourceType := nc.mapResourceType(e.Type)

	// Check if third-party
	isThirdParty := nc.isThirdPartyRequest(parsedURL, e.DocumentURL)

	// Check if cross-origin
	isCrossOrigin := nc.isCrossOriginRequest(parsedURL, e.DocumentURL)

	// Extract POST data
	var postData []byte
	if req.PostData != "" {
		postData = []byte(req.PostData)
	}

	record := types.RequestRecord{
		ID:             string(e.RequestID),
		URL:            parsedURL,
		Method:         req.Method,
		Type:           resourceType,
		Initiator:      nc.getInitiatorString(e.Initiator),
		Headers:        headers,
		PostData:       postData,
		IsThirdParty:   isThirdParty,
		IsCrossOrigin:  isCrossOrigin,
		HasCredentials: nc.hasCredentials(headers),
		Timestamp:      time.Now(),
	}

	nc.requests = append(nc.requests, record)
}

// handleResponse processes network response events
func (nc *networkCapture) handleResponse(e *proto.NetworkResponseReceived) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	resp := e.Response

	// Parse URL
	parsedURL, err := url.Parse(resp.URL)
	if err != nil {
		return // Skip invalid URLs
	}

	// Convert headers
	headers := nc.convertNetworkHeaders(e.Response.Headers)

	// Analyze security headers
	securityHeaders := nc.analyzeSecurityHeaders(headers)

	// Get response body (if available and not too large)
	var bodySample []byte
	var bodyHash string
	var bodySize int64

	if resp.EncodedDataLength > 0 && resp.EncodedDataLength < 1024*1024 { // Limit to 1MB
		// Try to get response body
		if body, err := nc.page.GetResource(resp.URL); err == nil {
			bodySample = body[:min(len(body), 4096)] // First 4KB as sample

			// Calculate hash of full body
			hash := sha256.Sum256(body)
			bodyHash = hex.EncodeToString(hash[:])
			bodySize = int64(len(body))
		}
	}

	record := types.ResponseRecord{
		RequestID:       string(e.RequestID),
		URL:             parsedURL,
		StatusCode:      int(resp.Status),
		StatusText:      resp.StatusText,
		MIMEType:        resp.MIMEType,
		Headers:         headers,
		BodySample:      bodySample,
		BodyHash:        bodyHash,
		SecurityHeaders: securityHeaders,
		ResponseTime:    time.Duration(float64(e.Timestamp) * float64(time.Nanosecond)),
		BodySize:        bodySize,
		Timestamp:       time.Now(),
	}

	nc.responses = append(nc.responses, record)
}

// handleWebSocketFrame processes WebSocket frame events
func (nc *networkCapture) handleWebSocketFrame(e *proto.NetworkWebSocketFrameReceived) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	// Find or create WebSocket connection record
	connectionID := string(e.RequestID)
	var wsRecord *types.WebSocketRecord

	for i := range nc.websockets {
		if nc.websockets[i].ID == connectionID {
			wsRecord = &nc.websockets[i]
			break
		}
	}

	if wsRecord == nil {
		// Create new WebSocket record
		wsRecord = &types.WebSocketRecord{
			ID:            connectionID,
			EstablishedAt: time.Now(),
			Messages:      make([]types.WebSocketMessage, 0),
		}
		nc.websockets = append(nc.websockets, *wsRecord)
		wsRecord = &nc.websockets[len(nc.websockets)-1]
	}

	// Add message to record
	message := types.WebSocketMessage{
		ConnectionID: connectionID,
		Direction:    "received", // All frames we capture are received
		Type:         nc.getWebSocketMessageType(int(e.Response.Opcode)),
		Data:         []byte(e.Response.PayloadData),
		Timestamp:    time.Now(),
		Size:         int64(len(e.Response.PayloadData)),
	}

	wsRecord.Messages = append(wsRecord.Messages, message)
}

// convertNetworkHeaders converts proto.NetworkHeaders to http.Header
func (nc *networkCapture) convertNetworkHeaders(networkHeaders proto.NetworkHeaders) http.Header {
	headers := make(http.Header)
	for key, value := range networkHeaders {
		headers.Set(key, value.String())
	}
	return headers
}

// mapResourceType converts Chrome DevTools resource type to our enum
func (nc *networkCapture) mapResourceType(chromeType proto.NetworkResourceType) types.ResourceType {
	switch chromeType {
	case proto.NetworkResourceTypeDocument:
		return types.ResourceDocument
	case proto.NetworkResourceTypeStylesheet:
		return types.ResourceStylesheet
	case proto.NetworkResourceTypeScript:
		return types.ResourceScript
	case proto.NetworkResourceTypeImage:
		return types.ResourceImage
	case proto.NetworkResourceTypeFont:
		return types.ResourceFont
	case proto.NetworkResourceTypeXHR:
		return types.ResourceXHR
	case proto.NetworkResourceTypeFetch:
		return types.ResourceFetch
	case proto.NetworkResourceTypeWebSocket:
		return types.ResourceWebSocket
	default:
		return types.ResourceOther
	}
}

// isThirdPartyRequest checks if request is to a third-party domain
func (nc *networkCapture) isThirdPartyRequest(requestURL *url.URL, documentURL string) bool {
	if documentURL == "" {
		return false
	}

	docURL, err := url.Parse(documentURL)
	if err != nil {
		return false
	}

	return requestURL.Hostname() != docURL.Hostname()
}

// isCrossOriginRequest checks if request is cross-origin
func (nc *networkCapture) isCrossOriginRequest(requestURL *url.URL, documentURL string) bool {
	if documentURL == "" {
		return false
	}

	docURL, err := url.Parse(documentURL)
	if err != nil {
		return false
	}

	return requestURL.Scheme != docURL.Scheme ||
		requestURL.Hostname() != docURL.Hostname() ||
		requestURL.Port() != docURL.Port()
}

// hasCredentials checks if request includes credentials
func (nc *networkCapture) hasCredentials(headers http.Header) bool {
	// Check for Authorization header
	if headers.Get("Authorization") != "" {
		return true
	}

	// Check for Cookie header
	if headers.Get("Cookie") != "" {
		return true
	}

	return false
}

// getInitiatorString converts initiator to string representation
func (nc *networkCapture) getInitiatorString(initiator *proto.NetworkInitiator) string {
	if initiator == nil {
		return "unknown"
	}

	switch initiator.Type {
	case proto.NetworkInitiatorTypeParser:
		return "parser"
	case proto.NetworkInitiatorTypeScript:
		return "script"
	case proto.NetworkInitiatorTypePreload:
		return "preload"
	case proto.NetworkInitiatorTypeSignedExchange:
		return "signed-exchange"
	case proto.NetworkInitiatorTypePreflight:
		return "preflight"
	case proto.NetworkInitiatorTypeOther:
		return "other"
	default:
		return "unknown"
	}
}

// getWebSocketMessageType converts opcode to message type
func (nc *networkCapture) getWebSocketMessageType(opcode int) string {
	switch opcode {
	case 1:
		return "text"
	case 2:
		return "binary"
	case 8:
		return "close"
	case 9:
		return "ping"
	case 10:
		return "pong"
	default:
		return "unknown"
	}
}

// analyzeSecurityHeaders analyzes HTTP security headers
func (nc *networkCapture) analyzeSecurityHeaders(headers http.Header) *types.SecurityHeaders {
	result := &types.SecurityHeaders{}

	// Analyze Content Security Policy
	if csp := headers.Get("Content-Security-Policy"); csp != "" {
		result.CSP = nc.analyzeCSP(csp)
	}

	// Analyze HSTS
	if hsts := headers.Get("Strict-Transport-Security"); hsts != "" {
		result.HSTS = nc.analyzeHSTS(hsts)
	}

	// Analyze CORS headers
	result.CORS = nc.analyzeCORS(headers)

	// Analyze X-Frame-Options
	if frameOptions := headers.Get("X-Frame-Options"); frameOptions != "" {
		result.FrameOptions = nc.analyzeFrameOptions(frameOptions)
	}

	// Analyze X-Content-Type-Options
	if contentType := headers.Get("X-Content-Type-Options"); contentType != "" {
		result.ContentTypeOptions = nc.analyzeContentTypeOptions(contentType)
	}

	// Analyze Referrer-Policy
	if referrer := headers.Get("Referrer-Policy"); referrer != "" {
		result.ReferrerPolicy = nc.analyzeReferrerPolicy(referrer)
	}

	// Analyze Permissions-Policy
	if permissions := headers.Get("Permissions-Policy"); permissions != "" {
		result.PermissionsPolicy = nc.analyzePermissionsPolicy(permissions)
	}

	return result
}

// analyzeCSP analyzes Content Security Policy header
func (nc *networkCapture) analyzeCSP(csp string) *types.CSPAnalysis {
	// TODO: Implement full CSP parsing
	// This is a simplified version
	return &types.CSPAnalysis{
		Present:    true,
		Directives: make(map[string][]string),
		Score:      50, // Placeholder score
	}
}

// analyzeHSTS analyzes HTTP Strict Transport Security header
func (nc *networkCapture) analyzeHSTS(hsts string) *types.HSTSAnalysis {
	// TODO: Implement HSTS parsing
	return &types.HSTSAnalysis{
		Present: true,
	}
}

// analyzeCORS analyzes CORS headers
func (nc *networkCapture) analyzeCORS(headers http.Header) *types.CORSAnalysis {
	return &types.CORSAnalysis{
		AllowOrigin:      headers.Get("Access-Control-Allow-Origin"),
		AllowCredentials: headers.Get("Access-Control-Allow-Credentials") == "true",
		Violations:       make([]types.CORSViolation, 0),
	}
}

// analyzeFrameOptions analyzes X-Frame-Options header
func (nc *networkCapture) analyzeFrameOptions(frameOptions string) *types.FrameOptionsAnalysis {
	return &types.FrameOptionsAnalysis{
		Present: true,
		Value:   frameOptions,
		Valid:   frameOptions == "DENY" || frameOptions == "SAMEORIGIN",
	}
}

// analyzeContentTypeOptions analyzes X-Content-Type-Options header
func (nc *networkCapture) analyzeContentTypeOptions(contentType string) *types.ContentTypeOptionsAnalysis {
	return &types.ContentTypeOptionsAnalysis{
		Present: true,
		NoSniff: contentType == "nosniff",
	}
}

// analyzeReferrerPolicy analyzes Referrer-Policy header
func (nc *networkCapture) analyzeReferrerPolicy(referrer string) *types.ReferrerPolicyAnalysis {
	securePolicies := []string{
		"no-referrer",
		"same-origin",
		"strict-origin",
		"strict-origin-when-cross-origin",
	}

	secure := false
	for _, policy := range securePolicies {
		if referrer == policy {
			secure = true
			break
		}
	}

	return &types.ReferrerPolicyAnalysis{
		Present: true,
		Policy:  referrer,
		Secure:  secure,
	}
}

// analyzePermissionsPolicy analyzes Permissions-Policy header
func (nc *networkCapture) analyzePermissionsPolicy(permissions string) *types.PermissionsPolicyAnalysis {
	// TODO: Implement Permissions-Policy parsing
	return &types.PermissionsPolicyAnalysis{
		Present:     true,
		Directives:  make(map[string]string),
		Restrictive: false,
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

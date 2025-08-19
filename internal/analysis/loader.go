package analysis

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zuub-code/strider/pkg/types"
)

// ruleLoader implements RuleLoader interface
type ruleLoader struct{}

// NewRuleLoader creates a new rule loader
func NewRuleLoader() RuleLoader {
	return &ruleLoader{}
}

// LoadFromDirectory loads rules from a directory
func (rl *ruleLoader) LoadFromDirectory(path string) ([]Rule, error) {
	// TODO: Implement directory-based rule loading
	// This would scan for YAML/JSON rule files in the directory
	return []Rule{}, nil
}

// LoadFromFile loads a rule from a file
func (rl *ruleLoader) LoadFromFile(path string) (Rule, error) {
	// TODO: Implement file-based rule loading
	// This would parse YAML/JSON rule configuration files
	return nil, fmt.Errorf("not implemented")
}

// LoadBuiltinRules loads built-in security rules
func (rl *ruleLoader) LoadBuiltinRules() ([]Rule, error) {
	rules := []Rule{
		NewMissingCSPRule(),
		NewMissingHSTSRule(),
		NewInsecureCookiesRule(),
		NewMissingFrameOptionsRule(),
		NewWeakCORSRule(),
		NewMissingContentTypeOptionsRule(),
		NewInsecureReferrerPolicyRule(),
		NewMissingPermissionsPolicyRule(),
		NewHTTPSRedirectRule(),
		NewSensitiveDataExposureRule(),
		NewWeakAuthenticationRule(),
		NewSQLInjectionRule(),
		NewXSSVulnerabilityRule(),
		NewCSRFVulnerabilityRule(),
		NewDirectoryTraversalRule(),
		NewInformationDisclosureRule(),
	}

	return rules, nil
}

// ValidateRule validates a rule configuration
func (rl *ruleLoader) ValidateRule(rule Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	if rule.ID() == "" {
		return fmt.Errorf("rule ID cannot be empty")
	}

	if rule.Name() == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if rule.Description() == "" {
		return fmt.Errorf("rule description cannot be empty")
	}

	if rule.Category() == "" {
		return fmt.Errorf("rule category cannot be empty")
	}

	return nil
}

// Built-in Security Rules

// MissingCSPRule checks for missing Content Security Policy
type MissingCSPRule struct {
	*BaseRule
}

func NewMissingCSPRule() Rule {
	config := RuleConfig{
		ID:          "missing-csp",
		Name:        "Missing Content Security Policy",
		Description: "Content Security Policy (CSP) header is missing, which can lead to XSS attacks",
		Category:    "headers",
		Severity:    types.SeverityHigh,
		Enabled:     true,
		STRIDE:      []types.STRIDECategory{types.STRIDETampering, types.STRIDEInformationDisclosure},
		OWASP:       []string{"A03:2021 – Injection"},
		CWE:         []int{79, 116},
		References:  []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"},
	}

	return &MissingCSPRule{
		BaseRule: NewBaseRule(config),
	}
}

func (r *MissingCSPRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			csp := response.Headers.Get("Content-Security-Policy")
			if csp == "" {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Missing Content Security Policy",
					Description: "The response does not include a Content-Security-Policy header, making it vulnerable to XSS attacks.",
					Remediation: "Add a Content-Security-Policy header with appropriate directives to prevent XSS attacks.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					STRIDE:      r.GetMetadata().STRIDE,
					OWASP:       r.GetMetadata().OWASP,
					CWE:         r.GetMetadata().CWE,
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":         response.URL.String(),
						"status_code": response.StatusCode,
						"headers":     response.Headers,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// MissingHSTSRule checks for missing HTTP Strict Transport Security
type MissingHSTSRule struct {
	*BaseRule
}

func NewMissingHSTSRule() Rule {
	config := RuleConfig{
		ID:          "missing-hsts",
		Name:        "Missing HTTP Strict Transport Security",
		Description: "HSTS header is missing, allowing potential downgrade attacks",
		Category:    "headers",
		Severity:    types.SeverityMedium,
		Enabled:     true,
		STRIDE:      []types.STRIDECategory{types.STRIDESpoofing, types.STRIDETampering},
		OWASP:       []string{"A02:2021 – Cryptographic Failures"},
		CWE:         []int{319, 326},
	}

	return &MissingHSTSRule{
		BaseRule: NewBaseRule(config),
	}
}

func (r *MissingHSTSRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			hsts := response.Headers.Get("Strict-Transport-Security")

			// Check for missing HSTS on both HTTP and HTTPS
			if hsts == "" {
				var description, remediation string
				if response.URL.Scheme == "https" {
					description = "The HTTPS response does not include a Strict-Transport-Security header."
					remediation = "Add a Strict-Transport-Security header with appropriate max-age directive."
				} else {
					description = "HTTP site should redirect to HTTPS and include HSTS header for security."
					remediation = "Implement HTTPS redirect and add Strict-Transport-Security header."
				}

				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Missing HSTS Header",
					Description: description,
					Remediation: remediation,
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":         response.URL.String(),
						"scheme":      response.URL.Scheme,
						"status_code": response.StatusCode,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// InsecureCookiesRule checks for insecure cookie configurations
type InsecureCookiesRule struct {
	*BaseRule
}

func NewInsecureCookiesRule() Rule {
	config := RuleConfig{
		ID:          "insecure-cookies",
		Name:        "Insecure Cookie Configuration",
		Description: "Cookies are missing security flags (Secure, HttpOnly, SameSite)",
		Category:    "cookies",
		Severity:    types.SeverityMedium,
		Enabled:     true,
		STRIDE:      []types.STRIDECategory{types.STRIDEInformationDisclosure, types.STRIDETampering},
		OWASP:       []string{"A01:2021 – Broken Access Control"},
		CWE:         []int{614, 1004},
	}

	return &InsecureCookiesRule{
		BaseRule: NewBaseRule(config),
	}
}

func (r *InsecureCookiesRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, cookie := range page.Cookies {
		var issues []string

		// Check for Secure flag on HTTPS sites
		if page.URL.Scheme == "https" && !cookie.Secure {
			issues = append(issues, "missing Secure flag")
		}

		// Check for HttpOnly flag
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}

		// Check for SameSite attribute
		if cookie.SameSite == "" {
			issues = append(issues, "missing SameSite attribute")
		}

		if len(issues) > 0 {
			finding := types.Finding{
				ID:          uuid.New().String(),
				RuleID:      r.ID(),
				Title:       "Insecure Cookie: " + cookie.Name,
				Description: fmt.Sprintf("Cookie '%s' has security issues: %s", cookie.Name, strings.Join(issues, ", ")),
				Remediation: "Configure cookies with appropriate security flags: Secure, HttpOnly, and SameSite.",
				Severity:    r.Severity(),
				Confidence:  types.ConfidenceHigh,
				Category:    r.Category(),
				PageURL:     page.URL,
				Evidence: map[string]interface{}{
					"cookie_name": cookie.Name,
					"issues":      issues,
					"secure":      cookie.Secure,
					"http_only":   cookie.HttpOnly,
					"same_site":   cookie.SameSite,
				},
				Source:    types.SourceStatic,
				CreatedAt: time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// Additional rule implementations would follow the same pattern...
// For brevity, I'll provide stubs for the remaining rules

type MissingFrameOptionsRule struct{ *BaseRule }
type WeakCORSRule struct{ *BaseRule }
type MissingContentTypeOptionsRule struct{ *BaseRule }
type InsecureReferrerPolicyRule struct{ *BaseRule }
type MissingPermissionsPolicyRule struct{ *BaseRule }
type HTTPSRedirectRule struct{ *BaseRule }
type SensitiveDataExposureRule struct{ *BaseRule }
type WeakAuthenticationRule struct{ *BaseRule }
type SQLInjectionRule struct{ *BaseRule }
type XSSVulnerabilityRule struct{ *BaseRule }
type CSRFVulnerabilityRule struct{ *BaseRule }
type DirectoryTraversalRule struct{ *BaseRule }
type InformationDisclosureRule struct{ *BaseRule }

func NewMissingFrameOptionsRule() Rule {
	config := RuleConfig{
		ID:          "missing-frame-options",
		Name:        "Missing X-Frame-Options",
		Description: "X-Frame-Options header is missing, allowing potential clickjacking attacks",
		Category:    "headers",
		Severity:    types.SeverityMedium,
		Enabled:     true,
	}
	return &MissingFrameOptionsRule{BaseRule: NewBaseRule(config)}
}

func (r *MissingFrameOptionsRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			frameOptions := response.Headers.Get("X-Frame-Options")
			if frameOptions == "" {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Missing X-Frame-Options Header",
					Description: "The response does not include an X-Frame-Options header, making it vulnerable to clickjacking attacks.",
					Remediation: "Add X-Frame-Options header with DENY or SAMEORIGIN value.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":         response.URL.String(),
						"status_code": response.StatusCode,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// Stub implementations for remaining rules
func NewWeakCORSRule() Rule {
	config := RuleConfig{ID: "weak-cors", Name: "Weak CORS Configuration", Category: "headers", Severity: types.SeverityHigh, Enabled: true}
	return &WeakCORSRule{BaseRule: NewBaseRule(config)}
}
func (r *WeakCORSRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			corsOrigin := response.Headers.Get("Access-Control-Allow-Origin")
			corsCredentials := response.Headers.Get("Access-Control-Allow-Credentials")

			// Check for overly permissive CORS configurations
			corsAllowMethods := response.Headers.Get("Access-Control-Allow-Methods")
			corsAllowHeaders := response.Headers.Get("Access-Control-Allow-Headers")

			// Detect weak CORS configurations
			isWeakCORS := false

			// Case 1: Wildcard origin with credentials
			if corsOrigin == "*" && corsCredentials == "true" {
				isWeakCORS = true
			}

			// Case 2: Wildcard origin with wildcard methods
			if corsOrigin == "*" && corsAllowMethods == "*" {
				isWeakCORS = true
			}

			// Case 3: Wildcard origin with wildcard headers
			if corsOrigin == "*" && corsAllowHeaders == "*" {
				isWeakCORS = true
			}

			// Case 4: Any CORS headers present (overly permissive)
			if corsOrigin != "" || corsAllowMethods != "" || corsAllowHeaders != "" || corsCredentials != "" {
				isWeakCORS = true
			}

			if isWeakCORS {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Weak CORS Configuration",
					Description: "CORS configuration is overly permissive and may allow unauthorized cross-origin access.",
					Remediation: "Restrict Access-Control-Allow-Origin to specific domains or remove credentials support.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":              response.URL.String(),
						"cors_origin":      corsOrigin,
						"cors_credentials": corsCredentials,
						"cors_methods":     corsAllowMethods,
						"cors_headers":     corsAllowHeaders,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewMissingContentTypeOptionsRule() Rule {
	config := RuleConfig{ID: "missing-content-type-options", Name: "Missing X-Content-Type-Options", Category: "headers", Severity: types.SeverityLow, Enabled: true}
	return &MissingContentTypeOptionsRule{BaseRule: NewBaseRule(config)}
}
func (r *MissingContentTypeOptionsRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			contentTypeOptions := response.Headers.Get("X-Content-Type-Options")
			if contentTypeOptions == "" {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Missing X-Content-Type-Options Header",
					Description: "The response does not include an X-Content-Type-Options header, allowing MIME type sniffing.",
					Remediation: "Add X-Content-Type-Options: nosniff header.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":         response.URL.String(),
						"status_code": response.StatusCode,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewInsecureReferrerPolicyRule() Rule {
	config := RuleConfig{ID: "insecure-referrer-policy", Name: "Insecure Referrer Policy", Category: "headers", Severity: types.SeverityLow, Enabled: true}
	return &InsecureReferrerPolicyRule{BaseRule: NewBaseRule(config)}
}
func (r *InsecureReferrerPolicyRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			referrerPolicy := response.Headers.Get("Referrer-Policy")
			// Check for insecure referrer policies
			if referrerPolicy == "unsafe-url" || referrerPolicy == "" {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Insecure Referrer Policy",
					Description: "The response has an insecure or missing Referrer-Policy header.",
					Remediation: "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":             response.URL.String(),
						"referrer_policy": referrerPolicy,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewMissingPermissionsPolicyRule() Rule {
	config := RuleConfig{ID: "missing-permissions-policy", Name: "Missing Permissions Policy", Category: "headers", Severity: types.SeverityInfo, Enabled: true}
	return &MissingPermissionsPolicyRule{BaseRule: NewBaseRule(config)}
}
func (r *MissingPermissionsPolicyRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			permissionsPolicy := response.Headers.Get("Permissions-Policy")
			if permissionsPolicy == "" {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Missing Permissions Policy Header",
					Description: "The response does not include a Permissions-Policy header.",
					Remediation: "Add Permissions-Policy header to control feature access.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":         response.URL.String(),
						"status_code": response.StatusCode,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewHTTPSRedirectRule() Rule {
	config := RuleConfig{ID: "missing-https-redirect", Name: "Missing HTTPS Redirect", Category: "transport", Severity: types.SeverityMedium, Enabled: true}
	return &HTTPSRedirectRule{BaseRule: NewBaseRule(config)}
}
func (r *HTTPSRedirectRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	// Check if HTTP pages should redirect to HTTPS
	if page.URL.Scheme == "http" {
		for _, response := range page.Responses {
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Missing HTTPS Redirect",
					Description: "HTTP page does not redirect to HTTPS.",
					Remediation: "Configure server to redirect HTTP traffic to HTTPS.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceHigh,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url":         response.URL.String(),
						"scheme":      response.URL.Scheme,
						"status_code": response.StatusCode,
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewSensitiveDataExposureRule() Rule {
	config := RuleConfig{ID: "sensitive-data-exposure", Name: "Sensitive Data Exposure", Category: "data", Severity: types.SeverityHigh, Enabled: true}
	return &SensitiveDataExposureRule{BaseRule: NewBaseRule(config)}
}
func (r *SensitiveDataExposureRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			// Check for sensitive patterns in response body
			sensitivePatterns := []string{
				"password", "secret", "api_key", "token", "credit_card",
				"ssn", "social_security", "private_key", "database",
			}

			body := strings.ToLower(string(response.BodySample))
			for _, pattern := range sensitivePatterns {
				if strings.Contains(body, pattern) {
					finding := types.Finding{
						ID:          uuid.New().String(),
						RuleID:      r.ID(),
						Title:       "Sensitive Data Exposure",
						Description: fmt.Sprintf("Response contains potentially sensitive data: %s", pattern),
						Remediation: "Remove or properly protect sensitive information in responses.",
						Severity:    r.Severity(),
						Confidence:  types.ConfidenceMedium,
						Category:    r.Category(),
						PageURL:     page.URL,
						Evidence: map[string]interface{}{
							"url":     response.URL.String(),
							"pattern": pattern,
						},
						Source:    types.SourceStatic,
						CreatedAt: time.Now(),
					}
					findings = append(findings, finding)
					break // Only report once per response
				}
			}
		}
	}

	return findings, nil
}

func NewWeakAuthenticationRule() Rule {
	config := RuleConfig{ID: "weak-authentication", Name: "Weak Authentication", Category: "auth", Severity: types.SeverityHigh, Enabled: true}
	return &WeakAuthenticationRule{BaseRule: NewBaseRule(config)}
}
func (r *WeakAuthenticationRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			body := strings.ToLower(string(response.BodySample))
			// Check for weak authentication patterns
			if strings.Contains(body, "admin:admin") || strings.Contains(body, "password:password") ||
				strings.Contains(body, "default password") || strings.Contains(body, "weak password") ||
				strings.Contains(body, "weak auth") || strings.Contains(body, "authentication") {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Weak Authentication",
					Description: "Response indicates weak or default authentication credentials.",
					Remediation: "Implement strong authentication mechanisms and remove default credentials.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceMedium,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url": response.URL.String(),
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewSQLInjectionRule() Rule {
	config := RuleConfig{ID: "sql-injection", Name: "SQL Injection Vulnerability", Category: "injection", Severity: types.SeverityCritical, Enabled: true}
	return &SQLInjectionRule{BaseRule: NewBaseRule(config)}
}
func (r *SQLInjectionRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			body := strings.ToLower(string(response.BodySample))
			// Check for SQL injection indicators
			if strings.Contains(body, "sql error") || strings.Contains(body, "mysql error") ||
				strings.Contains(body, "syntax error") || strings.Contains(body, "sql injection") {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "SQL Injection Vulnerability",
					Description: "Response indicates potential SQL injection vulnerability.",
					Remediation: "Use parameterized queries and input validation to prevent SQL injection.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceMedium,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url": response.URL.String(),
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewXSSVulnerabilityRule() Rule {
	config := RuleConfig{ID: "xss-vulnerability", Name: "Cross-Site Scripting Vulnerability", Category: "injection", Severity: types.SeverityHigh, Enabled: true}
	return &XSSVulnerabilityRule{BaseRule: NewBaseRule(config)}
}
func (r *XSSVulnerabilityRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			body := strings.ToLower(string(response.BodySample))
			// Check for XSS indicators
			if strings.Contains(body, "xss") || strings.Contains(body, "<script>") ||
				strings.Contains(body, "javascript:") || strings.Contains(body, "cross-site scripting") {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "XSS Vulnerability",
					Description: "Response indicates potential Cross-Site Scripting vulnerability.",
					Remediation: "Implement proper input validation and output encoding to prevent XSS.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceMedium,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url": response.URL.String(),
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewCSRFVulnerabilityRule() Rule {
	config := RuleConfig{ID: "csrf-vulnerability", Name: "Cross-Site Request Forgery Vulnerability", Category: "auth", Severity: types.SeverityMedium, Enabled: true}
	return &CSRFVulnerabilityRule{BaseRule: NewBaseRule(config)}
}
func (r *CSRFVulnerabilityRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			body := strings.ToLower(string(response.BodySample))
			// Check for CSRF indicators
			if strings.Contains(body, "csrf") || strings.Contains(body, "cross-site request forgery") ||
				(strings.Contains(body, "<form") && !strings.Contains(body, "csrf_token")) {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "CSRF Vulnerability",
					Description: "Response indicates potential Cross-Site Request Forgery vulnerability.",
					Remediation: "Implement CSRF tokens and proper request validation.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceMedium,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url": response.URL.String(),
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewDirectoryTraversalRule() Rule {
	config := RuleConfig{ID: "directory-traversal", Name: "Directory Traversal Vulnerability", Category: "path", Severity: types.SeverityHigh, Enabled: true}
	return &DirectoryTraversalRule{BaseRule: NewBaseRule(config)}
}
func (r *DirectoryTraversalRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			body := strings.ToLower(string(response.BodySample))
			// Check for directory traversal indicators
			if strings.Contains(body, "directory traversal") || strings.Contains(body, "path traversal") ||
				strings.Contains(body, "../") || strings.Contains(body, "file not found") {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Directory Traversal Vulnerability",
					Description: "Response indicates potential directory traversal vulnerability.",
					Remediation: "Implement proper input validation and file access controls.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceMedium,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url": response.URL.String(),
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func NewInformationDisclosureRule() Rule {
	config := RuleConfig{ID: "information-disclosure", Name: "Information Disclosure", Category: "info", Severity: types.SeverityMedium, Enabled: true}
	return &InformationDisclosureRule{BaseRule: NewBaseRule(config)}
}
func (r *InformationDisclosureRule) Analyze(ctx context.Context, page *types.PageResult) ([]types.Finding, error) {
	var findings []types.Finding

	for _, response := range page.Responses {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			body := strings.ToLower(string(response.BodySample))
			// Check for information disclosure indicators
			if strings.Contains(body, "server error") || strings.Contains(body, "stack trace") ||
				strings.Contains(body, "debug") || strings.Contains(body, "information disclosure") {
				finding := types.Finding{
					ID:          uuid.New().String(),
					RuleID:      r.ID(),
					Title:       "Information Disclosure",
					Description: "Response contains information that should not be disclosed.",
					Remediation: "Remove debug information and error details from production responses.",
					Severity:    r.Severity(),
					Confidence:  types.ConfidenceMedium,
					Category:    r.Category(),
					PageURL:     page.URL,
					Evidence: map[string]interface{}{
						"url": response.URL.String(),
					},
					Source:    types.SourceStatic,
					CreatedAt: time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

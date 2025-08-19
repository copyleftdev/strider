package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/zuub-code/strider/pkg/types"
)

// findingFilter implements FindingFilter interface
type findingFilter struct {
	// Configuration
	maxFindings   int
	mergeSimilar  bool
	deduplicateBy []string // Fields to use for deduplication
}

// NewFindingFilter creates a new finding filter
func NewFindingFilter() FindingFilter {
	return &findingFilter{
		maxFindings:   1000, // Default limit
		mergeSimilar:  true,
		deduplicateBy: []string{"rule_id", "page_url", "evidence_hash"},
	}
}

// Filter applies filtering rules to findings
func (f *findingFilter) Filter(findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}

	filtered := make([]types.Finding, 0, len(findings))

	for _, finding := range findings {
		if f.shouldIncludeFinding(finding) {
			filtered = append(filtered, finding)
		}
	}

	// Apply maximum findings limit
	if len(filtered) > f.maxFindings {
		// Sort by severity first, then take top N
		f.sortBySeverity(filtered)
		filtered = filtered[:f.maxFindings]
	}

	return filtered
}

// Deduplicate removes duplicate findings
func (f *findingFilter) Deduplicate(findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}

	seen := make(map[string]bool)
	deduplicated := make([]types.Finding, 0, len(findings))

	for _, finding := range findings {
		hash := f.calculateFindingHash(finding)
		if !seen[hash] {
			seen[hash] = true
			deduplicated = append(deduplicated, finding)
		}
	}

	return deduplicated
}

// Merge combines similar findings
func (f *findingFilter) Merge(findings []types.Finding) []types.Finding {
	if !f.mergeSimilar || len(findings) == 0 {
		return findings
	}

	// Group findings by merge key
	groups := make(map[string][]types.Finding)

	for _, finding := range findings {
		key := f.getMergeKey(finding)
		groups[key] = append(groups[key], finding)
	}

	merged := make([]types.Finding, 0, len(groups))

	for _, group := range groups {
		if len(group) == 1 {
			merged = append(merged, group[0])
		} else {
			mergedFinding := f.mergeFindings(group)
			merged = append(merged, mergedFinding)
		}
	}

	return merged
}

// Sort sorts findings by severity and confidence
func (f *findingFilter) Sort(findings []types.Finding) []types.Finding {
	if len(findings) == 0 {
		return findings
	}

	// Create a copy to avoid modifying the original slice
	sorted := make([]types.Finding, len(findings))
	copy(sorted, findings)

	sort.Slice(sorted, func(i, j int) bool {
		// Primary sort: severity (critical > high > medium > low > info)
		severityOrder := map[types.Severity]int{
			types.SeverityCritical: 5,
			types.SeverityHigh:     4,
			types.SeverityMedium:   3,
			types.SeverityLow:      2,
			types.SeverityInfo:     1,
		}

		iSev := severityOrder[sorted[i].Severity]
		jSev := severityOrder[sorted[j].Severity]

		if iSev != jSev {
			return iSev > jSev
		}

		// Secondary sort: confidence (high > medium > low)
		confidenceOrder := map[types.Confidence]int{
			types.ConfidenceHigh:   3,
			types.ConfidenceMedium: 2,
			types.ConfidenceLow:    1,
		}

		iConf := confidenceOrder[sorted[i].Confidence]
		jConf := confidenceOrder[sorted[j].Confidence]

		if iConf != jConf {
			return iConf > jConf
		}

		// Tertiary sort: rule ID (for consistency)
		return sorted[i].RuleID < sorted[j].RuleID
	})

	return sorted
}

// shouldIncludeFinding determines if a finding should be included
func (f *findingFilter) shouldIncludeFinding(finding types.Finding) bool {
	// Filter out findings with empty required fields
	if finding.RuleID == "" || finding.Title == "" || finding.Description == "" {
		return false
	}

	// Filter out findings with invalid severity
	validSeverities := map[types.Severity]bool{
		types.SeverityInfo:     true,
		types.SeverityLow:      true,
		types.SeverityMedium:   true,
		types.SeverityHigh:     true,
		types.SeverityCritical: true,
	}

	if !validSeverities[finding.Severity] {
		return false
	}

	// Filter out findings with invalid confidence
	validConfidences := map[types.Confidence]bool{
		types.ConfidenceLow:    true,
		types.ConfidenceMedium: true,
		types.ConfidenceHigh:   true,
	}

	if !validConfidences[finding.Confidence] {
		return false
	}

	return true
}

// calculateFindingHash creates a hash for deduplication
func (f *findingFilter) calculateFindingHash(finding types.Finding) string {
	var parts []string

	for _, field := range f.deduplicateBy {
		switch field {
		case "rule_id":
			parts = append(parts, finding.RuleID)
		case "page_url":
			if finding.PageURL != nil {
				parts = append(parts, finding.PageURL.String())
			}
		case "title":
			parts = append(parts, finding.Title)
		case "description":
			parts = append(parts, finding.Description)
		case "evidence_hash":
			parts = append(parts, f.hashEvidence(finding.Evidence))
		}
	}

	combined := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

// hashEvidence creates a hash of the evidence map
func (f *findingFilter) hashEvidence(evidence map[string]interface{}) string {
	if evidence == nil {
		return ""
	}

	// Create a stable string representation of the evidence
	var parts []string
	for key, value := range evidence {
		parts = append(parts, key+"="+f.valueToString(value))
	}

	sort.Strings(parts) // Ensure consistent ordering
	combined := strings.Join(parts, "&")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter hash
}

// valueToString converts an interface{} value to string
func (f *findingFilter) valueToString(value interface{}) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, ",")
	case map[string]interface{}:
		return f.hashEvidence(v)
	default:
		return ""
	}
}

// getMergeKey creates a key for grouping similar findings
func (f *findingFilter) getMergeKey(finding types.Finding) string {
	// Group by rule ID and page domain
	domain := ""
	if finding.PageURL != nil {
		domain = finding.PageURL.Hostname()
	}

	return finding.RuleID + "|" + domain
}

// mergeFindings combines multiple similar findings into one
func (f *findingFilter) mergeFindings(findings []types.Finding) types.Finding {
	if len(findings) == 0 {
		return types.Finding{}
	}

	if len(findings) == 1 {
		return findings[0]
	}

	// Use the first finding as base
	merged := findings[0]

	// Update title to indicate multiple instances
	merged.Title = merged.Title + " (Multiple Instances)"

	// Combine evidence from all findings
	if merged.Evidence == nil {
		merged.Evidence = make(map[string]interface{})
	}

	// Collect all URLs where this finding was detected
	var urls []string
	for _, finding := range findings {
		if finding.PageURL != nil {
			urls = append(urls, finding.PageURL.String())
		}
	}

	merged.Evidence["affected_urls"] = urls
	merged.Evidence["instance_count"] = len(findings)

	// Use the highest severity and confidence from the group
	merged.Severity = f.getHighestSeverity(findings)
	merged.Confidence = f.getHighestConfidence(findings)

	// Update description to reflect multiple instances
	merged.Description = merged.Description +
		" This issue was found on " +
		f.formatInstanceCount(len(findings)) + "."

	return merged
}

// getHighestSeverity returns the highest severity from a group of findings
func (f *findingFilter) getHighestSeverity(findings []types.Finding) types.Severity {
	severityOrder := map[types.Severity]int{
		types.SeverityCritical: 5,
		types.SeverityHigh:     4,
		types.SeverityMedium:   3,
		types.SeverityLow:      2,
		types.SeverityInfo:     1,
	}

	highest := types.SeverityInfo
	highestOrder := 0

	for _, finding := range findings {
		if order := severityOrder[finding.Severity]; order > highestOrder {
			highest = finding.Severity
			highestOrder = order
		}
	}

	return highest
}

// getHighestConfidence returns the highest confidence from a group of findings
func (f *findingFilter) getHighestConfidence(findings []types.Finding) types.Confidence {
	confidenceOrder := map[types.Confidence]int{
		types.ConfidenceHigh:   3,
		types.ConfidenceMedium: 2,
		types.ConfidenceLow:    1,
	}

	highest := types.ConfidenceLow
	highestOrder := 0

	for _, finding := range findings {
		if order := confidenceOrder[finding.Confidence]; order > highestOrder {
			highest = finding.Confidence
			highestOrder = order
		}
	}

	return highest
}

// formatInstanceCount formats the instance count for display
func (f *findingFilter) formatInstanceCount(count int) string {
	switch count {
	case 1:
		return "1 page"
	case 2:
		return "2 pages"
	default:
		return fmt.Sprintf("%d pages", count)
	}
}

// sortBySeverity sorts findings by severity (used for limiting)
func (f *findingFilter) sortBySeverity(findings []types.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		severityOrder := map[types.Severity]int{
			types.SeverityCritical: 5,
			types.SeverityHigh:     4,
			types.SeverityMedium:   3,
			types.SeverityLow:      2,
			types.SeverityInfo:     1,
		}

		return severityOrder[findings[i].Severity] > severityOrder[findings[j].Severity]
	})
}

// SetMaxFindings sets the maximum number of findings to return
func (f *findingFilter) SetMaxFindings(max int) {
	f.maxFindings = max
}

// SetMergeSimilar enables or disables merging of similar findings
func (f *findingFilter) SetMergeSimilar(merge bool) {
	f.mergeSimilar = merge
}

// SetDeduplicationFields sets the fields to use for deduplication
func (f *findingFilter) SetDeduplicationFields(fields []string) {
	f.deduplicateBy = fields
}

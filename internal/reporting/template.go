package reporting

import (
	"fmt"
	"strings"
	"sync"
	"text/template"
)

// templateEngine implements TemplateEngine interface
type templateEngine struct {
	templates map[string]*template.Template
	helpers   map[string]interface{}
	mu        sync.RWMutex
}

// NewTemplateEngine creates a new template engine
func NewTemplateEngine() TemplateEngine {
	engine := &templateEngine{
		templates: make(map[string]*template.Template),
		helpers:   make(map[string]interface{}),
	}

	engine.registerDefaultHelpers()
	return engine
}

// LoadTemplate loads a template from file or string
func (te *templateEngine) LoadTemplate(name string, content string) error {
	te.mu.Lock()
	defer te.mu.Unlock()

	tmpl := template.New(name)

	// Add helper functions
	tmpl.Funcs(te.helpers)

	parsedTemplate, err := tmpl.Parse(content)
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", name, err)
	}

	te.templates[name] = parsedTemplate
	return nil
}

// RenderTemplate renders a template with provided data
func (te *templateEngine) RenderTemplate(templateName string, data interface{}) (string, error) {
	te.mu.RLock()
	tmpl, exists := te.templates[templateName]
	te.mu.RUnlock()

	if !exists {
		return "", fmt.Errorf("template not found: %s", templateName)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// RegisterHelper registers a template helper function
func (te *templateEngine) RegisterHelper(name string, helper interface{}) error {
	te.mu.Lock()
	defer te.mu.Unlock()

	te.helpers[name] = helper

	// Update existing templates with new helper
	for templateName, tmpl := range te.templates {
		tmpl.Funcs(te.helpers)
		// Note: In a real implementation, you'd need to re-parse templates
		// when adding new helpers to existing templates
		_ = templateName // Avoid unused variable warning
	}

	return nil
}

// ListTemplates returns available template names
func (te *templateEngine) ListTemplates() []string {
	te.mu.RLock()
	defer te.mu.RUnlock()

	names := make([]string, 0, len(te.templates))
	for name := range te.templates {
		names = append(names, name)
	}

	return names
}

// registerDefaultHelpers registers default template helper functions
func (te *templateEngine) registerDefaultHelpers() {
	// String manipulation helpers
	te.helpers["upper"] = strings.ToUpper
	te.helpers["lower"] = strings.ToLower
	te.helpers["title"] = strings.Title
	te.helpers["trim"] = strings.TrimSpace

	// Formatting helpers
	te.helpers["printf"] = fmt.Sprintf
	te.helpers["join"] = strings.Join

	// Conditional helpers
	te.helpers["eq"] = func(a, b interface{}) bool { return a == b }
	te.helpers["ne"] = func(a, b interface{}) bool { return a != b }
	te.helpers["gt"] = func(a, b int) bool { return a > b }
	te.helpers["lt"] = func(a, b int) bool { return a < b }
	te.helpers["gte"] = func(a, b int) bool { return a >= b }
	te.helpers["lte"] = func(a, b int) bool { return a <= b }

	// Collection helpers
	te.helpers["len"] = func(v interface{}) int {
		switch val := v.(type) {
		case []interface{}:
			return len(val)
		case map[string]interface{}:
			return len(val)
		case string:
			return len(val)
		default:
			return 0
		}
	}

	te.helpers["index"] = func(m map[string]interface{}, key string) interface{} {
		return m[key]
	}

	// Security-specific helpers
	te.helpers["severityColor"] = func(severity string) string {
		switch strings.ToLower(severity) {
		case "critical":
			return "#8B0000" // Dark red
		case "high":
			return "#DC143C" // Crimson
		case "medium":
			return "#FF8C00" // Dark orange
		case "low":
			return "#32CD32" // Lime green
		case "info":
			return "#4169E1" // Royal blue
		default:
			return "#808080" // Gray
		}
	}

	te.helpers["severityIcon"] = func(severity string) string {
		switch strings.ToLower(severity) {
		case "critical":
			return "🔴"
		case "high":
			return "🟠"
		case "medium":
			return "🟡"
		case "low":
			return "🟢"
		case "info":
			return "🔵"
		default:
			return "⚪"
		}
	}

	te.helpers["confidenceIcon"] = func(confidence string) string {
		switch strings.ToLower(confidence) {
		case "high":
			return "✅"
		case "medium":
			return "⚠️"
		case "low":
			return "❓"
		default:
			return "❔"
		}
	}

	// Utility helpers
	te.helpers["default"] = func(defaultVal, val interface{}) interface{} {
		if val == nil || val == "" {
			return defaultVal
		}
		return val
	}

	te.helpers["truncate"] = func(s string, length int) string {
		if len(s) <= length {
			return s
		}
		return s[:length] + "..."
	}

	te.helpers["pluralize"] = func(count int, singular, plural string) string {
		if count == 1 {
			return singular
		}
		return plural
	}
}

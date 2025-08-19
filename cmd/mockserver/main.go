package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// VulnerableServer implements all known security vulnerabilities for testing STRIDER
type VulnerableServer struct {
	port int
}

func main() {
	port := 9999
	if p := os.Getenv("PORT"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		}
	}

	server := &VulnerableServer{port: port}
	server.setupRoutes()

	log.Printf("🚨 VULNERABLE MOCK SERVER starting on port %d", port)
	log.Printf("⚠️  WARNING: This server contains intentional security vulnerabilities for testing purposes only!")
	log.Printf("🔗 Access at: http://localhost:%d", port)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		log.Fatal(err)
	}
}

func (s *VulnerableServer) setupRoutes() {
	// Main vulnerable pages
	http.HandleFunc("/", s.homePage)
	http.HandleFunc("/login", s.loginPage)
	http.HandleFunc("/admin", s.adminPage)
	http.HandleFunc("/api/users", s.apiUsers)
	http.HandleFunc("/api/data", s.apiData)
	http.HandleFunc("/upload", s.uploadPage)
	http.HandleFunc("/search", s.searchPage)
	http.HandleFunc("/profile", s.profilePage)
	http.HandleFunc("/redirect", s.redirectPage)
	http.HandleFunc("/files/", s.fileServer)

	// Specific vulnerability endpoints
	http.HandleFunc("/xss", s.xssVulnerable)
	http.HandleFunc("/sql", s.sqlInjectable)
	http.HandleFunc("/csrf", s.csrfVulnerable)
	http.HandleFunc("/directory-traversal", s.directoryTraversal)
	http.HandleFunc("/info-disclosure", s.infoDisclosure)
	http.HandleFunc("/weak-auth", s.weakAuth)
	http.HandleFunc("/sensitive-data", s.sensitiveDataExposure)

	// Additional pages to trigger all 16 rules
	http.HandleFunc("/missing-hsts", s.missingHSTSPage)
	http.HandleFunc("/missing-frame-options", s.missingFrameOptionsPage)
	http.HandleFunc("/missing-content-type-options", s.missingContentTypeOptionsPage)
	http.HandleFunc("/missing-permissions-policy", s.missingPermissionsPolicyPage)
	http.HandleFunc("/insecure-referrer-policy", s.insecureReferrerPolicyPage)
	http.HandleFunc("/weak-cors", s.weakCORSPage)
	http.HandleFunc("/no-https-redirect", s.noHTTPSRedirectPage)

	// Static files with vulnerabilities
	http.HandleFunc("/robots.txt", s.robotsTxt)
	http.HandleFunc("/config.json", s.configFile)
	http.HandleFunc("/backup.sql", s.backupFile)
}

// Home page - triggers multiple header-based vulnerabilities
func (s *VulnerableServer) homePage(w http.ResponseWriter, r *http.Request) {
	// Intentionally missing security headers:
	// - No Content-Security-Policy (missing-csp)
	// - No Strict-Transport-Security (missing-hsts)
	// - No X-Frame-Options (missing-frame-options)
	// - No X-Content-Type-Options (missing-content-type-options)
	// - No Permissions-Policy (missing-permissions-policy)
	// - Insecure Referrer-Policy (insecure-referrer-policy)

	// Set insecure headers
	w.Header().Set("Referrer-Policy", "unsafe-url")    // Insecure referrer policy
	w.Header().Set("Access-Control-Allow-Origin", "*") // Weak CORS

	// Set insecure cookies
	http.SetCookie(w, &http.Cookie{
		Name:  "session_id",
		Value: "abc123",
		Path:  "/",
		// Missing: Secure, HttpOnly, SameSite flags (insecure-cookies)
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "tracking",
		Value:    "user123",
		Path:     "/",
		Secure:   false,                 // Insecure over HTTP
		HttpOnly: false,                 // Accessible via JavaScript
		SameSite: http.SameSiteNoneMode, // No CSRF protection
	})

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test Application</title>
    <meta charset="utf-8">
</head>
<body>
    <h1>🚨 Intentionally Vulnerable Test Application</h1>
    <p>This application contains security vulnerabilities for testing STRIDER.</p>
    
    <nav>
        <a href="/login">Login</a> |
        <a href="/admin">Admin</a> |
        <a href="/api/users">API</a> |
        <a href="/search">Search</a> |
        <a href="/upload">Upload</a> |
        <a href="/xss">XSS Test</a> |
        <a href="/sql">SQL Test</a> |
        <a href="/csrf">CSRF Test</a> |
        <a href="/directory-traversal">Path Traversal</a> |
        <a href="/info-disclosure">Info Disclosure</a> |
        <a href="/weak-auth">Weak Auth</a> |
        <a href="/sensitive-data">Sensitive Data</a>
    </nav>
    
    <h2>Security Header Tests</h2>
    <nav>
        <a href="/missing-hsts">Missing HSTS</a> |
        <a href="/missing-frame-options">Missing Frame Options</a> |
        <a href="/missing-content-type-options">Missing Content Type Options</a> |
        <a href="/missing-permissions-policy">Missing Permissions Policy</a> |
        <a href="/insecure-referrer-policy">Insecure Referrer Policy</a> |
        <a href="/weak-cors">Weak CORS</a> |
        <a href="/no-https-redirect">No HTTPS Redirect</a>
    </nav>
    
    <h2>Features</h2>
    <ul>
        <li>Missing security headers (CSP, HSTS, X-Frame-Options, etc.)</li>
        <li>Insecure cookies</li>
        <li>XSS vulnerabilities</li>
        <li>SQL injection</li>
        <li>CSRF vulnerabilities</li>
        <li>Directory traversal</li>
        <li>Information disclosure</li>
        <li>Weak authentication</li>
        <li>Sensitive data exposure</li>
    </ul>
    
    <script>
        // Inline JavaScript (CSP violation)
        console.log('Vulnerable app loaded');
        document.cookie = "js_cookie=vulnerable; path=/";
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// Login page - weak authentication
func (s *VulnerableServer) loginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Weak authentication - accepts any credentials (weak-authentication)
		if username != "" && password != "" {
			w.Header().Set("Location", "/admin")
			w.WriteHeader(302)
			return
		}
	}

	html := `<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <input type="submit" value="Login">
    </form>
    <p><small>Any username/password combination works!</small></p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// Admin page - CSRF vulnerable
func (s *VulnerableServer) adminPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head><title>Admin Panel</title></head>
<body>
    <h1>Admin Panel</h1>
    <form method="POST" action="/admin">
        <input type="text" name="action" placeholder="Admin Action">
        <input type="submit" value="Execute">
    </form>
    <p>No CSRF protection!</p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// API endpoint - information disclosure
func (s *VulnerableServer) apiUsers(w http.ResponseWriter, r *http.Request) {
	// Sensitive data exposure
	users := map[string]interface{}{
		"users": []map[string]interface{}{
			{
				"id":       1,
				"username": "admin",
				"password": "admin123", // Exposed password
				"email":    "admin@vulnerable.com",
				"ssn":      "123-45-6789",          // Sensitive data
				"api_key":  "sk_live_abc123def456", // API key exposure
			},
			{
				"id":          2,
				"username":    "user",
				"password":    "password", // Weak password
				"email":       "user@vulnerable.com",
				"credit_card": "4111-1111-1111-1111", // PCI data
			},
		},
		"database_version": "MySQL 5.7.32",
		"server_info": map[string]string{
			"os":      "Ubuntu 20.04",
			"php":     "7.4.3",
			"apache":  "2.4.41",
			"openssl": "1.1.1f",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// XSS vulnerable endpoint
func (s *VulnerableServer) xssVulnerable(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("input")
	if userInput == "" {
		userInput = "Enter something in the 'input' parameter"
	}

	// Reflected XSS vulnerability
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>XSS Test</title></head>
<body>
    <h1>XSS Vulnerability Test</h1>
    <p>Your input: %s</p>
    <p>Try: <code>?input=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
</body>
</html>`, userInput) // Direct injection without escaping

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// SQL injection vulnerable endpoint
func (s *VulnerableServer) sqlInjectable(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("id")
	if userID == "" {
		userID = "1"
	}

	// Simulated SQL injection vulnerability
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)

	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>SQL Injection Test</title></head>
<body>
    <h1>SQL Injection Vulnerability</h1>
    <p>Query executed: <code>%s</code></p>
    <p>Try: <code>?id=1 OR 1=1</code></p>
    <p>User data would be displayed here...</p>
</body>
</html>`, query)

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// CSRF vulnerable endpoint
func (s *VulnerableServer) csrfVulnerable(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		action := r.FormValue("action")
		w.Write([]byte(fmt.Sprintf("Action executed: %s (No CSRF protection!)", action)))
		return
	}

	html := `<!DOCTYPE html>
<html>
<head><title>CSRF Test</title></head>
<body>
    <h1>CSRF Vulnerability</h1>
    <form method="POST">
        <input type="hidden" name="action" value="delete_all_users">
        <input type="submit" value="Dangerous Action (No CSRF Token)">
    </form>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

// Directory traversal vulnerable endpoint
func (s *VulnerableServer) directoryTraversal(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	if file == "" {
		file = "welcome.txt"
	}

	// Simulated directory traversal
	content := fmt.Sprintf("File requested: %s\n", file)
	if strings.Contains(file, "..") {
		content += "Directory traversal attempt detected!\n"
		content += "Contents of /etc/passwd would be shown here...\n"
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(content))
}

// Information disclosure endpoint
func (s *VulnerableServer) infoDisclosure(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"server_info": map[string]string{
			"version":     "Apache/2.4.41",
			"php_version": "7.4.3",
			"os":          "Ubuntu 20.04.3 LTS",
		},
		"database": map[string]string{
			"host":     "localhost",
			"name":     "vulnerable_app",
			"user":     "root",
			"password": "root123",
		},
		"api_keys": map[string]string{
			"stripe":     "sk_live_abc123",
			"aws":        "AKIAIOSFODNN7EXAMPLE",
			"jwt_secret": "super_secret_key_123",
		},
		"debug_info": map[string]interface{}{
			"memory_usage": "45MB",
			"queries": []string{
				"SELECT * FROM users WHERE active = 1",
				"SELECT password FROM admin WHERE id = 1",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// Additional vulnerable endpoints
func (s *VulnerableServer) searchPage(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Search</title></head>
<body>
    <h1>Search Results</h1>
    <p>You searched for: %s</p>
</body>
</html>`, query) // XSS vulnerability

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (s *VulnerableServer) uploadPage(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head><title>File Upload</title></head>
<body>
    <h1>File Upload (No validation!)</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" accept="*">
        <input type="submit" value="Upload">
    </form>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (s *VulnerableServer) profilePage(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>User Profile</title></head>
<body>
    <h1>Profile for user: %s</h1>
    <p>Personal information displayed here...</p>
</body>
</html>`, userID)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (s *VulnerableServer) redirectPage(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	if url != "" {
		// Open redirect vulnerability
		w.Header().Set("Location", url)
		w.WriteHeader(302)
		return
	}

	w.Write([]byte("Provide a 'url' parameter for redirection"))
}

func (s *VulnerableServer) fileServer(w http.ResponseWriter, r *http.Request) {
	// Simulated file access
	path := strings.TrimPrefix(r.URL.Path, "/files/")
	w.Write([]byte(fmt.Sprintf("File content for: %s", path)))
}

func (s *VulnerableServer) weakAuth(w http.ResponseWriter, r *http.Request) {
	// Weak authentication endpoint
	auth := r.Header.Get("Authorization")
	if auth == "" || auth == "Bearer weak_token" {
		w.WriteHeader(200)
		w.Write([]byte("Access granted with weak authentication!"))
		return
	}
	w.WriteHeader(401)
	w.Write([]byte("Unauthorized"))
}

func (s *VulnerableServer) sensitiveDataExposure(w http.ResponseWriter, r *http.Request) {
	// Expose sensitive data
	data := map[string]interface{}{
		"credit_cards": []string{"4111-1111-1111-1111", "5555-5555-5555-4444"},
		"ssns":         []string{"123-45-6789", "987-65-4321"},
		"passwords":    []string{"admin123", "password", "123456"},
		"api_keys":     []string{"sk_live_abc123", "pk_test_def456"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *VulnerableServer) apiData(w http.ResponseWriter, r *http.Request) {
	// API with weak CORS and information disclosure
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	data := map[string]interface{}{
		"internal_data": "This should not be exposed",
		"server_time":   time.Now(),
		"version":       "1.0.0-vulnerable",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *VulnerableServer) robotsTxt(w http.ResponseWriter, r *http.Request) {
	robots := `User-agent: *
Disallow: /admin
Disallow: /config
Disallow: /backup
Disallow: /private
Allow: /

# Sensitive directories exposed in robots.txt
Disallow: /database-backup/
Disallow: /.env
Disallow: /api-keys.txt`

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(robots))
}

func (s *VulnerableServer) configFile(w http.ResponseWriter, r *http.Request) {
	config := map[string]interface{}{
		"database": map[string]string{
			"host":     "localhost",
			"username": "root",
			"password": "super_secret_password",
			"name":     "production_db",
		},
		"api_keys": map[string]string{
			"stripe_secret": "sk_live_abc123def456",
			"aws_access":    "AKIAIOSFODNN7EXAMPLE",
			"jwt_secret":    "my_super_secret_jwt_key",
		},
		"debug":       true,
		"environment": "production",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *VulnerableServer) backupFile(w http.ResponseWriter, r *http.Request) {
	backup := `-- Database backup file
-- Contains sensitive user data

CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(100),
    email VARCHAR(100),
    ssn VARCHAR(11),
    credit_card VARCHAR(19)
);

INSERT INTO users VALUES 
(1, 'admin', 'admin123', 'admin@company.com', '123-45-6789', '4111-1111-1111-1111'),
(2, 'user', 'password', 'user@company.com', '987-65-4321', '5555-5555-5555-4444');`

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(backup))
}

// Additional vulnerability pages to trigger all 16 rules

func (s *VulnerableServer) missingHSTSPage(w http.ResponseWriter, r *http.Request) {
	// Intentionally missing HSTS header for HTTPS sites
	html := `<!DOCTYPE html>
<html>
<head><title>Missing HSTS Test</title></head>
<body>
    <h1>Missing HSTS Header Test</h1>
    <p>This page should have Strict-Transport-Security header but doesn't.</p>
    <p>Vulnerable to downgrade attacks.</p>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

func (s *VulnerableServer) missingFrameOptionsPage(w http.ResponseWriter, r *http.Request) {
	// Intentionally missing X-Frame-Options header
	html := `<!DOCTYPE html>
<html>
<head><title>Missing X-Frame-Options Test</title></head>
<body>
    <h1>Missing X-Frame-Options Header</h1>
    <p>This page can be embedded in frames, vulnerable to clickjacking.</p>
    <iframe src="/login" width="300" height="200"></iframe>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

func (s *VulnerableServer) missingContentTypeOptionsPage(w http.ResponseWriter, r *http.Request) {
	// Intentionally missing X-Content-Type-Options header
	html := `<!DOCTYPE html>
<html>
<head><title>Missing X-Content-Type-Options Test</title></head>
<body>
    <h1>Missing X-Content-Type-Options Header</h1>
    <p>This page allows MIME type sniffing attacks.</p>
    <script>console.log('Vulnerable to MIME confusion');</script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

func (s *VulnerableServer) missingPermissionsPolicyPage(w http.ResponseWriter, r *http.Request) {
	// Intentionally missing Permissions-Policy header
	html := `<!DOCTYPE html>
<html>
<head><title>Missing Permissions Policy Test</title></head>
<body>
    <h1>Missing Permissions Policy Header</h1>
    <p>This page doesn't restrict feature access.</p>
    <button onclick="navigator.geolocation.getCurrentPosition()">Get Location</button>
    <button onclick="navigator.mediaDevices.getUserMedia({video: true})">Access Camera</button>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

func (s *VulnerableServer) insecureReferrerPolicyPage(w http.ResponseWriter, r *http.Request) {
	// Insecure referrer policy
	w.Header().Set("Referrer-Policy", "unsafe-url")

	html := `<!DOCTYPE html>
<html>
<head><title>Insecure Referrer Policy Test</title></head>
<body>
    <h1>Insecure Referrer Policy</h1>
    <p>This page sends full referrer information to all sites.</p>
    <a href="https://external-site.com/tracker">External Link</a>
    <img src="https://tracker.com/pixel.gif" alt="tracking pixel">
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

func (s *VulnerableServer) weakCORSPage(w http.ResponseWriter, r *http.Request) {
	// Weak CORS configuration
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	data := map[string]interface{}{
		"sensitive_data": "This should not be accessible cross-origin",
		"user_tokens":    []string{"token1", "token2", "token3"},
		"api_keys":       map[string]string{"service": "secret_key_123"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *VulnerableServer) noHTTPSRedirectPage(w http.ResponseWriter, r *http.Request) {
	// No HTTPS redirect - serves content over HTTP
	html := `<!DOCTYPE html>
<html>
<head><title>No HTTPS Redirect Test</title></head>
<body>
    <h1>No HTTPS Redirect</h1>
    <p>This page should redirect to HTTPS but doesn't.</p>
    <form method="POST" action="/login">
        <input type="password" name="password" placeholder="Password sent over HTTP">
        <input type="submit" value="Insecure Login">
    </form>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(html))
}

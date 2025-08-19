package crawler

import (
	"container/heap"
	"net/url"
	"sync"
	"time"
)

// priorityQueue implements a priority queue for URL frontier management
type priorityQueue []*FrontierItem

func (pq priorityQueue) Len() int { return len(pq) }

func (pq priorityQueue) Less(i, j int) bool {
	// Higher priority first, then by timestamp (FIFO for same priority)
	if pq[i].Priority == pq[j].Priority {
		return pq[i].Added < pq[j].Added
	}
	return pq[i].Priority > pq[j].Priority
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *priorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*FrontierItem))
}

func (pq *priorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

// frontierManager implements FrontierManager using a priority queue
type frontierManager struct {
	queue priorityQueue
	mu    sync.RWMutex
}

// NewFrontierManager creates a new frontier manager
func NewFrontierManager() FrontierManager {
	fm := &frontierManager{
		queue: make(priorityQueue, 0),
	}
	heap.Init(&fm.queue)
	return fm
}

// Add adds URLs to the frontier with priority
func (fm *frontierManager) Add(urls []*url.URL, priority int, depth int) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	timestamp := time.Now().UnixNano()

	for _, u := range urls {
		item := &FrontierItem{
			URL:      u,
			Priority: priority,
			Depth:    depth,
			Added:    timestamp,
		}
		heap.Push(&fm.queue, item)
	}
}

// Next returns the next URL to crawl
func (fm *frontierManager) Next() (*FrontierItem, bool) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if len(fm.queue) == 0 {
		return nil, false
	}

	item := heap.Pop(&fm.queue).(*FrontierItem)
	return item, true
}

// Size returns the current frontier size
func (fm *frontierManager) Size() int {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return len(fm.queue)
}

// IsEmpty returns true if frontier is empty
func (fm *frontierManager) IsEmpty() bool {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return len(fm.queue) == 0
}

// Clear empties the frontier
func (fm *frontierManager) Clear() {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.queue = make(priorityQueue, 0)
	heap.Init(&fm.queue)
}

// domainFrontierManager implements domain-aware frontier management
type domainFrontierManager struct {
	domainQueues map[string]*frontierManager
	domains      []string
	roundRobin   int
	mu           sync.RWMutex
}

// NewDomainFrontierManager creates a domain-aware frontier manager
func NewDomainFrontierManager() FrontierManager {
	return &domainFrontierManager{
		domainQueues: make(map[string]*frontierManager),
		domains:      make([]string, 0),
		roundRobin:   0,
	}
}

// Add adds URLs to the appropriate domain queue
func (dfm *domainFrontierManager) Add(urls []*url.URL, priority int, depth int) {
	dfm.mu.Lock()
	defer dfm.mu.Unlock()

	for _, u := range urls {
		domain := u.Hostname()

		// Get or create domain queue
		if _, exists := dfm.domainQueues[domain]; !exists {
			dfm.domainQueues[domain] = NewFrontierManager().(*frontierManager)
			dfm.domains = append(dfm.domains, domain)
		}

		// Add to domain-specific queue
		dfm.domainQueues[domain].Add([]*url.URL{u}, priority, depth)
	}
}

// Next returns the next URL using round-robin across domains
func (dfm *domainFrontierManager) Next() (*FrontierItem, bool) {
	dfm.mu.Lock()
	defer dfm.mu.Unlock()

	if len(dfm.domains) == 0 {
		return nil, false
	}

	// Round-robin through domains to ensure fair distribution
	startIndex := dfm.roundRobin
	for i := 0; i < len(dfm.domains); i++ {
		domainIndex := (startIndex + i) % len(dfm.domains)
		domain := dfm.domains[domainIndex]

		if queue, exists := dfm.domainQueues[domain]; exists && !queue.IsEmpty() {
			dfm.roundRobin = (domainIndex + 1) % len(dfm.domains)
			return queue.Next()
		}
	}

	return nil, false
}

// Size returns the total size across all domain queues
func (dfm *domainFrontierManager) Size() int {
	dfm.mu.RLock()
	defer dfm.mu.RUnlock()

	total := 0
	for _, queue := range dfm.domainQueues {
		total += queue.Size()
	}
	return total
}

// IsEmpty returns true if all domain queues are empty
func (dfm *domainFrontierManager) IsEmpty() bool {
	dfm.mu.RLock()
	defer dfm.mu.RUnlock()

	for _, queue := range dfm.domainQueues {
		if !queue.IsEmpty() {
			return false
		}
	}
	return true
}

// Clear empties all domain queues
func (dfm *domainFrontierManager) Clear() {
	dfm.mu.Lock()
	defer dfm.mu.Unlock()

	for _, queue := range dfm.domainQueues {
		queue.Clear()
	}
	dfm.domainQueues = make(map[string]*frontierManager)
	dfm.domains = make([]string, 0)
	dfm.roundRobin = 0
}

// GetDomainStats returns statistics for each domain
func (dfm *domainFrontierManager) GetDomainStats() map[string]int {
	dfm.mu.RLock()
	defer dfm.mu.RUnlock()

	stats := make(map[string]int)
	for domain, queue := range dfm.domainQueues {
		stats[domain] = queue.Size()
	}
	return stats
}

// priorityCalculator provides URL priority calculation
type priorityCalculator struct {
	baseScores map[string]int
}

// NewPriorityCalculator creates a new priority calculator
func NewPriorityCalculator() *priorityCalculator {
	return &priorityCalculator{
		baseScores: map[string]int{
			"html": 100,
			"htm":  100,
			"php":  90,
			"asp":  90,
			"jsp":  90,
			"js":   70,
			"css":  50,
			"json": 80,
			"xml":  70,
			"api":  95,
		},
	}
}

// CalculatePriority calculates priority score for a URL
func (pc *priorityCalculator) CalculatePriority(u *url.URL, depth int, context map[string]interface{}) int {
	priority := 50 // Base priority

	// Depth penalty (deeper pages have lower priority)
	priority -= depth * 10

	// File extension bonus
	path := u.Path
	if len(path) > 0 {
		// Check for file extensions
		for ext, score := range pc.baseScores {
			if len(path) > len(ext) && path[len(path)-len(ext):] == ext {
				priority += score
				break
			}
		}
	}

	// API endpoint bonus
	if pc.isAPIEndpoint(u) {
		priority += 50
	}

	// Admin/sensitive path bonus
	if pc.isSensitivePath(u) {
		priority += 30
	}

	// Query parameter bonus (dynamic content)
	if u.RawQuery != "" {
		priority += 20
	}

	// Context-based adjustments
	if context != nil {
		if referrer, ok := context["referrer"].(string); ok && referrer != "" {
			priority += 10 // Linked pages get slight bonus
		}

		if linkText, ok := context["link_text"].(string); ok {
			if pc.isImportantLinkText(linkText) {
				priority += 15
			}
		}
	}

	// Ensure priority is within reasonable bounds
	if priority < 1 {
		priority = 1
	}
	if priority > 1000 {
		priority = 1000
	}

	return priority
}

// isAPIEndpoint checks if the URL looks like an API endpoint
func (pc *priorityCalculator) isAPIEndpoint(u *url.URL) bool {
	path := u.Path

	// Common API patterns
	apiPatterns := []string{
		"/api/",
		"/rest/",
		"/graphql",
		"/v1/",
		"/v2/",
		"/v3/",
		".json",
		".xml",
	}

	for _, pattern := range apiPatterns {
		if len(path) >= len(pattern) {
			for i := 0; i <= len(path)-len(pattern); i++ {
				if path[i:i+len(pattern)] == pattern {
					return true
				}
			}
		}
	}

	return false
}

// isSensitivePath checks if the URL contains sensitive paths
func (pc *priorityCalculator) isSensitivePath(u *url.URL) bool {
	path := u.Path

	sensitivePaths := []string{
		"/admin",
		"/login",
		"/auth",
		"/config",
		"/settings",
		"/dashboard",
		"/panel",
		"/management",
		"/secure",
		"/private",
	}

	for _, sensitive := range sensitivePaths {
		if len(path) >= len(sensitive) {
			for i := 0; i <= len(path)-len(sensitive); i++ {
				if path[i:i+len(sensitive)] == sensitive {
					return true
				}
			}
		}
	}

	return false
}

// isImportantLinkText checks if link text indicates important content
func (pc *priorityCalculator) isImportantLinkText(text string) bool {
	importantTerms := []string{
		"admin",
		"login",
		"dashboard",
		"api",
		"documentation",
		"settings",
		"config",
		"management",
		"secure",
		"private",
	}

	textLower := text
	for i := 0; i < len(textLower); i++ {
		if textLower[i] >= 'A' && textLower[i] <= 'Z' {
			textLower = textLower[:i] + string(textLower[i]+32) + textLower[i+1:]
		}
	}

	for _, term := range importantTerms {
		if len(textLower) >= len(term) {
			for i := 0; i <= len(textLower)-len(term); i++ {
				if textLower[i:i+len(term)] == term {
					return true
				}
			}
		}
	}

	return false
}

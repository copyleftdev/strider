package crawler

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// rateLimiter implements RateLimiter interface using token bucket algorithm
type rateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex

	// Default settings
	defaultRate  rate.Limit
	defaultBurst int
	perHost      bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSecond float64, burstSize int, perHost bool) RateLimiter {
	return &rateLimiter{
		limiters:     make(map[string]*rate.Limiter),
		defaultRate:  rate.Limit(requestsPerSecond),
		defaultBurst: burstSize,
		perHost:      perHost,
	}
}

// Wait blocks until the next request is allowed
func (rl *rateLimiter) Wait(ctx context.Context, domain string) error {
	limiter := rl.getLimiter(domain)
	return limiter.Wait(ctx)
}

// Allow checks if a request is currently allowed
func (rl *rateLimiter) Allow(domain string) bool {
	limiter := rl.getLimiter(domain)
	return limiter.Allow()
}

// SetRate updates the rate limit for a domain
func (rl *rateLimiter) SetRate(domain string, requestsPerSecond float64, burstSize int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.limiters[domain] = rate.NewLimiter(rate.Limit(requestsPerSecond), burstSize)
}

// getLimiter gets or creates a rate limiter for a domain
func (rl *rateLimiter) getLimiter(domain string) *rate.Limiter {
	key := domain
	if !rl.perHost {
		key = "global"
	}

	rl.mu.RLock()
	limiter, exists := rl.limiters[key]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	// Create new limiter
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rl.limiters[key]; exists {
		return limiter
	}

	limiter = rate.NewLimiter(rl.defaultRate, rl.defaultBurst)
	rl.limiters[key] = limiter
	return limiter
}

// adaptiveRateLimiter adjusts rate limits based on server responses
type adaptiveRateLimiter struct {
	*rateLimiter

	// Response time tracking
	responseTimes map[string]*responseTimeTracker
	mu            sync.RWMutex

	// Adaptive settings
	minRate         rate.Limit
	maxRate         rate.Limit
	targetLatency   time.Duration
	adjustmentRatio float64
}

type responseTimeTracker struct {
	samples    []time.Duration
	index      int
	windowSize int
	average    time.Duration
}

// NewAdaptiveRateLimiter creates a rate limiter that adapts to server performance
func NewAdaptiveRateLimiter(initialRate float64, burstSize int, perHost bool) RateLimiter {
	base := NewRateLimiter(initialRate, burstSize, perHost).(*rateLimiter)

	return &adaptiveRateLimiter{
		rateLimiter:     base,
		responseTimes:   make(map[string]*responseTimeTracker),
		minRate:         rate.Limit(0.1),  // Minimum 1 request per 10 seconds
		maxRate:         rate.Limit(10.0), // Maximum 10 requests per second
		targetLatency:   2 * time.Second,  // Target 2 second response time
		adjustmentRatio: 0.1,              // Adjust by 10% each time
	}
}

// RecordResponseTime records a response time for adaptive adjustment
func (arl *adaptiveRateLimiter) RecordResponseTime(domain string, responseTime time.Duration) {
	arl.mu.Lock()
	defer arl.mu.Unlock()

	tracker, exists := arl.responseTimes[domain]
	if !exists {
		tracker = &responseTimeTracker{
			samples:    make([]time.Duration, 10), // 10-sample window
			windowSize: 10,
		}
		arl.responseTimes[domain] = tracker
	}

	// Add sample to circular buffer
	tracker.samples[tracker.index] = responseTime
	tracker.index = (tracker.index + 1) % tracker.windowSize

	// Calculate average
	var total time.Duration
	count := 0
	for _, sample := range tracker.samples {
		if sample > 0 {
			total += sample
			count++
		}
	}

	if count > 0 {
		tracker.average = total / time.Duration(count)
		arl.adjustRateForDomain(domain, tracker.average)
	}
}

// adjustRateForDomain adjusts the rate limit based on response times
func (arl *adaptiveRateLimiter) adjustRateForDomain(domain string, avgResponseTime time.Duration) {
	currentLimiter := arl.getLimiter(domain)
	currentRate := currentLimiter.Limit()

	var newRate rate.Limit

	if avgResponseTime > arl.targetLatency {
		// Slow responses - decrease rate
		newRate = rate.Limit(float64(currentRate) * (1.0 - arl.adjustmentRatio))
	} else {
		// Fast responses - increase rate
		newRate = rate.Limit(float64(currentRate) * (1.0 + arl.adjustmentRatio))
	}

	// Apply bounds
	if newRate < arl.minRate {
		newRate = arl.minRate
	}
	if newRate > arl.maxRate {
		newRate = arl.maxRate
	}

	// Update if significantly different
	if newRate != currentRate {
		arl.SetRate(domain, float64(newRate), arl.defaultBurst)
	}
}

// politenessRateLimiter implements polite crawling with robots.txt respect
type politenessRateLimiter struct {
	*adaptiveRateLimiter
	robotsDelays map[string]time.Duration
	mu           sync.RWMutex
}

// NewPolitenessRateLimiter creates a polite rate limiter that respects robots.txt
func NewPolitenessRateLimiter(initialRate float64, burstSize int) RateLimiter {
	base := NewAdaptiveRateLimiter(initialRate, burstSize, true).(*adaptiveRateLimiter)

	return &politenessRateLimiter{
		adaptiveRateLimiter: base,
		robotsDelays:        make(map[string]time.Duration),
	}
}

// SetRobotsDelay sets the crawl delay from robots.txt for a domain
func (prl *politenessRateLimiter) SetRobotsDelay(domain string, delay time.Duration) {
	prl.mu.Lock()
	defer prl.mu.Unlock()

	prl.robotsDelays[domain] = delay

	// Adjust rate limit to respect robots.txt delay
	if delay > 0 {
		maxRate := 1.0 / delay.Seconds()
		currentLimiter := prl.getLimiter(domain)

		if float64(currentLimiter.Limit()) > maxRate {
			prl.SetRate(domain, maxRate, 1) // Burst of 1 for robots.txt compliance
		}
	}
}

// Wait overrides to include robots.txt delays
func (prl *politenessRateLimiter) Wait(ctx context.Context, domain string) error {
	// First wait for rate limiter
	if err := prl.adaptiveRateLimiter.Wait(ctx, domain); err != nil {
		return err
	}

	// Then apply additional robots.txt delay if needed
	prl.mu.RLock()
	robotsDelay, exists := prl.robotsDelays[domain]
	prl.mu.RUnlock()

	if exists && robotsDelay > 0 {
		select {
		case <-time.After(robotsDelay):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// circuitBreakerRateLimiter implements circuit breaker pattern for failing domains
type circuitBreakerRateLimiter struct {
	*politenessRateLimiter

	// Circuit breaker state
	failures    map[string]int
	lastFailure map[string]time.Time
	state       map[string]circuitState
	mu          sync.RWMutex

	// Configuration
	failureThreshold int
	recoveryTimeout  time.Duration
}

type circuitState int

const (
	circuitClosed circuitState = iota
	circuitOpen
	circuitHalfOpen
)

// NewCircuitBreakerRateLimiter creates a rate limiter with circuit breaker
func NewCircuitBreakerRateLimiter(initialRate float64, burstSize int) RateLimiter {
	base := NewPolitenessRateLimiter(initialRate, burstSize).(*politenessRateLimiter)

	return &circuitBreakerRateLimiter{
		politenessRateLimiter: base,
		failures:              make(map[string]int),
		lastFailure:           make(map[string]time.Time),
		state:                 make(map[string]circuitState),
		failureThreshold:      5,
		recoveryTimeout:       5 * time.Minute,
	}
}

// Allow checks circuit breaker state before allowing requests
func (cbrl *circuitBreakerRateLimiter) Allow(domain string) bool {
	cbrl.mu.RLock()
	state := cbrl.state[domain]
	lastFailure := cbrl.lastFailure[domain]
	cbrl.mu.RUnlock()

	switch state {
	case circuitOpen:
		// Check if we should transition to half-open
		if time.Since(lastFailure) > cbrl.recoveryTimeout {
			cbrl.mu.Lock()
			cbrl.state[domain] = circuitHalfOpen
			cbrl.mu.Unlock()
			return cbrl.politenessRateLimiter.Allow(domain)
		}
		return false

	case circuitHalfOpen:
		// Allow one request to test if service is recovered
		return cbrl.politenessRateLimiter.Allow(domain)

	default: // circuitClosed
		return cbrl.politenessRateLimiter.Allow(domain)
	}
}

// RecordSuccess records a successful request
func (cbrl *circuitBreakerRateLimiter) RecordSuccess(domain string) {
	cbrl.mu.Lock()
	defer cbrl.mu.Unlock()

	// Reset failure count and close circuit
	cbrl.failures[domain] = 0
	cbrl.state[domain] = circuitClosed
}

// RecordFailure records a failed request
func (cbrl *circuitBreakerRateLimiter) RecordFailure(domain string) {
	cbrl.mu.Lock()
	defer cbrl.mu.Unlock()

	cbrl.failures[domain]++
	cbrl.lastFailure[domain] = time.Now()

	// Open circuit if threshold exceeded
	if cbrl.failures[domain] >= cbrl.failureThreshold {
		cbrl.state[domain] = circuitOpen
	}
}

// GetCircuitState returns the current circuit state for a domain
func (cbrl *circuitBreakerRateLimiter) GetCircuitState(domain string) circuitState {
	cbrl.mu.RLock()
	defer cbrl.mu.RUnlock()

	return cbrl.state[domain]
}

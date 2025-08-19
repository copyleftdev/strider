package metrics

import (
	"runtime"
	"sync"
	"time"
)

// Metrics holds performance metrics for STRIDER scans
type Metrics struct {
	mu sync.RWMutex

	// Timing metrics
	StartTime         time.Time
	CrawlStartTime    time.Time
	CrawlEndTime      time.Time
	AnalysisStartTime time.Time
	AnalysisEndTime   time.Time
	AIStartTime       time.Time
	AIEndTime         time.Time
	StorageStartTime  time.Time
	StorageEndTime    time.Time
	ReportStartTime   time.Time
	ReportEndTime     time.Time
	EndTime           time.Time

	// Scan metrics
	PagesScanned      int64
	RequestsCaptured  int64
	ResponsesCaptured int64
	FindingsGenerated int64
	RulesExecuted     int64

	// Memory metrics
	StartMemory runtime.MemStats
	PeakMemory  runtime.MemStats
	EndMemory   runtime.MemStats

	// Performance metrics
	CrawlDuration    time.Duration
	AnalysisDuration time.Duration
	AIDuration       time.Duration
	StorageDuration  time.Duration
	ReportDuration   time.Duration
	TotalDuration    time.Duration
}

// NewMetrics creates a new metrics instance
func NewMetrics() *Metrics {
	m := &Metrics{
		StartTime: time.Now(),
	}
	runtime.ReadMemStats(&m.StartMemory)
	return m
}

// StartCrawl marks the beginning of the crawling phase
func (m *Metrics) StartCrawl() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CrawlStartTime = time.Now()
}

// EndCrawl marks the end of the crawling phase
func (m *Metrics) EndCrawl() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CrawlEndTime = time.Now()
	m.CrawlDuration = m.CrawlEndTime.Sub(m.CrawlStartTime)
}

// StartAnalysis marks the beginning of the analysis phase
func (m *Metrics) StartAnalysis() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AnalysisStartTime = time.Now()
}

// EndAnalysis marks the end of the analysis phase
func (m *Metrics) EndAnalysis() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AnalysisEndTime = time.Now()
	m.AnalysisDuration = m.AnalysisEndTime.Sub(m.AnalysisStartTime)
}

// StartAI marks the beginning of the AI analysis phase
func (m *Metrics) StartAI() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AIStartTime = time.Now()
}

// EndAI marks the end of the AI analysis phase
func (m *Metrics) EndAI() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.AIEndTime = time.Now()
	m.AIDuration = m.AIEndTime.Sub(m.AIStartTime)
}

// StartStorage marks the beginning of the storage phase
func (m *Metrics) StartStorage() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StorageStartTime = time.Now()
}

// EndStorage marks the end of the storage phase
func (m *Metrics) EndStorage() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.StorageEndTime = time.Now()
	m.StorageDuration = m.StorageEndTime.Sub(m.StorageStartTime)
}

// StartReport marks the beginning of the report generation phase
func (m *Metrics) StartReport() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReportStartTime = time.Now()
}

// EndReport marks the end of the report generation phase
func (m *Metrics) EndReport() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ReportEndTime = time.Now()
	m.ReportDuration = m.ReportEndTime.Sub(m.ReportStartTime)
}

// Finalize completes the metrics collection
func (m *Metrics) Finalize() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.EndTime = time.Now()
	m.TotalDuration = m.EndTime.Sub(m.StartTime)
	runtime.ReadMemStats(&m.EndMemory)
}

// UpdateMemoryPeak updates the peak memory usage
func (m *Metrics) UpdateMemoryPeak() {
	m.mu.Lock()
	defer m.mu.Unlock()

	var current runtime.MemStats
	runtime.ReadMemStats(&current)

	if current.Alloc > m.PeakMemory.Alloc {
		m.PeakMemory = current
	}
}

// IncrementPagesScanned increments the pages scanned counter
func (m *Metrics) IncrementPagesScanned() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PagesScanned++
}

// IncrementRequestsCaptured increments the requests captured counter
func (m *Metrics) IncrementRequestsCaptured() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RequestsCaptured++
}

// IncrementResponsesCaptured increments the responses captured counter
func (m *Metrics) IncrementResponsesCaptured() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ResponsesCaptured++
}

// IncrementFindingsGenerated increments the findings generated counter
func (m *Metrics) IncrementFindingsGenerated() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FindingsGenerated++
}

// IncrementRulesExecuted increments the rules executed counter
func (m *Metrics) IncrementRulesExecuted() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.RulesExecuted++
}

// GetThroughputMetrics returns calculated throughput metrics
func (m *Metrics) GetThroughputMetrics() ThroughputMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	totalSeconds := m.TotalDuration.Seconds()
	if totalSeconds == 0 {
		totalSeconds = 1 // Avoid division by zero
	}

	return ThroughputMetrics{
		PagesPerSecond:    float64(m.PagesScanned) / totalSeconds,
		FindingsPerSecond: float64(m.FindingsGenerated) / totalSeconds,
		RequestsPerSecond: float64(m.RequestsCaptured) / totalSeconds,
		RulesPerSecond:    float64(m.RulesExecuted) / totalSeconds,
	}
}

// ThroughputMetrics holds calculated throughput values
type ThroughputMetrics struct {
	PagesPerSecond    float64
	FindingsPerSecond float64
	RequestsPerSecond float64
	RulesPerSecond    float64
}

// GetMemoryMetrics returns memory usage metrics in MB
func (m *Metrics) GetMemoryMetrics() MemoryMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MemoryMetrics{
		StartAllocMB: float64(m.StartMemory.Alloc) / 1024 / 1024,
		PeakAllocMB:  float64(m.PeakMemory.Alloc) / 1024 / 1024,
		EndAllocMB:   float64(m.EndMemory.Alloc) / 1024 / 1024,
		StartSysMB:   float64(m.StartMemory.Sys) / 1024 / 1024,
		PeakSysMB:    float64(m.PeakMemory.Sys) / 1024 / 1024,
		EndSysMB:     float64(m.EndMemory.Sys) / 1024 / 1024,
		GCCycles:     m.EndMemory.NumGC - m.StartMemory.NumGC,
	}
}

// MemoryMetrics holds memory usage information
type MemoryMetrics struct {
	StartAllocMB float64
	PeakAllocMB  float64
	EndAllocMB   float64
	StartSysMB   float64
	PeakSysMB    float64
	EndSysMB     float64
	GCCycles     uint32
}

// GetPhaseMetrics returns timing for each phase
func (m *Metrics) GetPhaseMetrics() PhaseMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return PhaseMetrics{
		CrawlDuration:    m.CrawlDuration,
		AnalysisDuration: m.AnalysisDuration,
		AIDuration:       m.AIDuration,
		StorageDuration:  m.StorageDuration,
		ReportDuration:   m.ReportDuration,
		TotalDuration:    m.TotalDuration,
	}
}

// PhaseMetrics holds timing information for each scan phase
type PhaseMetrics struct {
	CrawlDuration    time.Duration
	AnalysisDuration time.Duration
	AIDuration       time.Duration
	StorageDuration  time.Duration
	ReportDuration   time.Duration
	TotalDuration    time.Duration
}

// GetSummary returns a comprehensive metrics summary
func (m *Metrics) GetSummary() Summary {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return Summary{
		Throughput: m.GetThroughputMetrics(),
		Memory:     m.GetMemoryMetrics(),
		Phases:     m.GetPhaseMetrics(),
		Counters: CounterMetrics{
			PagesScanned:      m.PagesScanned,
			RequestsCaptured:  m.RequestsCaptured,
			ResponsesCaptured: m.ResponsesCaptured,
			FindingsGenerated: m.FindingsGenerated,
			RulesExecuted:     m.RulesExecuted,
		},
	}
}

// Summary holds all metrics in a structured format
type Summary struct {
	Throughput ThroughputMetrics
	Memory     MemoryMetrics
	Phases     PhaseMetrics
	Counters   CounterMetrics
}

// CounterMetrics holds counter values
type CounterMetrics struct {
	PagesScanned      int64
	RequestsCaptured  int64
	ResponsesCaptured int64
	FindingsGenerated int64
	RulesExecuted     int64
}

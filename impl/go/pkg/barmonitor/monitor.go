// Package barmonitor implements Boundary Activation Rate (BAR) monitoring
// for ACP deployments.
//
// BAR measures whether the ACP admissibility boundary is actively exercised:
//
//	BAR_N = |{d_i ∈ D_N | d_i ∈ {ESCALATED, DENIED}}| / N
//
// where D_N is the sliding window of the last N evaluation decisions.
//
// BARMonitor tracks both BAR_N (current activation level) and ΔBAR (trend),
// and emits an Alert when either condition is detected:
//
//	- BAR_N < θ  (threshold condition): boundary insufficiently exercised
//	- ΔBAR < δ   (trend condition): boundary interaction declining
//
// BARMonitor is architecturally separate from the admission control engine
// and the LedgerQuerier. It does not alter decisions; it observes whether
// decisions remain meaningful.
//
// Usage:
//
//	m := barmonitor.New(barmonitor.DefaultConfig())
//	// after each risk.Evaluate():
//	if alert, _ := m.Record(result.Decision); alert != nil {
//	    // BAR is low or declining — investigate upstream pipeline
//	}
package barmonitor

import (
	"sync"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// Config holds BARMonitor configuration.
type Config struct {
	// WindowSize N: number of evaluations in the sliding window.
	// Must be >= 4 (required for ΔBAR computation). Default: 100.
	WindowSize int

	// Threshold θ: minimum acceptable BAR_N. Alert fires when BAR_N < θ.
	// Range: (0.0, 1.0). Default: 0.05.
	Threshold float64

	// TrendThreshold δ: minimum acceptable ΔBAR. Alert fires when ΔBAR < δ.
	// Negative value — decline magnitude before alerting.
	// Default: -0.10 (10-point drop between first and second half of window).
	TrendThreshold float64
}

// DefaultConfig returns a production-ready default configuration.
//
// WindowSize=100 provides statistically stable BAR estimates.
// Threshold=0.05 alerts when fewer than 5% of decisions exercise the boundary.
// TrendThreshold=-0.10 alerts when the second half of the window has 10+
// percentage points lower BAR than the first half (progressive decline detection).
func DefaultConfig() Config {
	return Config{
		WindowSize:     100,
		Threshold:      0.05,
		TrendThreshold: -0.10,
	}
}

// AlertReason categorizes the type of low-activation condition detected.
type AlertReason string

const (
	// AlertThreshold fires when BAR_N < θ (already in low-activation regime).
	AlertThreshold AlertReason = "THRESHOLD"

	// AlertTrend fires when ΔBAR < δ (progressive boundary interaction decline).
	// BAR may still be above θ, but the trend indicates collapse is approaching.
	AlertTrend AlertReason = "TREND"
)

// Alert is emitted by Record when a low-activation condition is detected.
type Alert struct {
	// BAR is the current Boundary Activation Rate over the window.
	BAR float64

	// Trend is ΔBAR: BAR(second half) - BAR(first half) of the window.
	// Negative = declining boundary interaction.
	Trend float64

	// Reason indicates which condition triggered the alert.
	Reason AlertReason

	// WindowFill is the number of evaluations currently in the window (≤ WindowSize).
	WindowFill int
}

// BARMonitor tracks Boundary Activation Rate over a sliding window of
// recent evaluation decisions.
//
// BARMonitor is safe for concurrent use.
type BARMonitor struct {
	mu   sync.Mutex
	cfg  Config
	ring []risk.Decision // circular buffer, capacity = cfg.WindowSize
	pos  int             // next write position in ring
	fill int             // number of valid entries (saturates at WindowSize)
}

// New creates a BARMonitor with the given configuration.
// Panics if cfg.WindowSize < 4 or cfg.Threshold not in (0,1).
func New(cfg Config) *BARMonitor {
	if cfg.WindowSize < 4 {
		panic("barmonitor: WindowSize must be >= 4")
	}
	if cfg.Threshold <= 0 || cfg.Threshold >= 1 {
		panic("barmonitor: Threshold must be in (0,1)")
	}
	return &BARMonitor{
		cfg:  cfg,
		ring: make([]risk.Decision, cfg.WindowSize),
	}
}

// Record adds a decision to the monitor.
//
// Returns (*Alert, bar):
//   - Alert != nil if a low-activation condition was detected.
//   - bar is the current BAR_N (always returned, regardless of alert).
//
// If both conditions hold (BAR_N < θ AND ΔBAR < δ), AlertThreshold takes precedence.
func (m *BARMonitor) Record(d risk.Decision) (*Alert, float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ring[m.pos] = d
	m.pos = (m.pos + 1) % m.cfg.WindowSize
	if m.fill < m.cfg.WindowSize {
		m.fill++
	}

	bar := m.computeBAR()
	trend := m.computeTrend()

	if bar < m.cfg.Threshold {
		return &Alert{BAR: bar, Trend: trend, Reason: AlertThreshold, WindowFill: m.fill}, bar
	}
	if trend < m.cfg.TrendThreshold {
		return &Alert{BAR: bar, Trend: trend, Reason: AlertTrend, WindowFill: m.fill}, bar
	}
	return nil, bar
}

// BAR returns the current Boundary Activation Rate.
//
//	BAR_N = |{d_i ∈ D_N | d_i ∈ {ESCALATED, DENIED}}| / N
func (m *BARMonitor) BAR() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.computeBAR()
}

// Trend returns ΔBAR: the difference between the BAR of the second half
// and the first half of the current window.
//
//	ΔBAR = BAR(D_N[N/2 : N]) - BAR(D_N[0 : N/2])
//
// A negative ΔBAR indicates declining boundary interaction.
// Returns 0 if fewer than 4 evaluations have been recorded.
func (m *BARMonitor) Trend() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.computeTrend()
}

// WindowFill returns the number of evaluations currently in the window.
// Starts at 0 and grows until it saturates at cfg.WindowSize.
func (m *BARMonitor) WindowFill() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fill
}

// Reset clears all accumulated state.
// After Reset(), BAR() == 0 and WindowFill() == 0.
func (m *BARMonitor) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ring = make([]risk.Decision, m.cfg.WindowSize)
	m.pos = 0
	m.fill = 0
}

// computeBAR counts ESCALATED+DENIED decisions in the current window.
// Caller must hold m.mu.
func (m *BARMonitor) computeBAR() float64 {
	if m.fill == 0 {
		return 0
	}
	var active int
	for i := 0; i < m.fill; i++ {
		if isActive(m.ring[i]) {
			active++
		}
	}
	return float64(active) / float64(m.fill)
}

// computeTrend computes ΔBAR = BAR(second half) - BAR(first half).
// Entries are read in temporal order (oldest first, newest last) to ensure
// ΔBAR reflects the direction of change over time.
//
// When the ring buffer has not yet wrapped (fill < WindowSize), temporal order
// equals insertion order (ring[0..fill-1]). When the buffer is full, temporal
// order starts at pos (the next write slot = the oldest existing entry) and
// wraps around the ring.
//
// Returns 0 if fill < 4 (insufficient data for meaningful trend).
// Caller must hold m.mu.
func (m *BARMonitor) computeTrend() float64 {
	if m.fill < 4 {
		return 0
	}
	half := m.fill / 2

	// start: index of the oldest entry in the ring.
	// When not yet full (fill < WindowSize), ring[0..fill-1] are in order and
	// pos == fill, so starting at 0 gives correct temporal order.
	// When full (fill == WindowSize), pos points to the next write slot which
	// is also the oldest existing entry.
	start := 0
	if m.fill == m.cfg.WindowSize {
		start = m.pos
	}

	var firstActive, secondActive int
	for i := 0; i < m.fill; i++ {
		idx := (start + i) % m.cfg.WindowSize
		if i < half {
			if isActive(m.ring[idx]) {
				firstActive++
			}
		} else {
			if isActive(m.ring[idx]) {
				secondActive++
			}
		}
	}
	firstBAR := float64(firstActive) / float64(half)
	secondBAR := float64(secondActive) / float64(m.fill-half)
	return secondBAR - firstBAR
}

// isActive returns true if the decision exercises the admissibility boundary.
func isActive(d risk.Decision) bool {
	return d == risk.ESCALATED || d == risk.DENIED
}

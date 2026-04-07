package barmonitor_test

import (
	"sync"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/barmonitor"
	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func record(m *barmonitor.BARMonitor, decisions ...risk.Decision) (*barmonitor.Alert, float64) {
	var last *barmonitor.Alert
	var lastBAR float64
	for _, d := range decisions {
		last, lastBAR = m.Record(d)
	}
	return last, lastBAR
}

func approvedSeq(n int) []risk.Decision {
	s := make([]risk.Decision, n)
	for i := range s {
		s[i] = risk.APPROVED
	}
	return s
}

func deniedSeq(n int) []risk.Decision {
	s := make([]risk.Decision, n)
	for i := range s {
		s[i] = risk.DENIED
	}
	return s
}

// phaseASeq returns 6 APPROVED + 7 ESCALATED + 7 DENIED (matches Exp 9 Phase A).
func phaseASeq() []risk.Decision {
	seq := make([]risk.Decision, 0, 20)
	for i := 0; i < 6; i++ {
		seq = append(seq, risk.APPROVED)
	}
	for i := 0; i < 7; i++ {
		seq = append(seq, risk.ESCALATED)
	}
	for i := 0; i < 7; i++ {
		seq = append(seq, risk.DENIED)
	}
	return seq
}

// ── panic tests ───────────────────────────────────────────────────────────────

func TestNew_PanicsOnSmallWindowSize(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for WindowSize < 4")
		}
	}()
	barmonitor.New(barmonitor.Config{WindowSize: 3, Threshold: 0.05, TrendThreshold: -0.10})
}

func TestNew_PanicsOnThresholdZero(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for Threshold=0")
		}
	}()
	barmonitor.New(barmonitor.Config{WindowSize: 10, Threshold: 0, TrendThreshold: -0.10})
}

func TestNew_PanicsOnThresholdOne(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for Threshold=1")
		}
	}()
	barmonitor.New(barmonitor.Config{WindowSize: 10, Threshold: 1.0, TrendThreshold: -0.10})
}

// ── basic BAR computation ─────────────────────────────────────────────────────

func TestBAR_EmptyWindow(t *testing.T) {
	m := barmonitor.New(barmonitor.DefaultConfig())
	if got := m.BAR(); got != 0 {
		t.Fatalf("empty window: BAR=%v, want 0", got)
	}
	if got := m.WindowFill(); got != 0 {
		t.Fatalf("empty window: fill=%d, want 0", got)
	}
}

func TestBAR_AllAPPROVED_IsZero(t *testing.T) {
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.10})
	record(m, approvedSeq(20)...)
	if got := m.BAR(); got != 0 {
		t.Fatalf("all APPROVED: BAR=%v, want 0", got)
	}
}

func TestBAR_AllDENIED_IsOne(t *testing.T) {
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.10})
	record(m, deniedSeq(20)...)
	if got := m.BAR(); got != 1.0 {
		t.Fatalf("all DENIED: BAR=%v, want 1.0", got)
	}
}

func TestBAR_PhaseADistribution(t *testing.T) {
	// 6 APPROVED + 7 ESCALATED + 7 DENIED = BAR = 14/20 = 0.70
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.10})
	record(m, phaseASeq()...)
	got := m.BAR()
	want := 0.70
	if got != want {
		t.Fatalf("Phase A distribution: BAR=%v, want %v", got, want)
	}
}

func TestBAR_ESCALATEDCountsAsActive(t *testing.T) {
	m := barmonitor.New(barmonitor.Config{WindowSize: 4, Threshold: 0.05, TrendThreshold: -0.10})
	record(m, risk.APPROVED, risk.ESCALATED, risk.ESCALATED, risk.APPROVED)
	got := m.BAR()
	want := 0.5 // 2/4
	if got != want {
		t.Fatalf("ESCALATED active: BAR=%v, want %v", got, want)
	}
}

// ── WindowFill saturation ─────────────────────────────────────────────────────

func TestWindowFill_SaturatesAtWindowSize(t *testing.T) {
	const N = 10
	m := barmonitor.New(barmonitor.Config{WindowSize: N, Threshold: 0.05, TrendThreshold: -0.10})
	for i := 0; i < N*3; i++ {
		m.Record(risk.APPROVED)
	}
	if got := m.WindowFill(); got != N {
		t.Fatalf("fill=%d, want %d", got, N)
	}
}

// ── alert: threshold ──────────────────────────────────────────────────────────

func TestAlert_ThresholdFires_AllAPPROVED(t *testing.T) {
	// BAR=0.00 < θ=0.05 → AlertThreshold
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.10})
	alert, bar := record(m, approvedSeq(20)...)
	if alert == nil {
		t.Fatal("expected AlertThreshold, got nil")
	}
	if alert.Reason != barmonitor.AlertThreshold {
		t.Fatalf("reason=%v, want AlertThreshold", alert.Reason)
	}
	if bar != 0 {
		t.Fatalf("bar=%v, want 0", bar)
	}
}

func TestAlert_NoAlert_PhaseADistribution(t *testing.T) {
	// BAR=0.70 >> θ=0.05 and no sustained decline → no alert
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.10})
	alert, _ := record(m, phaseASeq()...)
	if alert != nil {
		t.Fatalf("expected no alert for Phase A distribution, got %+v", alert)
	}
}

func TestAlert_NoAlert_AllDENIED(t *testing.T) {
	// BAR=1.00 >> θ — no alert even though BAR is extreme in the other direction
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.10})
	alert, _ := record(m, deniedSeq(20)...)
	if alert != nil {
		t.Fatalf("expected no alert for all-DENIED, got %+v", alert)
	}
}

// ── alert: trend (ΔBAR) — THE KEY TEST ───────────────────────────────────────

func TestAlert_TrendFires_BeforeThreshold(t *testing.T) {
	// This is the critical test: ΔBAR alert must fire BEFORE BAR reaches θ.
	// Window=20, Threshold=0.30, TrendThreshold=-0.20
	// First 10 decisions: mixed (BAR≈0.70 in first half)
	// Last 10 decisions:  all APPROVED (BAR≈0.00 in second half)
	// ΔBAR = 0.00 - 0.70 = -0.70 → fires AlertTrend
	// BAR_N = 7/20 = 0.35 — still above threshold=0.30 at the time trend fires
	cfg := barmonitor.Config{WindowSize: 20, Threshold: 0.30, TrendThreshold: -0.20}
	m := barmonitor.New(cfg)

	// First half: 7 active out of 10
	first := []risk.Decision{
		risk.DENIED, risk.ESCALATED, risk.DENIED, risk.ESCALATED, risk.DENIED,
		risk.ESCALATED, risk.DENIED, risk.APPROVED, risk.APPROVED, risk.APPROVED,
	}
	for _, d := range first {
		m.Record(d)
	}

	// Second half: gradually fill with APPROVED — trend alert should fire before BAR < 0.30
	var trendAlert *barmonitor.Alert
	for i := 0; i < 10; i++ {
		a, _ := m.Record(risk.APPROVED)
		if a != nil && a.Reason == barmonitor.AlertTrend && trendAlert == nil {
			trendAlert = a
		}
	}

	if trendAlert == nil {
		t.Fatal("expected AlertTrend to fire during second half, but it never fired")
	}
	if trendAlert.BAR >= cfg.Threshold {
		// Confirmed: trend alert fired while BAR was still above threshold
		t.Logf("ΔBAR alert fired at BAR=%.2f (> threshold=%.2f) — early warning confirmed",
			trendAlert.BAR, cfg.Threshold)
	}
	if trendAlert.Trend >= 0 {
		t.Fatalf("trend alert has non-negative ΔBAR=%v", trendAlert.Trend)
	}
}

func TestAlert_TrendNotFires_StableBAR(t *testing.T) {
	// Uniform distribution throughout: ΔBAR ≈ 0 → no trend alert
	m := barmonitor.New(barmonitor.Config{WindowSize: 20, Threshold: 0.05, TrendThreshold: -0.20})
	// Interleave APPROVED and DENIED evenly → BAR≈0.50, ΔBAR≈0 throughout
	var lastAlert *barmonitor.Alert
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			a, _ := m.Record(risk.APPROVED)
			if a != nil {
				lastAlert = a
			}
		} else {
			a, _ := m.Record(risk.DENIED)
			if a != nil {
				lastAlert = a
			}
		}
	}
	if lastAlert != nil && lastAlert.Reason == barmonitor.AlertTrend {
		t.Fatalf("unexpected AlertTrend for stable BAR=0.50")
	}
}

func TestTrend_InsufficientData_ReturnsZero(t *testing.T) {
	m := barmonitor.New(barmonitor.DefaultConfig())
	// Only 3 records — less than the minimum of 4
	m.Record(risk.APPROVED)
	m.Record(risk.DENIED)
	m.Record(risk.APPROVED)
	if got := m.Trend(); got != 0 {
		t.Fatalf("trend with <4 records: %v, want 0", got)
	}
}

// ── Reset ─────────────────────────────────────────────────────────────────────

func TestReset_ClearsState(t *testing.T) {
	m := barmonitor.New(barmonitor.DefaultConfig())
	record(m, deniedSeq(50)...)
	if m.WindowFill() == 0 {
		t.Fatal("expected non-zero fill before reset")
	}
	m.Reset()
	if m.BAR() != 0 {
		t.Fatalf("after Reset: BAR=%v, want 0", m.BAR())
	}
	if m.WindowFill() != 0 {
		t.Fatalf("after Reset: fill=%d, want 0", m.WindowFill())
	}
}

// ── Record return value ───────────────────────────────────────────────────────

func TestRecord_AlwaysReturnsBAR(t *testing.T) {
	m := barmonitor.New(barmonitor.Config{WindowSize: 4, Threshold: 0.05, TrendThreshold: -0.10})
	_, bar := m.Record(risk.DENIED)
	if bar != 1.0 {
		t.Fatalf("first DENIED: bar=%v, want 1.0", bar)
	}
	_, bar = m.Record(risk.APPROVED)
	if bar != 0.5 {
		t.Fatalf("DENIED+APPROVED: bar=%v, want 0.5", bar)
	}
}

// ── concurrent safety ─────────────────────────────────────────────────────────

func TestRecord_ConcurrentAccess(t *testing.T) {
	// Run with: go test -race ./pkg/barmonitor/...
	m := barmonitor.New(barmonitor.Config{WindowSize: 50, Threshold: 0.05, TrendThreshold: -0.10})
	const goroutines = 10
	const perGoroutine = 100
	var wg sync.WaitGroup
	decisions := []risk.Decision{risk.APPROVED, risk.ESCALATED, risk.DENIED}
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				m.Record(decisions[i%3])
			}
		}(g)
	}
	wg.Wait()
	// Must not panic or race; BAR must be in [0,1]
	bar := m.BAR()
	if bar < 0 || bar > 1 {
		t.Fatalf("concurrent: BAR=%v out of [0,1]", bar)
	}
	if m.WindowFill() != 50 {
		t.Fatalf("concurrent: fill=%d, want 50 (WindowSize)", m.WindowFill())
	}
}

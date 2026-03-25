package main

import (
	"fmt"
	"time"
)

// Metrics captures results for a single experiment run.
type Metrics struct {
	Total            int64
	Approved         int64
	Denied           int64         // real DENIED decisions (DeniedReason == "")
	CooldownHits     int64         // COOLDOWN_ACTIVE decisions
	FirstCooldownAt  int64         // request index when first COOLDOWN_ACTIVE hit; -1 if never
	SuccessfulBefore int64         // requests processed before first COOLDOWN_ACTIVE
	Duration         time.Duration
	Throughput       float64 // requests per second
}

func newMetrics() *Metrics {
	return &Metrics{FirstCooldownAt: -1}
}

// add records a single decision outcome.
// idx is the 0-based request index, used to mark FirstCooldownAt.
func (m *Metrics) add(decision, reason string, idx int64) {
	m.Total++
	switch {
	case reason == "COOLDOWN_ACTIVE":
		m.CooldownHits++
		if m.FirstCooldownAt == -1 {
			m.FirstCooldownAt = idx
			m.SuccessfulBefore = idx
		}
	case decision == "DENIED":
		m.Denied++
	default: // APPROVED or ESCALATED
		m.Approved++
	}
}

func (m *Metrics) finalize(dur time.Duration) {
	m.Duration = dur
	if dur > 0 {
		m.Throughput = float64(m.Total) / dur.Seconds()
	}
	if m.FirstCooldownAt < 0 {
		m.SuccessfulBefore = m.Total
	}
}

func (m *Metrics) print() {
	fmt.Printf("  Total requests       : %d\n", m.Total)
	fmt.Printf("  Approved             : %d\n", m.Approved)
	fmt.Printf("  Denied (real)        : %d\n", m.Denied)
	fmt.Printf("  Cooldown blocked     : %d\n", m.CooldownHits)
	if m.FirstCooldownAt >= 0 {
		fmt.Printf("  First cooldown at    : req #%d (%d requests processed before block)\n",
			m.FirstCooldownAt, m.SuccessfulBefore)
	}
	fmt.Printf("  Duration             : %v\n", m.Duration.Round(time.Microsecond))
	fmt.Printf("  Throughput           : %.0f req/s\n", m.Throughput)
}

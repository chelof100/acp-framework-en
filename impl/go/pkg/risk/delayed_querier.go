package risk

import "time"

// DelayedQuerier wraps any LedgerQuerier and injects a fixed latency before
// each state access call. Used in benchmarks to characterize admission
// throughput as a function of backend latency without external infrastructure.
//
// Each Evaluate() call in the clean (non-cooldown) path triggers 4 LedgerQuerier
// calls: CooldownActive, CountRequests, CountDenials, CountPattern.
// Total per-request injected latency is approximately 4× the per-call value.
//
// This isolates the architectural property that system throughput is bounded
// by state backend latency, not by the admission control logic itself.
type DelayedQuerier struct {
	wrapped LedgerQuerier
	latency time.Duration
}

// NewDelayedQuerier returns a DelayedQuerier that sleeps for latency before
// each call to the underlying querier.
func NewDelayedQuerier(q LedgerQuerier, latency time.Duration) *DelayedQuerier {
	return &DelayedQuerier{wrapped: q, latency: latency}
}

func (d *DelayedQuerier) CountRequests(agentID string, window time.Duration, now time.Time) (int, error) {
	time.Sleep(d.latency)
	return d.wrapped.CountRequests(agentID, window, now)
}

func (d *DelayedQuerier) CountDenials(agentID string, since time.Time) (int, error) {
	time.Sleep(d.latency)
	return d.wrapped.CountDenials(agentID, since)
}

func (d *DelayedQuerier) CountPattern(patternKey string, since time.Time) (int, error) {
	time.Sleep(d.latency)
	return d.wrapped.CountPattern(patternKey, since)
}

func (d *DelayedQuerier) CooldownActive(agentID string, now time.Time) bool {
	time.Sleep(d.latency)
	return d.wrapped.CooldownActive(agentID, now)
}

func (d *DelayedQuerier) CooldownUntil(agentID string) time.Time {
	time.Sleep(d.latency)
	return d.wrapped.CooldownUntil(agentID)
}

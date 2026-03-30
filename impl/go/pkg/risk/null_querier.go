package risk

import "time"

// NullQuerier implements LedgerQuerier with no state.
// All queries return zero counts and no cooldown.
// Used by StatelessEngine to isolate stateless scoring from behavioral accumulation.
type NullQuerier struct{}

func (n *NullQuerier) CountRequests(agentID string, window time.Duration, now time.Time) (int, error) {
	return 0, nil
}
func (n *NullQuerier) CountDenials(agentID string, since time.Time) (int, error) {
	return 0, nil
}
func (n *NullQuerier) CountPattern(patternKey string, since time.Time) (int, error) {
	return 0, nil
}
func (n *NullQuerier) CooldownActive(agentID string, now time.Time) bool { return false }
func (n *NullQuerier) CooldownUntil(agentID string) time.Time            { return time.Time{} }

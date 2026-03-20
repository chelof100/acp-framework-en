// divergence.go — ACP-REP-PORTABILITY-1.1 cross-org score divergence (§7).
package reputation

// ComputeDivergence returns the absolute difference between two ReputationSnapshot scores.
//
// Both snapshots MUST use the same Scale. Comparing snapshots with different scales
// is undefined — callers MUST verify scale equality before calling this function.
func ComputeDivergence(a, b *ReputationSnapshot) float64 {
	diff := a.Score - b.Score
	if diff < 0 {
		diff = -diff
	}
	return diff
}

// CheckDivergence returns whether the score divergence between a and b exceeds threshold,
// along with the computed divergence value.
//
// If exceeded is true, the caller SHOULD emit warning REP-WARN-002 (§10).
// The policy decision — accept, reject, or escalate — remains with the caller.
//
// Recommended default thresholds: 0.30 for scale "0-1", 30.0 for scale "0-100".
func CheckDivergence(a, b *ReputationSnapshot, threshold float64) (exceeded bool, divergence float64) {
	div := ComputeDivergence(a, b)
	return div > threshold, div
}

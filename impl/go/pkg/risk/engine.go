// Package risk implements the ACP-RISK-1.0 deterministic risk assessment engine.
// The risk score is computed from capability sensitivity, resource scope,
// and agent history. This is a reference implementation for v1.0.
package risk

import (
	"strings"
)

// Level represents a risk classification.
type Level int

const (
	LevelLow      Level = iota // Routine operations, read-only, low-value resources
	LevelMedium                // Write operations, moderate-value resources
	LevelHigh                  // Financial, sensitive PII, high-value resources
	LevelCritical              // Irreversible or high-impact financial transactions
)

// String returns the level name for logging and API responses.
func (l Level) String() string {
	switch l {
	case LevelLow:
		return "low"
	case LevelMedium:
		return "medium"
	case LevelHigh:
		return "high"
	case LevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Request represents an authorization request for risk assessment.
type Request struct {
	// AgentID of the requesting agent.
	AgentID string
	// Capability being requested (e.g., "acp:cap:financial.payment").
	Capability string
	// Resource being accessed.
	Resource string
	// Amount is optional; used for financial capability risk scaling.
	Amount *float64
}

// Assessment is the output of the risk engine.
type Assessment struct {
	Level       Level
	Score       int  // 0–100
	RequiresMFA bool // Whether multi-factor approval is required
	Approved    bool // Whether the request passes the risk threshold
}

// thresholdMFA is the score above which MFA is required.
const thresholdMFA = 60

// thresholdDeny is the score above which the request is automatically denied.
// Implementors may configure this per institution.
const thresholdDeny = 90

// Assess computes a deterministic risk score for the request.
// The score is derived from:
//   - Capability sensitivity (financial > operational > read)
//   - Resource scope (broad > specific)
//   - Amount (for financial capabilities)
func Assess(req Request) Assessment {
	score := baseCapabilityScore(req.Capability)
	score += resourceScopeScore(req.Resource)
	if req.Amount != nil {
		score += amountScore(*req.Amount)
	}
	if score > 100 {
		score = 100
	}

	level := scoreToLevel(score)
	return Assessment{
		Level:       level,
		Score:       score,
		RequiresMFA: score >= thresholdMFA,
		Approved:    score < thresholdDeny,
	}
}

// baseCapabilityScore returns a base score from capability classification.
func baseCapabilityScore(cap string) int {
	switch {
	case strings.HasPrefix(cap, "acp:cap:financial."):
		return 50
	case strings.HasPrefix(cap, "acp:cap:data.write"):
		return 30
	case strings.HasPrefix(cap, "acp:cap:data.read"):
		return 10
	case strings.HasPrefix(cap, "acp:cap:system."):
		return 40
	default:
		return 20
	}
}

// resourceScopeScore penalizes broad resource scopes.
func resourceScopeScore(resource string) int {
	parts := strings.Split(resource, "/")
	switch len(parts) {
	case 1:
		return 20 // Institution-wide scope
	case 2:
		return 10 // Top-level resource
	case 3:
		return 5 // Specific resource
	default:
		return 0 // Highly specific sub-resource
	}
}

// amountScore adds risk for high-value financial transactions.
func amountScore(amount float64) int {
	switch {
	case amount > 100000:
		return 30
	case amount > 10000:
		return 20
	case amount > 1000:
		return 10
	default:
		return 0
	}
}

// scoreToLevel maps a numeric score to a risk level.
func scoreToLevel(score int) Level {
	switch {
	case score >= 75:
		return LevelCritical
	case score >= 50:
		return LevelHigh
	case score >= 25:
		return LevelMedium
	default:
		return LevelLow
	}
}

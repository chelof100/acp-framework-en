// Package reputation implements ACP-REP-1.1: the agent reputation extension.
//
// # Model
//
// ACP-REP-1.1 uses a dual-track model:
//   - A continuous score [0.0, 1.0] updated by the EWA formula: score' = α·score + β·event_metric
//   - An administrative state machine: ACTIVE → PROBATION → SUSPENDED → BANNED
//
// # Asymmetry
//
// The event_metric values are intentionally asymmetric. Negative events (−0.30, −0.40)
// are much larger in magnitude than positive events (+0.05, +0.10). This is a deliberate
// security property: an agent that produces an invalid signature needs approximately 6
// successful verifications to recover. The asymmetry disincentivises probe attacks.
//
// # Cold Start
//
// A new agent has score=nil (not 0.0). nil means "no history", not "untrustworthy".
// Each institution defines its own policy for agents with nil score.
//
// # Normative values
//
// event_metric values are fixed in this specification and MUST NOT be changed
// by institutional configuration. They are normative.
package reputation

import "errors"

// ─── State Machine ────────────────────────────────────────────────────────────

// AgentState is the administrative state of an agent in the reputation system.
type AgentState string

const (
	// StateActive is the normal operating state. No restrictions.
	StateActive AgentState = "ACTIVE"

	// StateProbation indicates elevated monitoring. Operations continue but
	// the agent is flagged for review. Triggered when score < ProbationThreshold.
	StateProbation AgentState = "PROBATION"

	// StateSuspended means the agent cannot operate. Triggered when score < SuspensionThreshold
	// or by administrative decision. Recovery requires manual admin action.
	StateSuspended AgentState = "SUSPENDED"

	// StateBanned is a TERMINAL state. Irreversible. No algorithmic or administrative
	// path out of BANNED. This prevents reputation gaming.
	// Triggered by: 3+ critical violations, REV-008 (emergency revocation),
	// or explicit administrative BANNED decision.
	StateBanned AgentState = "BANNED"
)

// ─── Event Types (ACP-REP-1.1 §2.3) ─────────────────────────────────────────

// Event type constants. These are the only valid event types in ACP-REP-1.1 v1.
const (
	EvtVerifyOK        = "REP_EVT_VERIFY_OK"        // Successful token verification
	EvtAuditPass       = "REP_EVT_AUDIT_PASS"       // Institutional audit passed
	EvtSigLate         = "REP_EVT_SIG_LATE"         // Signature submitted after deadline
	EvtTokenMalformed  = "REP_EVT_TOKEN_MALFORMED"  // Token structure is invalid
	EvtRevInvalid      = "REP_EVT_REV_INVALID"      // Token was revoked but still used
	EvtSigInvalid      = "REP_EVT_SIG_INVALID"      // Cryptographic signature is invalid
	EvtPolicyViolation = "REP_EVT_POLICY_VIOLATION" // Institutional policy violated
)

// EventMetrics maps each event type to its fixed event_metric value.
//
// NORMATIVE: These values are defined by ACP-REP-1.1 and MUST NOT be changed
// by configuration. An implementation that allows institutions to change these
// values is NOT ACP-REP-1.1 conformant.
//
// Asymmetry is intentional — see package documentation.
var EventMetrics = map[string]float64{
	EvtVerifyOK:        +0.05,
	EvtAuditPass:       +0.10,
	EvtSigLate:         -0.05,
	EvtTokenMalformed:  -0.10,
	EvtRevInvalid:      -0.20,
	EvtSigInvalid:      -0.30,
	EvtPolicyViolation: -0.40,
}

// ─── Data Types ───────────────────────────────────────────────────────────────

// ReputationRecord is the current state of an agent's reputation.
type ReputationRecord struct {
	AgentID    string     `json:"agent_id"`
	Score      *float64   `json:"score"`       // null = cold start (no history)
	State      AgentState `json:"state"`
	EventCount int        `json:"event_count"`
	UpdatedAt  int64      `json:"updated_at"`
}

// ReputationEvent is a single reputation event applied to an agent.
type ReputationEvent struct {
	AgentID     string   `json:"agent_id"`
	EventType   string   `json:"event_type"`
	EventMetric float64  `json:"event_metric"`
	OldScore    *float64 `json:"old_score"` // null on first event
	NewScore    *float64 `json:"new_score"`
	Timestamp   int64    `json:"timestamp"`
	Note        string   `json:"note,omitempty"`
}

// StateTransition records an administrative state change.
type StateTransition struct {
	AgentID      string     `json:"agent_id"`
	FromState    AgentState `json:"from_state"`
	ToState      AgentState `json:"to_state"`
	Reason       string     `json:"reason"`
	AuthorizedBy string     `json:"authorized_by"`
	Timestamp    int64      `json:"timestamp"`
}

// ─── Configuration ────────────────────────────────────────────────────────────

// Config holds the tunable parameters for the reputation engine.
// event_metric values are NOT here — they are normative and non-configurable.
//
// All parameters are configurable per institution within the specified ranges.
type Config struct {
	// Alpha is the weight of the historical score in the EWA formula.
	// Default: 0.90. Range: [0.80, 0.99].
	// Higher alpha = score changes more slowly (more stable but less reactive).
	Alpha float64

	// Beta is the weight of the current event in the EWA formula.
	// Default: 0.10. Range: [0.01, 0.20].
	// Note: alpha + beta need not equal 1.0. The formula is NOT a convex combination.
	Beta float64

	// ProbationThreshold: score below which ACTIVE → PROBATION.
	// Default: 0.40. Range: [0.20, 0.60].
	ProbationThreshold float64

	// SuspensionThreshold: score below which PROBATION → SUSPENDED.
	// Default: 0.20. Range: [0.10, 0.40].
	SuspensionThreshold float64

	// RecoveryThreshold: score above which PROBATION → ACTIVE (algorithmic).
	// Default: 0.60. Range: [0.50, 0.80].
	// SUSPENDED → ACTIVE always requires manual admin action.
	RecoveryThreshold float64
}

// DefaultConfig returns the default ACP-REP-1.1 configuration.
func DefaultConfig() Config {
	return Config{
		Alpha:               0.90,
		Beta:                0.10,
		ProbationThreshold:  0.40,
		SuspensionThreshold: 0.20,
		RecoveryThreshold:   0.60,
	}
}

// ─── ReputationStore interface ────────────────────────────────────────────────

// ReputationStore persists reputation records, events, and state transitions.
// Implementations MUST be safe for concurrent use.
//
// A conformant ACP-REP-1.1 implementation MUST persist records across restarts.
// InMemoryReputationStore is NOT conformant (development only).
type ReputationStore interface {
	// GetRecord returns the current reputation record for an agent.
	// If the agent has no history, returns a cold-start record:
	//   Score=nil, State=ACTIVE, EventCount=0.
	GetRecord(agentID string) (*ReputationRecord, error)

	// RecordEvent persists a reputation event and updates the agent's score.
	RecordEvent(agentID string, event ReputationEvent) error

	// GetState returns the current administrative state of an agent.
	// Returns StateActive for unknown agents (cold start).
	GetState(agentID string) (AgentState, error)

	// SetState sets the administrative state of an agent.
	// MUST return ErrAgentBanned if the current state is BANNED (terminal).
	SetState(agentID string, state AgentState, reason, authorizedBy string) error

	// GetEvents returns a paginated list of reputation events for an agent.
	// Events are returned most-recent-first.
	// Returns (events, totalCount, error).
	GetEvents(agentID string, limit, offset int) ([]ReputationEvent, int, error)
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	// ErrAgentBanned is returned when an operation is attempted on a BANNED agent.
	// BANNED is a terminal state — no events can be recorded, no state changes allowed.
	ErrAgentBanned = errors.New("acp/reputation: agent is BANNED — terminal state")

	// ErrUnknownEventType is returned when an event type is not in EventMetrics.
	ErrUnknownEventType = errors.New("acp/reputation: unknown event type")

	// ErrInvalidConfig is returned when Config values are out of allowed ranges.
	ErrInvalidConfig = errors.New("acp/reputation: invalid configuration parameter")
)

// ─── ACP-REP-PORTABILITY-1.1 Types ───────────────────────────────────────────

// ReputationSnapshot is the ACP-REP-PORTABILITY-1.1 signed portable score.
//
// ver "1.0" snapshots omit ValidUntil, Scale, and ModelID; expiration is NOT
// enforced for those snapshots (§12 backward compat).
type ReputationSnapshot struct {
	Ver         string  `json:"ver"`
	RepID       string  `json:"rep_id"`
	SubjectID   string  `json:"subject_id"`
	Issuer      string  `json:"issuer"`
	Score       float64 `json:"score"`
	Scale       string  `json:"scale"`
	ModelID     string  `json:"model_id"`
	EvaluatedAt int64   `json:"evaluated_at"`
	ValidUntil  int64   `json:"valid_until"`
	Signature   string  `json:"signature"`
}

// signableReputation mirrors ReputationSnapshot without Signature.
// Used as the canonical payload for Ed25519 signing via JCS (RFC 8785).
type signableReputation struct {
	Ver         string  `json:"ver"`
	RepID       string  `json:"rep_id"`
	SubjectID   string  `json:"subject_id"`
	Issuer      string  `json:"issuer"`
	Score       float64 `json:"score"`
	Scale       string  `json:"scale"`
	ModelID     string  `json:"model_id"`
	EvaluatedAt int64   `json:"evaluated_at"`
	ValidUntil  int64   `json:"valid_until"`
}

// engine.go — ACP-REP-1.1 reputation scoring engine.
package reputation

import (
	"fmt"
	"time"
)

// Engine applies the ACP-REP-1.1 reputation model to a ReputationStore.
// It is the only component that should write to the store in production.
type Engine struct {
	store  ReputationStore
	config Config
}

// NewEngine creates a new reputation engine with the given store and config.
func NewEngine(store ReputationStore, cfg Config) (*Engine, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return &Engine{store: store, config: cfg}, nil
}

// NewDefaultEngine creates a new reputation engine with default configuration.
func NewDefaultEngine(store ReputationStore) *Engine {
	e, _ := NewEngine(store, DefaultConfig()) // DefaultConfig always valid
	return e
}

// ─── Public API ───────────────────────────────────────────────────────────────

// RecordEvent applies a reputation event to an agent's score.
//
// The event type MUST be one of the EvtXxx constants. Unknown event types
// return ErrUnknownEventType.
//
// Events on BANNED agents return ErrAgentBanned without modifying any state.
//
// After updating the score, the engine evaluates automatic state transitions:
//   - ACTIVE     → PROBATION  if score < ProbationThreshold
//   - PROBATION  → SUSPENDED  if score < SuspensionThreshold
//   - PROBATION  → ACTIVE     if score >= RecoveryThreshold (algorithmic recovery)
//
// SUSPENDED → ACTIVE and *→ BANNED always require manual admin action.
func (e *Engine) RecordEvent(agentID, eventType string) error {
	metric, ok := EventMetrics[eventType]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownEventType, eventType)
	}

	record, err := e.store.GetRecord(agentID)
	if err != nil {
		return fmt.Errorf("acp/reputation: get record: %w", err)
	}

	if record.State == StateBanned {
		return ErrAgentBanned
	}

	// ── Compute new score ─────────────────────────────────────────────────
	now := time.Now().Unix()
	var newScore float64
	var oldScore *float64

	if record.Score == nil {
		// Cold start: initialize from neutral baseline (0.5), then apply formula.
		// This ensures first events have meaningful impact without starting at 0.
		newScore = clamp(0.5+e.config.Beta*metric, 0.0, 1.0)
	} else {
		oldScore = record.Score
		newScore = clamp(e.config.Alpha*(*record.Score)+e.config.Beta*metric, 0.0, 1.0)
	}

	event := ReputationEvent{
		AgentID:     agentID,
		EventType:   eventType,
		EventMetric: metric,
		OldScore:    oldScore,
		NewScore:    &newScore,
		Timestamp:   now,
	}

	if err := e.store.RecordEvent(agentID, event); err != nil {
		return fmt.Errorf("acp/reputation: record event: %w", err)
	}

	// ── Evaluate automatic state transitions ──────────────────────────────
	return e.evaluateTransition(agentID, record.State, newScore)
}

// GetRecord returns the current reputation record for an agent.
func (e *Engine) GetRecord(agentID string) (*ReputationRecord, error) {
	return e.store.GetRecord(agentID)
}

// GetEvents returns paginated events for an agent (most-recent-first).
func (e *Engine) GetEvents(agentID string, limit, offset int) ([]ReputationEvent, int, error) {
	if limit <= 0 {
		limit = 20
	}
	return e.store.GetEvents(agentID, limit, offset)
}

// SetState manually sets the administrative state of an agent.
//
// Allowed manual transitions:
//   ACTIVE → PROBATION, SUSPENDED, BANNED
//   PROBATION → ACTIVE, SUSPENDED, BANNED
//   SUSPENDED → ACTIVE, BANNED
//   BANNED → (nothing — terminal)
//
// authorizedBy MUST be the AgentID of the admin performing the action.
func (e *Engine) SetState(agentID string, state AgentState, reason, authorizedBy string) error {
	if reason == "" {
		return fmt.Errorf("acp/reputation: reason must not be empty for state change")
	}
	if authorizedBy == "" {
		return fmt.Errorf("acp/reputation: authorizedBy must not be empty for state change")
	}

	record, err := e.store.GetRecord(agentID)
	if err != nil {
		return fmt.Errorf("acp/reputation: get record: %w", err)
	}
	if record.State == StateBanned {
		return ErrAgentBanned
	}

	return e.store.SetState(agentID, state, reason, authorizedBy)
}

// ─── Internal ─────────────────────────────────────────────────────────────────

// evaluateTransition checks if newScore triggers an automatic state change.
// Only ACTIVE and PROBATION can transition automatically.
// SUSPENDED and BANNED require manual action.
func (e *Engine) evaluateTransition(agentID string, current AgentState, newScore float64) error {
	var next AgentState
	var reason string

	switch current {
	case StateActive:
		if newScore < e.config.SuspensionThreshold {
			next = StateSuspended
			reason = fmt.Sprintf("score %.4f below suspension threshold %.4f", newScore, e.config.SuspensionThreshold)
		} else if newScore < e.config.ProbationThreshold {
			next = StateProbation
			reason = fmt.Sprintf("score %.4f below probation threshold %.4f", newScore, e.config.ProbationThreshold)
		}

	case StateProbation:
		if newScore < e.config.SuspensionThreshold {
			next = StateSuspended
			reason = fmt.Sprintf("score %.4f below suspension threshold %.4f", newScore, e.config.SuspensionThreshold)
		} else if newScore >= e.config.RecoveryThreshold {
			next = StateActive
			reason = fmt.Sprintf("score %.4f recovered above threshold %.4f (algorithmic)", newScore, e.config.RecoveryThreshold)
		}

	default:
		// SUSPENDED and BANNED: no automatic transitions.
		return nil
	}

	if next == "" {
		return nil
	}

	return e.store.SetState(agentID, next, reason, "system")
}

// validateConfig checks that all Config parameters are within allowed ranges.
func validateConfig(cfg Config) error {
	if cfg.Alpha < 0.80 || cfg.Alpha > 0.99 {
		return fmt.Errorf("%w: alpha %.2f not in [0.80, 0.99]", ErrInvalidConfig, cfg.Alpha)
	}
	if cfg.Beta < 0.01 || cfg.Beta > 0.20 {
		return fmt.Errorf("%w: beta %.2f not in [0.01, 0.20]", ErrInvalidConfig, cfg.Beta)
	}
	if cfg.ProbationThreshold < 0.20 || cfg.ProbationThreshold > 0.60 {
		return fmt.Errorf("%w: probation_threshold %.2f not in [0.20, 0.60]", ErrInvalidConfig, cfg.ProbationThreshold)
	}
	if cfg.SuspensionThreshold < 0.10 || cfg.SuspensionThreshold > 0.40 {
		return fmt.Errorf("%w: suspension_threshold %.2f not in [0.10, 0.40]", ErrInvalidConfig, cfg.SuspensionThreshold)
	}
	if cfg.RecoveryThreshold < 0.50 || cfg.RecoveryThreshold > 0.80 {
		return fmt.Errorf("%w: recovery_threshold %.2f not in [0.50, 0.80]", ErrInvalidConfig, cfg.RecoveryThreshold)
	}
	if cfg.SuspensionThreshold >= cfg.ProbationThreshold {
		return fmt.Errorf("%w: suspension_threshold must be < probation_threshold", ErrInvalidConfig)
	}
	return nil
}

// clamp constrains v to [lo, hi].
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
